package desktop

import (
	"context"
	"fmt"
	"strings"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// RunAsRunner wraps a base [exec.Runner] so every command it runs executes AS the
// session's user via runuser, with that user's desktop session environment (HOME,
// USER, XDG_RUNTIME_DIR, the session bus address) and the curated per-user PATH.
//
// It lets a capability built on the SDK Runner operate on behalf of a specific
// logged-in user without that capability knowing anything about runuser — most
// usefully a per-user Flatpak Manager:
//
//	r, _ := exec.NewRunner(exec.Direct) // the agent runs as root
//	ru, _ := desktop.RunAsRunner(r, session)
//	fp, _ := pkg.New(pkg.Flatpak, ru, pkg.WithUserScope())
//	fp.Install(ctx, pkg.InstallOptions{Remote: "flathub"}, "org.x.App") // installs for `session`
//
// The base Runner MUST run as root: runuser performs the privilege DROP to the
// target user, so the wrapped command is never escalated again. The caller's
// command env is screened by the same hijack blocklist as RunAsCommand.
func RunAsRunner(base pmexec.Runner, s Session) (pmexec.Runner, error) {
	if base == nil {
		return nil, fmt.Errorf("desktop.RunAsRunner: %w", pmexec.ErrRunnerRequired)
	}
	if s.Username == "" {
		return nil, fmt.Errorf("desktop.RunAsRunner: session has empty Username")
	}
	return &runAsRunner{base: base, s: s}, nil
}

type runAsRunner struct {
	base pmexec.Runner
	s    Session
}

func (ra *runAsRunner) Backend() pmexec.PrivilegeBackend { return ra.base.Backend() }

func (ra *runAsRunner) Run(ctx context.Context, c pmexec.Command) (pmexec.Result, error) {
	wrapped, err := ra.wrap(c)
	if err != nil {
		return pmexec.Result{}, err
	}
	return ra.base.Run(ctx, wrapped)
}

func (ra *runAsRunner) Stream(ctx context.Context, c pmexec.Command, onLine pmexec.OutputCallback) (pmexec.Result, error) {
	wrapped, err := ra.wrap(c)
	if err != nil {
		return pmexec.Result{}, err
	}
	return ra.base.Stream(ctx, wrapped, onLine)
}

// wrap rewrites c into `runuser -u <user> -- env <session-env> PATH=<curated>
// <name> <args...>`, running it as the session user with that user's desktop
// environment. PATH is forced last (a caller PATH is dropped, like RunAsCommand);
// the rest of the caller's env is screened through the hijack blocklist because
// it is spliced into the inner env wrapper, which the base Runner does not screen.
func (ra *runAsRunner) wrap(c pmexec.Command) (pmexec.Command, error) {
	if c.Name == "" {
		return pmexec.Command{}, fmt.Errorf("desktop.RunAsRunner: command name is required")
	}
	if err := validateExtraEnv(c.Env); err != nil {
		return pmexec.Command{}, err
	}
	env := EnvFor(ra.s)
	for _, e := range c.Env {
		if key, _, ok := strings.Cut(e, "="); ok && key == "PATH" {
			continue // PATH is always forced to the curated UserPath below
		}
		env = append(env, e)
	}
	env = append(env, "PATH="+UserPath(ra.s))

	args := append([]string{"-u", ra.s.Username, "--", envPath}, env...)
	args = append(args, c.Name)
	args = append(args, c.Args...)
	return pmexec.Command{
		Name:     runuserPath,
		Args:     args,
		Stdin:    c.Stdin,
		Escalate: false, // runuser from root IS the privilege drop
	}, nil
}
