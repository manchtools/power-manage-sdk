package desktop

import (
	"context"
	"fmt"
	osexec "os/exec"
	"strings"
)

// EnvFor builds the minimum environment a user-scoped command needs
// to behave like it was launched from inside that user's desktop
// session: HOME, USER, LOGNAME, XDG_RUNTIME_DIR, plus DBUS_SESSION_BUS_ADDRESS
// (so commands that talk to the user's session bus — Flatpak's
// notification path, GNOME settings, etc. — find it without falling
// back to a fresh autolaunched bus).
//
// PATH is not added here — callers append it (via UserPath) so they can
// pick a curated value rather than inherit the agent's PATH. RunAsCommand
// does this for the non-streaming path; the streaming caller passes
// UserPath(s) as the trusted child PATH.
func EnvFor(s Session) []string {
	return []string{
		"HOME=" + s.Home,
		"USER=" + s.Username,
		"LOGNAME=" + s.Username,
		"XDG_RUNTIME_DIR=" + s.RuntimeDir,
		"DBUS_SESSION_BUS_ADDRESS=unix:path=" + s.RuntimeDir + "/bus",
	}
}

// UserPath returns the curated PATH a per-user command should run with.
// It is built from the session — never from the agent's (root's) PATH —
// so a user-scoped command does not inherit root-only entries, and the
// user's own bin dirs come first so ~/.local/bin shadows a system binary
// of the same name. sbin dirs are included because usr-merged distros
// put them on every user's default PATH and a user running an sbin
// binary does so unprivileged (their own UID); excluding them only
// breaks command resolution without any privilege benefit.
func UserPath(s Session) string {
	return strings.Join([]string{
		s.Home + "/.local/bin",
		s.Home + "/bin",
		"/usr/local/bin",
		"/usr/bin",
		"/bin",
		"/usr/local/sbin",
		"/usr/sbin",
		"/sbin",
	}, ":")
}

// RunAsCommand returns an *exec.Cmd that runs `name args...` as the
// user owning the given session, with the per-user environment from
// EnvFor plus the caller-supplied opts.ExtraEnv merged on top.
//
// The wrapper is `runuser -u <name> -- <name> <args...>`. We use
// runuser rather than `sudo -u` because runuser doesn't go through
// sudoers (no policy to misconfigure, no audit-noise from auth
// failures) and has been part of util-linux on every supported
// distro since well before the lowest target.
//
// This path does NOT go through the SDK Runner and does NOT force the C
// locale: the command runs ON BEHALF OF a real user (a Flatpak install, a
// user script) whose output the SDK never parses, so the user keeps their
// own locale. The Runner's forced-C is for SDK-parsed probes only.
//
// opts.ExtraEnv may include anything action-specific; entries win over the
// per-user defaults if both set the same key (Go's exec honors the last
// occurrence) — except PATH, which is always re-applied last with the curated
// UserPath so an action cannot override it.
//
// Returns an error if name is empty (programming bug — runuser's own error in
// that case is a confusing "exec: required") or if the session has no Username
// (would silently run as the agent's own UID).
func (m *manager) RunAsCommand(ctx context.Context, s Session, opts RunAsOptions, name string, args ...string) (*osexec.Cmd, error) {
	if name == "" {
		return nil, fmt.Errorf("desktop.RunAsCommand: name is required")
	}
	if s.Username == "" {
		return nil, fmt.Errorf("desktop.RunAsCommand: session has empty Username")
	}
	full := append([]string{"-u", s.Username, "--", name}, args...)
	cmd := osexec.CommandContext(ctx, runuserPath, full...)
	// Replace inherited env wholesale — agent's env (LD_PRELOAD,
	// LD_LIBRARY_PATH, etc.) must not leak into a user-scoped command.
	// Caller's ExtraEnv is merged on top, then the curated user PATH is
	// applied LAST so it wins under exec's last-occurrence semantics: an
	// action must not be able to override PATH (parity with the
	// streaming path, which refuses a caller-supplied PATH outright).
	env := append(EnvFor(s), opts.ExtraEnv...)
	env = append(env, "PATH="+UserPath(s))
	cmd.Env = env
	cmd.Dir = s.Home
	return cmd, nil
}
