package exec

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PrivilegeBackend selects how a Runner escalates privilege for a Command whose
// Escalate flag is set. The zero value is INVALID (fail-closed): NewRunner
// rejects it with ErrUnknownBackend. Valid values start at 1 (Decision 5/6).
type PrivilegeBackend int

const (
	// Sudo escalates via `sudo -n` (non-interactive; never prompts).
	Sudo PrivilegeBackend = iota + 1
	// Doas escalates via `doas -n`.
	Doas
	// Direct runs with no wrapper — the process is already root. Rolling our
	// own no-op pass-through avoids sudo's distro-varying "root must be in
	// sudoers" check (opensuse rejects it by default) and the cost of forking
	// sudo just to re-exec the same binary.
	Direct
)

// Command describes one execution. The zero value is invalid — Name is
// required. The capability layer fills this in and sets Escalate per operation;
// it is escalation-method-agnostic. The Runner alone turns Escalate into the
// concrete sudo/doas/bare invocation.
type Command struct {
	Name      string    // resolved to an absolute path before escalation
	Args      []string  // operands; the caller pre-applies SeparatePositionals
	Dir       string    // "" = inherit cwd
	Env       []string  // extra KEY=VALUE; screened by the env hijack blocklist
	Stdin     io.Reader // "" = no stdin
	CLocale   bool      // force LC_ALL=C / LANG=C for stable English-only parsing
	ChildPath string    // explicit, isolating child PATH; "" = inherit/sanitized
	Escalate  bool      // run through the privilege backend
}

// Runner abstracts command execution + privilege escalation. It is injected
// into every capability constructor (Decision 2) so the SDK keeps no global
// escalation state and the whole capability layer is unit-testable with a fake
// (see exectest.FakeRunner) — no host, no sudo, no container.
type Runner interface {
	// Run executes c and returns its captured output. A non-zero exit is
	// reported in Result.ExitCode, NOT as an error; a non-nil error means the
	// command could not be executed (binary not found, blocked env var, ctx
	// cancelled) or escalation failed (ErrEscalation*).
	Run(ctx context.Context, c Command) (Result, error)
	// Stream is Run with real-time line delivery via onLine.
	Stream(ctx context.Context, c Command, onLine OutputCallback) (Result, error)
	// Backend reports the privilege backend, so a capability (e.g. fs) can pick
	// its fd-safe vs sudo code path.
	Backend() PrivilegeBackend
}

type runner struct{ backend PrivilegeBackend }

// NewRunner builds a Runner for the named backend. It is PURE: it validates the
// backend is known and does NOT probe the host (use Detect for that). The zero
// value and any unimplemented backend are rejected with ErrUnknownBackend.
func NewRunner(b PrivilegeBackend) (Runner, error) {
	switch b {
	case Sudo, Doas, Direct:
		return &runner{backend: b}, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownBackend, int(b))
	}
}

func (r *runner) Backend() PrivilegeBackend { return r.backend }

func (r *runner) Run(ctx context.Context, c Command) (Result, error) {
	return r.exec(ctx, c, nil)
}

func (r *runner) Stream(ctx context.Context, c Command, onLine OutputCallback) (Result, error) {
	return r.exec(ctx, c, onLine)
}

func (r *runner) exec(ctx context.Context, c Command, onLine OutputCallback) (Result, error) {
	// Fail closed on an already-cancelled context: never start a command with a
	// dead ctx (go-cmd's select could otherwise let a fast command win the race
	// against ctx.Done() and report success). Keeps the real Runner and the
	// fake behaviourally identical on cancellation.
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if c.Name == "" {
		return Result{}, fmt.Errorf("exec: command name is required")
	}
	// Compose + validate the child env FIRST, so a blocked env var (LD_PRELOAD,
	// PATH, …) is rejected before the child is ever spawned.
	env, err := buildChildEnv(c)
	if err != nil {
		return Result{}, err
	}
	// Resolve to an absolute path so it matches sudoers/doas.conf rules and is
	// deterministic regardless of the child's PATH.
	absPath, err := resolveAbsolute(c.Name)
	if err != nil {
		return Result{}, fmt.Errorf("command not found: %s", c.Name)
	}
	// When escalating through a wrapper, the wrapper itself must be installed —
	// fail closed with ErrEscalationUnavailable rather than running unescalated.
	if c.Escalate {
		if tool := escalationTool(r.backend); tool != "" {
			if _, err := exec.LookPath(tool); err != nil {
				return Result{}, fmt.Errorf("%w: %s", ErrEscalationUnavailable, tool)
			}
		}
	}
	name, argv := wrapEscalation(r.backend, c.Escalate, absPath, c.Args)

	res, runErr := runStreamingWithStdin(ctx, name, argv, c.Stdin, env, c.Dir, onLine)
	result := Result{}
	if res != nil {
		result = *res
	}
	if runErr != nil {
		return result, runErr
	}
	// A sudo/doas -n auth refusal is an escalation failure, distinct from the
	// wrapped command's own non-zero exit.
	if c.Escalate {
		if denied := detectEscalationDenied(r.backend, result); denied != nil {
			return result, denied
		}
	}
	return result, nil
}

// resolveAbsolute resolves name to an ABSOLUTE executable path. exec.LookPath
// returns a slash-containing relative name unchanged (e.g. "./tool") and with a
// nil error, so its result is not guaranteed absolute; filepath.Abs enforces it.
// An absolute path is required by the escalation contract — sudoers/doas match
// on absolute paths, and escalating a relative path is a security risk.
func resolveAbsolute(name string) (string, error) {
	p, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	return filepath.Abs(p)
}

// escalationTool returns the wrapper binary for a backend, or "" when the
// backend needs no wrapper (Direct).
func escalationTool(b PrivilegeBackend) string {
	switch b {
	case Sudo:
		return "sudo"
	case Doas:
		return "doas"
	default:
		return ""
	}
}

// wrapEscalation turns (backend, escalate, absolute-path, args) into the final
// (name, argv). Pure: no I/O. When escalation is requested and the backend uses
// a wrapper, the wrapper runs with -n (never prompt) and the resolved absolute
// path. The caller's args slice is never aliased or mutated.
func wrapEscalation(b PrivilegeBackend, escalate bool, absPath string, args []string) (string, []string) {
	tool := escalationTool(b)
	if !escalate || tool == "" { // bare invocation (no escalation, or Direct)
		return absPath, append([]string(nil), args...)
	}
	argv := make([]string, 0, len(args)+2)
	argv = append(argv, "-n", absPath)
	argv = append(argv, args...)
	return tool, argv
}

// detectEscalationDenied recognises a sudo/doas -n refusal (a password would be
// required) and turns it into ErrEscalationDenied — distinct from the wrapped
// command's own non-zero exit. Pure: it inspects only the Result, and matches
// the wrappers' own diagnostic strings so a genuine command failure is never
// misclassified.
func detectEscalationDenied(b PrivilegeBackend, res Result) error {
	if res.ExitCode == 0 {
		return nil
	}
	s := res.Stderr
	switch b {
	case Sudo:
		if strings.Contains(s, "a password is required") ||
			strings.Contains(s, "a terminal is required") ||
			strings.Contains(s, "no askpass program") {
			return fmt.Errorf("%w: %s", ErrEscalationDenied, strings.TrimSpace(s))
		}
	case Doas:
		if strings.Contains(s, "Authorization required") ||
			strings.Contains(s, "Authentication failed") {
			return fmt.Errorf("%w: %s", ErrEscalationDenied, strings.TrimSpace(s))
		}
	}
	return nil
}

// buildChildEnv composes and validates the Command's child environment. The
// hijack blocklist (LD_PRELOAD, PATH, BASH_ENV, …) is enforced on Command.Env;
// a curated PATH goes through ChildPath, which REPLACES (never augments) the
// parent env — the isolation the per-user runuser fan-out needs. A nil return
// means "inherit the parent fully" (the contract when no customization is
// requested).
func buildChildEnv(c Command) ([]string, error) {
	extra := append([]string(nil), c.Env...)
	if c.CLocale {
		extra = append(extra, "LC_ALL=C", "LANG=C")
	}
	if err := validateEnvVars(extra); err != nil {
		return nil, err
	}
	if c.ChildPath != "" {
		return composeEnv(c.ChildPath, extra), nil // curated PATH; parent NOT inherited
	}
	if len(extra) > 0 {
		return composeEnv(os.Getenv("PATH"), extra), nil // sanitized parent PATH + extras
	}
	return nil, nil // inherit parent fully
}
