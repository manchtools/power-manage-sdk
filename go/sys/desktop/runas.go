package desktop

import (
	"context"
	"fmt"
	"os/exec"
)

// runuserPath pins the absolute path to runuser. Like loginctlPath,
// pinning sidesteps PATH-injection concerns when the agent runs as
// root and matches what every supported distro ships.
const runuserPath = "/usr/sbin/runuser"

// EnvFor builds the minimum environment a user-scoped command needs
// to behave like it was launched from inside that user's desktop
// session: HOME, USER, LOGNAME, XDG_RUNTIME_DIR, plus DBUS_SESSION_BUS_ADDRESS
// (so commands that talk to the user's session bus — Flatpak's
// notification path, GNOME settings, etc. — find it without falling
// back to a fresh autolaunched bus).
//
// PATH is not added here — callers append it themselves so they can
// pick a curated value rather than inherit the agent's PATH (which
// may include /usr/local/sbin and other privileged dirs the user
// shouldn't reach via subshell expansion).
func EnvFor(s Session) []string {
	return []string{
		"HOME=" + s.Home,
		"USER=" + s.Username,
		"LOGNAME=" + s.Username,
		"XDG_RUNTIME_DIR=" + s.RuntimeDir,
		"DBUS_SESSION_BUS_ADDRESS=unix:path=" + s.RuntimeDir + "/bus",
	}
}

// RunAsCommand returns an *exec.Cmd that runs `name args...` as the
// user owning the given session, with the per-user environment from
// EnvFor plus the caller-supplied extraEnv merged on top.
//
// The wrapper is `runuser -u <name> -- <name> <args...>`. We use
// runuser rather than `sudo -u` because runuser doesn't go through
// sudoers (no policy to misconfigure, no audit-noise from auth
// failures) and has been part of util-linux on every supported
// distro since well before the lowest target.
//
// extraEnv may include PATH or anything action-specific; entries win
// over the per-user defaults if both set the same key (Go's exec
// honors the last occurrence).
//
// Returns an error if name is empty (programming bug) — runuser's
// own error in that case is a confusing "exec: required") so
// short-circuit with something meaningful.
func RunAsCommand(ctx context.Context, s Session, extraEnv []string, name string, args ...string) (*exec.Cmd, error) {
	if name == "" {
		return nil, fmt.Errorf("desktop.RunAsCommand: name is required")
	}
	if s.Username == "" {
		return nil, fmt.Errorf("desktop.RunAsCommand: session has empty Username")
	}
	full := append([]string{"-u", s.Username, "--", name}, args...)
	cmd := exec.CommandContext(ctx, runuserPath, full...)
	// Replace inherited env wholesale — agent's env (LD_PRELOAD,
	// LD_LIBRARY_PATH, etc.) must not leak into a user-scoped
	// command. Caller's extraEnv is appended last so it wins on
	// duplicate keys.
	cmd.Env = append(EnvFor(s), extraEnv...)
	cmd.Dir = s.Home
	return cmd, nil
}
