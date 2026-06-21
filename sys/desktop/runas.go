package desktop

import (
	"strings"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// EnvFor builds the minimum environment a user-scoped command needs
// to behave like it was launched from inside that user's desktop
// session: HOME, USER, LOGNAME, XDG_RUNTIME_DIR, plus DBUS_SESSION_BUS_ADDRESS
// (so commands that talk to the user's session bus — Flatpak's
// notification path, GNOME settings, etc. — find it without falling
// back to a fresh autolaunched bus).
//
// PATH is not added here — callers append it (via UserPath) so they can
// pick a curated value rather than inherit the agent's PATH; RunAsRunner
// passes UserPath(s) as the trusted child PATH.
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

// validateExtraEnv runs a caller's extra env through the Runner's env hijack
// gate (exec.ValidateCommandEnv) so a desktop run-as inherits the same
// LD_PRELOAD/LD_LIBRARY_PATH/GCONV_PATH refusal as every Runner-driven command.
// PATH entries are dropped before the gate: the per-user run-as always overrides
// PATH with the curated UserPath, so a caller "PATH=" value is inert and is not a
// hijack — exec.ValidateCommandEnv would otherwise reject it (PATH is on the
// blocklist) and break the documented PATH-is-re-applied contract.
func validateExtraEnv(extraEnv []string) error {
	filtered := make([]string, 0, len(extraEnv))
	for _, e := range extraEnv {
		if key, _, ok := strings.Cut(e, "="); ok && key == "PATH" {
			continue // overridden by UserPath; never forwarded, so never a hijack
		}
		filtered = append(filtered, e)
	}
	return pmexec.ValidateCommandEnv(filtered)
}
