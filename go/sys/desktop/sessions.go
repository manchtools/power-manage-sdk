// Package desktop discovers active graphical desktop sessions on the
// host so user-scoped actions (Flatpak --user installs, shell scripts
// that need a real $HOME and DBus session bus, etc.) can fan out to
// every currently-signed-in user instead of running under the agent's
// own root context.
//
// The discovery contract is intentionally narrow: only sessions that
//   - are local (Remote=no)
//   - are graphical (Type ∈ {x11, wayland, mir})
//   - are active (Active=yes)
//
// count. SSH sessions, getty TTYs, headless sessions, and inactive
// graphical sessions are filtered out — they don't have a usable
// XDG_RUNTIME_DIR / DBus session bus that user-scoped commands need.
//
// All discovery goes through systemd-logind (`loginctl`). Hosts
// without systemd return an empty list with no error so callers can
// uniformly treat "no signed-in users" as a no-op.
package desktop

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
)

// Session is a single active graphical desktop session.
//
// All fields are populated from systemd-logind (loginctl) plus a
// passwd lookup for Home / GID. Callers should treat the struct as
// immutable — the SDK constructs it once per ActiveSessions call.
type Session struct {
	// ID is the systemd-logind session ID (e.g. "c1", "2"). Stable for
	// the lifetime of the session; not stable across logout/login.
	ID string
	// Username is the Linux account name (`loginctl show-session ... -p Name`).
	Username string
	// UID is the numeric user ID. Used to derive XDG_RUNTIME_DIR.
	UID int
	// GID is the user's primary group ID, looked up via os/user.
	GID int
	// Home is the user's home directory, looked up via os/user. Required
	// for Flatpak --user installs (which resolve everything against
	// $HOME) and for shell scripts that expect a sane working directory.
	Home string
	// RuntimeDir is /run/user/<UID>. Populated unconditionally — the
	// caller decides whether to verify it exists before invoking a
	// command that needs it (e.g. anything touching DBus).
	RuntimeDir string
	// Type is the session type (`x11`, `wayland`, `mir`). Always one of
	// the graphical types because non-graphical sessions are filtered
	// out before construction.
	Type string
}

// loginctlPath is the absolute path to the loginctl binary. Pinned to
// /usr/bin/loginctl because that's where systemd installs it on every
// supported distro and absolute paths sidestep PATH-injection
// concerns when the agent runs as root.
const loginctlPath = "/usr/bin/loginctl"

// ActiveSessions returns every active local graphical session on the
// host, ready for fanning a user-scoped command out to each.
//
// Returns an empty slice (not an error) when:
//   - loginctl is missing (host without systemd-logind)
//   - no graphical sessions are active (machine is at login screen,
//     headless server, etc.)
//
// Returns an error only when loginctl is present but its output is
// malformed or the per-session detail probe fails for a reason other
// than the session disappearing mid-call.
func ActiveSessions(ctx context.Context) ([]Session, error) {
	if _, err := exec.LookPath(loginctlPath); err != nil {
		// Host doesn't ship systemd-logind. Treat as "no sessions" so
		// the caller's empty-set policy (skip-with-warn vs fail) drives
		// the user-facing behavior consistently regardless of the
		// underlying init system.
		return nil, nil
	}

	ids, err := listSessionIDs(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]Session, 0, len(ids))
	for _, id := range ids {
		s, ok, err := loadSession(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("loginctl show-session %q: %w", id, err)
		}
		if !ok {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

// listSessionIDs runs `loginctl list-sessions --no-legend` and returns
// the bare session IDs from the first column. The --no-legend flag
// suppresses the trailing "N sessions listed" line which would
// otherwise leak into the parse loop on older systemd builds.
//
// Returns ([], nil) — not an error — when systemd-logind isn't
// running on the host. Loginctl reports this in two distinct ways
// depending on the underlying failure mode:
//
//   - "System has not been booted with systemd as init system (PID 1).
//     Can't operate." — typical inside docker/podman containers, CI
//     runners, and minimal Linux setups using SysV/OpenRC. The binary
//     is on PATH but logind has nothing to connect to.
//   - "Failed to connect to bus: ..." — loginctl is present and
//     systemd is PID 1, but the user dbus / system bus path is
//     unavailable (sandbox restrictions, namespace gaps).
//
// Either case is "no usable logind, no sessions to report" rather
// than a true probe failure — the caller's empty-set policy
// (skip-with-Warn for installs, no-op for uninstalls) gives the
// right end-user behavior. Only loginctl errors that AREN'T one of
// those two patterns get surfaced as an actual error so genuine
// permission/IO faults still page operators.
func listSessionIDs(ctx context.Context) ([]string, error) {
	cmd := exec.CommandContext(ctx, loginctlPath, "list-sessions", "--no-legend")
	stdout, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if isLoginctlNoLogindStderr(string(exitErr.Stderr)) {
				return nil, nil
			}
			return nil, fmt.Errorf("loginctl list-sessions failed: %w (stderr: %s)", err, string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("loginctl list-sessions: %w", err)
	}
	var ids []string
	for _, line := range strings.Split(string(stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		ids = append(ids, fields[0])
	}
	return ids, nil
}

// loadSession runs `loginctl show-session <id> -p ...` and returns a
// fully-populated Session if the session passes the active+local+
// graphical filter, or (zero, false, nil) if it should be skipped.
//
// Returns an error only on truly-broken probes: a missing session
// (race with logout) is treated as "skip" rather than failing the
// whole ActiveSessions call.
func loadSession(ctx context.Context, id string) (Session, bool, error) {
	cmd := exec.CommandContext(ctx, loginctlPath, "show-session", id,
		"--property=Name",
		"--property=User",
		"--property=Type",
		"--property=Active",
		"--property=Remote",
	)
	stdout, err := cmd.Output()
	if err != nil {
		// Session disappeared between list-sessions and show-session
		// — common when a user logs out concurrently with our probe.
		// loginctl exits 1 with "Failed to get session: No session
		// 'X'." on stderr in that case. Skip rather than fail.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if strings.Contains(string(exitErr.Stderr), "No session") {
				return Session{}, false, nil
			}
			return Session{}, false, fmt.Errorf("%w (stderr: %s)", err, string(exitErr.Stderr))
		}
		return Session{}, false, err
	}

	props := parseLoginctlProperties(string(stdout))
	if props["Remote"] != "no" {
		return Session{}, false, nil
	}
	if props["Active"] != "yes" {
		return Session{}, false, nil
	}
	if !isGraphicalType(props["Type"]) {
		return Session{}, false, nil
	}

	uidStr := props["User"]
	uid, err := strconv.Atoi(uidStr)
	if err != nil {
		return Session{}, false, fmt.Errorf("loginctl returned non-numeric User=%q for session %q", uidStr, id)
	}

	// passwd lookup for Home + GID. Username from logind is
	// authoritative for "who's signed in," but we still need the
	// passwd entry for $HOME — logind's session metadata doesn't
	// carry it.
	u, err := user.LookupId(uidStr)
	if err != nil {
		// Account exists in logind but not in passwd — extremely
		// unusual (would mean the user was deleted while logged in).
		// Skip rather than synthesize a fake $HOME.
		return Session{}, false, nil
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return Session{}, false, fmt.Errorf("non-numeric GID %q for user %q", u.Gid, u.Username)
	}

	return Session{
		ID:         id,
		Username:   props["Name"],
		UID:        uid,
		GID:        gid,
		Home:       u.HomeDir,
		RuntimeDir: "/run/user/" + uidStr,
		Type:       props["Type"],
	}, true, nil
}

// parseLoginctlProperties parses the `Key=Value` lines that
// `loginctl show-session ... -p Key` emits. One key per line,
// no quoting (loginctl already strips it for the property form).
func parseLoginctlProperties(s string) map[string]string {
	out := make(map[string]string, 8)
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		out[line[:eq]] = line[eq+1:]
	}
	return out
}

// isGraphicalType reports whether the loginctl "Type" property names
// a session that owns a desktop ($DISPLAY / Wayland socket). Pinned
// here rather than inlined so future session types (e.g. a hypothetical
// "wayland-headless") can be added in one place.
func isGraphicalType(t string) bool {
	switch t {
	case "x11", "wayland", "mir":
		return true
	default:
		return false
	}
}

// isLoginctlNoLogindStderr matches the two stderr fingerprints
// loginctl produces when systemd-logind is not available to query —
// distinct from genuine probe failures (permission denied, IO error)
// which should still surface to the caller.
//
// Match on substrings rather than exact equality so the helper
// survives a localised systemd build (rare on the agent's target
// distros but cheap to be tolerant of) or a future systemd that
// rewords the message slightly. The substrings chosen are stable
// across every systemd version since v220 (2015) on Linux.
func isLoginctlNoLogindStderr(stderr string) bool {
	switch {
	case strings.Contains(stderr, "has not been booted with systemd"):
		return true
	case strings.Contains(stderr, "Failed to connect to bus"):
		return true
	default:
		return false
	}
}
