package desktop

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	pmexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
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
func (m *manager) ActiveSessions(ctx context.Context) ([]Session, error) {
	if _, pathErr := lookPath(loginctlPath); pathErr != nil {
		// Host doesn't ship systemd-logind. Treat as "no sessions" so
		// the caller's empty-set policy (skip-with-warn vs fail) drives
		// the user-facing behavior consistently regardless of the
		// underlying init system. Return a non-nil empty slice to match
		// the documented contract and the success path's make(). (pathErr
		// is named distinctly from err so the nilerr linter sees this is
		// an intentional "absent → empty, no error" mapping.)
		return []Session{}, nil
	}

	ids, err := m.listSessionIDs(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]Session, 0, len(ids))
	for _, id := range ids {
		s, ok, err := m.loadSession(ctx, id)
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

// listSessionIDs runs `loginctl list-sessions --no-legend` through the Runner
// and returns the bare session IDs from the first column. The --no-legend flag
// suppresses the trailing "N sessions listed" line which would otherwise leak
// into the parse loop on older systemd builds.
//
// The command runs through the Runner (no escalation needed for loginctl), so it
// inherits the forced C locale — the no-logind stderr fingerprints below are
// therefore matched against stable English text regardless of the host locale.
//
// Returns ([], nil) — not an error — when systemd-logind isn't running on the
// host. Loginctl reports this in two distinct ways depending on the underlying
// failure mode:
//
//   - "System has not been booted with systemd as init system (PID 1).
//     Can't operate." — typical inside docker/podman containers, CI runners, and
//     minimal Linux setups using SysV/OpenRC. The binary is on PATH but logind
//     has nothing to connect to.
//   - "Failed to connect to bus: ..." — loginctl is present and systemd is
//     PID 1, but the user dbus / system bus path is unavailable (sandbox
//     restrictions, namespace gaps).
//
// Either case is "no usable logind, no sessions to report" rather than a true
// probe failure — the caller's empty-set policy (skip-with-Warn for installs,
// no-op for uninstalls) gives the right end-user behavior. Only loginctl errors
// that AREN'T one of those two patterns get surfaced as an actual error so
// genuine permission/IO faults still page operators.
func (m *manager) listSessionIDs(ctx context.Context) ([]string, error) {
	res, err := m.r.Run(ctx, pmexec.Command{Name: loginctlPath, Args: []string{"list-sessions", "--no-legend"}})
	if err != nil {
		return nil, fmt.Errorf("loginctl list-sessions: %w", err)
	}
	if res.ExitCode != 0 {
		if isLoginctlNoLogindStderr(res.Stderr) {
			return nil, nil
		}
		return nil, fmt.Errorf("loginctl list-sessions failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	var ids []string
	for _, line := range strings.Split(res.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// A non-empty trimmed line always has a first field; take it as the ID.
		ids = append(ids, strings.Fields(line)[0])
	}
	return ids, nil
}

// loadSession runs `loginctl show-session <id> -p ...` through the Runner and
// returns a fully-populated Session if the session passes the active+local+
// graphical filter, or (zero, false, nil) if it should be skipped.
//
// Returns an error only on truly-broken probes: a missing session (race with
// logout) is treated as "skip" rather than failing the whole ActiveSessions
// call.
func (m *manager) loadSession(ctx context.Context, id string) (Session, bool, error) {
	res, err := m.r.Run(ctx, pmexec.Command{Name: loginctlPath, Args: []string{
		"show-session", id,
		"--property=Name",
		"--property=User",
		"--property=Type",
		"--property=Active",
		"--property=Remote",
	}})
	if err != nil {
		return Session{}, false, fmt.Errorf("loginctl show-session: %w", err)
	}
	if res.ExitCode != 0 {
		// Session disappeared between list-sessions and show-session — common
		// when a user logs out concurrently with our probe. loginctl exits
		// non-zero with "Failed to get session: No session 'X'." on stderr in
		// that case. Skip rather than fail.
		if strings.Contains(res.Stderr, "No session") {
			return Session{}, false, nil
		}
		return Session{}, false, fmt.Errorf("exit %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}

	props := parseLoginctlProperties(res.Stdout)
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

	// passwd lookup for Home + GID. Username from logind is authoritative for
	// "who's signed in," but we still need the passwd entry for $HOME — logind's
	// session metadata doesn't carry it.
	u, err := lookupID(uidStr)
	if err != nil {
		// Account exists in logind but not in passwd — extremely unusual (would
		// mean the user was deleted while logged in). Skip rather than
		// synthesize a fake $HOME.
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
// survives a future systemd that rewords the message slightly. The
// substrings chosen are stable across every systemd version since v220
// (2015) on Linux. The loginctl probe runs under the forced C locale
// (it goes through the Runner), so these English fingerprints are not
// defeated by the host's configured language.
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
