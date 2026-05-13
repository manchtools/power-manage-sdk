package desktop

import (
	"strings"
	"testing"
)

func TestParseLoginctlProperties(t *testing.T) {
	in := strings.Join([]string{
		"Name=alice",
		"User=1000",
		"Type=wayland",
		"Active=yes",
		"Remote=no",
		"",
	}, "\n")

	got := parseLoginctlProperties(in)
	want := map[string]string{
		"Name":   "alice",
		"User":   "1000",
		"Type":   "wayland",
		"Active": "yes",
		"Remote": "no",
	}
	if len(got) != len(want) {
		t.Fatalf("parseLoginctlProperties: got %d keys, want %d (got=%v)", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("key %q: got %q, want %q", k, got[k], v)
		}
	}
}

func TestParseLoginctlProperties_IgnoresMalformed(t *testing.T) {
	in := strings.Join([]string{
		"Name=alice",
		"no_equals_here",
		"=empty_key",
		"Active=yes",
	}, "\n")
	got := parseLoginctlProperties(in)
	if got["Name"] != "alice" || got["Active"] != "yes" {
		t.Errorf("legitimate keys lost when parsing malformed lines: %v", got)
	}
	if _, ok := got["no_equals_here"]; ok {
		t.Errorf("malformed line treated as a key: %v", got)
	}
	if _, ok := got[""]; ok {
		t.Errorf("empty-key line silently kept: %v", got)
	}
}

func TestIsGraphicalType(t *testing.T) {
	tests := map[string]bool{
		// Anything that owns a display surface counts. Pinning the
		// allow-list rather than excluding from a blocklist keeps a
		// future systemd session-type addition (say, "wayland-headless")
		// from accidentally enabling user-scoped fan-out into a
		// session that has no usable DBus / XDG runtime dir.
		"x11":     true,
		"wayland": true,
		"mir":     true,
		// Common non-graphical types we explicitly do NOT fan out to
		// — these have no $DISPLAY / Wayland socket / session bus,
		// so a Flatpak --user install would land in the right $HOME
		// but a script that needs the desktop bus would silently
		// degrade to autolaunching a fresh session bus.
		"tty":         false,
		"unspecified": false,
		"":            false,
		"WAYLAND":     false, // case-sensitive — loginctl always emits lowercase
	}
	for in, want := range tests {
		if got := isGraphicalType(in); got != want {
			t.Errorf("isGraphicalType(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestEnvFor_HasMinimumDesktopEnv(t *testing.T) {
	s := Session{
		Username:   "alice",
		UID:        1000,
		Home:       "/home/alice",
		RuntimeDir: "/run/user/1000",
	}
	env := EnvFor(s)

	mustContain := []string{
		"HOME=/home/alice",
		"USER=alice",
		"LOGNAME=alice",
		"XDG_RUNTIME_DIR=/run/user/1000",
		// DBus session bus is critical for any user-scoped command
		// that touches notifications or GNOME settings — pin its
		// presence so a future refactor doesn't drop it back to
		// the autolaunched-fresh-bus default.
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
	}
	envSet := make(map[string]struct{}, len(env))
	for _, e := range env {
		envSet[e] = struct{}{}
	}
	for _, e := range mustContain {
		if _, ok := envSet[e]; !ok {
			t.Errorf("EnvFor missing %q\nfull env: %v", e, env)
		}
	}

	// Negative: PATH must NOT be set here. Callers add their own
	// curated PATH so the user can't reach /usr/local/sbin via
	// subshell expansion. Pin the absence so a well-meaning future
	// "just add PATH" PR has to update this test deliberately.
	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			t.Errorf("EnvFor must not set PATH (caller picks one); got %q", e)
		}
	}
}
