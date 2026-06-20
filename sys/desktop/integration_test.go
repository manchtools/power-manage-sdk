//go:build integration

package desktop_test

import (
	"context"
	"os"
	osexec "os/exec"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/desktop"
	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

func systemdRunning() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// TestActiveSessions_Integration drives ActiveSessions against a REAL
// systemd-logind: under the test-sys container loginctl is present and logind is
// running, so list-sessions + per-session show-session must run and parse without
// error (the drift guard against a `loginctl` output-format change). The result
// is typically empty — a headless container has no GRAPHICAL (x11/wayland)
// session, and one cannot be created without a display — so this pins the
// real read path and the active/local/graphical filter on real output, with the
// populated-graphical enumeration remaining a documented hard-CI residual.
func TestActiveSessions_Integration(t *testing.T) {
	if _, err := osexec.LookPath("loginctl"); err != nil {
		t.Skip("loginctl not present; logind path not exercisable")
	}
	r, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	m, err := desktop.New(r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sessions, err := m.ActiveSessions(context.Background())

	// Universal invariant: whatever is returned, every session must have passed
	// the active/local/graphical filter — checked regardless of how logind is
	// (or isn't) reached.
	for _, s := range sessions {
		if s.Type != "x11" && s.Type != "wayland" && s.Type != "mir" {
			t.Errorf("ActiveSessions returned a non-graphical session type %q", s.Type)
		}
	}

	if systemdRunning() {
		// loginctl present + logind running: the real read+parse+filter MUST
		// succeed (empty is fine; an error means the loginctl contract drifted).
		if err != nil {
			t.Fatalf("ActiveSessions against real logind: %v", err)
		}
		t.Logf("ActiveSessions returned %d graphical session(s)", len(sessions))
		return
	}
	// No systemd as PID 1: ActiveSessions reports "no logind, no sessions" as an
	// empty slice with NO error — or skips if loginctl can't reach a bus at all.
	if err != nil {
		t.Skipf("loginctl present but logind not reachable here: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("without a running logind, ActiveSessions should be empty, got %d", len(sessions))
	}
}
