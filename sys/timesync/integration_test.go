//go:build integration

package timesync_test

import (
	"context"
	"os"
	"testing"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/timesync"
)

// systemdRunning reports whether systemd is PID 1 (so timedatectl can reach
// timedated). /run/systemd/system exists exactly then.
func systemdRunning() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// READ-ONLY: Detect + a real Status read from whichever backend is present.
// `timedatectl show` and `chronyc tracking` are both unprivileged. Under a real
// systemd (the test-sys container) the Timedatectl read MUST succeed and parse —
// that is the drift guard against a `timedatectl show` output-format change.
func TestStatus_Integration(t *testing.T) {
	backends := timesync.Detect(context.Background())
	if len(backends) == 0 {
		t.Skip("no time-sync backend on PATH")
	}
	r, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	for _, b := range backends {
		m, err := timesync.New(b, r)
		if err != nil {
			t.Fatalf("New(%v): %v", b, err)
		}
		status, err := m.Status(context.Background())
		switch {
		case b == timesync.Timedatectl && systemdRunning():
			// Hard assertion: real timedatectl under systemd must parse cleanly.
			if err != nil {
				t.Fatalf("Timedatectl Status under systemd: %v", err)
			}
			t.Logf("Timedatectl Status = %+v", status)
		case err != nil:
			// e.g. chronyc present but chronyd not running, or no systemd —
			// informative, not fatal.
			t.Logf("Status(%v): %v", b, err)
		}
	}
}
