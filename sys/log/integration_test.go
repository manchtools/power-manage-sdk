//go:build integration

package log_test

import (
	"context"
	"os"
	"os/exec"
	"testing"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	syslog "github.com/manchtools/power-manage-sdk/sys/log"
)

func systemdRunning() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// READ-ONLY: Detect + a small real Query against journald. Under a real systemd
// (the test-sys container, where power-manage is in the systemd-journal group)
// the Query MUST succeed and return real journal lines — the drift guard against
// a journalctl output change. Elsewhere it skips gracefully.
func TestQuery_Integration(t *testing.T) {
	for _, b := range syslog.Detect(context.Background()) {
		if b != syslog.Journald && b != syslog.Syslog {
			t.Errorf("Detect returned unexpected backend %v", b)
		}
	}
	if _, err := exec.LookPath("journalctl"); err != nil {
		t.Skip("journalctl not present")
	}
	r, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	s, err := syslog.New(syslog.Journald, r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	lines, err := s.Query(context.Background(), syslog.Query{Lines: 5})
	if systemdRunning() {
		if err != nil {
			t.Fatalf("journalctl Query under systemd: %v", err)
		}
		if len(lines) == 0 {
			t.Fatal("journalctl returned no lines under systemd (journal-group access missing, or empty journal)")
		}
		t.Logf("journalctl returned %d line(s)", len(lines))
		return
	}
	if err != nil {
		t.Skipf("journalctl read unusable here (no privilege/journal): %v", err)
	}
}
