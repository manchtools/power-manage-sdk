//go:build integration

package log_test

import (
	"context"
	"os/exec"
	"testing"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	syslog "github.com/manchtools/power-manage-sdk/sys/log"
)

// READ-ONLY: Detect + a small real Query against journald if present. Skips when
// the tool/privilege is unavailable (common in unprivileged CI).
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
	if _, err := s.Query(context.Background(), syslog.Query{Lines: 5}); err != nil {
		t.Skipf("journalctl read unusable here (no privilege/journal): %v", err)
	}
}
