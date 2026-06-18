//go:build integration

package timesync_test

import (
	"context"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/timesync"
)

// READ-ONLY: Detect + a real Status read from whichever backend is present.
// `timedatectl show` and `chronyc tracking` are both unprivileged.
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
		if _, err := m.Status(context.Background()); err != nil {
			// chronyc present but daemon not running, etc. — informative, not fatal.
			t.Logf("Status(%v): %v", b, err)
		}
	}
}
