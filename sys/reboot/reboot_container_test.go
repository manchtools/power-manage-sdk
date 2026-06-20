//go:build container

// Container-based real-execution test for the reboot detector. The fake-runner /
// seam unit tests stub the marker stat and needs-restarting; this drives the real
// /var/run/reboot-required marker on a real filesystem.
//
// Hard CI limit: Schedule/Cancel invoke real `shutdown -r`/`shutdown -c`, which
// would schedule (and then cancel) an actual system reboot — not safe to drive in
// shared CI. Their argv construction is unit-tested; the live shutdown round-trip
// is a documented residual. What IS real here: IsRequired's marker-file detection.
//
// Runs in the container-tests lane (root) → Direct runner (the marker write needs
// root; the IsRequired probe itself is unprivileged).
package reboot_test

import (
	"context"
	"os"
	"testing"
	"time"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/reboot"
)

// debianRebootMarker is the Debian/Ubuntu reboot-required marker the detector
// reads (kept in sync with reboot.rebootRequiredPath).
const debianRebootMarker = "/var/run/reboot-required"

// TestIsRequired_Marker_Container drives IsRequired against the REAL marker file:
// absent → false, present → true, removed → false. Pins the marker-detection
// contract on a real filesystem (no needs-restarting on the Debian image, so the
// marker is the sole signal).
func TestIsRequired_Marker_Container(t *testing.T) {
	r, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	m, err := reboot.New(r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start from a known-clean state and always clean up.
	_ = os.Remove(debianRebootMarker)
	t.Cleanup(func() { _ = os.Remove(debianRebootMarker) })

	if req, err := m.IsRequired(ctx); err != nil {
		t.Fatalf("IsRequired (no marker): %v", err)
	} else if req {
		t.Error("IsRequired = true with no marker present, want false")
	}

	if err := os.WriteFile(debianRebootMarker, []byte("*** System restart required ***\n"), 0o644); err != nil {
		t.Fatalf("create marker: %v", err)
	}
	if req, err := m.IsRequired(ctx); err != nil {
		t.Fatalf("IsRequired (marker present): %v", err)
	} else if !req {
		t.Error("IsRequired = false with the marker present, want true")
	}

	if err := os.Remove(debianRebootMarker); err != nil {
		t.Fatalf("remove marker: %v", err)
	}
	if req, err := m.IsRequired(ctx); err != nil {
		t.Fatalf("IsRequired (marker removed): %v", err)
	} else if req {
		t.Error("IsRequired = true after the marker was removed, want false")
	}
}
