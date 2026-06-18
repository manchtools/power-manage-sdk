//go:build integration

package smart_test

import (
	"context"
	"os/exec"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/smart"
)

// READ-ONLY: Scan (and a per-device read for whatever it finds). Skips when
// smartctl is absent or unusable (no root / no devices, common in CI/VMs).
func TestScan_Integration(t *testing.T) {
	if _, err := exec.LookPath("smartctl"); err != nil {
		t.Skip("smartctl not present")
	}
	r, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	c, err := smart.New(r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	devs, err := c.Scan(context.Background())
	if err != nil {
		t.Skipf("smartctl --scan unusable here (no privilege/devices): %v", err)
	}
	for _, d := range devs {
		if _, err := c.Device(context.Background(), d.Name); err != nil {
			t.Logf("Device(%s): %v", d.Name, err) // not fatal — a device may be unreadable
		}
	}
}
