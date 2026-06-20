//go:build container

// Container-based real-execution tests for the SMART collector. The fake-runner
// unit tests feed captured smartctl JSON; these run the real smartctl binary
// inside the container, so a change to smartctl's `--scan -j` JSON shape or its
// exit-status-bit contract is caught here.
//
// Hard CI limit: a CI runner / container has no disk with real, PASSING SMART
// health to read, so the healthy-device happy path (Healthy/Temperature/
// PowerOnHours populated) cannot be exercised here — it is unit-tested against
// captured output and documented as a hardware residual. What IS real here: the
// pre-exec path validation, the `--scan -j` parse, and the fatal-exit-status-bit
// error path against a /dev node smartctl cannot inspect.
//
// Runs in the container-tests lane (root) → Direct runner (smartctl needs root;
// Escalate is a no-op wrapper over the already-root process).
package smart_test

import (
	"context"
	"errors"
	osexec "os/exec"
	"testing"
	"time"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/smart"
)

func realSmart(t *testing.T) smart.Collector {
	t.Helper()
	if _, err := osexec.LookPath("smartctl"); err != nil {
		t.Skip("smartctl not installed here; SMART collector not exercisable")
	}
	r, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	c, err := smart.New(r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func smartCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestDevice_RejectsInvalidPath_Container: a path that is not under /dev/ or that
// contains a traversal is rejected by validation BEFORE smartctl is ever invoked.
func TestDevice_RejectsInvalidPath_Container(t *testing.T) {
	c := realSmart(t)
	ctx := smartCtx(t)
	for _, bad := range []string{"etc/passwd", "/etc/shadow", "/dev/../etc/shadow"} {
		if _, err := c.Device(ctx, bad); !errors.Is(err, smart.ErrInvalidDevice) {
			t.Errorf("Device(%q) = %v, want ErrInvalidDevice", bad, err)
		}
	}
}

// TestScan_RealSmartctl_Container pins the `smartctl --scan -j` JSON parse against
// the real binary. A container/VM typically has no SMART-capable device, so the
// list may be empty — the assertion is that the real output decodes without
// error (a format change would break the parse).
func TestScan_RealSmartctl_Container(t *testing.T) {
	if _, err := realSmart(t).Scan(smartCtx(t)); err != nil {
		t.Fatalf("Scan against real `smartctl --scan -j`: %v", err)
	}
}

// TestDevice_NotInspectable_Container drives the real fatal-exit-status-bit path:
// smartctl cannot inspect a non-block /dev node, so it sets the fatal bits in
// `smartctl.exit_status`, and the collector must surface that as an error (not a
// bogus healthy Device). Pins the real exit-status-bit contract.
func TestDevice_NotInspectable_Container(t *testing.T) {
	c := realSmart(t)
	if _, err := c.Device(smartCtx(t), "/dev/null"); err == nil {
		t.Error("Device(/dev/null) returned no error; smartctl fatal exit-status bits must surface")
	}
}
