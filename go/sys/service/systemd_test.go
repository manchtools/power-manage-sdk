//go:build integration

package service_test

import (
	"context"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/fs"
	"github.com/manchtools/power-manage/sdk/go/sys/service"
)

const testUnitName = "pm-test-unit.service"
const testUnitContent = `[Unit]
Description=Power Manage SDK Test Unit

[Service]
Type=oneshot
ExecStart=/bin/true
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`

func cleanupUnit(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	_, _ = exec.Privileged(ctx, "systemctl", "stop", testUnitName)
	_, _ = exec.Privileged(ctx, "systemctl", "disable", testUnitName)
	_, _ = exec.Privileged(ctx, "systemctl", "unmask", testUnitName)
	fs.Remove(ctx, "/etc/systemd/system/"+testUnitName)
	_, _ = exec.Privileged(ctx, "systemctl", "daemon-reload")
}

func TestWriteUnit(t *testing.T) {
	ctx := context.Background()
	defer cleanupUnit(t)

	err := service.WriteUnit(ctx, testUnitName, testUnitContent)
	if err != nil {
		t.Fatalf("WriteUnit failed: %v", err)
	}

	// Verify the unit file exists
	if !fs.FileExists(ctx, "/etc/systemd/system/"+testUnitName) {
		t.Error("unit file should exist")
	}

	// Verify content
	content, err := fs.ReadFile(ctx, "/etc/systemd/system/"+testUnitName)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if content != testUnitContent {
		t.Errorf("content mismatch:\nexpected: %q\ngot:      %q", testUnitContent, content)
	}
}

func TestWriteUnitAtomic(t *testing.T) {
	ctx := context.Background()
	defer cleanupUnit(t)

	err := service.WriteUnit(ctx, testUnitName, testUnitContent)
	if err != nil {
		t.Fatalf("WriteUnit failed: %v", err)
	}

	// Verify permissions: should be 0644, owned by root:root
	out, err := exec.Query("stat", "-c", "%a", "/etc/systemd/system/"+testUnitName)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if strings.TrimSpace(out) != "644" {
		t.Errorf("expected mode 644, got %s", strings.TrimSpace(out))
	}

	owner, group := fs.GetOwnership("/etc/systemd/system/" + testUnitName)
	if owner != "root" || group != "root" {
		t.Errorf("expected root:root, got %s:%s", owner, group)
	}
}

func TestRemoveUnit(t *testing.T) {
	ctx := context.Background()

	// Write then remove
	if err := service.WriteUnit(ctx, testUnitName, testUnitContent); err != nil {
		t.Fatalf("WriteUnit failed: %v", err)
	}

	if err := service.RemoveUnit(ctx, testUnitName); err != nil {
		t.Fatalf("RemoveUnit failed: %v", err)
	}

	if fs.FileExists(ctx, "/etc/systemd/system/"+testUnitName) {
		t.Error("unit file should be removed")
	}
}

func TestRemoveUnitMissing(t *testing.T) {
	ctx := context.Background()
	if err := service.RemoveUnit(ctx, "pm-nonexistent-unit.service"); err != nil {
		t.Fatalf("RemoveUnit should tolerate missing files: %v", err)
	}
}

func TestStatus(t *testing.T) {
	// Query ssh.service which should be enabled in the test container
	status, err := service.Status("ssh.service")
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	t.Logf("ssh status: enabled=%v active=%v masked=%v static=%v", status.Enabled, status.Active, status.Masked, status.Static)
	if !status.Enabled {
		t.Error("ssh.service should be enabled")
	}
}

func TestStatusMissingUnit(t *testing.T) {
	// systemctl is-enabled on a non-existent unit prints "not-found"
	// and exits 4. Status now surfaces that as an error so callers
	// can distinguish "unit doesn't exist" from "unit exists but is
	// disabled" — collapsing both into a zero-value UnitStatus drove
	// callers into the wrong remediation path. CR finding on PR #57.
	if _, err := service.Status("pm-nonexistent-12345.service"); err == nil {
		t.Fatal("expected Status on missing unit to return an error, got nil")
	}
}

func TestDaemonReload(t *testing.T) {
	ctx := context.Background()
	err := service.DaemonReload(ctx)
	if err != nil {
		t.Fatalf("DaemonReload failed: %v", err)
	}
}

func TestIsEnabled(t *testing.T) {
	ctx := context.Background()
	defer cleanupUnit(t)

	if err := service.WriteUnit(ctx, testUnitName, testUnitContent); err != nil {
		t.Fatalf("WriteUnit failed: %v", err)
	}
	if err := service.DaemonReload(ctx); err != nil {
		t.Fatalf("DaemonReload failed: %v", err)
	}

	// Not enabled yet
	if enabled, err := service.IsEnabled(testUnitName); err != nil {
		t.Fatalf("IsEnabled failed: %v", err)
	} else if enabled {
		t.Error("unit should not be enabled initially")
	}

	// Enable it
	if err := service.Enable(ctx, testUnitName); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	if enabled, err := service.IsEnabled(testUnitName); err != nil {
		t.Fatalf("IsEnabled failed: %v", err)
	} else if !enabled {
		t.Error("unit should be enabled after Enable")
	}
}

func TestIsActive(t *testing.T) {
	ctx := context.Background()
	defer cleanupUnit(t)

	if err := service.WriteUnit(ctx, testUnitName, testUnitContent); err != nil {
		t.Fatalf("WriteUnit failed: %v", err)
	}
	if err := service.DaemonReload(ctx); err != nil {
		t.Fatalf("DaemonReload failed: %v", err)
	}

	// Not active yet
	if active, err := service.IsActive(testUnitName); err != nil {
		t.Fatalf("IsActive failed: %v", err)
	} else if active {
		t.Error("unit should not be active initially")
	}

	// Start it
	if err := service.Start(ctx, testUnitName); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if active, err := service.IsActive(testUnitName); err != nil {
		t.Fatalf("IsActive failed: %v", err)
	} else if !active {
		t.Error("unit should be active after Start")
	}

	// Stop it
	if err := service.Stop(ctx, testUnitName); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if active, err := service.IsActive(testUnitName); err != nil {
		t.Fatalf("IsActive failed: %v", err)
	} else if active {
		t.Error("unit should not be active after Stop")
	}
}

func TestIsMasked(t *testing.T) {
	ctx := context.Background()
	defer cleanupUnit(t)

	// Initial probe: the unit doesn't exist yet, so IsMasked returns
	// the strict "unit not found" error (per CR fix on PR #57). Mask
	// is what then materialises the unit on disk as a /dev/null
	// symlink — writing the unit first would make Mask fail with
	// "Cannot mask, a regular file exists at <path>" because mask
	// refuses to clobber a real file.
	if _, err := service.IsMasked(testUnitName); err == nil {
		t.Fatal("expected IsMasked on nonexistent unit to return an error before Mask creates it")
	}

	// Mask the unit (no file at this path, so mask creates a symlink to /dev/null).
	// Note: systemctl mask fails if a regular file already exists at the path,
	// so masking works for units installed by packages (in /lib/systemd/system/)
	// or units that don't have a file in /etc/systemd/system/.
	if err := service.Mask(ctx, testUnitName); err != nil {
		t.Fatalf("Mask failed: %v", err)
	}

	if masked, err := service.IsMasked(testUnitName); err != nil {
		t.Fatalf("IsMasked failed: %v", err)
	} else if !masked {
		t.Error("unit should be masked after Mask")
	}

	// Unmask it. After Unmask the /dev/null symlink is removed so
	// the unit no longer exists at all — IsMasked then returns the
	// strict "not found" error per the runSystemctlQuery whitelist
	// (the symmetric counterpart to the initial probe at the top of
	// the test). That error IS the "no longer masked" signal here.
	if err := service.Unmask(ctx, testUnitName); err != nil {
		t.Fatalf("Unmask failed: %v", err)
	}
	if _, err := service.IsMasked(testUnitName); err == nil {
		t.Fatal("expected IsMasked to error after Unmask removed the unit symlink")
	}
}

func TestEnableDisable(t *testing.T) {
	ctx := context.Background()
	defer cleanupUnit(t)

	if err := service.WriteUnit(ctx, testUnitName, testUnitContent); err != nil {
		t.Fatalf("WriteUnit failed: %v", err)
	}
	if err := service.DaemonReload(ctx); err != nil {
		t.Fatalf("DaemonReload failed: %v", err)
	}

	if err := service.Enable(ctx, testUnitName); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}
	if enabled, err := service.IsEnabled(testUnitName); err != nil {
		t.Fatalf("IsEnabled failed: %v", err)
	} else if !enabled {
		t.Error("should be enabled after Enable")
	}

	if err := service.Disable(ctx, testUnitName); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}
	if enabled, err := service.IsEnabled(testUnitName); err != nil {
		t.Fatalf("IsEnabled failed: %v", err)
	} else if enabled {
		t.Error("should not be enabled after Disable")
	}
}
