//go:build integration

package systemd_test

import (
	"context"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/fs"
	"github.com/manchtools/power-manage/sdk/go/sys/systemd"
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
	exec.Sudo(ctx, "systemctl", "stop", testUnitName)
	exec.Sudo(ctx, "systemctl", "disable", testUnitName)
	exec.Sudo(ctx, "systemctl", "unmask", testUnitName)
	fs.Remove(ctx, "/etc/systemd/system/"+testUnitName)
	exec.Sudo(ctx, "systemctl", "daemon-reload")
}

func TestWriteUnit(t *testing.T) {
	ctx := context.Background()
	defer cleanupUnit(t)

	err := systemd.WriteUnit(ctx, testUnitName, testUnitContent)
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

	err := systemd.WriteUnit(ctx, testUnitName, testUnitContent)
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
	if err := systemd.WriteUnit(ctx, testUnitName, testUnitContent); err != nil {
		t.Fatalf("WriteUnit failed: %v", err)
	}

	systemd.RemoveUnit(ctx, testUnitName)

	if fs.FileExists(ctx, "/etc/systemd/system/"+testUnitName) {
		t.Error("unit file should be removed")
	}
}

func TestRemoveUnitMissing(t *testing.T) {
	ctx := context.Background()
	// Should not panic
	systemd.RemoveUnit(ctx, "pm-nonexistent-unit.service")
}

func TestStatus(t *testing.T) {
	// Query ssh.service which should be enabled in the test container
	status := systemd.Status("ssh.service")
	t.Logf("ssh status: enabled=%v active=%v masked=%v static=%v", status.Enabled, status.Active, status.Masked, status.Static)
	if !status.Enabled {
		t.Error("ssh.service should be enabled")
	}
}

func TestStatusUnknown(t *testing.T) {
	status := systemd.Status("pm-nonexistent-12345.service")
	if status.Enabled {
		t.Error("unknown unit should not be enabled")
	}
	if status.Active {
		t.Error("unknown unit should not be active")
	}
	if status.Masked {
		t.Error("unknown unit should not be masked")
	}
}

func TestDaemonReload(t *testing.T) {
	ctx := context.Background()
	err := systemd.DaemonReload(ctx)
	if err != nil {
		t.Fatalf("DaemonReload failed: %v", err)
	}
}

func TestIsEnabled(t *testing.T) {
	ctx := context.Background()
	defer cleanupUnit(t)

	if err := systemd.WriteUnit(ctx, testUnitName, testUnitContent); err != nil {
		t.Fatalf("WriteUnit failed: %v", err)
	}
	if err := systemd.DaemonReload(ctx); err != nil {
		t.Fatalf("DaemonReload failed: %v", err)
	}

	// Not enabled yet
	if systemd.IsEnabled(testUnitName) {
		t.Error("unit should not be enabled initially")
	}

	// Enable it
	if err := systemd.Enable(ctx, testUnitName); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	if !systemd.IsEnabled(testUnitName) {
		t.Error("unit should be enabled after Enable")
	}
}

func TestIsActive(t *testing.T) {
	ctx := context.Background()
	defer cleanupUnit(t)

	if err := systemd.WriteUnit(ctx, testUnitName, testUnitContent); err != nil {
		t.Fatalf("WriteUnit failed: %v", err)
	}
	if err := systemd.DaemonReload(ctx); err != nil {
		t.Fatalf("DaemonReload failed: %v", err)
	}

	// Not active yet
	if systemd.IsActive(testUnitName) {
		t.Error("unit should not be active initially")
	}

	// Start it
	if err := systemd.Start(ctx, testUnitName); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !systemd.IsActive(testUnitName) {
		t.Error("unit should be active after Start")
	}

	// Stop it
	if err := systemd.Stop(ctx, testUnitName); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if systemd.IsActive(testUnitName) {
		t.Error("unit should not be active after Stop")
	}
}

func TestIsMasked(t *testing.T) {
	ctx := context.Background()
	defer cleanupUnit(t)

	if systemd.IsMasked(testUnitName) {
		t.Error("unit should not be masked initially")
	}

	// Mask the unit (no file at this path, so mask creates a symlink to /dev/null).
	// Note: systemctl mask fails if a regular file already exists at the path,
	// so masking works for units installed by packages (in /lib/systemd/system/)
	// or units that don't have a file in /etc/systemd/system/.
	if err := systemd.Mask(ctx, testUnitName); err != nil {
		t.Fatalf("Mask failed: %v", err)
	}

	if !systemd.IsMasked(testUnitName) {
		t.Error("unit should be masked after Mask")
	}

	// Unmask it
	if err := systemd.Unmask(ctx, testUnitName); err != nil {
		t.Fatalf("Unmask failed: %v", err)
	}

	if systemd.IsMasked(testUnitName) {
		t.Error("unit should not be masked after Unmask")
	}
}

func TestEnableDisable(t *testing.T) {
	ctx := context.Background()
	defer cleanupUnit(t)

	if err := systemd.WriteUnit(ctx, testUnitName, testUnitContent); err != nil {
		t.Fatalf("WriteUnit failed: %v", err)
	}
	if err := systemd.DaemonReload(ctx); err != nil {
		t.Fatalf("DaemonReload failed: %v", err)
	}

	if err := systemd.Enable(ctx, testUnitName); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}
	if !systemd.IsEnabled(testUnitName) {
		t.Error("should be enabled after Enable")
	}

	if err := systemd.Disable(ctx, testUnitName); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}
	if systemd.IsEnabled(testUnitName) {
		t.Error("should not be enabled after Disable")
	}
}
