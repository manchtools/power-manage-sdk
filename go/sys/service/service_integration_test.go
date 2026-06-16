//go:build integration

package service_test

import (
	"context"
	"os"
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

// newManager builds a real-Runner service.Manager. The integration container
// runs as the non-root power-manage user with passwordless sudo.
func newManager(t *testing.T) service.Manager {
	t.Helper()
	r, err := exec.NewRunner(exec.Sudo)
	if err != nil {
		t.Fatalf("NewRunner(Sudo): %v", err)
	}
	m, err := service.New(service.Systemd, r)
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}
	return m
}

func cleanupUnit(t *testing.T, m service.Manager) {
	t.Helper()
	ctx := context.Background()
	_ = m.Stop(ctx, testUnitName)
	_ = m.Disable(ctx, testUnitName)
	_ = m.Unmask(ctx, testUnitName)
	_ = m.RemoveUnit(ctx, testUnitName)
	_ = m.DaemonReload(ctx)
}

func TestWriteUnit_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	defer cleanupUnit(t, m)

	if err := m.WriteUnit(ctx, testUnitName, testUnitContent); err != nil {
		t.Fatalf("WriteUnit: %v", err)
	}
	path := "/etc/systemd/system/" + testUnitName
	if !fs.FileExists(ctx, path) {
		t.Fatal("unit file should exist after WriteUnit")
	}
	content, err := fs.ReadFile(ctx, path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if content != testUnitContent {
		t.Errorf("content mismatch:\n want %q\n  got %q", testUnitContent, content)
	}
}

func TestWriteUnitPermissions_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	defer cleanupUnit(t, m)

	if err := m.WriteUnit(ctx, testUnitName, testUnitContent); err != nil {
		t.Fatalf("WriteUnit: %v", err)
	}
	path := "/etc/systemd/system/" + testUnitName
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("mode = %o, want 0644", perm)
	}
	if owner, group := fs.GetOwnership(path); owner != "root" || group != "root" {
		t.Errorf("ownership = %s:%s, want root:root", owner, group)
	}
}

func TestRemoveUnit_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)

	if err := m.WriteUnit(ctx, testUnitName, testUnitContent); err != nil {
		t.Fatalf("WriteUnit: %v", err)
	}
	if err := m.RemoveUnit(ctx, testUnitName); err != nil {
		t.Fatalf("RemoveUnit: %v", err)
	}
	if fs.FileExists(ctx, "/etc/systemd/system/"+testUnitName) {
		t.Error("unit file should be gone after RemoveUnit")
	}
}

func TestRemoveUnitMissing_Integration(t *testing.T) {
	if err := newManager(t).RemoveUnit(context.Background(), "pm-nonexistent-unit.service"); err != nil {
		t.Fatalf("RemoveUnit should tolerate a missing file: %v", err)
	}
}

func TestStatus_Integration(t *testing.T) {
	st, err := newManager(t).Status(context.Background(), "ssh.service")
	if err != nil {
		t.Fatalf("Status(ssh.service): %v", err)
	}
	t.Logf("ssh status: %+v", st)
	if !st.Enabled {
		t.Error("ssh.service should be enabled in the test container")
	}
}

func TestStatusMissingUnit_Integration(t *testing.T) {
	// systemctl is-enabled on a non-existent unit prints "not-found"/exits 4;
	// Status surfaces that as an error so callers can tell "doesn't exist" from
	// "exists but disabled".
	if _, err := newManager(t).Status(context.Background(), "pm-nonexistent-12345.service"); err == nil {
		t.Fatal("Status on a missing unit returned nil, want an error")
	}
}

func TestDaemonReload_Integration(t *testing.T) {
	if err := newManager(t).DaemonReload(context.Background()); err != nil {
		t.Fatalf("DaemonReload: %v", err)
	}
}

func TestEnableDisableCycle_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	defer cleanupUnit(t, m)

	if err := m.WriteUnit(ctx, testUnitName, testUnitContent); err != nil {
		t.Fatalf("WriteUnit: %v", err)
	}
	if err := m.DaemonReload(ctx); err != nil {
		t.Fatalf("DaemonReload: %v", err)
	}
	if enabled, err := m.IsEnabled(ctx, testUnitName); err != nil || enabled {
		t.Fatalf("IsEnabled before enable = (%v,%v), want (false,nil)", enabled, err)
	}
	if err := m.Enable(ctx, testUnitName); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if enabled, err := m.IsEnabled(ctx, testUnitName); err != nil || !enabled {
		t.Errorf("IsEnabled after enable = (%v,%v), want (true,nil)", enabled, err)
	}
	if err := m.Disable(ctx, testUnitName); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if enabled, err := m.IsEnabled(ctx, testUnitName); err != nil || enabled {
		t.Errorf("IsEnabled after disable = (%v,%v), want (false,nil)", enabled, err)
	}
}

func TestStartStopCycle_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	defer cleanupUnit(t, m)

	if err := m.WriteUnit(ctx, testUnitName, testUnitContent); err != nil {
		t.Fatalf("WriteUnit: %v", err)
	}
	if err := m.DaemonReload(ctx); err != nil {
		t.Fatalf("DaemonReload: %v", err)
	}
	if active, err := m.IsActive(ctx, testUnitName); err != nil || active {
		t.Fatalf("IsActive before start = (%v,%v), want (false,nil)", active, err)
	}
	if err := m.Start(ctx, testUnitName); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if active, err := m.IsActive(ctx, testUnitName); err != nil || !active {
		t.Errorf("IsActive after start = (%v,%v), want (true,nil)", active, err)
	}
	if err := m.Stop(ctx, testUnitName); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if active, err := m.IsActive(ctx, testUnitName); err != nil || active {
		t.Errorf("IsActive after stop = (%v,%v), want (false,nil)", active, err)
	}
}

func TestMaskUnmask_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	defer cleanupUnit(t, m)

	// Before Mask the unit doesn't exist → IsMasked errors (strict not-found).
	// Mask materialises it as a /dev/null symlink (writing a real file first
	// would make mask fail with "a regular file exists").
	if _, err := m.IsMasked(ctx, testUnitName); err == nil {
		t.Fatal("IsMasked on a nonexistent unit returned nil, want an error before Mask")
	}
	if err := m.Mask(ctx, testUnitName); err != nil {
		t.Fatalf("Mask: %v", err)
	}
	if masked, err := m.IsMasked(ctx, testUnitName); err != nil || !masked {
		t.Errorf("IsMasked after Mask = (%v,%v), want (true,nil)", masked, err)
	}
	if err := m.Unmask(ctx, testUnitName); err != nil {
		t.Fatalf("Unmask: %v", err)
	}
	// After Unmask the symlink is gone → the unit no longer exists → strict error.
	if _, err := m.IsMasked(ctx, testUnitName); err == nil {
		t.Fatal("IsMasked after Unmask returned nil, want a not-found error")
	}
}
