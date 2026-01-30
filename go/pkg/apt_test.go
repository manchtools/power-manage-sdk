package pkg

import (
	"context"
	"os"
	"testing"
	"time"
)

func skipIfNotApt(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/usr/bin/apt-get"); os.IsNotExist(err) {
		t.Skip("apt-get not available on this system")
	}
}

// =============================================================================
// Apt Unit Tests
// =============================================================================

func TestNewApt(t *testing.T) {
	apt := NewApt()
	if apt == nil {
		t.Fatal("expected non-nil Apt")
	}
	if apt.ctx == nil {
		t.Error("expected non-nil context")
	}
}

func TestNewAptWithContext(t *testing.T) {
	ctx := context.Background()
	apt := NewAptWithContext(ctx)
	if apt == nil {
		t.Fatal("expected non-nil Apt")
	}
	if apt.ctx != ctx {
		t.Error("expected context to be set")
	}
}

func TestAptWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	apt := NewAptWithContext(ctx)

	// Operations should fail with cancelled context
	_, _, err := apt.Info()
	if err == nil {
		t.Error("expected error with cancelled context")
	}
}

func TestAptWithTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for timeout to expire
	time.Sleep(10 * time.Millisecond)

	apt := NewAptWithContext(ctx)

	_, _, err := apt.Info()
	if err == nil {
		t.Error("expected error with expired timeout")
	}
}

// =============================================================================
// Apt Integration Tests (require apt to be installed)
// =============================================================================

func TestApt_Info_Integration(t *testing.T) {
	skipIfNotApt(t)

	apt := NewApt()
	name, version, err := apt.Info()

	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}
	if name != "apt" {
		t.Errorf("expected name 'apt', got '%s'", name)
	}
	if version == "" {
		t.Error("expected non-empty version")
	}
}

func TestApt_List_Integration(t *testing.T) {
	skipIfNotApt(t)

	apt := NewApt()
	packages, err := apt.List()

	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(packages) == 0 {
		t.Error("expected at least some installed packages")
	}

	// Check that packages have required fields
	for _, pkg := range packages[:min(5, len(packages))] {
		if pkg.Name == "" {
			t.Error("expected non-empty package name")
		}
		if pkg.Version == "" {
			t.Error("expected non-empty package version")
		}
		if pkg.Status != "installed" {
			t.Errorf("expected status 'installed', got '%s'", pkg.Status)
		}
	}
}

func TestApt_Search_Integration(t *testing.T) {
	skipIfNotApt(t)

	apt := NewApt()
	results, err := apt.Search("bash")

	if err != nil {
		t.Fatalf("Search() error: %v", err)
	}
	if len(results) == 0 {
		t.Skip("no search results found (may need to run 'apt update' first)")
	}

	// Check first result has required fields
	if results[0].Name == "" {
		t.Error("expected non-empty result name")
	}
}

func TestApt_Show_Integration(t *testing.T) {
	skipIfNotApt(t)

	apt := NewApt()
	// bash should be installed on virtually all systems
	pkg, err := apt.Show("bash")

	if err != nil {
		t.Fatalf("Show() error: %v", err)
	}
	if pkg.Name != "bash" {
		t.Errorf("expected name 'bash', got '%s'", pkg.Name)
	}
	if pkg.Version == "" {
		t.Error("expected non-empty version")
	}
}

func TestApt_IsInstalled_Integration(t *testing.T) {
	skipIfNotApt(t)

	apt := NewApt()

	// bash should be installed
	installed, err := apt.IsInstalled("bash")
	if err != nil {
		t.Fatalf("IsInstalled() error: %v", err)
	}
	if !installed {
		t.Error("expected bash to be installed")
	}

	// nonexistent-package-xyz should not be installed
	installed, err = apt.IsInstalled("nonexistent-package-xyz-123456")
	if err != nil {
		t.Fatalf("IsInstalled() error: %v", err)
	}
	if installed {
		t.Error("expected nonexistent package to not be installed")
	}
}

func TestApt_GetInstalledVersion_Integration(t *testing.T) {
	skipIfNotApt(t)

	apt := NewApt()
	version, err := apt.GetInstalledVersion("bash")

	if err != nil {
		t.Fatalf("GetInstalledVersion() error: %v", err)
	}
	if version == "" {
		t.Error("expected non-empty version for bash")
	}
}

func TestApt_ListVersions_Integration(t *testing.T) {
	skipIfNotApt(t)

	apt := NewApt()
	info, err := apt.ListVersions("bash")

	if err != nil {
		t.Fatalf("ListVersions() error: %v", err)
	}
	if info.Name != "bash" {
		t.Errorf("expected name 'bash', got '%s'", info.Name)
	}
	if len(info.Versions) == 0 {
		t.Error("expected at least one version available")
	}
}

func TestApt_IsPinned_Integration(t *testing.T) {
	skipIfNotApt(t)

	apt := NewApt()
	// Most packages are not pinned by default
	pinned, err := apt.IsPinned("bash")

	if err != nil {
		t.Fatalf("IsPinned() error: %v", err)
	}
	// We just check that the function returns without error
	_ = pinned
}

func TestApt_ListPinned_Integration(t *testing.T) {
	skipIfNotApt(t)

	apt := NewApt()
	packages, err := apt.ListPinned()

	if err != nil {
		t.Fatalf("ListPinned() error: %v", err)
	}
	// Might be empty, which is fine
	for _, pkg := range packages {
		if !pkg.Pinned {
			t.Error("expected all listed packages to be pinned")
		}
	}
}

func TestApt_ListUpgradable_Integration(t *testing.T) {
	skipIfNotApt(t)

	apt := NewApt()
	updates, err := apt.ListUpgradable()

	if err != nil {
		t.Fatalf("ListUpgradable() error: %v", err)
	}
	// May or may not have updates, just check structure
	for _, update := range updates {
		if update.Name == "" {
			t.Error("expected non-empty package name")
		}
		if update.NewVersion == "" {
			t.Error("expected non-empty new version")
		}
	}
}

// =============================================================================
// Apt Empty Package Handling
// =============================================================================

func TestApt_Install_EmptyPackages(t *testing.T) {
	apt := NewApt()
	result, err := apt.Install()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty install")
	}
}

func TestApt_Remove_EmptyPackages(t *testing.T) {
	apt := NewApt()
	result, err := apt.Remove()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty remove")
	}
}

func TestApt_Purge_EmptyPackages(t *testing.T) {
	apt := NewApt()
	result, err := apt.Purge()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty purge")
	}
}

func TestApt_Upgrade_EmptyPackages_Integration(t *testing.T) {
	skipIfNotApt(t)
	// Note: This would actually run apt-get upgrade -y if packages is empty
	// So we skip this test to avoid modifying the system
	t.Skip("skipping to avoid system modification")
}

func TestApt_Pin_EmptyPackages(t *testing.T) {
	apt := NewApt()
	result, err := apt.Pin()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty pin")
	}
}

func TestApt_Unpin_EmptyPackages(t *testing.T) {
	apt := NewApt()
	result, err := apt.Unpin()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty unpin")
	}
}

// =============================================================================
// Apt Builder Pattern Integration
// =============================================================================

func TestApt_InstallBuilder_Integration(t *testing.T) {
	skipIfNotApt(t)

	apt := NewApt()
	pm := NewPackageManager(apt)

	// Test that builder works with real Apt
	builder := pm.Install("nonexistent-test-pkg-12345")
	if builder == nil {
		t.Fatal("expected non-nil builder")
	}

	// We don't actually run the install to avoid modifying the system
	// Just verify the builder chain works
	builder2 := builder.Version("1.0.0").AllowDowngrade()
	if builder2 != builder {
		t.Error("expected same builder instance")
	}
}

func TestApt_RemoveBuilder_Purge_Integration(t *testing.T) {
	skipIfNotApt(t)

	apt := NewApt()
	pm := NewPackageManager(apt)

	builder := pm.Remove("nonexistent-test-pkg-12345")
	builder2 := builder.Purge()

	if builder2 != builder {
		t.Error("expected same builder instance")
	}
	if !builder.purge {
		t.Error("expected purge to be true")
	}
}

// =============================================================================
// Helper
// =============================================================================

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
