package pkg

import (
	"context"
	"os"
	"testing"
	"time"
)

func skipIfNotDnf(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/usr/bin/dnf"); os.IsNotExist(err) {
		t.Skip("dnf not available on this system")
	}
}

// =============================================================================
// Dnf Unit Tests
// =============================================================================

func TestNewDnf(t *testing.T) {
	dnf := NewDnf()
	if dnf == nil {
		t.Fatal("expected non-nil Dnf")
	}
	if dnf.ctx == nil {
		t.Error("expected non-nil context")
	}
}

func TestNewDnfWithContext(t *testing.T) {
	ctx := context.Background()
	dnf := NewDnfWithContext(ctx)
	if dnf == nil {
		t.Fatal("expected non-nil Dnf")
	}
	if dnf.ctx != ctx {
		t.Error("expected context to be set")
	}
}

func TestDnfWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	dnf := NewDnfWithContext(ctx)

	// Operations should fail with cancelled context
	_, _, err := dnf.Info()
	if err == nil {
		t.Error("expected error with cancelled context")
	}
}

func TestDnfWithTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for timeout to expire
	time.Sleep(10 * time.Millisecond)

	dnf := NewDnfWithContext(ctx)

	_, _, err := dnf.Info()
	if err == nil {
		t.Error("expected error with expired timeout")
	}
}

// =============================================================================
// Dnf Integration Tests (require dnf to be installed)
// =============================================================================

func TestDnf_Info_Integration(t *testing.T) {
	skipIfNotDnf(t)

	dnf := NewDnf()
	name, version, err := dnf.Info()

	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}
	if name != "dnf" {
		t.Errorf("expected name 'dnf', got '%s'", name)
	}
	if version == "" {
		t.Error("expected non-empty version")
	}
}

func TestDnf_List_Integration(t *testing.T) {
	skipIfNotDnf(t)

	dnf := NewDnf()
	packages, err := dnf.List()

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

func TestDnf_Search_Integration(t *testing.T) {
	skipIfNotDnf(t)

	dnf := NewDnf()
	results, err := dnf.Search("bash")

	if err != nil {
		t.Fatalf("Search() error: %v", err)
	}
	if len(results) == 0 {
		t.Skip("no search results found (may need to run 'dnf makecache' first)")
	}

	// Check first result has required fields
	if results[0].Name == "" {
		t.Error("expected non-empty result name")
	}
}

func TestDnf_Show_Integration(t *testing.T) {
	skipIfNotDnf(t)

	dnf := NewDnf()
	// bash should be installed on virtually all systems
	pkg, err := dnf.Show("bash")

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

func TestDnf_IsInstalled_Integration(t *testing.T) {
	skipIfNotDnf(t)

	dnf := NewDnf()

	// bash should be installed
	installed, err := dnf.IsInstalled("bash")
	if err != nil {
		t.Fatalf("IsInstalled() error: %v", err)
	}
	if !installed {
		t.Error("expected bash to be installed")
	}

	// nonexistent-package-xyz should not be installed
	installed, err = dnf.IsInstalled("nonexistent-package-xyz-123456")
	if err != nil {
		t.Fatalf("IsInstalled() error: %v", err)
	}
	if installed {
		t.Error("expected nonexistent package to not be installed")
	}
}

func TestDnf_GetInstalledVersion_Integration(t *testing.T) {
	skipIfNotDnf(t)

	dnf := NewDnf()
	version, err := dnf.GetInstalledVersion("bash")

	if err != nil {
		t.Fatalf("GetInstalledVersion() error: %v", err)
	}
	if version == "" {
		t.Error("expected non-empty version for bash")
	}
}

func TestDnf_ListVersions_Integration(t *testing.T) {
	skipIfNotDnf(t)

	dnf := NewDnf()
	info, err := dnf.ListVersions("bash")

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

func TestDnf_ListUpgradable_Integration(t *testing.T) {
	skipIfNotDnf(t)

	dnf := NewDnf()
	updates, err := dnf.ListUpgradable()

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
// Dnf Empty Package Handling
// =============================================================================

func TestDnf_Install_EmptyPackages(t *testing.T) {
	dnf := NewDnf()
	result, err := dnf.Install()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty install")
	}
}

func TestDnf_Remove_EmptyPackages(t *testing.T) {
	dnf := NewDnf()
	result, err := dnf.Remove()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty remove")
	}
}

func TestDnf_Upgrade_EmptyPackages_Integration(t *testing.T) {
	skipIfNotDnf(t)
	// Note: This would actually run dnf upgrade -y if packages is empty
	// So we skip this test to avoid modifying the system
	t.Skip("skipping to avoid system modification")
}

func TestDnf_Pin_EmptyPackages(t *testing.T) {
	dnf := NewDnf()
	result, err := dnf.Pin()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty pin")
	}
}

func TestDnf_Unpin_EmptyPackages(t *testing.T) {
	dnf := NewDnf()
	result, err := dnf.Unpin()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty unpin")
	}
}

// =============================================================================
// Dnf Builder Pattern Integration
// =============================================================================

func TestDnf_InstallBuilder_Integration(t *testing.T) {
	skipIfNotDnf(t)

	dnf := NewDnf()
	pm := NewPackageManager(dnf)

	// Test that builder works with real Dnf
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

func TestDnf_RemoveBuilder_Integration(t *testing.T) {
	skipIfNotDnf(t)

	dnf := NewDnf()
	pm := NewPackageManager(dnf)

	builder := pm.Remove("nonexistent-test-pkg-12345")
	if builder == nil {
		t.Fatal("expected non-nil builder")
	}
}

// =============================================================================
// Dnf VersionLock Plugin Tests
// =============================================================================

func TestDnf_EnsureVersionLock_Integration(t *testing.T) {
	skipIfNotDnf(t)

	// This test verifies that the versionlock plugin check doesn't crash
	// We don't actually install the plugin in tests
	dnf := NewDnf()

	// ListPinned will trigger ensureVersionLock
	// If the plugin is not installed, it will try to install it
	// This may fail without root, but shouldn't panic
	_, _ = dnf.ListPinned()
}

// =============================================================================
// Dnf-specific Methods
// =============================================================================

func TestDnf_InstallVersion_Format(t *testing.T) {
	skipIfNotDnf(t)

	// Test that version format is correct (name-version)
	// We don't actually run the install, just verify the builder setup
	dnf := NewDnf()
	pm := NewPackageManager(dnf)

	builder := pm.Install("nginx").Version("1.24.0-1.fc39")
	if builder.version != "1.24.0-1.fc39" {
		t.Errorf("expected version '1.24.0-1.fc39', got '%s'", builder.version)
	}
}
