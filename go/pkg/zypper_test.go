package pkg

import (
	"context"
	"os"
	"testing"
	"time"
)

func skipIfNotZypper(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/usr/bin/zypper"); os.IsNotExist(err) {
		t.Skip("zypper not available on this system")
	}
}

// =============================================================================
// Zypper Unit Tests
// =============================================================================

func TestNewZypper(t *testing.T) {
	zypper := NewZypper()
	if zypper == nil {
		t.Fatal("expected non-nil Zypper")
	}
	if zypper.ctx == nil {
		t.Error("expected non-nil context")
	}
}

func TestNewZypperWithContext(t *testing.T) {
	ctx := context.Background()
	zypper := NewZypperWithContext(ctx)
	if zypper == nil {
		t.Fatal("expected non-nil Zypper")
	}
	if zypper.ctx != ctx {
		t.Error("expected context to be set")
	}
}

func TestZypperWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	zypper := NewZypperWithContext(ctx)

	// Operations should fail with cancelled context
	_, _, err := zypper.Info()
	if err == nil {
		t.Error("expected error with cancelled context")
	}
}

func TestZypperWithTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for timeout to expire
	time.Sleep(10 * time.Millisecond)

	zypper := NewZypperWithContext(ctx)

	_, _, err := zypper.Info()
	if err == nil {
		t.Error("expected error with expired timeout")
	}
}

// =============================================================================
// Zypper Integration Tests (require zypper to be installed)
// =============================================================================

func TestZypper_Info_Integration(t *testing.T) {
	skipIfNotZypper(t)

	zypper := NewZypper()
	name, version, err := zypper.Info()

	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}
	if name != "zypper" {
		t.Errorf("expected name 'zypper', got '%s'", name)
	}
	if version == "" {
		t.Error("expected non-empty version")
	}
}

func TestZypper_List_Integration(t *testing.T) {
	skipIfNotZypper(t)

	zypper := NewZypper()
	packages, err := zypper.List()

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

func TestZypper_Search_Integration(t *testing.T) {
	skipIfNotZypper(t)

	zypper := NewZypper()
	results, err := zypper.Search("bash")

	if err != nil {
		t.Fatalf("Search() error: %v", err)
	}
	if len(results) == 0 {
		t.Skip("no search results found (may need to run 'zypper refresh' first)")
	}

	// Check first result has required fields
	if results[0].Name == "" {
		t.Error("expected non-empty result name")
	}
}

func TestZypper_Show_Integration(t *testing.T) {
	skipIfNotZypper(t)

	zypper := NewZypper()
	// bash should be installed on virtually all systems
	pkg, err := zypper.Show("bash")

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

func TestZypper_IsInstalled_Integration(t *testing.T) {
	skipIfNotZypper(t)

	zypper := NewZypper()

	// bash should be installed
	installed, err := zypper.IsInstalled("bash")
	if err != nil {
		t.Fatalf("IsInstalled() error: %v", err)
	}
	if !installed {
		t.Error("expected bash to be installed")
	}

	// nonexistent-package-xyz should not be installed
	installed, err = zypper.IsInstalled("nonexistent-package-xyz-123456")
	if err != nil {
		t.Fatalf("IsInstalled() error: %v", err)
	}
	if installed {
		t.Error("expected nonexistent package to not be installed")
	}
}

func TestZypper_GetInstalledVersion_Integration(t *testing.T) {
	skipIfNotZypper(t)

	zypper := NewZypper()
	version, err := zypper.GetInstalledVersion("bash")

	if err != nil {
		t.Fatalf("GetInstalledVersion() error: %v", err)
	}
	if version == "" {
		t.Error("expected non-empty version for bash")
	}
}

func TestZypper_ListVersions_Integration(t *testing.T) {
	skipIfNotZypper(t)

	zypper := NewZypper()
	info, err := zypper.ListVersions("bash")

	if err != nil {
		t.Fatalf("ListVersions() error: %v", err)
	}
	if info.Name != "bash" {
		t.Errorf("expected name 'bash', got '%s'", info.Name)
	}
}

func TestZypper_IsPinned_Integration(t *testing.T) {
	skipIfNotZypper(t)

	zypper := NewZypper()
	// Most packages are not pinned by default
	pinned, err := zypper.IsPinned("bash")

	if err != nil {
		t.Fatalf("IsPinned() error: %v", err)
	}
	// We just check that the function returns without error
	_ = pinned
}

func TestZypper_ListPinned_Integration(t *testing.T) {
	skipIfNotZypper(t)

	zypper := NewZypper()
	packages, err := zypper.ListPinned()

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

func TestZypper_ListUpgradable_Integration(t *testing.T) {
	skipIfNotZypper(t)

	zypper := NewZypper()
	updates, err := zypper.ListUpgradable()

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
// Zypper Empty Package Handling
// =============================================================================

func TestZypper_Install_EmptyPackages(t *testing.T) {
	zypper := NewZypper()
	result, err := zypper.Install()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty install")
	}
}

func TestZypper_Remove_EmptyPackages(t *testing.T) {
	zypper := NewZypper()
	result, err := zypper.Remove()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty remove")
	}
}

func TestZypper_Purge_EmptyPackages(t *testing.T) {
	zypper := NewZypper()
	result, err := zypper.Purge()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty purge")
	}
}

func TestZypper_Pin_EmptyPackages(t *testing.T) {
	zypper := NewZypper()
	result, err := zypper.Pin()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty pin")
	}
}

func TestZypper_Unpin_EmptyPackages(t *testing.T) {
	zypper := NewZypper()
	result, err := zypper.Unpin()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty unpin")
	}
}

// =============================================================================
// Zypper Builder Pattern Integration
// =============================================================================

func TestZypper_InstallBuilder_Integration(t *testing.T) {
	skipIfNotZypper(t)

	zypper := NewZypper()
	pm := NewPackageManager(zypper)

	// Test that builder works with real Zypper
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

func TestZypper_RemoveBuilder_Purge_Integration(t *testing.T) {
	skipIfNotZypper(t)

	zypper := NewZypper()
	pm := NewPackageManager(zypper)

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
// Zypper Helper Function Tests
// =============================================================================

func TestZypper_ParseZypperValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Version        : 5.1.16-4", "5.1.16-4"},
		{"Architecture   : x86_64", "x86_64"},
		{"Summary        : The GNU Bourne Again shell", "The GNU Bourne Again shell"},
		{"NoColon", ""},
	}

	for _, tt := range tests {
		result := parseZypperValue(tt.input)
		if result != tt.expected {
			t.Errorf("parseZypperValue(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestZypper_ParseZypperSize(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"1024 B", 1024},
		{"1 KiB", 1024},
		{"1 MiB", 1024 * 1024},
		{"1 GiB", 1024 * 1024 * 1024},
		{"1.5 MiB", int64(1.5 * 1024 * 1024)},
	}

	for _, tt := range tests {
		result := parseZypperSize(tt.input)
		if result != tt.expected {
			t.Errorf("parseZypperSize(%q) = %d, want %d", tt.input, result, tt.expected)
		}
	}
}
