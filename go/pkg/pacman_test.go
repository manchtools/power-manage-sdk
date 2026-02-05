package pkg

import (
	"context"
	"os"
	"testing"
	"time"
)

func skipIfNotPacman(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/usr/bin/pacman"); os.IsNotExist(err) {
		t.Skip("pacman not available on this system")
	}
}

// =============================================================================
// Pacman Unit Tests
// =============================================================================

func TestNewPacman(t *testing.T) {
	pacman := NewPacman()
	if pacman == nil {
		t.Fatal("expected non-nil Pacman")
	}
	if pacman.ctx == nil {
		t.Error("expected non-nil context")
	}
}

func TestNewPacmanWithContext(t *testing.T) {
	ctx := context.Background()
	pacman := NewPacmanWithContext(ctx)
	if pacman == nil {
		t.Fatal("expected non-nil Pacman")
	}
	if pacman.ctx != ctx {
		t.Error("expected context to be set")
	}
}

func TestPacmanWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	pacman := NewPacmanWithContext(ctx)

	// Operations should fail with cancelled context
	_, _, err := pacman.Info()
	if err == nil {
		t.Error("expected error with cancelled context")
	}
}

func TestPacmanWithTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for timeout to expire
	time.Sleep(10 * time.Millisecond)

	pacman := NewPacmanWithContext(ctx)

	_, _, err := pacman.Info()
	if err == nil {
		t.Error("expected error with expired timeout")
	}
}

// =============================================================================
// Pacman Integration Tests (require pacman to be installed)
// =============================================================================

func TestPacman_Info_Integration(t *testing.T) {
	skipIfNotPacman(t)

	pacman := NewPacman()
	name, version, err := pacman.Info()

	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}
	if name != "pacman" {
		t.Errorf("expected name 'pacman', got '%s'", name)
	}
	if version == "" {
		t.Error("expected non-empty version")
	}
}

func TestPacman_List_Integration(t *testing.T) {
	skipIfNotPacman(t)

	pacman := NewPacman()
	packages, err := pacman.List()

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

func TestPacman_Search_Integration(t *testing.T) {
	skipIfNotPacman(t)

	pacman := NewPacman()
	results, err := pacman.Search("bash")

	if err != nil {
		t.Fatalf("Search() error: %v", err)
	}
	if len(results) == 0 {
		t.Skip("no search results found (may need to run 'pacman -Sy' first)")
	}

	// Check first result has required fields
	if results[0].Name == "" {
		t.Error("expected non-empty result name")
	}
}

func TestPacman_Show_Integration(t *testing.T) {
	skipIfNotPacman(t)

	pacman := NewPacman()
	// bash should be installed on virtually all systems
	pkg, err := pacman.Show("bash")

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

func TestPacman_IsInstalled_Integration(t *testing.T) {
	skipIfNotPacman(t)

	pacman := NewPacman()

	// bash should be installed
	installed, err := pacman.IsInstalled("bash")
	if err != nil {
		t.Fatalf("IsInstalled() error: %v", err)
	}
	if !installed {
		t.Error("expected bash to be installed")
	}

	// nonexistent-package-xyz should not be installed
	installed, err = pacman.IsInstalled("nonexistent-package-xyz-123456")
	if err != nil {
		t.Fatalf("IsInstalled() error: %v", err)
	}
	if installed {
		t.Error("expected nonexistent package to not be installed")
	}
}

func TestPacman_GetInstalledVersion_Integration(t *testing.T) {
	skipIfNotPacman(t)

	pacman := NewPacman()
	version, err := pacman.GetInstalledVersion("bash")

	if err != nil {
		t.Fatalf("GetInstalledVersion() error: %v", err)
	}
	if version == "" {
		t.Error("expected non-empty version for bash")
	}
}

func TestPacman_ListVersions_Integration(t *testing.T) {
	skipIfNotPacman(t)

	pacman := NewPacman()
	info, err := pacman.ListVersions("bash")

	if err != nil {
		t.Fatalf("ListVersions() error: %v", err)
	}
	if info.Name != "bash" {
		t.Errorf("expected name 'bash', got '%s'", info.Name)
	}
	// Pacman typically only has latest version in repos
}

func TestPacman_IsPinned_Integration(t *testing.T) {
	skipIfNotPacman(t)

	pacman := NewPacman()
	// Most packages are not pinned by default
	pinned, err := pacman.IsPinned("bash")

	if err != nil {
		t.Fatalf("IsPinned() error: %v", err)
	}
	// We just check that the function returns without error
	_ = pinned
}

func TestPacman_ListPinned_Integration(t *testing.T) {
	skipIfNotPacman(t)

	pacman := NewPacman()
	packages, err := pacman.ListPinned()

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

func TestPacman_ListUpgradable_Integration(t *testing.T) {
	skipIfNotPacman(t)

	pacman := NewPacman()
	updates, err := pacman.ListUpgradable()

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
// Pacman Empty Package Handling
// =============================================================================

func TestPacman_Install_EmptyPackages(t *testing.T) {
	pacman := NewPacman()
	result, err := pacman.Install()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty install")
	}
}

func TestPacman_Remove_EmptyPackages(t *testing.T) {
	pacman := NewPacman()
	result, err := pacman.Remove()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty remove")
	}
}

func TestPacman_Purge_EmptyPackages(t *testing.T) {
	pacman := NewPacman()
	result, err := pacman.Purge()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty purge")
	}
}

func TestPacman_Pin_EmptyPackages(t *testing.T) {
	pacman := NewPacman()
	result, err := pacman.Pin()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty pin")
	}
}

func TestPacman_Unpin_EmptyPackages(t *testing.T) {
	pacman := NewPacman()
	result, err := pacman.Unpin()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty unpin")
	}
}

// =============================================================================
// Pacman Builder Pattern Integration
// =============================================================================

func TestPacman_InstallBuilder_Integration(t *testing.T) {
	skipIfNotPacman(t)

	pacman := NewPacman()
	pm := NewPackageManager(pacman)

	// Test that builder works with real Pacman
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

func TestPacman_RemoveBuilder_Purge_Integration(t *testing.T) {
	skipIfNotPacman(t)

	pacman := NewPacman()
	pm := NewPackageManager(pacman)

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
// Pacman Helper Function Tests
// =============================================================================

func TestPacman_ParsePacmanValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Version         : 5.1.16-4", "5.1.16-4"},
		{"Architecture    : x86_64", "x86_64"},
		{"Description     : The GNU Bourne Again shell", "The GNU Bourne Again shell"},
		{"NoColon", ""},
	}

	for _, tt := range tests {
		result := parsePacmanValue(tt.input)
		if result != tt.expected {
			t.Errorf("parsePacmanValue(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestPacman_ParsePacmanSize(t *testing.T) {
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
		result := parsePacmanSize(tt.input)
		if result != tt.expected {
			t.Errorf("parsePacmanSize(%q) = %d, want %d", tt.input, result, tt.expected)
		}
	}
}

func TestPacman_Contains(t *testing.T) {
	slice := []string{"foo", "bar", "baz"}

	if !contains(slice, "foo") {
		t.Error("expected contains to return true for 'foo'")
	}
	if !contains(slice, "bar") {
		t.Error("expected contains to return true for 'bar'")
	}
	if contains(slice, "qux") {
		t.Error("expected contains to return false for 'qux'")
	}
	if contains(nil, "foo") {
		t.Error("expected contains to return false for nil slice")
	}
	if contains([]string{}, "foo") {
		t.Error("expected contains to return false for empty slice")
	}
}
