package pkg

import (
	"context"
	"os"
	"testing"
	"time"
)

func skipIfNotFlatpak(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/usr/bin/flatpak"); os.IsNotExist(err) {
		t.Skip("flatpak not available on this system")
	}
}

// =============================================================================
// Flatpak Unit Tests
// =============================================================================

func TestNewFlatpak(t *testing.T) {
	flatpak := NewFlatpak()
	if flatpak == nil {
		t.Fatal("expected non-nil Flatpak")
	}
	if flatpak.ctx == nil {
		t.Error("expected non-nil context")
	}
	if !flatpak.useSudo {
		t.Error("expected useSudo to be true by default")
	}
}

func TestNewFlatpakWithContext(t *testing.T) {
	ctx := context.Background()
	flatpak := NewFlatpakWithContext(ctx)
	if flatpak == nil {
		t.Fatal("expected non-nil Flatpak")
	}
	if flatpak.ctx != ctx {
		t.Error("expected context to be set")
	}
}

func TestFlatpakWithSudo(t *testing.T) {
	flatpak := NewFlatpak()
	if !flatpak.useSudo {
		t.Error("expected useSudo to be true by default")
	}

	flatpak.WithSudo(false)
	if flatpak.useSudo {
		t.Error("expected useSudo to be false after WithSudo(false)")
	}

	flatpak.WithSudo(true)
	if !flatpak.useSudo {
		t.Error("expected useSudo to be true after WithSudo(true)")
	}
}

func TestFlatpakWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	flatpak := NewFlatpakWithContext(ctx)

	// Operations should fail with cancelled context
	_, _, err := flatpak.Info()
	if err == nil {
		t.Error("expected error with cancelled context")
	}
}

func TestFlatpakWithTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for timeout to expire
	time.Sleep(10 * time.Millisecond)

	flatpak := NewFlatpakWithContext(ctx)

	_, _, err := flatpak.Info()
	if err == nil {
		t.Error("expected error with expired timeout")
	}
}

// =============================================================================
// Flatpak Integration Tests (require flatpak to be installed)
// =============================================================================

func TestFlatpak_Info_Integration(t *testing.T) {
	skipIfNotFlatpak(t)

	flatpak := NewFlatpak().WithSudo(false)
	name, version, err := flatpak.Info()

	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}
	if name != "flatpak" {
		t.Errorf("expected name 'flatpak', got '%s'", name)
	}
	if version == "" {
		t.Error("expected non-empty version")
	}
}

func TestFlatpak_List_Integration(t *testing.T) {
	skipIfNotFlatpak(t)

	flatpak := NewFlatpak().WithSudo(false)
	packages, err := flatpak.List()

	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	// May have no packages installed, which is fine
	for _, pkg := range packages {
		if pkg.Name == "" {
			t.Error("expected non-empty package name")
		}
		if pkg.Status != "installed" {
			t.Errorf("expected status 'installed', got '%s'", pkg.Status)
		}
	}
}

func TestFlatpak_Search_Integration(t *testing.T) {
	skipIfNotFlatpak(t)

	flatpak := NewFlatpak().WithSudo(false)
	results, err := flatpak.Search("firefox")

	if err != nil {
		t.Fatalf("Search() error: %v", err)
	}
	// May have no results if no remotes configured
	for _, result := range results {
		if result.Name == "" {
			t.Error("expected non-empty result name")
		}
	}
}

func TestFlatpak_ListRemotes_Integration(t *testing.T) {
	skipIfNotFlatpak(t)

	flatpak := NewFlatpak().WithSudo(false)
	remotes, err := flatpak.ListRemotes()

	if err != nil {
		t.Fatalf("ListRemotes() error: %v", err)
	}
	// May have no remotes configured, which is fine
	_ = remotes
}

func TestFlatpak_ListUpgradable_Integration(t *testing.T) {
	skipIfNotFlatpak(t)

	flatpak := NewFlatpak().WithSudo(false)
	updates, err := flatpak.ListUpgradable()

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

func TestFlatpak_IsInstalled_Integration(t *testing.T) {
	skipIfNotFlatpak(t)

	flatpak := NewFlatpak().WithSudo(false)

	// nonexistent-package should not be installed
	installed, err := flatpak.IsInstalled("com.nonexistent.package.xyz123456")
	if err != nil {
		t.Fatalf("IsInstalled() error: %v", err)
	}
	if installed {
		t.Error("expected nonexistent package to not be installed")
	}
}

func TestFlatpak_IsPinned_Integration(t *testing.T) {
	skipIfNotFlatpak(t)

	flatpak := NewFlatpak().WithSudo(false)
	// Most packages are not pinned by default
	pinned, err := flatpak.IsPinned("org.mozilla.firefox")

	if err != nil {
		t.Fatalf("IsPinned() error: %v", err)
	}
	// We just check that the function returns without error
	_ = pinned
}

func TestFlatpak_ListPinned_Integration(t *testing.T) {
	skipIfNotFlatpak(t)

	flatpak := NewFlatpak().WithSudo(false)
	packages, err := flatpak.ListPinned()

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

// =============================================================================
// Flatpak Empty Package Handling
// =============================================================================

func TestFlatpak_Install_EmptyPackages(t *testing.T) {
	flatpak := NewFlatpak()
	result, err := flatpak.Install()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty install")
	}
}

func TestFlatpak_Remove_EmptyPackages(t *testing.T) {
	flatpak := NewFlatpak()
	result, err := flatpak.Remove()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty remove")
	}
}

func TestFlatpak_Purge_EmptyPackages(t *testing.T) {
	flatpak := NewFlatpak()
	result, err := flatpak.Purge()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty purge")
	}
}

func TestFlatpak_Pin_EmptyPackages(t *testing.T) {
	flatpak := NewFlatpak()
	result, err := flatpak.Pin()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty pin")
	}
}

func TestFlatpak_Unpin_EmptyPackages(t *testing.T) {
	flatpak := NewFlatpak()
	result, err := flatpak.Unpin()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty unpin")
	}
}

// =============================================================================
// Flatpak Builder Pattern Integration
// =============================================================================

func TestFlatpak_InstallBuilder_Integration(t *testing.T) {
	skipIfNotFlatpak(t)

	flatpak := NewFlatpak().WithSudo(false)
	pm := NewPackageManager(flatpak)

	// Test that builder works with real Flatpak
	builder := pm.Install("com.nonexistent.test.pkg.12345")
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

func TestFlatpak_RemoveBuilder_Purge_Integration(t *testing.T) {
	skipIfNotFlatpak(t)

	flatpak := NewFlatpak().WithSudo(false)
	pm := NewPackageManager(flatpak)

	builder := pm.Remove("com.nonexistent.test.pkg.12345")
	builder2 := builder.Purge()

	if builder2 != builder {
		t.Error("expected same builder instance")
	}
	if !builder.purge {
		t.Error("expected purge to be true")
	}
}

// =============================================================================
// Flatpak Helper Function Tests
// =============================================================================

func TestFlatpak_ParseFlatpakValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Version: 1.14.4", "1.14.4"},
		{"Arch: x86_64", "x86_64"},
		{"Description: A web browser", "A web browser"},
		{"NoColon", ""},
		{"Origin: flathub", "flathub"},
	}

	for _, tt := range tests {
		result := parseFlatpakValue(tt.input)
		if result != tt.expected {
			t.Errorf("parseFlatpakValue(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestFlatpak_ParseFlatpakSize(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"1000 bytes", 1000},
		{"1 kB", 1000},
		{"1 KB", 1000},
		{"1 KiB", 1024},
		{"1 MB", 1000 * 1000},
		{"1 MiB", 1024 * 1024},
		{"1 GB", 1000 * 1000 * 1000},
		{"1 GiB", 1024 * 1024 * 1024},
		{"1.5 MB", int64(1.5 * 1000 * 1000)},
		{"2.5 GiB", int64(2.5 * 1024 * 1024 * 1024)},
	}

	for _, tt := range tests {
		result := parseFlatpakSize(tt.input)
		if result != tt.expected {
			t.Errorf("parseFlatpakSize(%q) = %d, want %d", tt.input, result, tt.expected)
		}
	}
}

func TestFlatpak_ParseFlatpakSearchLine(t *testing.T) {
	tests := []struct {
		input    string
		expected *SearchResult
	}{
		{
			"Firefox\tFast, Private & Safe Web Browser\torg.mozilla.firefox\t123.0\tstable\tflathub",
			&SearchResult{Name: "org.mozilla.firefox", Description: "Fast, Private & Safe Web Browser"},
		},
		{
			"Too\tShort",
			nil,
		},
		{
			"",
			nil,
		},
	}

	for _, tt := range tests {
		result := parseFlatpakSearchLine(tt.input)
		if tt.expected == nil {
			if result != nil {
				t.Errorf("parseFlatpakSearchLine(%q) = %v, want nil", tt.input, result)
			}
		} else {
			if result == nil {
				t.Errorf("parseFlatpakSearchLine(%q) = nil, want %v", tt.input, tt.expected)
			} else if result.Name != tt.expected.Name || result.Description != tt.expected.Description {
				t.Errorf("parseFlatpakSearchLine(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		}
	}
}
