package pkg

import (
	"context"
	"slices"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// These are real-system integration tests: they build a Manager over a real
// Direct runner and exercise the read paths against the actual package manager,
// validating that the argv + output parsing match real tool output (not just
// scripted fixtures). Each skips when its backend is absent, so the suite is
// safe to run anywhere — and the dedicated apt/dnf CI jobs (which run
// `go test ./...` on apt/dnf hosts) exercise the matching backend for real.
//
// Read-only by design: nothing here installs, removes, or pins (those would
// need escalation and would mutate the host). The hermetic FakeRunner tests in
// the per-backend *_test.go files cover the mutating paths and every branch.

// realManager builds a Manager for b over a Direct runner, skipping when b is
// not installed. Reads do not escalate, so Direct is sufficient.
func realManager(t *testing.T, b Backend) Manager {
	t.Helper()
	if !slices.Contains(Detect(context.Background()), b) {
		t.Skipf("%s not available on this host", b)
	}
	r, err := exec.NewRunner(exec.Direct)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	m, err := New(b, r)
	if err != nil {
		t.Fatalf("New(%s): %v", b, err)
	}
	return m
}

// readIntegration runs the common read-path assertions against a real backend.
// knownPkg must be a package installed on every host that ships the backend
// (bash is part of the base install on Debian/Ubuntu/Fedora/Arch/openSUSE).
func readIntegration(t *testing.T, m Manager, knownPkg string) {
	t.Helper()
	ctx := context.Background()

	if v, err := m.Version(ctx); err != nil {
		t.Errorf("Version: %v", err)
	} else if v == "" {
		t.Error("Version returned empty string")
	}

	pkgs, err := m.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(pkgs) == 0 {
		t.Error("List returned no installed packages")
	}
	for _, p := range pkgs[:min(5, len(pkgs))] {
		if p.Name == "" {
			t.Error("List returned a package with an empty name")
		}
		if p.Status != "installed" {
			t.Errorf("List package %q status = %q, want installed", p.Name, p.Status)
		}
	}

	if n, err := m.InstalledCount(ctx); err != nil {
		t.Errorf("InstalledCount: %v", err)
	} else if n <= 0 {
		t.Errorf("InstalledCount = %d, want > 0", n)
	}

	if installed, err := m.IsInstalled(ctx, knownPkg); err != nil {
		t.Errorf("IsInstalled(%s): %v", knownPkg, err)
	} else if !installed {
		t.Errorf("IsInstalled(%s) = false, want true", knownPkg)
	}
	if installed, err := m.IsInstalled(ctx, "nonexistent-package-xyz-123456"); err != nil {
		t.Errorf("IsInstalled(ghost): %v", err)
	} else if installed {
		t.Error("IsInstalled(ghost) = true, want false")
	}

	if v, err := m.InstalledVersion(ctx, knownPkg); err != nil {
		t.Errorf("InstalledVersion(%s): %v", knownPkg, err)
	} else if v == "" {
		t.Errorf("InstalledVersion(%s) returned empty", knownPkg)
	}

	if p, err := m.Show(ctx, knownPkg); err != nil {
		t.Errorf("Show(%s): %v", knownPkg, err)
	} else if p == nil {
		t.Errorf("Show(%s) returned nil package without error", knownPkg)
	} else if p.Name != knownPkg {
		t.Errorf("Show(%s).Name = %q", knownPkg, p.Name)
	}

	// Repo-metadata reads: assert no error and well-formed structure. The CI
	// jobs prime the cache (apt-get update / dnf makecache).
	if _, err := m.Search(ctx, knownPkg); err != nil {
		t.Errorf("Search(%s): %v", knownPkg, err)
	}
	if info, err := m.ListVersions(ctx, knownPkg); err != nil {
		t.Errorf("ListVersions(%s): %v", knownPkg, err)
	} else if info == nil {
		t.Errorf("ListVersions(%s) returned nil info without error", knownPkg)
	} else if info.Name != knownPkg {
		t.Errorf("ListVersions(%s).Name = %q", knownPkg, info.Name)
	}
	if ups, err := m.ListUpgradable(ctx); err != nil {
		t.Errorf("ListUpgradable: %v", err)
	} else {
		for _, u := range ups {
			if u.Name == "" {
				t.Error("ListUpgradable returned an update with an empty name")
			}
		}
	}
	if _, err := m.HasUpdates(ctx, false); err != nil {
		t.Errorf("HasUpdates: %v", err)
	}

	if _, err := m.IsPinned(ctx, knownPkg); err != nil {
		t.Errorf("IsPinned(%s): %v", knownPkg, err)
	}

	// ListPinned is a pure read for apt/pacman/zypper/flatpak, but dnf's path
	// installs the versionlock plugin (an escalated write) — skip it there.
	if m.Backend() != Dnf {
		if pinned, err := m.ListPinned(ctx); err != nil {
			t.Errorf("ListPinned: %v", err)
		} else {
			for _, p := range pinned {
				if !p.Pinned {
					t.Errorf("ListPinned returned an unpinned package %q", p.Name)
				}
			}
		}
	}
}

func TestIntegration_Apt(t *testing.T)    { readIntegration(t, realManager(t, Apt), "bash") }
func TestIntegration_Dnf(t *testing.T)    { readIntegration(t, realManager(t, Dnf), "bash") }
func TestIntegration_Pacman(t *testing.T) { readIntegration(t, realManager(t, Pacman), "bash") }
func TestIntegration_Zypper(t *testing.T) { readIntegration(t, realManager(t, Zypper), "bash") }

// Flatpak has no guaranteed-installed application, so it gets a lighter probe:
// version, an error-free list/search, and remote enumeration.
func TestIntegration_Flatpak(t *testing.T) {
	m := realManager(t, Flatpak)
	ctx := context.Background()
	if v, err := m.Version(ctx); err != nil {
		t.Errorf("Version: %v", err)
	} else if v == "" {
		t.Error("Version returned empty string")
	}
	if _, err := m.List(ctx); err != nil {
		t.Errorf("List: %v", err)
	}
	if _, err := m.Search(ctx, "org.gnome.Calculator"); err != nil {
		t.Errorf("Search: %v", err)
	}
	if fm, ok := m.(FlatpakManager); ok {
		if _, err := fm.ListRemotes(ctx); err != nil {
			t.Errorf("ListRemotes: %v", err)
		}
	} else {
		t.Error("flatpak Manager must satisfy FlatpakManager")
	}
}
