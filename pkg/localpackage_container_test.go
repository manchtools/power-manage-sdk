//go:build container

// Real-execution coverage for LocalPackageInfo. The fake-runner unit tests assert
// the dpkg-deb/rpm argv and parse scripted output; this builds a REAL .deb with
// dpkg-deb and reads it back through the actual binary — which is what caught the
// apt parse bug the fake-runner test could not (dpkg-deb -f with multiple fields
// emits a labeled "Package: <name>" stanza, not bare values, so the label leaked
// into Name). apt-only: runs on the debian/base pkg cell.
package pkg

import (
	"context"
	"os"
	osexec "os/exec"
	"path/filepath"
	"testing"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

func TestLocalPackageInfo_AptRealDeb_Container(t *testing.T) {
	if _, err := osexec.LookPath("dpkg-deb"); err != nil {
		t.Skip("dpkg-deb not on PATH")
	}
	dir := t.TempDir()
	pkgRoot := filepath.Join(dir, "pm-testpkg")
	if err := os.MkdirAll(filepath.Join(pkgRoot, "DEBIAN"), 0o755); err != nil {
		t.Fatal(err)
	}
	control := "Package: pm-testpkg\n" +
		"Version: 1.2.3\n" +
		"Architecture: all\n" +
		"Maintainer: PM Test <test@power-manage.invalid>\n" +
		"Description: PM LocalPackageInfo real-execution fixture\n"
	if err := os.WriteFile(filepath.Join(pkgRoot, "DEBIAN", "control"), []byte(control), 0o644); err != nil {
		t.Fatal(err)
	}
	debPath := filepath.Join(dir, "pm-testpkg.deb")
	if out, err := osexec.Command("dpkg-deb", "--build", pkgRoot, debPath).CombinedOutput(); err != nil {
		t.Fatalf("dpkg-deb --build: %v\n%s", err, out)
	}

	r, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	m, err := New(Apt, r)
	if err != nil {
		t.Fatalf("New(Apt): %v", err)
	}
	info, err := m.LocalPackageInfo(context.Background(), debPath)
	if err != nil {
		t.Fatalf("LocalPackageInfo on a real .deb: %v", err)
	}
	if info.Name != "pm-testpkg" {
		t.Errorf("Name = %q, want pm-testpkg (the VALUE, not the 'Package:' label)", info.Name)
	}
	if info.Version != "1.2.3" || info.Arch != "all" {
		t.Errorf("info = %+v, want version=1.2.3 arch=all", info)
	}
}
