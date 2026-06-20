//go:build container

// Container-based real-execution tests for the package-manager MUTATION paths.
// The fake-runner unit tests assert argv shape; these run REAL apt operations
// inside a disposable Debian container — Install/Remove, Pin/Unpin, a local-file
// install (InstallLocal), and a safe full UpgradeAll — and assert the POST-STATE
// against the real dpkg database, so a wrong flag, a parse mismatch, or a tool-
// behaviour drift is caught against the actual binary instead of assumed.
//
// Destructive by design (it installs and removes a real package); the container
// is thrown away after the run. apt-only: the matrix runs this on the
// debian/base stage. The dnf/pacman/zypper query paths are covered per-distro by
// the read-side integration_test.go; their mutation cells would need their own
// distro images.
package pkg

import (
	"context"
	"os"
	osexec "os/exec"
	"path/filepath"
	"testing"
	"time"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// mutTestPackage is a tiny, dependency-light package in the Debian archive —
// fast to install/remove and innocuous.
const mutTestPackage = "hello"

func aptMutManager(t *testing.T) Manager {
	t.Helper()
	if _, err := osexec.LookPath("apt-get"); err != nil {
		t.Skip("apt-get not on PATH; apt mutation tests not exercisable")
	}
	r, err := pmexec.NewRunner(pmexec.Direct) // the container runs the test as root
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	m, err := New(Apt, r)
	if err != nil {
		t.Fatalf("New(Apt): %v", err)
	}
	// Refresh metadata so Install/InstallLocal can resolve the package in a
	// fresh container; a failure here means no network/mirror — skip rather than
	// fail, so the lane is correct on an offline runner.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := m.Update(ctx); err != nil {
		t.Skipf("apt-get update failed (no network/mirror?): %v", err)
	}
	return m
}

func mutCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// cleanupPkg registers a best-effort teardown that removes (and optionally first
// unpins) the test package under a BOUNDED context, so a wedged apt can never
// hang the cleanup indefinitely.
func cleanupPkg(t *testing.T, m Manager, unpin bool) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if unpin {
			_, _ = m.Unpin(ctx, mutTestPackage)
		}
		_, _ = m.Remove(ctx, RemoveOptions{}, mutTestPackage)
	})
}

// TestApt_InstallRemove_Container installs then removes a real package, asserting
// the post-state via the real dpkg database (IsInstalled), not just exit 0.
func TestApt_InstallRemove_Container(t *testing.T) {
	m := aptMutManager(t)
	ctx := mutCtx(t)
	cleanupPkg(t, m, false)

	if _, err := m.Install(ctx, InstallOptions{}, mutTestPackage); err != nil {
		t.Fatalf("Install(%s): %v", mutTestPackage, err)
	}
	if ok, err := m.IsInstalled(ctx, mutTestPackage); err != nil || !ok {
		t.Fatalf("after Install, IsInstalled(%s) = (%v, %v), want (true, nil)", mutTestPackage, ok, err)
	}

	if _, err := m.Remove(ctx, RemoveOptions{}, mutTestPackage); err != nil {
		t.Fatalf("Remove(%s): %v", mutTestPackage, err)
	}
	if ok, err := m.IsInstalled(ctx, mutTestPackage); err != nil || ok {
		t.Fatalf("after Remove, IsInstalled(%s) = (%v, %v), want (false, nil)", mutTestPackage, ok, err)
	}
}

// TestApt_PinUnpin_Container holds then releases a real package (apt-mark hold),
// asserting IsPinned reads the real hold state in both directions.
func TestApt_PinUnpin_Container(t *testing.T) {
	m := aptMutManager(t)
	ctx := mutCtx(t)
	cleanupPkg(t, m, true)
	if _, err := m.Install(ctx, InstallOptions{}, mutTestPackage); err != nil {
		t.Fatalf("Install: %v", err)
	}

	if _, err := m.Pin(ctx, mutTestPackage); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if ok, err := m.IsPinned(ctx, mutTestPackage); err != nil || !ok {
		t.Fatalf("after Pin, IsPinned = (%v, %v), want (true, nil)", ok, err)
	}
	if _, err := m.Unpin(ctx, mutTestPackage); err != nil {
		t.Fatalf("Unpin: %v", err)
	}
	if ok, err := m.IsPinned(ctx, mutTestPackage); err != nil || ok {
		t.Fatalf("after Unpin, IsPinned = (%v, %v), want (false, nil)", ok, err)
	}
}

// TestApt_InstallLocal_Container downloads a real .deb and installs it FROM THE
// LOCAL FILE — the path the agent's deb executor delegates to — asserting the
// post-state.
func TestApt_InstallLocal_Container(t *testing.T) {
	m := aptMutManager(t)
	ctx := mutCtx(t)
	cleanupPkg(t, m, false)

	// apt-get download drops to the unprivileged _apt user, so the target dir
	// must be writable by it — t.TempDir() is 0700/root-owned. Make it traversable
	// + writable so the .deb lands.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod tempdir: %v", err)
	}
	dl := osexec.CommandContext(ctx, "apt-get", "download", mutTestPackage)
	dl.Dir = dir
	if out, err := dl.CombinedOutput(); err != nil {
		t.Skipf("apt-get download %s failed (no network/mirror?): %v\n%s", mutTestPackage, err, out)
	}
	debs, err := filepath.Glob(filepath.Join(dir, mutTestPackage+"_*.deb"))
	if err != nil {
		t.Fatalf("glob for downloaded .deb: %v", err)
	}
	if len(debs) == 0 {
		t.Fatalf("apt-get download produced no .deb in %s", dir)
	}

	if _, err := m.InstallLocal(ctx, debs[0], InstallLocalOptions{}); err != nil {
		t.Fatalf("InstallLocal(%s): %v", debs[0], err)
	}
	if ok, err := m.IsInstalled(ctx, mutTestPackage); err != nil || !ok {
		t.Fatalf("after InstallLocal, IsInstalled(%s) = (%v, %v), want (true, nil)", mutTestPackage, ok, err)
	}
}

// TestApt_UpgradeAll_Container runs a full dist-upgrade on the freshly-updated
// container: it must complete without error. The point is that the real
// dist-upgrade argv/flow succeeds (a flag or parse regression would fail), not a
// specific upgrade delta — a minimal base image may have nothing to upgrade.
func TestApt_UpgradeAll_Container(t *testing.T) {
	m := aptMutManager(t)
	ctx := mutCtx(t)
	if _, err := m.UpgradeAll(ctx, UpgradeOptions{}); err != nil {
		t.Fatalf("UpgradeAll: %v", err)
	}
}
