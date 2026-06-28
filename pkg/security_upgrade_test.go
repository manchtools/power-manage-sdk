package pkg

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// stubUnattendedUpgradePaths overrides the known absolute-path probe list so the
// apt security-upgrade tests don't depend on whether the test host actually has
// /usr/bin/unattended-upgrade installed. Empty = no known path, fall to $PATH.
func stubUnattendedUpgradePaths(t *testing.T, paths ...string) {
	t.Helper()
	orig := unattendedUpgradeBinPaths
	unattendedUpgradeBinPaths = paths
	t.Cleanup(func() { unattendedUpgradeBinPaths = orig })
}

// TestUpgradeAll_SecurityOnly pins the per-backend security-only upgrade contract
// added so callers (the agent's UPDATE action) can apply ONLY security updates
// through the SDK instead of shelling out. apt/dnf/zypper support it natively;
// pacman (rolling) and flatpak (no security channel) fail closed with
// ErrSecurityOnlyUnsupported rather than silently doing a full upgrade.
func TestUpgradeAll_SecurityOnly(t *testing.T) {
	ctx := context.Background()

	t.Run("dnf upgrade --security", func(t *testing.T) {
		m, f := dnfM(t)
		ok(f, "")
		if _, err := m.UpgradeAll(ctx, UpgradeOptions{SecurityOnly: true}); err != nil {
			t.Fatal(err)
		}
		if got := argv(f.Calls()[0]); got != "dnf upgrade -y --security" {
			t.Errorf("argv = %q, want `dnf upgrade -y --security`", got)
		}
	})

	t.Run("zypper patch --category security", func(t *testing.T) {
		m, f := zypperM(t)
		ok(f, "")
		if _, err := m.UpgradeAll(ctx, UpgradeOptions{SecurityOnly: true}); err != nil {
			t.Fatal(err)
		}
		if got := argv(f.Calls()[0]); got != "zypper --non-interactive patch --category security" {
			t.Errorf("argv = %q, want `zypper --non-interactive patch --category security`", got)
		}
	})

	t.Run("apt via unattended-upgrade (escalated, absolute path)", func(t *testing.T) {
		stubUnattendedUpgradePaths(t) // no known absolute paths -> resolve via $PATH
		stubLookPath(t, "apt", "apt-get", "unattended-upgrade")
		m, f := mustNew(t, Apt)
		ok(f, "")
		if _, err := m.UpgradeAll(ctx, UpgradeOptions{SecurityOnly: true}); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		// The binary is run by absolute path (stubLookPath resolves to /usr/bin/<name>),
		// so a hardened systemd $PATH can't break the exec.
		if argv(c) != "/usr/bin/unattended-upgrade -v" || !c.Escalate {
			t.Errorf("argv = %q (escalate=%v), want escalated `/usr/bin/unattended-upgrade -v`", argv(c), c.Escalate)
		}
	})

	t.Run("apt without unattended-upgrade fails closed (ErrBackendUnavailable, no command run)", func(t *testing.T) {
		stubUnattendedUpgradePaths(t) // no known absolute paths, and $PATH won't resolve it either
		m, f := aptM(t)               // stub resolves apt/apt-get only — unattended-upgrade absent
		_, err := m.UpgradeAll(ctx, UpgradeOptions{SecurityOnly: true})
		if !errors.Is(err, pmexec.ErrBackendUnavailable) {
			t.Fatalf("err = %v, want ErrBackendUnavailable", err)
		}
		if len(f.Calls()) != 0 {
			t.Errorf("nothing must run when unattended-upgrade is absent; got %d calls", len(f.Calls()))
		}
	})

	t.Run("pacman security-only unsupported", func(t *testing.T) {
		m, _ := pacmanM(t)
		if _, err := m.UpgradeAll(ctx, UpgradeOptions{SecurityOnly: true}); !errors.Is(err, ErrSecurityOnlyUnsupported) {
			t.Errorf("err = %v, want ErrSecurityOnlyUnsupported", err)
		}
	})

	t.Run("flatpak security-only unsupported", func(t *testing.T) {
		m, _ := flatpakM(t)
		if _, err := m.UpgradeAll(ctx, UpgradeOptions{SecurityOnly: true}); !errors.Is(err, ErrSecurityOnlyUnsupported) {
			t.Errorf("err = %v, want ErrSecurityOnlyUnsupported", err)
		}
	})
}

// TestResolveUnattendedUpgrade_PrefersAbsolutePath pins the carry-forward fix: a
// known absolute path is used even when $PATH cannot resolve the bare name — the
// exact case that broke under a hardened systemd unit whose $PATH omits /usr/sbin.
func TestResolveUnattendedUpgrade_PrefersAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "unattended-upgrade")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// First known path is missing, second exists — and $PATH resolves nothing.
	stubUnattendedUpgradePaths(t, filepath.Join(dir, "missing"), bin)
	stubLookPath(t)

	got, err := resolveUnattendedUpgrade()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != bin {
		t.Fatalf("got %q, want the known absolute path %q (must not depend on $PATH)", got, bin)
	}
}

// TestResolveUnattendedUpgrade_FallsBackToPath covers the no-known-path case:
// resolution defers to $PATH, and is absent → ErrBackendUnavailable.
func TestResolveUnattendedUpgrade_FallsBackToPath(t *testing.T) {
	stubUnattendedUpgradePaths(t, filepath.Join(t.TempDir(), "missing"))

	stubLookPath(t, "unattended-upgrade")
	if got, err := resolveUnattendedUpgrade(); err != nil || got != "/usr/bin/unattended-upgrade" {
		t.Fatalf("got (%q, %v), want (/usr/bin/unattended-upgrade, nil)", got, err)
	}

	stubLookPath(t) // resolves nothing
	if _, err := resolveUnattendedUpgrade(); !errors.Is(err, pmexec.ErrBackendUnavailable) {
		t.Fatalf("err = %v, want ErrBackendUnavailable", err)
	}
}
