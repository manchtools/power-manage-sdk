package pkg

import (
	"context"
	"errors"
	"testing"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

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

	t.Run("apt via unattended-upgrade (escalated)", func(t *testing.T) {
		stubLookPath(t, "apt", "apt-get", "unattended-upgrade")
		m, f := mustNew(t, Apt)
		ok(f, "")
		if _, err := m.UpgradeAll(ctx, UpgradeOptions{SecurityOnly: true}); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		if argv(c) != "unattended-upgrade -v" || !c.Escalate {
			t.Errorf("argv = %q (escalate=%v), want escalated `unattended-upgrade -v`", argv(c), c.Escalate)
		}
	})

	t.Run("apt without unattended-upgrade fails closed (ErrBackendUnavailable, no command run)", func(t *testing.T) {
		m, f := aptM(t) // stub resolves apt/apt-get only — unattended-upgrade absent
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
