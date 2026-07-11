package repo

import (
	"context"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/pkg"
	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

func TestZypper_Apply_FullSequence(t *testing.T) {
	m, _, fr := newTestManager(t, pkg.Zypper)
	out, err := m.Apply(context.Background(), Repository{Name: "corp", Zypper: &ZypperConfig{
		URL:         "https://h/r",
		Description: "Corp Repo",
		Enabled:     true,
		Autorefresh: true,
		GPGCheck:    true,
		GPGKey:      "https://h/KEY",
		Type:        "rpm-md",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Changed {
		t.Error("a successful addrepo reports Changed=true")
	}
	want := []string{
		"zypper --non-interactive removerepo corp",                                  // best-effort pre-removal
		"zypper --non-interactive addrepo --refresh --type rpm-md https://h/r corp", // --refresh ⇒ Autorefresh
		"zypper --non-interactive modifyrepo --name=Corp Repo corp",                 // glued --name= blocks flag injection
		"zypper --non-interactive modifyrepo --enable corp",
		"rpm --import -- https://h/KEY",
		"zypper --non-interactive refresh corp",
	}
	if got := argvs(fr); strings.Join(got, " | ") != strings.Join(want, " | ") {
		t.Errorf("commands =\n%v\nwant\n%v", got, want)
	}
}

// Autorefresh must be controlled solely by the addrepo --refresh flag: when
// Autorefresh is false the repo must NOT be created auto-refreshing. (A prior
// implementation always passed addrepo --refresh and only re-enabled when true,
// leaving Autorefresh=false repos auto-refreshing against operator intent.)
func TestZypper_Apply_AutorefreshControlsAddrepoFlag(t *testing.T) {
	addrepoCmd := func(fr *exectest.FakeRunner) string {
		for _, c := range argvs(fr) {
			if strings.HasPrefix(c, "zypper --non-interactive addrepo") {
				return c
			}
		}
		return ""
	}
	t.Run("true → addrepo carries --refresh", func(t *testing.T) {
		m, _, fr := newTestManager(t, pkg.Zypper)
		if _, err := m.Apply(context.Background(), Repository{Name: "r", Zypper: &ZypperConfig{URL: "https://h/r", GPGCheck: true, Autorefresh: true}}); err != nil {
			t.Fatal(err)
		}
		if got := addrepoCmd(fr); got != "zypper --non-interactive addrepo --refresh https://h/r r" {
			t.Errorf("addrepo = %q, want it to carry --refresh", got)
		}
	})
	t.Run("false → addrepo has no --refresh (repo must not auto-refresh)", func(t *testing.T) {
		m, _, fr := newTestManager(t, pkg.Zypper)
		if _, err := m.Apply(context.Background(), Repository{Name: "r", Zypper: &ZypperConfig{URL: "https://h/r", GPGCheck: true, Autorefresh: false}}); err != nil {
			t.Fatal(err)
		}
		if got := addrepoCmd(fr); got != "zypper --non-interactive addrepo https://h/r r" {
			t.Errorf("addrepo = %q, want NO --refresh for Autorefresh=false", got)
		}
		// And nothing later may re-enable autorefresh.
		for _, c := range argvs(fr) {
			if strings.Contains(c, "modifyrepo --refresh") {
				t.Errorf("Autorefresh=false but a modifyrepo --refresh ran: %q", c)
			}
		}
	})
}

func TestZypper_Apply_NoGpgcheckAndDisabled(t *testing.T) {
	m, _, fr := newTestManager(t, pkg.Zypper)
	if _, err := m.Apply(context.Background(), Repository{Name: "r", Zypper: &ZypperConfig{
		URL: "https://h/r", GPGCheck: false, Enabled: false,
	}}); err != nil {
		t.Fatal(err)
	}
	cmds := strings.Join(argvs(fr), " | ")
	// Autorefresh defaults false here, so addrepo carries no --refresh.
	if !strings.Contains(cmds, "addrepo --no-gpgcheck https://h/r r") {
		t.Errorf("addrepo missing --no-gpgcheck for GPGCheck=false: %s", cmds)
	}
	if !strings.Contains(cmds, "modifyrepo --disable r") {
		t.Errorf("expected --disable for Enabled=false: %s", cmds)
	}
	if strings.Contains(cmds, "--enable") {
		t.Errorf("Enabled=false must not --enable: %s", cmds)
	}
}

func TestZypper_Apply_AddrepoFailureIsFatal(t *testing.T) {
	m, _, fr := newTestManager(t, pkg.Zypper)
	fr.Push(pmexec.Result{}, nil)                                        // removerepo (pre) clean
	fr.Push(pmexec.Result{ExitCode: 1, Stderr: "addrepo: bad url"}, nil) // addrepo fails
	out, err := m.Apply(context.Background(), Repository{Name: "r", Zypper: &ZypperConfig{URL: "https://h/r", GPGCheck: true}})
	if err == nil || !strings.Contains(err.Error(), "add repository") {
		t.Fatalf("err = %v, want a wrapped addrepo failure", err)
	}
	if out.Changed {
		t.Error("a failed addrepo must report Changed=false")
	}
}

func TestZypper_Apply_DescriptionFailureIsFatal(t *testing.T) {
	m, _, fr := newTestManager(t, pkg.Zypper)
	fr.Push(pmexec.Result{}, nil)                                        // removerepo
	fr.Push(pmexec.Result{}, nil)                                        // addrepo ok
	fr.Push(pmexec.Result{ExitCode: 1, Stderr: "modifyrepo: name"}, nil) // modifyrepo --name fails
	if _, err := m.Apply(context.Background(), Repository{Name: "r", Zypper: &ZypperConfig{
		URL: "https://h/r", GPGCheck: true, Description: "X",
	}}); err == nil || !strings.Contains(err.Error(), "set repo description") {
		t.Fatalf("err = %v, want a wrapped description failure", err)
	}
}

func TestZypper_Apply_KeyImportFailureIsNonFatal(t *testing.T) {
	m, _, fr := newTestManager(t, pkg.Zypper)
	// removerepo, addrepo, enable all clean; rpm --import fails; refresh clean.
	fr.Push(pmexec.Result{}, nil)                                  // removerepo
	fr.Push(pmexec.Result{}, nil)                                  // addrepo
	fr.Push(pmexec.Result{}, nil)                                  // modifyrepo --enable
	fr.Push(pmexec.Result{ExitCode: 1, Stderr: "rpm import"}, nil) // rpm --import
	out, err := m.Apply(context.Background(), Repository{Name: "r", Zypper: &ZypperConfig{
		URL: "https://h/r", GPGCheck: true, Enabled: true, GPGKey: "https://h/K",
	}})
	if err != nil {
		t.Fatalf("key-import failure must be non-fatal, got %v", err)
	}
	if !strings.Contains(out.Result.Stdout, "warning: failed to import GPG key") {
		t.Errorf("expected key-import warning, got %q", out.Result.Stdout)
	}
}

func TestZypper_Remove(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		m, _, fr := newTestManager(t, pkg.Zypper)
		out, err := m.Remove(context.Background(), "corp")
		if err != nil {
			t.Fatal(err)
		}
		if !out.Changed {
			t.Error("removing a present repo reports Changed=true")
		}
		if got := argvs(fr); len(got) != 1 || got[0] != "zypper --non-interactive removerepo corp" {
			t.Errorf("commands = %v, want a single removerepo", got)
		}
	})
	t.Run("not found is idempotent", func(t *testing.T) {
		m, _, fr := newTestManager(t, pkg.Zypper)
		// REAL zypper behaviour: `removerepo` of an absent alias EXITS 0 and
		// reports the absence with a "not found" message on stderr — it does NOT
		// exit non-zero. So idempotency must be keyed off the message, not the
		// exit code (the earlier fake scripted exit 1, hiding that removing an
		// absent repo wrongly reported Changed=true against real zypper).
		fr.Push(pmexec.Result{ExitCode: 0, Stderr: "Repository 'corp' not found by alias, number or URI."}, nil)
		out, err := m.Remove(context.Background(), "corp")
		if err != nil {
			t.Fatalf("a 'not found' removerepo must be a no-op, got %v", err)
		}
		if out.Changed {
			t.Error("not-found removal must report Changed=false")
		}
	})
	t.Run("other failure is fatal", func(t *testing.T) {
		m, _, fr := newTestManager(t, pkg.Zypper)
		fr.Push(pmexec.Result{ExitCode: 1, Stderr: "permission denied"}, nil)
		if _, err := m.Remove(context.Background(), "corp"); err == nil ||
			!strings.Contains(err.Error(), "remove repository") {
			t.Fatalf("err = %v, want a wrapped removerepo failure", err)
		}
	})
}

// TestZypper_Apply_GPGCheckFalseIgnoresKey guards the trust-downgrade fix
// (parity with TestDnf_Apply_GPGCheckFalseIgnoresKey): with GPGCheck=false
// the repo is added --no-gpgcheck, so importing the GPGKey would trust it
// system-wide in the rpm keyring while the repo verifies nothing. The key
// import must be gated on GPGCheck.
func TestZypper_Apply_GPGCheckFalseIgnoresKey(t *testing.T) {
	m, _, fr := newTestManager(t, pkg.Zypper)
	if _, err := m.Apply(context.Background(), Repository{Name: "r", Zypper: &ZypperConfig{
		URL: "https://h/r", Enabled: true, GPGCheck: false, GPGKey: "https://h/KEY",
	}}); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range argvs(fr) {
		if strings.Contains(cmd, "rpm --import") {
			t.Fatalf("rpm --import ran despite GPGCheck=false — trust downgrade:\n%v", argvs(fr))
		}
	}
}
