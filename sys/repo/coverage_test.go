package repo

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/pkg"
	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/fs"
)

// Apply runs Validate first: an invalid config is rejected before any side effect.
func TestApply_ValidatesBeforeWork(t *testing.T) {
	m, ff, fr := newTestManager(t, pkg.Dnf)
	if _, err := m.Apply(context.Background(), Repository{Name: "-rf", Dnf: &DnfConfig{BaseURL: "https://h/r"}}); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("err = %v, want ErrInvalidName", err)
	}
	if len(ff.calls) != 0 || len(fr.Calls()) != 0 {
		t.Error("a validation failure must do no file or command work")
	}
}

// A runner-level error (escalation denied, not just a non-zero exit) on a
// non-fatal step is surfaced as a warning.
func TestRunPriv_RunnerErrorBranch(t *testing.T) {
	m, _, fr := newTestManager(t, pkg.Dnf)
	fr.Push(pmexec.Result{}, pmexec.ErrEscalationDenied) // makecache (no key → first call)
	out, err := m.Apply(context.Background(), Repository{Name: "r", Dnf: &DnfConfig{BaseURL: "https://h/r"}})
	if err != nil {
		t.Fatalf("a non-fatal step's runner error must not fail Apply, got %v", err)
	}
	if !strings.Contains(out.Result.Stdout, "warning: failed to refresh repo metadata") {
		t.Errorf("expected a refresh warning, got %q", out.Result.Stdout)
	}
}

// A runner-level error during gpg --dearmor is fatal (the key path can't proceed).
func TestRunStdin_RunnerErrorBranch(t *testing.T) {
	m, _, fr := newTestManager(t, pkg.Apt)
	fr.Push(pmexec.Result{}, pmexec.ErrEscalationUnavailable)
	if _, err := m.Apply(context.Background(), Repository{Name: "r", Apt: &AptConfig{URL: "https://h/a", GPGKey: []byte("k")}}); err == nil ||
		!strings.Contains(err.Error(), "dearmor GPG key") {
		t.Fatalf("err = %v, want a wrapped dearmor failure on a runner error", err)
	}
}

// Command stdout is appended to the Apply log across backends.
func TestApply_StdoutIsLogged(t *testing.T) {
	t.Run("dnf", func(t *testing.T) {
		m, _, fr := newTestManager(t, pkg.Dnf)
		fr.Push(pmexec.Result{Stdout: "imported-key\n"}, nil)    // rpm --import
		fr.Push(pmexec.Result{Stdout: "metadata cached\n"}, nil) // makecache
		out, err := m.Apply(context.Background(), Repository{Name: "r", Dnf: &DnfConfig{BaseURL: "https://h/r", GPGCheck: true, GPGKey: "https://h/K"}})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.Result.Stdout, "imported-key") || !strings.Contains(out.Result.Stdout, "metadata cached") {
			t.Errorf("command stdout not logged: %q", out.Result.Stdout)
		}
	})
	t.Run("pacman", func(t *testing.T) {
		m, ff, fr := newTestManager(t, pkg.Pacman)
		ff.read["/etc/pacman.conf"] = []byte("[options]\n")
		fr.Push(pmexec.Result{Stdout: "synced db\n"}, nil)
		out, _ := m.Apply(context.Background(), Repository{Name: "r", Pacman: &PacmanConfig{Server: "https://h/"}})
		if !strings.Contains(out.Result.Stdout, "synced db") {
			t.Errorf("pacman stdout not logged: %q", out.Result.Stdout)
		}
	})
	t.Run("apt update", func(t *testing.T) {
		m, _, fr := newTestManager(t, pkg.Apt)
		fr.Push(pmexec.Result{Stdout: "Hit:1 https://h/a\n"}, nil) // apt-get update (no key → first call)
		out, _ := m.Apply(context.Background(), Repository{Name: "r", Apt: &AptConfig{URL: "https://h/a"}})
		if !strings.Contains(out.Result.Stdout, "Hit:1") {
			t.Errorf("apt-get update stdout not logged: %q", out.Result.Stdout)
		}
	})
	t.Run("zypper", func(t *testing.T) {
		m, _, fr := newTestManager(t, pkg.Zypper)
		fr.Push(pmexec.Result{}, nil)                       // removerepo
		fr.Push(pmexec.Result{Stdout: "added repo\n"}, nil) // addrepo
		fr.Push(pmexec.Result{}, nil)                       // disable
		fr.Push(pmexec.Result{Stdout: "imported\n"}, nil)   // rpm import
		fr.Push(pmexec.Result{Stdout: "refreshed\n"}, nil)  // refresh
		out, err := m.Apply(context.Background(), Repository{Name: "r", Zypper: &ZypperConfig{URL: "https://h/r", GPGCheck: true, GPGKey: "https://h/K"}})
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"added repo", "imported", "refreshed"} {
			if !strings.Contains(out.Result.Stdout, want) {
				t.Errorf("zypper stdout missing %q in %q", want, out.Result.Stdout)
			}
		}
	})
}

// --- apt legacy-cleanup error / warn branches ------------------------------

func TestApt_Apply_LegacyExistsErrorsAreFatal(t *testing.T) {
	t.Run("legacy .list probe error", func(t *testing.T) {
		m, ff, _ := newTestManager(t, pkg.Apt)
		ff.errs["Exists:/etc/apt/sources.list.d/r.list"] = errors.New("probe")
		if _, err := m.Apply(context.Background(), Repository{Name: "r", Apt: &AptConfig{URL: "https://h/a"}}); err == nil ||
			!strings.Contains(err.Error(), "check legacy repo file") {
			t.Fatalf("err = %v, want a wrapped legacy-list probe failure", err)
		}
	})
	t.Run("legacy key probe error", func(t *testing.T) {
		m, ff, _ := newTestManager(t, pkg.Apt)
		ff.errs["Exists:/etc/apt/trusted.gpg.d/r.gpg"] = errors.New("probe")
		if _, err := m.Apply(context.Background(), Repository{Name: "r", Apt: &AptConfig{URL: "https://h/a"}}); err == nil ||
			!strings.Contains(err.Error(), "check legacy GPG key") {
			t.Fatalf("err = %v, want a wrapped legacy-key probe failure", err)
		}
	})
}

func TestApt_Apply_LegacyRemoveWarningsAreNonFatal(t *testing.T) {
	m, ff, _ := newTestManager(t, pkg.Apt)
	ff.present["/etc/apt/sources.list.d/r.list"] = true
	ff.present["/etc/apt/trusted.gpg.d/r.gpg"] = true
	ff.errs["Remove:/etc/apt/sources.list.d/r.list"] = errors.New("busy")
	ff.errs["Remove:/etc/apt/trusted.gpg.d/r.gpg"] = errors.New("busy")
	out, err := m.Apply(context.Background(), Repository{Name: "r", Apt: &AptConfig{URL: "https://h/a"}})
	if err != nil {
		t.Fatalf("legacy remove failures must be non-fatal, got %v", err)
	}
	if !strings.Contains(out.Result.Stdout, "failed to remove legacy repo file") ||
		!strings.Contains(out.Result.Stdout, "failed to remove legacy GPG key") {
		t.Errorf("expected legacy-remove warnings, got %q", out.Result.Stdout)
	}
}

func TestApt_Apply_RepoFileReadErrorIsFatal(t *testing.T) {
	m, ff, _ := newTestManager(t, pkg.Apt)
	ff.errs["ReadFile:/etc/apt/sources.list.d/r.sources"] = errors.New("io")
	if _, err := m.Apply(context.Background(), Repository{Name: "r", Apt: &AptConfig{URL: "https://h/a"}}); err == nil ||
		!strings.Contains(err.Error(), "read existing repo file") {
		t.Fatalf("err = %v, want a wrapped sources-read failure", err)
	}
}

func TestApt_UpdateAptKey_ReadKeyErrorIsFatal(t *testing.T) {
	m, ff, fr := newTestManager(t, pkg.Apt)
	fr.Push(pmexec.Result{Stdout: "BINKEY"}, nil)
	ff.errs["ReadFile:/etc/apt/keyrings/r.gpg"] = errors.New("io")
	if _, err := m.Apply(context.Background(), Repository{Name: "r", Apt: &AptConfig{URL: "https://h/a", GPGKey: []byte("k")}}); err == nil ||
		!strings.Contains(err.Error(), "read existing GPG key") {
		t.Fatalf("err = %v, want a wrapped key-read failure", err)
	}
}

// removeConflictKeys: the target's own key and non-absolute references are
// skipped; an absolute key whose removal fails is warned (non-fatal).
func TestApt_Cleanup_KeySkipsAndRemoveWarning(t *testing.T) {
	m, ff, _ := newTestManager(t, pkg.Apt)
	dir := "/etc/apt/sources.list.d"
	ff.entries[dir] = []fs.DirEntry{{Name: "c.sources", IsDir: false}}
	ff.read[dir+"/c.sources"] = []byte(strings.Join([]string{
		"URIs: https://h/a",
		"Signed-By: /etc/apt/keyrings/corp.gpg", // == target's key → skipped
		"Signed-By: relative/key.gpg",           // non-absolute → skipped
		"Signed-By: /etc/apt/keyrings/doomed.gpg",
		"",
	}, "\n"))
	ff.errs["Remove:/etc/apt/keyrings/doomed.gpg"] = errors.New("busy")
	out, err := m.Apply(context.Background(), Repository{Name: "corp", Apt: &AptConfig{URL: "https://h/a"}})
	if err != nil {
		t.Fatal(err)
	}
	if ff.didCall("Remove:/etc/apt/keyrings/corp.gpg") {
		t.Error("cleanup must skip the target repo's own key")
	}
	if ff.didCall("Remove:relative/key.gpg") {
		t.Error("cleanup must skip a non-absolute key reference")
	}
	if !strings.Contains(out.Result.Stdout, "failed to remove conflicting GPG key") {
		t.Errorf("expected a conflicting-key remove warning, got %q", out.Result.Stdout)
	}
}

// A conflicting repo FILE whose removal fails is warned (non-fatal).
func TestApt_Cleanup_RepoFileRemoveWarning(t *testing.T) {
	m, ff, _ := newTestManager(t, pkg.Apt)
	dir := "/etc/apt/sources.list.d"
	ff.entries[dir] = []fs.DirEntry{{Name: "c.sources", IsDir: false}}
	ff.read[dir+"/c.sources"] = []byte("URIs: https://h/a\n")
	ff.errs["Remove:"+dir+"/c.sources"] = errors.New("busy")
	out, err := m.Apply(context.Background(), Repository{Name: "corp", Apt: &AptConfig{URL: "https://h/a"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Result.Stdout, "failed to remove conflicting repo file") {
		t.Errorf("expected a conflicting-file remove warning, got %q", out.Result.Stdout)
	}
}

// removeApt: the secondary (legacy + key) removals are best-effort warnings.
func TestApt_Remove_SecondaryWarnings(t *testing.T) {
	m, ff, _ := newTestManager(t, pkg.Apt)
	ff.present["/etc/apt/sources.list.d/corp.sources"] = true
	ff.errs["Remove:/etc/apt/sources.list.d/corp.list"] = errors.New("busy")
	ff.errs["Remove:/etc/apt/keyrings/corp.gpg"] = errors.New("busy")
	out, err := m.Remove(context.Background(), "corp")
	if err != nil {
		t.Fatalf("secondary remove failures must be non-fatal, got %v", err)
	}
	if !strings.Contains(out.Result.Stdout, "failed to remove legacy repo file") ||
		!strings.Contains(out.Result.Stdout, "failed to remove GPG key") {
		t.Errorf("expected secondary-remove warnings, got %q", out.Result.Stdout)
	}
}

// cleanupConflictingApt skip branches: the target's own legacy .list, an
// unreadable entry, and an entry that does not reference the URL are all skipped.
func TestApt_Cleanup_SkipBranches(t *testing.T) {
	m, ff, _ := newTestManager(t, pkg.Apt)
	dir := "/etc/apt/sources.list.d"
	ff.entries[dir] = []fs.DirEntry{
		{Name: "corp.list", IsDir: false},     // legacy .list form of the target → skipped
		{Name: "bad.sources", IsDir: false},   // unreadable → skipped
		{Name: "other.sources", IsDir: false}, // readable but no URL match → skipped
	}
	ff.errs["ReadFile:"+dir+"/bad.sources"] = errors.New("io")
	ff.read[dir+"/other.sources"] = []byte("URIs: https://different/repo\n")
	out, err := m.Apply(context.Background(), Repository{Name: "corp", Apt: &AptConfig{URL: "https://h/a"}})
	if err != nil {
		t.Fatal(err)
	}
	// Nothing matched → no conflict removals at all.
	for _, p := range []string{dir + "/corp.list", dir + "/bad.sources", dir + "/other.sources"} {
		if ff.didCall("Remove:" + p) {
			t.Errorf("unexpected removal of skipped entry %s", p)
		}
	}
	if strings.Contains(out.Result.Stdout, "removing conflicting") {
		t.Errorf("no entry should have been treated as a conflict: %q", out.Result.Stdout)
	}
}

// The best-effort pre-add removerepo failure is a logged note, never fatal.
func TestZypper_Apply_PreRemoveFailureIsNoted(t *testing.T) {
	m, _, fr := newTestManager(t, pkg.Zypper)
	fr.Push(pmexec.Result{ExitCode: 1, Stderr: "not found"}, nil) // pre-removerepo fails
	// addrepo + disable + refresh unscripted → clean.
	out, err := m.Apply(context.Background(), Repository{Name: "r", Zypper: &ZypperConfig{URL: "https://h/r", GPGCheck: true}})
	if err != nil {
		t.Fatalf("a failed pre-removerepo must not fail Apply, got %v", err)
	}
	if !strings.Contains(out.Result.Stdout, "pre-add removerepo failed") {
		t.Errorf("expected a pre-remove note, got %q", out.Result.Stdout)
	}
}

func TestZypper_Apply_DisableFailureIsFatal(t *testing.T) {
	m, _, fr := newTestManager(t, pkg.Zypper)
	fr.Push(pmexec.Result{}, nil)                               // removerepo
	fr.Push(pmexec.Result{}, nil)                               // addrepo
	fr.Push(pmexec.Result{ExitCode: 1, Stderr: "disable"}, nil) // modifyrepo --disable fails
	if _, err := m.Apply(context.Background(), Repository{Name: "r", Zypper: &ZypperConfig{URL: "https://h/r", GPGCheck: true, Enabled: false}}); err == nil ||
		!strings.Contains(err.Error(), "disable repo") {
		t.Fatalf("err = %v, want a wrapped disable failure", err)
	}
}

// zypper enable/autorefresh fatal-failure branches.
func TestZypper_Apply_EnableAndAutorefreshFailures(t *testing.T) {
	t.Run("enable fails", func(t *testing.T) {
		m, _, fr := newTestManager(t, pkg.Zypper)
		fr.Push(pmexec.Result{}, nil) // removerepo
		fr.Push(pmexec.Result{}, nil) // addrepo
		fr.Push(pmexec.Result{ExitCode: 1, Stderr: "enable"}, nil)
		if _, err := m.Apply(context.Background(), Repository{Name: "r", Zypper: &ZypperConfig{URL: "https://h/r", GPGCheck: true, Enabled: true}}); err == nil ||
			!strings.Contains(err.Error(), "enable repo") {
			t.Fatalf("err = %v, want a wrapped enable failure", err)
		}
	})
	t.Run("refresh failure non-fatal", func(t *testing.T) {
		m, _, fr := newTestManager(t, pkg.Zypper)
		fr.Push(pmexec.Result{}, nil)                                   // removerepo
		fr.Push(pmexec.Result{}, nil)                                   // addrepo
		fr.Push(pmexec.Result{}, nil)                                   // disable
		fr.Push(pmexec.Result{ExitCode: 1, Stderr: "refresh net"}, nil) // refresh
		out, err := m.Apply(context.Background(), Repository{Name: "r", Zypper: &ZypperConfig{URL: "https://h/r", GPGCheck: true}})
		if err != nil {
			t.Fatalf("final refresh failure must be non-fatal, got %v", err)
		}
		if !strings.Contains(out.Result.Stdout, "warning: failed to refresh repo") {
			t.Errorf("expected a refresh warning, got %q", out.Result.Stdout)
		}
	})
}
