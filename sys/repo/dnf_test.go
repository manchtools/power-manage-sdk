package repo

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/pkg"
	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

func TestDnf_Apply_WritesRepoFileImportsKeyAndRefreshes(t *testing.T) {
	m, ff, fr := newTestManager(t, pkg.Dnf)
	out, err := m.Apply(context.Background(), Repository{Name: "corp", Dnf: &DnfConfig{
		BaseURL:        "https://packages.example.com/el9",
		Description:    "Corp EL9",
		Enabled:        true,
		GPGCheck:       true,
		GPGKey:         "https://packages.example.com/RPM-GPG-KEY",
		ModuleHotfixes: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Changed {
		t.Error("first Apply must report Changed=true")
	}
	want := "[corp]\n" +
		"name=Corp EL9\n" +
		"baseurl=https://packages.example.com/el9\n" +
		"enabled=1\n" +
		"gpgcheck=1\n" +
		"gpgkey=https://packages.example.com/RPM-GPG-KEY\n" +
		"module_hotfixes=1\n"
	if got := ff.wrote("/etc/yum.repos.d/corp.repo"); got != want {
		t.Errorf("repo file =\n%q\nwant\n%q", got, want)
	}
	// rpm --import -- <ref> (the `--` blocks a flag-shaped ref), then a
	// repo-scoped makecache.
	wantCmds := []string{
		"rpm --import -- https://packages.example.com/RPM-GPG-KEY",
		"dnf -y makecache --repo corp",
	}
	if got := argvs(fr); strings.Join(got, " | ") != strings.Join(wantCmds, " | ") {
		t.Errorf("commands = %v\nwant %v", got, wantCmds)
	}
}

func TestDnf_Apply_NoKeyDisabledNoGpgcheck(t *testing.T) {
	m, ff, fr := newTestManager(t, pkg.Dnf)
	if _, err := m.Apply(context.Background(), Repository{Name: "r", Dnf: &DnfConfig{
		BaseURL: "https://h/r", Enabled: false, GPGCheck: false,
	}}); err != nil {
		t.Fatal(err)
	}
	want := "[r]\nname=r\nbaseurl=https://h/r\nenabled=0\ngpgcheck=0\n"
	if got := ff.wrote("/etc/yum.repos.d/r.repo"); got != want {
		t.Errorf("repo file = %q, want %q", got, want)
	}
	// No gpgkey → no rpm --import; only the makecache runs.
	if got := argvs(fr); len(got) != 1 || got[0] != "dnf -y makecache --repo r" {
		t.Errorf("commands = %v, want just makecache (no rpm import)", got)
	}
}

func TestDnf_Apply_GPGCheckFalseIgnoresKey(t *testing.T) {
	m, ff, fr := newTestManager(t, pkg.Dnf)
	if _, err := m.Apply(context.Background(), Repository{Name: "r", Dnf: &DnfConfig{
		BaseURL: "https://h/r", Enabled: true, GPGCheck: false, GPGKey: "https://h/KEY",
	}}); err != nil {
		t.Fatal(err)
	}
	body := ff.wrote("/etc/yum.repos.d/r.repo")
	if strings.Contains(body, "gpgkey=") {
		t.Fatalf("repo file contains gpgkey despite gpgcheck=0:\n%s", body)
	}
	if got := argvs(fr); len(got) != 1 || got[0] != "dnf -y makecache --repo r" {
		t.Fatalf("commands = %v, want only makecache and no rpm import", got)
	}
}

func TestDnf_Apply_Idempotent(t *testing.T) {
	m, ff, fr := newTestManager(t, pkg.Dnf)
	desired := "[r]\nname=r\nbaseurl=https://h/r\nenabled=1\ngpgcheck=0\n"
	ff.read["/etc/yum.repos.d/r.repo"] = []byte(desired)
	out, err := m.Apply(context.Background(), Repository{Name: "r", Dnf: &DnfConfig{BaseURL: "https://h/r", Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Changed {
		t.Error("identical existing file must report Changed=false")
	}
	if ff.didCall("WriteFile:/etc/yum.repos.d/r.repo") {
		t.Error("idempotent Apply must not rewrite the file")
	}
	if n := len(fr.Calls()); n != 0 {
		t.Errorf("idempotent Apply ran %d commands, want 0 (no makecache)", n)
	}
}

func TestDnf_Apply_KeyImportFailureIsNonFatal(t *testing.T) {
	m, _, fr := newTestManager(t, pkg.Dnf)
	fr.Push(pmexec.Result{ExitCode: 1, Stderr: "rpm: import failed"}, nil) // rpm --import
	out, err := m.Apply(context.Background(), Repository{Name: "r", Dnf: &DnfConfig{
		BaseURL: "https://h/r", GPGCheck: true, GPGKey: "https://h/KEY",
	}})
	if err != nil {
		t.Fatalf("key-import failure must be non-fatal, got err = %v", err)
	}
	if !out.Changed {
		t.Error("the repo file was still written, so Changed=true")
	}
	if !strings.Contains(out.Result.Stdout, "warning: failed to import GPG key") {
		t.Errorf("expected a key-import warning in output, got %q", out.Result.Stdout)
	}
}

func TestDnf_Apply_RefreshFailureIsNonFatal(t *testing.T) {
	m, _, fr := newTestManager(t, pkg.Dnf)
	fr.Push(pmexec.Result{ExitCode: 1, Stderr: "makecache failed"}, nil) // makecache (no key → first cmd)
	out, err := m.Apply(context.Background(), Repository{Name: "r", Dnf: &DnfConfig{BaseURL: "https://h/r"}})
	if err != nil {
		t.Fatalf("refresh failure must be non-fatal, got %v", err)
	}
	if !strings.Contains(out.Result.Stdout, "warning: failed to refresh repo metadata") {
		t.Errorf("expected a refresh warning, got %q", out.Result.Stdout)
	}
}

func TestDnf_Apply_WriteErrorIsFatal(t *testing.T) {
	m, ff, _ := newTestManager(t, pkg.Dnf)
	ff.errs["WriteFile:/etc/yum.repos.d/r.repo"] = errors.New("disk full")
	if _, err := m.Apply(context.Background(), Repository{Name: "r", Dnf: &DnfConfig{BaseURL: "https://h/r"}}); err == nil ||
		!strings.Contains(err.Error(), "write repo file") {
		t.Fatalf("err = %v, want a wrapped write failure", err)
	}
}

func TestDnf_Apply_ReadErrorIsFatal(t *testing.T) {
	m, ff, _ := newTestManager(t, pkg.Dnf)
	ff.errs["ReadFile:/etc/yum.repos.d/r.repo"] = errors.New("io error")
	if _, err := m.Apply(context.Background(), Repository{Name: "r", Dnf: &DnfConfig{BaseURL: "https://h/r"}}); err == nil ||
		!strings.Contains(err.Error(), "read existing repo file") {
		t.Fatalf("err = %v, want a wrapped read failure", err)
	}
}

func TestDnf_Remove(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		m, ff, _ := newTestManager(t, pkg.Dnf)
		ff.present["/etc/yum.repos.d/r.repo"] = true
		out, err := m.Remove(context.Background(), "r")
		if err != nil {
			t.Fatal(err)
		}
		if !out.Changed || !ff.didCall("Remove:/etc/yum.repos.d/r.repo") {
			t.Errorf("Remove(present) must delete the file and report Changed=true (changed=%v)", out.Changed)
		}
	})
	t.Run("absent is idempotent", func(t *testing.T) {
		m, ff, _ := newTestManager(t, pkg.Dnf)
		out, err := m.Remove(context.Background(), "r")
		if err != nil {
			t.Fatal(err)
		}
		if out.Changed || ff.didCall("Remove:/etc/yum.repos.d/r.repo") {
			t.Error("Remove(absent) must be a no-op (Changed=false, no delete)")
		}
	})
	t.Run("exists error is fatal", func(t *testing.T) {
		m, ff, _ := newTestManager(t, pkg.Dnf)
		ff.errs["Exists:/etc/yum.repos.d/r.repo"] = errors.New("probe failed")
		if _, err := m.Remove(context.Background(), "r"); err == nil {
			t.Fatal("a probe failure must fail closed, not report absent")
		}
	})
	t.Run("remove error is fatal", func(t *testing.T) {
		m, ff, _ := newTestManager(t, pkg.Dnf)
		ff.present["/etc/yum.repos.d/r.repo"] = true
		ff.errs["Remove:/etc/yum.repos.d/r.repo"] = errors.New("denied")
		if _, err := m.Remove(context.Background(), "r"); err == nil {
			t.Fatal("a remove failure must surface")
		}
	})
	t.Run("invalid name rejected", func(t *testing.T) {
		m, _, _ := newTestManager(t, pkg.Dnf)
		if _, err := m.Remove(context.Background(), "-rf"); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("err = %v, want ErrInvalidName", err)
		}
	})
}
