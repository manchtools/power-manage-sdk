package repo

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/pkg"
	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

func TestPacman_Apply_AppendsSectionAndSyncs(t *testing.T) {
	m, ff, fr := newTestManager(t, pkg.Pacman)
	ff.read["/etc/pacman.conf"] = []byte("[options]\nHoldPkg = pacman\n\n[core]\nInclude = /etc/pacman.d/mirrorlist\n")
	out, err := m.Apply(context.Background(), Repository{Name: "corp", Pacman: &PacmanConfig{
		Server: "https://h/$repo/$arch", SigLevel: "Optional TrustAll",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Changed {
		t.Error("first Apply must report Changed=true")
	}
	got := ff.wrote("/etc/pacman.conf")
	wantSection := "\n[corp]\nSigLevel = Optional TrustAll\nServer = https://h/$repo/$arch\n"
	if !strings.HasSuffix(got, wantSection) {
		t.Errorf("pacman.conf =\n%q\nwant it to end with\n%q", got, wantSection)
	}
	// The pre-existing content must be preserved (only appended to).
	if !strings.Contains(got, "[options]") || !strings.Contains(got, "[core]") {
		t.Errorf("pacman.conf lost pre-existing sections:\n%q", got)
	}
	if cmds := argvs(fr); len(cmds) != 1 || cmds[0] != "pacman -Sy --noconfirm" {
		t.Errorf("commands = %v, want a single pacman -Sy", cmds)
	}
}

func TestPacman_Apply_ReplacesExistingSection(t *testing.T) {
	m, ff, _ := newTestManager(t, pkg.Pacman)
	ff.read["/etc/pacman.conf"] = []byte("[options]\nX = 1\n\n[corp]\nServer = https://old/\n\n[extra]\nInclude = /m\n")
	if _, err := m.Apply(context.Background(), Repository{Name: "corp", Pacman: &PacmanConfig{Server: "https://new/"}}); err != nil {
		t.Fatal(err)
	}
	got := ff.wrote("/etc/pacman.conf")
	if strings.Contains(got, "https://old/") {
		t.Errorf("old Server survived the replace:\n%q", got)
	}
	if !strings.Contains(got, "Server = https://new/") {
		t.Errorf("new Server missing:\n%q", got)
	}
	// [extra] (a sibling that followed the replaced section) must survive.
	if !strings.Contains(got, "[extra]") {
		t.Errorf("replacing [corp] wrongly consumed the following [extra] section:\n%q", got)
	}
}

func TestPacman_Apply_Idempotent(t *testing.T) {
	m, ff, fr := newTestManager(t, pkg.Pacman)
	// The conf already ends with exactly the section Apply would append.
	existing := "[options]\nX = 1\n[corp]\nServer = https://h/\n"
	ff.read["/etc/pacman.conf"] = []byte(existing)
	out, err := m.Apply(context.Background(), Repository{Name: "corp", Pacman: &PacmanConfig{Server: "https://h/"}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Changed {
		t.Errorf("already-configured repo must report Changed=false; conf rewritten to %q", ff.wrote("/etc/pacman.conf"))
	}
	if ff.didCall("WriteFile:/etc/pacman.conf") {
		t.Error("idempotent Apply must not rewrite pacman.conf")
	}
	if n := len(fr.Calls()); n != 0 {
		t.Errorf("idempotent Apply ran %d commands, want 0", n)
	}
}

func TestPacman_Apply_NoSigLevel(t *testing.T) {
	m, ff, _ := newTestManager(t, pkg.Pacman)
	ff.read["/etc/pacman.conf"] = []byte("[options]\n")
	if _, err := m.Apply(context.Background(), Repository{Name: "r", Pacman: &PacmanConfig{Server: "https://h/"}}); err != nil {
		t.Fatal(err)
	}
	got := ff.wrote("/etc/pacman.conf")
	if strings.Contains(got, "SigLevel") {
		t.Errorf("no SigLevel configured, but one was written:\n%q", got)
	}
}

func TestPacman_Apply_SyncFailureIsNonFatal(t *testing.T) {
	m, ff, fr := newTestManager(t, pkg.Pacman)
	ff.read["/etc/pacman.conf"] = []byte("[options]\n")
	fr.Push(pmexec.Result{ExitCode: 1, Stderr: "db sync failed"}, nil)
	out, err := m.Apply(context.Background(), Repository{Name: "r", Pacman: &PacmanConfig{Server: "https://h/"}})
	if err != nil {
		t.Fatalf("db-sync failure must be non-fatal, got %v", err)
	}
	if !strings.Contains(out.Result.Stdout, "warning: failed to sync repository database") {
		t.Errorf("expected a sync warning, got %q", out.Result.Stdout)
	}
}

func TestPacman_Apply_ReadAndWriteErrors(t *testing.T) {
	t.Run("read error", func(t *testing.T) {
		m, ff, _ := newTestManager(t, pkg.Pacman)
		ff.errs["ReadFile:/etc/pacman.conf"] = errors.New("io")
		if _, err := m.Apply(context.Background(), Repository{Name: "r", Pacman: &PacmanConfig{Server: "https://h/"}}); err == nil ||
			!strings.Contains(err.Error(), "read pacman.conf") {
			t.Fatalf("err = %v, want a wrapped read failure", err)
		}
	})
	t.Run("write error", func(t *testing.T) {
		m, ff, _ := newTestManager(t, pkg.Pacman)
		ff.read["/etc/pacman.conf"] = []byte("[options]\n")
		ff.errs["WriteFile:/etc/pacman.conf"] = errors.New("ro")
		if _, err := m.Apply(context.Background(), Repository{Name: "r", Pacman: &PacmanConfig{Server: "https://h/"}}); err == nil ||
			!strings.Contains(err.Error(), "write pacman.conf") {
			t.Fatalf("err = %v, want a wrapped write failure", err)
		}
	})
}

func TestPacman_Remove(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		m, ff, _ := newTestManager(t, pkg.Pacman)
		ff.read["/etc/pacman.conf"] = []byte("[options]\nX = 1\n[corp]\nServer = https://h/\n")
		out, err := m.Remove(context.Background(), "corp")
		if err != nil {
			t.Fatal(err)
		}
		if !out.Changed {
			t.Error("removing a present section must report Changed=true")
		}
		if got := ff.wrote("/etc/pacman.conf"); strings.Contains(got, "[corp]") {
			t.Errorf("[corp] survived removal:\n%q", got)
		}
	})
	t.Run("absent is idempotent", func(t *testing.T) {
		m, ff, _ := newTestManager(t, pkg.Pacman)
		ff.read["/etc/pacman.conf"] = []byte("[options]\n")
		out, err := m.Remove(context.Background(), "corp")
		if err != nil {
			t.Fatal(err)
		}
		if out.Changed || ff.didCall("WriteFile:/etc/pacman.conf") {
			t.Error("removing an absent section must be a no-op")
		}
	})
	t.Run("read error", func(t *testing.T) {
		m, ff, _ := newTestManager(t, pkg.Pacman)
		ff.errs["ReadFile:/etc/pacman.conf"] = errors.New("io")
		if _, err := m.Remove(context.Background(), "corp"); err == nil {
			t.Fatal("a read failure must surface")
		}
	})
	t.Run("write error", func(t *testing.T) {
		m, ff, _ := newTestManager(t, pkg.Pacman)
		ff.read["/etc/pacman.conf"] = []byte("[corp]\nServer = https://h/\n")
		ff.errs["WriteFile:/etc/pacman.conf"] = errors.New("ro")
		if _, err := m.Remove(context.Background(), "corp"); err == nil {
			t.Fatal("a write failure must surface")
		}
	})
}

func TestRemovePacmanSection_EndOfFile(t *testing.T) {
	// A section that runs to EOF (no following [section]) is fully removed.
	in := "[options]\nX = 1\n[last]\nServer = https://h/\nKey = v\n"
	got := removePacmanSection(in, "last")
	if strings.Contains(got, "[last]") || strings.Contains(got, "Server = https://h/") {
		t.Errorf("EOF section not fully removed:\n%q", got)
	}
	if !strings.Contains(got, "[options]") {
		t.Errorf("removed too much:\n%q", got)
	}
}
