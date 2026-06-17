package pkg

import (
	"context"
	"errors"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

// aptM builds an apt Manager over a fresh fake with "apt" resolvable on PATH
// (so aptCommand() == "apt", making argv assertions deterministic).
func aptM(t *testing.T) (Manager, *exectest.FakeRunner) {
	t.Helper()
	stubLookPath(t, "apt", "apt-get")
	return mustNew(t, Apt)
}

func TestApt_Version(t *testing.T) {
	t.Run("parses version field", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "apt 2.7.14build2 (amd64)\n")
		v, err := m.Version(context.Background())
		if err != nil || v != "2.7.14build2" {
			t.Fatalf("v=%q err=%v", v, err)
		}
		if argv(f.Calls()[0]) != "apt --version" || f.Calls()[0].Escalate {
			t.Errorf("argv = %q (escalate=%v)", argv(f.Calls()[0]), f.Calls()[0].Escalate)
		}
	})
	t.Run("short output yields empty version", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "apt\n")
		if v, err := m.Version(context.Background()); err != nil || v != "" {
			t.Fatalf("v=%q err=%v", v, err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("not found"))
		if _, err := m.Version(context.Background()); err == nil {
			t.Fatal("want exec error")
		}
	})
}

func TestApt_AptGetFallback(t *testing.T) {
	stubLookPath(t) // neither apt nor apt-get on PATH -> resolves to apt-get
	m, f := mustNew(t, Apt)
	ok(f, "")
	if err := m.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := f.Calls()[0]; c.Name != "apt-get" {
		t.Errorf("expected apt-get fallback, got %q", c.Name)
	}
}

func TestApt_Install(t *testing.T) {
	ctx := context.Background()
	t.Run("multiple packages, latest", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if err := m.Install(ctx, InstallOptions{}, "vim", "git"); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		if argv(c) != "apt install -y --fix-broken vim git" || !c.Escalate {
			t.Errorf("argv = %q (escalate=%v)", argv(c), c.Escalate)
		}
		if len(c.Env) == 0 || c.Env[0] != "DEBIAN_FRONTEND=noninteractive" {
			t.Errorf("env = %v, want DEBIAN_FRONTEND", c.Env)
		}
	})
	t.Run("pinned version", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if err := m.Install(ctx, InstallOptions{Version: "2:8.2.3995-1ubuntu2"}, "vim"); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); !strings.Contains(a, "vim=2:8.2.3995-1ubuntu2") {
			t.Errorf("argv = %q, want name=version", a)
		}
	})
	t.Run("allow downgrade", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if err := m.Install(ctx, InstallOptions{Version: "1.0", AllowDowngrade: true}, "vim"); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); !strings.Contains(a, "--allow-downgrades") {
			t.Errorf("argv = %q, want --allow-downgrades", a)
		}
	})
	t.Run("empty is a no-op", func(t *testing.T) {
		m, f := aptM(t)
		if err := m.Install(ctx, InstallOptions{}); err != nil {
			t.Fatal(err)
		}
		if len(f.Calls()) != 0 {
			t.Error("empty install must run nothing")
		}
	})
	t.Run("bad name rejected before exec", func(t *testing.T) {
		m, f := aptM(t)
		err := m.Install(ctx, InstallOptions{}, "vim;rm -rf /")
		if err == nil || !strings.Contains(err.Error(), "invalid package name") {
			t.Fatalf("err = %v, want validation rejection", err)
		}
		if len(f.Calls()) != 0 {
			t.Error("rejected name must run nothing")
		}
	})
	t.Run("bad version rejected before exec", func(t *testing.T) {
		m, f := aptM(t)
		err := m.Install(ctx, InstallOptions{Version: "1.0;evil"}, "vim")
		if err == nil || !strings.Contains(err.Error(), "version") {
			t.Fatalf("err = %v, want version rejection", err)
		}
		if len(f.Calls()) != 0 {
			t.Error("rejected version must run nothing")
		}
	})
	t.Run("version with multiple packages rejected", func(t *testing.T) {
		m, f := aptM(t)
		err := m.Install(ctx, InstallOptions{Version: "1.0"}, "vim", "git")
		if err == nil || !strings.Contains(err.Error(), "exactly one package") {
			t.Fatalf("err = %v, want one-package rejection", err)
		}
		if len(f.Calls()) != 0 {
			t.Error("must run nothing")
		}
	})
	t.Run("version with zero packages rejected", func(t *testing.T) {
		m, _ := aptM(t)
		if err := m.Install(ctx, InstallOptions{Version: "1.0"}); err == nil {
			t.Fatal("version with no package must be rejected")
		}
	})
}

func TestApt_Remove(t *testing.T) {
	ctx := context.Background()
	t.Run("remove", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if err := m.Remove(ctx, RemoveOptions{}, "vim"); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[0]) != "apt remove -y vim" {
			t.Errorf("argv = %q", argv(f.Calls()[0]))
		}
	})
	t.Run("purge", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if err := m.Remove(ctx, RemoveOptions{Purge: true}, "vim"); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[0]) != "apt purge -y vim" {
			t.Errorf("argv = %q, want purge", argv(f.Calls()[0]))
		}
	})
	t.Run("empty no-op", func(t *testing.T) {
		m, f := aptM(t)
		if err := m.Remove(ctx, RemoveOptions{}); err != nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(f.Calls()))
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := aptM(t)
		if err := m.Remove(ctx, RemoveOptions{}, "--force"); err == nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d, want rejection", err, len(f.Calls()))
		}
	})
}

func TestApt_Update(t *testing.T) {
	m, f := aptM(t)
	ok(f, "")
	if err := m.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := f.Calls()[0]
	if argv(c) != "apt update" || !c.Escalate {
		t.Errorf("argv = %q (escalate=%v)", argv(c), c.Escalate)
	}
}

func TestApt_Upgrade(t *testing.T) {
	ctx := context.Background()
	t.Run("all -> dist-upgrade", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if err := m.Upgrade(ctx); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); !strings.HasPrefix(a, "apt dist-upgrade -y") {
			t.Errorf("argv = %q, want dist-upgrade", a)
		}
	})
	t.Run("specific -> only-upgrade", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if err := m.Upgrade(ctx, "vim"); err != nil {
			t.Fatal(err)
		}
		a := argv(f.Calls()[0])
		if !strings.Contains(a, "install -y --only-upgrade") || !strings.HasSuffix(a, "vim") {
			t.Errorf("argv = %q", a)
		}
	})
	t.Run("bad name", func(t *testing.T) {
		m, f := aptM(t)
		if err := m.Upgrade(ctx, "vim|sh"); err == nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(f.Calls()))
		}
	})
}

func TestApt_PinUnpin(t *testing.T) {
	ctx := context.Background()
	t.Run("pin", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if err := m.Pin(ctx, "vim"); err != nil {
			t.Fatal(err)
		}
		if c := f.Calls()[0]; argv(c) != "apt-mark hold vim" || !c.Escalate {
			t.Errorf("argv = %q (escalate=%v)", argv(c), c.Escalate)
		}
	})
	t.Run("unpin", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "")
		if err := m.Unpin(ctx, "vim"); err != nil {
			t.Fatal(err)
		}
		if argv(f.Calls()[0]) != "apt-mark unhold vim" {
			t.Errorf("argv = %q", argv(f.Calls()[0]))
		}
	})
	t.Run("pin empty no-op", func(t *testing.T) {
		m, f := aptM(t)
		if err := m.Pin(ctx); err != nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(f.Calls()))
		}
	})
	t.Run("unpin empty no-op", func(t *testing.T) {
		m, f := aptM(t)
		if err := m.Unpin(ctx); err != nil || len(f.Calls()) != 0 {
			t.Fatalf("err=%v calls=%d", err, len(f.Calls()))
		}
	})
	t.Run("pin bad name", func(t *testing.T) {
		m, f := aptM(t)
		if err := m.Pin(ctx, "a b"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection, no exec")
		}
	})
	t.Run("unpin bad name", func(t *testing.T) {
		m, f := aptM(t)
		if err := m.Unpin(ctx, "a b"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection, no exec")
		}
	})
}

func TestApt_Autoremove(t *testing.T) {
	m, f := aptM(t)
	ok(f, "")
	if err := m.Autoremove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := f.Calls()[0]; argv(c) != "apt autoremove -y" || !c.Escalate {
		t.Errorf("argv = %q (escalate=%v)", argv(c), c.Escalate)
	}
}

func TestApt_WriteFailure(t *testing.T) {
	m, f := aptM(t)
	f.Push(pmexec.Result{ExitCode: 100, Stderr: "E: Unable to locate package ghost"}, nil)
	err := m.Install(context.Background(), InstallOptions{}, "ghost")
	var ce *pmexec.CommandError
	if !errors.As(err, &ce) || ce.ExitCode != 100 {
		t.Fatalf("err = %v, want CommandError(exit 100)", err)
	}
	if !strings.Contains(ce.Stderr, "Unable to locate") {
		t.Errorf("stderr not preserved: %q", ce.Stderr)
	}
}

func TestApt_WriteExecError(t *testing.T) {
	m, f := aptM(t)
	f.Push(pmexec.Result{}, pmexec.ErrEscalationDenied)
	if err := m.Update(context.Background()); !errors.Is(err, pmexec.ErrEscalationDenied) {
		t.Fatalf("err = %v, want ErrEscalationDenied", err)
	}
}

func TestApt_Repair(t *testing.T) {
	ctx := context.Background()
	t.Run("happy path", func(t *testing.T) {
		stubLookPath(t, "apt")
		stubStatFile(t, nil) // no lock files present
		m, f := mustNew(t, Apt)
		ok(f, "") // dpkg --configure -a
		ok(f, "") // apt --fix-broken install
		ok(f, "") // apt update
		if err := m.Repair(ctx); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, c := range f.Calls() {
			got = append(got, c.Name+" "+strings.Join(c.Args[:1], ""))
		}
		if len(f.Calls()) != 3 {
			t.Fatalf("want 3 repair commands, got %d: %v", len(f.Calls()), got)
		}
	})
	t.Run("intermediate failures are warnings, final failure returned", func(t *testing.T) {
		stubLookPath(t, "apt")
		stubStatFile(t, nil)
		m, f := mustNew(t, Apt)
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "dpkg busy"}, nil)     // configure fails (warn)
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "still broken"}, nil)  // fix-broken fails (warn)
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "update failed"}, nil) // update fails (returned)
		err := m.Repair(ctx)
		if err == nil || !strings.Contains(err.Error(), "apt update failed") {
			t.Fatalf("err = %v, want apt update failure", err)
		}
	})
	t.Run("cancelled context stops at lock loop", func(t *testing.T) {
		stubLookPath(t, "apt")
		stubStatFile(t, nil)
		cctx, cancel := context.WithCancel(context.Background())
		cancel()
		m, f := mustNew(t, Apt)
		if err := m.Repair(cctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if len(f.Calls()) != 0 {
			t.Error("cancelled repair must run nothing")
		}
	})
	t.Run("cancellation during a repair step is propagated", func(t *testing.T) {
		stubLookPath(t, "apt")
		ctx2, cancel := context.WithCancel(context.Background())
		probes := 0
		// No lock files exist; cancel the context once the lock loop has finished
		// probing all four, so the first best-effort step sees the cancellation.
		stubStatFile(t, func() {
			probes++
			if probes >= 4 {
				cancel()
			}
		})
		m, _ := mustNew(t, Apt)
		if err := m.Repair(ctx2); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})
}

// --- reads -----------------------------------------------------------------

func TestApt_Search(t *testing.T) {
	t.Run("apt path parses 'name - desc'", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "vim - Vi IMproved\nneovim - heavily refactored vim fork\nnot-a-result\n")
		res, err := m.Search(context.Background(), "vim")
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 2 || res[0].Name != "vim" || res[0].Description != "Vi IMproved" {
			t.Fatalf("results = %+v", res)
		}
		if a := argv(f.Calls()[0]); a != "apt search --names-only vim" {
			t.Errorf("argv = %q", a)
		}
	})
	t.Run("apt-cache path when apt absent", func(t *testing.T) {
		stubLookPath(t) // no apt
		m, f := mustNew(t, Apt)
		ok(f, "vim - Vi IMproved\n")
		if _, err := m.Search(context.Background(), "vim"); err != nil {
			t.Fatal(err)
		}
		if a := argv(f.Calls()[0]); a != "apt-cache search vim" {
			t.Errorf("argv = %q, want apt-cache", a)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.Search(context.Background(), "vim"); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestApt_List(t *testing.T) {
	t.Run("parses installed, applies size and pin", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "vim\t2:8.2\tamd64\tinstall ok installed\t3000\tVi IMproved\n"+
			"halfpkg\t1.0\tamd64\tdeinstall ok config-files\t10\tleftover\n"+
			"short\tfields\n")
		ok(f, "vim\n") // getPinnedSet (apt-mark showhold)
		pkgs, err := m.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(pkgs) != 1 {
			t.Fatalf("want only the installed package, got %+v", pkgs)
		}
		p := pkgs[0]
		if p.Name != "vim" || p.Size != 3000*1024 || p.Description != "Vi IMproved" || !p.Pinned {
			t.Errorf("package = %+v", p)
		}
	})
	t.Run("pin-set lookup failure leaves packages unpinned", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "vim\t2:8.2\tamd64\tinstall ok installed\t3000\tVi IMproved\n")
		f.Push(pmexec.Result{}, errors.New("apt-mark missing")) // getPinnedSet fails
		pkgs, err := m.List(context.Background())
		if err != nil {
			t.Fatalf("List must tolerate a pin-set lookup failure, got %v", err)
		}
		if len(pkgs) != 1 || pkgs[0].Pinned {
			t.Errorf("packages = %+v, want one unpinned package", pkgs)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.List(context.Background()); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestApt_ListUpgradable(t *testing.T) {
	t.Run("parses upgradable rows", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "Listing...\n"+
			"vim/jammy-updates 2:8.2.2 amd64 [upgradable from: 2:8.2.1]\n"+
			"garbage line without match\n")
		ups, err := m.ListUpgradable(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(ups) != 1 {
			t.Fatalf("ups = %+v", ups)
		}
		u := ups[0]
		if u.Name != "vim" || u.NewVersion != "2:8.2.2" || u.CurrentVersion != "2:8.2.1" || u.Architecture != "amd64" {
			t.Errorf("update = %+v", u)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.ListUpgradable(context.Background()); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestApt_Show(t *testing.T) {
	ctx := context.Background()
	t.Run("installed and pinned", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "Package: vim\nVersion: 2:8.2\nArchitecture: amd64\nInstalled-Size: 3000\nDescription: Vi IMproved\n")
		f.Push(pmexec.Result{ExitCode: 0}, nil) // IsInstalled: dpkg -s -> installed
		ok(f, "vim\n")                          // IsPinned: apt-mark showhold vim
		p, err := m.Show(ctx, "vim")
		if err != nil {
			t.Fatal(err)
		}
		if p.Status != "installed" || p.Version != "2:8.2" || p.Size != 3000*1024 || !p.Pinned {
			t.Errorf("pkg = %+v", p)
		}
	})
	t.Run("available (not installed)", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "Package: vim\nVersion: 2:8.2\n")
		f.Push(pmexec.Result{ExitCode: 1}, nil) // dpkg -s -> not installed
		ok(f, "")                               // apt-mark showhold vim -> not pinned
		p, err := m.Show(ctx, "vim")
		if err != nil {
			t.Fatal(err)
		}
		if p.Status != "available" || p.Pinned {
			t.Errorf("pkg = %+v", p)
		}
	})
	t.Run("pin-check failure is tolerated", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "Package: vim\nVersion: 2:8.2\n")
		f.Push(pmexec.Result{ExitCode: 0}, nil)             // IsInstalled -> installed
		f.Push(pmexec.Result{}, errors.New("apt-mark err")) // IsPinned errors
		p, err := m.Show(ctx, "vim")
		if err != nil {
			t.Fatalf("Show must tolerate a pin-check failure, got %v", err)
		}
		if p.Pinned {
			t.Error("a failed pin check must leave Pinned false")
		}
	})
	t.Run("exec error on show", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.Show(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("validation reject", func(t *testing.T) {
		m, f := aptM(t)
		if _, err := m.Show(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection, no exec")
		}
	})
}

func TestApt_ListVersions(t *testing.T) {
	ctx := context.Background()
	t.Run("parses madison, dedups versions", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "  vim | 2:8.2 | http://archive jammy/main amd64\n"+
			"  vim | 2:8.2 | http://archive jammy/main i386\n"+
			"  vim | 2:8.1 | http://archive jammy/universe amd64\n"+
			"short | line\n")
		ok(f, "2:8.2\n") // InstalledVersion (dpkg-query)
		info, err := m.ListVersions(ctx, "vim")
		if err != nil {
			t.Fatal(err)
		}
		if info.Installed != "2:8.2" || len(info.Versions) != 2 {
			t.Fatalf("info = %+v", info)
		}
	})
	t.Run("installed-version lookup failure is tolerated", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "  vim | 2:8.2 | http://archive jammy/main amd64\n")
		f.Push(pmexec.Result{}, errors.New("dpkg-query err")) // InstalledVersion fails
		info, err := m.ListVersions(ctx, "vim")
		if err != nil {
			t.Fatalf("ListVersions must tolerate an installed-version lookup failure, got %v", err)
		}
		if info.Installed != "" || len(info.Versions) != 1 {
			t.Errorf("info = %+v", info)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.ListVersions(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("validation reject", func(t *testing.T) {
		m, f := aptM(t)
		if _, err := m.ListVersions(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection, no exec")
		}
	})
}

func TestApt_IsInstalled(t *testing.T) {
	ctx := context.Background()
	t.Run("installed (exit 0)", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{ExitCode: 0}, nil)
		got, err := m.IsInstalled(ctx, "vim")
		if err != nil || !got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("not installed (exit 1)", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{ExitCode: 1}, nil)
		if got, err := m.IsInstalled(ctx, "ghost"); err != nil || got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.IsInstalled(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("validation reject", func(t *testing.T) {
		m, f := aptM(t)
		if _, err := m.IsInstalled(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection, no exec")
		}
	})
}

func TestApt_InstalledVersion(t *testing.T) {
	ctx := context.Background()
	t.Run("trims output", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "2:8.2\n")
		if v, err := m.InstalledVersion(ctx, "vim"); err != nil || v != "2:8.2" {
			t.Fatalf("v=%q err=%v", v, err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.InstalledVersion(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("validation reject", func(t *testing.T) {
		m, f := aptM(t)
		if _, err := m.InstalledVersion(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection, no exec")
		}
	})
}

func TestApt_InstalledCount(t *testing.T) {
	t.Run("counts lines", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, ".\n.\n.\n")
		if n, err := m.InstalledCount(context.Background()); err != nil || n != 3 {
			t.Fatalf("n=%d err=%v", n, err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.InstalledCount(context.Background()); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestApt_HasUpdates(t *testing.T) {
	t.Run("Inst lines mean updates", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "Reading package lists...\nInst vim [2:8.2.1] (2:8.2.2 jammy [amd64])\nConf vim\n")
		got, err := m.HasUpdates(context.Background(), false)
		if err != nil || !got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("no Inst lines mean none", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "Reading package lists...\nCalculating upgrade...\n")
		if got, err := m.HasUpdates(context.Background(), true); err != nil || got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.HasUpdates(context.Background(), false); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestApt_IsPinned(t *testing.T) {
	ctx := context.Background()
	t.Run("held", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "vim\n")
		if got, err := m.IsPinned(ctx, "vim"); err != nil || !got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("not held", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "\n")
		if got, err := m.IsPinned(ctx, "vim"); err != nil || got {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.IsPinned(ctx, "vim"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("validation reject", func(t *testing.T) {
		m, f := aptM(t)
		if _, err := m.IsPinned(ctx, "v;m"); err == nil || len(f.Calls()) != 0 {
			t.Fatal("want rejection, no exec")
		}
	})
}

func TestApt_ListPinned(t *testing.T) {
	t.Run("lists held with versions", func(t *testing.T) {
		m, f := aptM(t)
		ok(f, "vim\n\ngit\n") // showhold (blank line skipped)
		ok(f, "2:8.2\n")      // InstalledVersion vim
		ok(f, "1:2.39\n")     // InstalledVersion git
		pkgs, err := m.ListPinned(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(pkgs) != 2 || pkgs[0].Name != "vim" || pkgs[0].Version != "2:8.2" || !pkgs[0].Pinned {
			t.Fatalf("pkgs = %+v", pkgs)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		m, f := aptM(t)
		f.Push(pmexec.Result{}, errors.New("boom"))
		if _, err := m.ListPinned(context.Background()); err == nil {
			t.Fatal("want error")
		}
	})
}
