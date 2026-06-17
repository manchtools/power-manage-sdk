package user

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

func mgr(t *testing.T, f *exectest.FakeRunner) Manager {
	t.Helper()
	m, err := New(ShadowUtils, f)
	if err != nil {
		t.Fatalf("New(ShadowUtils): %v", err)
	}
	return m
}

// wantOneCmd asserts exactly one command was run, with the given name, argv, and
// escalation flag.
func wantOneCmd(t *testing.T, f *exectest.FakeRunner, name string, args []string, escalate bool) {
	t.Helper()
	calls := f.Calls()
	if len(calls) != 1 {
		t.Fatalf("got %d commands, want 1: %+v", len(calls), calls)
	}
	c := calls[0]
	if c.Name != name {
		t.Errorf("command name = %q, want %q", c.Name, name)
	}
	if strings.Join(c.Args, "\x00") != strings.Join(args, "\x00") {
		t.Errorf("argv = %v\n want %v", c.Args, args)
	}
	if c.Escalate != escalate {
		t.Errorf("Escalate = %v, want %v", c.Escalate, escalate)
	}
}

func TestNew_FailClosed(t *testing.T) {
	f := exectest.New(exec.Direct)
	for _, b := range []Backend{0, Backend(-1), Backend(99)} {
		if _, err := New(b, f); !errors.Is(err, ErrUnknownBackend) {
			t.Errorf("New(%d) err = %v, want ErrUnknownBackend", b, err)
		}
	}
	if _, err := New(ShadowUtils, nil); err == nil {
		t.Error("New with nil runner returned nil error, want a required-runner error")
	}
	if _, err := New(ShadowUtils, f); err != nil {
		t.Errorf("New(ShadowUtils, runner) err = %v, want nil", err)
	}
}

// Create — golden argv across option combinations. HomeDir is set explicitly so
// the -m/-M home-exists stat is deterministic.
func TestCreate_GoldenArgv(t *testing.T) {
	nonexistent := filepath.Join(t.TempDir(), "nohome")

	t.Run("minimal interactive with home", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		if err := mgr(t, f).Create(context.Background(), "deploy", CreateOptions{HomeDir: nonexistent, CreateHome: true}); err != nil {
			t.Fatal(err)
		}
		wantOneCmd(t, f, "useradd", []string{"-d", nonexistent, "-s", "/bin/bash", "-m", "deploy"}, true)
	})

	t.Run("system account gets nologin + -r + -M", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		if err := mgr(t, f).Create(context.Background(), "svc", CreateOptions{System: true}); err != nil {
			t.Fatal(err)
		}
		wantOneCmd(t, f, "useradd", []string{"-s", "/usr/sbin/nologin", "-r", "-M", "svc"}, true)
	})

	t.Run("full options in canonical order", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		opts := CreateOptions{
			UID: 1500, PrimaryGroup: "staff", Groups: []string{"docker", "sudo"},
			HomeDir: nonexistent, Comment: "Service Acct", System: true, CreateHome: false,
		}
		if err := mgr(t, f).Create(context.Background(), "svc", opts); err != nil {
			t.Fatal(err)
		}
		wantOneCmd(t, f, "useradd", []string{
			"-u", "1500", "-g", "staff", "-G", "docker,sudo", "-d", nonexistent,
			"-s", "/usr/sbin/nologin", "-r", "-M", "-c", "Service Acct", "svc",
		}, true)
	})

	t.Run("explicit shell overrides the default", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		if err := mgr(t, f).Create(context.Background(), "ops", CreateOptions{Shell: "/bin/zsh"}); err != nil {
			t.Fatal(err)
		}
		wantOneCmd(t, f, "useradd", []string{"-s", "/bin/zsh", "-M", "ops"}, true)
	})
}

// Create over a PRE-EXISTING home uses -M (useradd -m would fail) and fixes
// ownership afterwards — exercised via the fs seam so the test stays hermetic.
func TestCreate_ExistingHomeUsesMinusMAndChowns(t *testing.T) {
	existing := t.TempDir() // exists
	f := exectest.New(exec.Direct)

	ffs := newFakeFS().install(t)

	if err := mgr(t, f).Create(context.Background(), "deploy", CreateOptions{HomeDir: existing, CreateHome: true, PrimaryGroup: "staff"}); err != nil {
		t.Fatal(err)
	}
	wantOneCmd(t, f, "useradd", []string{"-g", "staff", "-d", existing, "-s", "/bin/bash", "-M", "deploy"}, true)
	if !ffs.chown.called {
		t.Fatal("ownership of the pre-existing home was not fixed")
	}
	if ffs.chown.path != existing || ffs.chown.owner != "deploy" || ffs.chown.group != "staff" {
		t.Errorf("chown(%q,%q,%q), want (%q,deploy,staff)", ffs.chown.path, ffs.chown.owner, ffs.chown.group, existing)
	}
}

func TestCreate_ChownDefaultsGroupToUsername(t *testing.T) {
	existing := t.TempDir()
	f := exectest.New(exec.Direct)
	ffs := newFakeFS().install(t)

	if err := mgr(t, f).Create(context.Background(), "deploy", CreateOptions{HomeDir: existing, CreateHome: true}); err != nil {
		t.Fatal(err)
	}
	if ffs.chown.group != "deploy" {
		t.Errorf("chown group = %q, want the username (useradd matching-group default)", ffs.chown.group)
	}
}

func TestCreate_RejectsInvalidNameBeforeRunner(t *testing.T) {
	f := exectest.New(exec.Direct)
	if err := mgr(t, f).Create(context.Background(), "-rf", CreateOptions{}); err == nil {
		t.Error("Create with a flag-shaped name returned nil error")
	}
	if len(f.Calls()) != 0 {
		t.Errorf("runner was called for an invalid name: %+v", f.Calls())
	}
}

func TestCreate_MapsNonZeroExitToCommandError(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{ExitCode: 9, Stderr: "useradd: user 'deploy' already exists"}, nil)
	err := mgr(t, f).Create(context.Background(), "deploy", CreateOptions{})
	var ce *exec.CommandError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v, want *exec.CommandError", err)
	}
	if ce.ExitCode != 9 || !strings.Contains(ce.Stderr, "already exists") {
		t.Errorf("CommandError = %+v, want exit 9 + stderr", ce)
	}
}

func TestModify(t *testing.T) {
	t.Run("golden each field", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		opts := ModifyOptions{Shell: "/bin/zsh", HomeDir: "/srv/deploy", Comment: "Deploy Service", PrimaryGroup: "staff"}
		if err := mgr(t, f).Modify(context.Background(), "deploy", opts); err != nil {
			t.Fatal(err)
		}
		wantOneCmd(t, f, "usermod", []string{"-s", "/bin/zsh", "-d", "/srv/deploy", "-c", "Deploy Service", "-g", "staff", "deploy"}, true)
	})
	t.Run("empty options is a no-op (no usermod)", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		if err := mgr(t, f).Modify(context.Background(), "deploy", ModifyOptions{}); err != nil {
			t.Fatal(err)
		}
		if len(f.Calls()) != 0 {
			t.Errorf("empty Modify ran a command: %+v", f.Calls())
		}
	})
}

func TestDelete(t *testing.T) {
	t.Run("with home", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		if err := mgr(t, f).Delete(context.Background(), "deploy", DeleteOptions{RemoveHome: true}); err != nil {
			t.Fatal(err)
		}
		wantOneCmd(t, f, "userdel", []string{"-r", "deploy"}, true)
	})
	t.Run("without home", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		if err := mgr(t, f).Delete(context.Background(), "deploy", DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		wantOneCmd(t, f, "userdel", []string{"deploy"}, true)
	})
}

func TestLockUnlock(t *testing.T) {
	f := exectest.New(exec.Direct)
	if err := mgr(t, f).Lock(context.Background(), "deploy"); err != nil {
		t.Fatal(err)
	}
	wantOneCmd(t, f, "usermod", []string{"-L", "deploy"}, true)

	f2 := exectest.New(exec.Direct)
	if err := mgr(t, f2).Unlock(context.Background(), "deploy"); err != nil {
		t.Fatal(err)
	}
	wantOneCmd(t, f2, "usermod", []string{"-U", "deploy"}, true)
}

func TestGet(t *testing.T) {
	t.Run("parses passwd + groups + unlocked shadow", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{Stdout: "deploy:x:1000:1000:Deploy User:/home/deploy:/bin/bash\n"}, nil) // getent passwd
		f.Push(exec.Result{Stdout: "deploy:x:1000:\n"}, nil)                                        // getent group 1000
		f.Push(exec.Result{Stdout: "deploy docker sudo\n"}, nil)                                    // id -Gn
		f.Push(exec.Result{Stdout: "deploy:$6$abc:19000:0:99999:7:::\n"}, nil)                      // getent shadow

		info, err := mgr(t, f).Get(context.Background(), "deploy")
		if err != nil {
			t.Fatal(err)
		}
		if info.UID != 1000 || info.GID != 1000 || info.Comment != "Deploy User" || info.HomeDir != "/home/deploy" || info.Shell != "/bin/bash" {
			t.Errorf("Info = %+v", info)
		}
		if strings.Join(info.Groups, ",") != "docker,sudo" {
			t.Errorf("Groups = %v, want [docker sudo] (primary filtered)", info.Groups)
		}
		if info.Locked {
			t.Error("Locked = true, want false for a hashed shadow entry")
		}
		// The shadow read must be escalated.
		if c := f.Calls()[3]; c.Name != "getent" || !c.Escalate {
			t.Errorf("shadow read = %+v, want escalated getent", c)
		}
	})

	t.Run("detects locked account", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{Stdout: "deploy:x:1000:1000::/home/deploy:/bin/bash\n"}, nil)
		f.Push(exec.Result{Stdout: "deploy:x:1000:\n"}, nil)
		f.Push(exec.Result{Stdout: "deploy\n"}, nil)
		f.Push(exec.Result{Stdout: "deploy:!$6$abc:19000:0:99999:7:::\n"}, nil)
		info, err := mgr(t, f).Get(context.Background(), "deploy")
		if err != nil {
			t.Fatal(err)
		}
		if !info.Locked {
			t.Error("Locked = false, want true for a '!'-prefixed shadow entry")
		}
	})

	t.Run("malformed passwd entry errors", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{Stdout: "deploy:x:1000\n"}, nil)
		if _, err := mgr(t, f).Get(context.Background(), "deploy"); err == nil {
			t.Error("Get with a malformed passwd entry returned nil error")
		}
	})
}

func TestExists(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{ExitCode: 0}, nil)
		ok, err := mgr(t, f).Exists(context.Background(), "deploy")
		if err != nil || !ok {
			t.Errorf("Exists = (%v,%v), want (true,nil)", ok, err)
		}
	})
	t.Run("absent", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{ExitCode: 1}, nil)
		ok, _ := mgr(t, f).Exists(context.Background(), "ghost")
		if ok {
			t.Error("Exists = true for an absent user")
		}
	})
	t.Run("invalid name short-circuits without running id", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		ok, err := mgr(t, f).Exists(context.Background(), "-rf")
		if ok || err != nil {
			t.Errorf("Exists(-rf) = (%v,%v), want (false,nil)", ok, err)
		}
		if len(f.Calls()) != 0 {
			t.Error("ran id for an invalid name")
		}
	})
}

func TestPrimaryAndSupplementaryGroups(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: "staff\n"}, nil)
	pg, err := mgr(t, f).PrimaryGroup(context.Background(), "deploy")
	if err != nil || pg != "staff" {
		t.Errorf("PrimaryGroup = (%q,%v), want (staff,nil)", pg, err)
	}

	f2 := exectest.New(exec.Direct)
	f2.Push(exec.Result{Stdout: "staff docker sudo\n"}, nil) // id -Gn
	f2.Push(exec.Result{Stdout: "staff\n"}, nil)             // id -gn (primary)
	sg, err := mgr(t, f2).SupplementaryGroups(context.Background(), "deploy")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(sg, ",") != "docker,sudo" {
		t.Errorf("SupplementaryGroups = %v, want [docker sudo] (primary filtered)", sg)
	}
}

// TestEveryMethodRejectsUnsafeNameBeforeRunner is the self-discovering security
// guard: for EVERY Manager method, a flag-shaped name ("-rf") must never reach
// the Runner as a command argument. Discovered by reflection over the interface,
// so a newly-added method is covered automatically.
func TestEveryMethodRejectsUnsafeNameBeforeRunner(t *testing.T) {
	const unsafe = "-rf"
	mt := reflect.TypeOf((*Manager)(nil)).Elem()
	if mt.NumMethod() == 0 {
		t.Fatal("matches-zero guard: Manager has no methods — reflection is mis-scoped")
	}
	secretType := reflect.TypeOf(exec.Secret{})
	ctxType := reflect.TypeOf((*context.Context)(nil)).Elem()
	checked := 0

	// safe is a valid name/group placed in every OTHER string position, so each
	// string parameter is tested for validation INDIVIDUALLY — a method that
	// validates only one of several string params is still caught.
	const safe = "deploy"

	for i := 0; i < mt.NumMethod(); i++ {
		name := mt.Method(i).Name
		ft := reflect.ValueOf(mgr(t, exectest.New(exec.Direct))).MethodByName(name).Type()

		var stringParams []int
		for p := 0; p < ft.NumIn(); p++ {
			if ft.In(p).Kind() == reflect.String {
				stringParams = append(stringParams, p)
			}
		}
		if len(stringParams) == 0 {
			continue
		}

		// One sub-case per string parameter: only that param is unsafe, the
		// rest are valid. Catches a method that validates one string but not another.
		for _, target := range stringParams {
			f := exectest.New(exec.Direct)
			fn := reflect.ValueOf(mgr(t, f)).MethodByName(name)
			args := make([]reflect.Value, ft.NumIn())
			for p := 0; p < ft.NumIn(); p++ {
				pt := ft.In(p)
				switch {
				case pt == ctxType:
					args[p] = reflect.ValueOf(context.Background())
				case pt.Kind() == reflect.String:
					if p == target {
						args[p] = reflect.ValueOf(unsafe)
					} else {
						args[p] = reflect.ValueOf(safe)
					}
				case pt == secretType:
					args[p] = reflect.ValueOf(exec.Secret{})
				default:
					args[p] = reflect.Zero(pt)
				}
			}
			fn.Call(args)
			if n := len(f.Calls()); n != 0 {
				t.Errorf("%s ran %d command(s) when only string param #%d was unsafe (%q) — every string param must be validated before the Runner", name, n, target, unsafe)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("matches-zero guard: no name-taking methods were exercised")
	}
}
