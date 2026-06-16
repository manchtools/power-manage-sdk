package service

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

func mgr(t *testing.T, f *exectest.FakeRunner) Manager {
	t.Helper()
	m, err := New(Systemd, f)
	if err != nil {
		t.Fatalf("New(Systemd): %v", err)
	}
	return m
}

func wantOneCmd(t *testing.T, f *exectest.FakeRunner, args []string, escalate bool) {
	t.Helper()
	calls := f.Calls()
	if len(calls) != 1 {
		t.Fatalf("got %d commands, want 1: %+v", len(calls), calls)
	}
	c := calls[0]
	if c.Name != "systemctl" {
		t.Errorf("command name = %q, want systemctl", c.Name)
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
	if _, err := New(Systemd, nil); err == nil {
		t.Error("New with nil runner returned nil error")
	}
	if _, err := New(Systemd, f); err != nil {
		t.Errorf("New(Systemd, runner) err = %v, want nil", err)
	}
}

// Mutations — golden argv, all escalated, all with the "--" separator.
func TestMutations_GoldenArgv(t *testing.T) {
	const unit = "nginx.service"
	tests := []struct {
		name string
		call func(Manager) error
		args []string
	}{
		{"Enable", func(m Manager) error { return m.Enable(context.Background(), unit) }, []string{"enable", "--", unit}},
		{"Disable", func(m Manager) error { return m.Disable(context.Background(), unit) }, []string{"disable", "--", unit}},
		{"EnableNow", func(m Manager) error { return m.EnableNow(context.Background(), unit) }, []string{"enable", "--now", "--", unit}},
		{"DisableNow", func(m Manager) error { return m.DisableNow(context.Background(), unit) }, []string{"disable", "--now", "--", unit}},
		{"Start", func(m Manager) error { return m.Start(context.Background(), unit) }, []string{"start", "--", unit}},
		{"Stop", func(m Manager) error { return m.Stop(context.Background(), unit) }, []string{"stop", "--", unit}},
		{"Restart", func(m Manager) error { return m.Restart(context.Background(), unit) }, []string{"restart", "--", unit}},
		{"Mask", func(m Manager) error { return m.Mask(context.Background(), unit) }, []string{"mask", "--", unit}},
		{"Unmask", func(m Manager) error { return m.Unmask(context.Background(), unit) }, []string{"unmask", "--", unit}},
		{"DaemonReload", func(m Manager) error { return m.DaemonReload(context.Background()) }, []string{"daemon-reload"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := exectest.New(exec.Direct)
			if err := tc.call(mgr(t, f)); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			wantOneCmd(t, f, tc.args, true)
		})
	}
}

// Queries run UNescalated as `systemctl <verb> -- <unit>`.
func TestQueries_GoldenArgvUnescalated(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: "enabled\n"}, nil)
	if _, err := mgr(t, f).IsEnabled(context.Background(), "nginx.service"); err != nil {
		t.Fatal(err)
	}
	wantOneCmd(t, f, []string{"is-enabled", "--", "nginx.service"}, false)
}

func TestIsEnabled(t *testing.T) {
	cases := []struct {
		out  string
		want bool
	}{
		{"enabled", true},
		{"enabled-runtime", true},
		{"disabled", false}, // exits 1 but whitelisted → a real "no"
		{"static", false},   // boots via deps; not toggleable
		{"indirect", false},
		{"masked", false},
	}
	for _, c := range cases {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{Stdout: c.out + "\n", ExitCode: 1}, nil) // non-zero exit is fine
		got, err := mgr(t, f).IsEnabled(context.Background(), "nginx.service")
		if err != nil {
			t.Fatalf("%s: %v", c.out, err)
		}
		if got != c.want {
			t.Errorf("IsEnabled(%s) = %v, want %v", c.out, got, c.want)
		}
	}
}

func TestIsActiveAndMasked(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: "active\n"}, nil)
	if ok, err := mgr(t, f).IsActive(context.Background(), "nginx.service"); err != nil || !ok {
		t.Errorf("IsActive(active) = (%v,%v), want (true,nil)", ok, err)
	}
	f2 := exectest.New(exec.Direct)
	f2.Push(exec.Result{Stdout: "inactive\n", ExitCode: 3}, nil)
	if ok, err := mgr(t, f2).IsActive(context.Background(), "nginx.service"); ok || err != nil {
		t.Errorf("IsActive(inactive) = (%v, %v), want (false, nil)", ok, err)
	}
	f3 := exectest.New(exec.Direct)
	f3.Push(exec.Result{Stdout: "masked-runtime\n"}, nil)
	if ok, err := mgr(t, f3).IsMasked(context.Background(), "nginx.service"); err != nil || !ok {
		t.Errorf("IsMasked(masked-runtime) = (%v,%v), want (true,nil)", ok, err)
	}
}

func TestStatus_Combinations(t *testing.T) {
	t.Run("enabled + active", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{Stdout: "enabled\n"}, nil)
		f.Push(exec.Result{Stdout: "active\n"}, nil)
		st, err := mgr(t, f).Status(context.Background(), "nginx.service")
		if err != nil {
			t.Fatal(err)
		}
		if !st.Enabled || !st.Active || st.Static || st.Masked {
			t.Errorf("Status = %+v, want Enabled+Active", st)
		}
	})
	t.Run("static + inactive", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{Stdout: "static\n"}, nil)
		f.Push(exec.Result{Stdout: "inactive\n", ExitCode: 3}, nil)
		st, err := mgr(t, f).Status(context.Background(), "dbus.service")
		if err != nil {
			t.Fatal(err)
		}
		if st.Enabled || !st.Static || st.Active {
			t.Errorf("Status = %+v, want Static only", st)
		}
	})
	t.Run("masked", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{Stdout: "masked\n"}, nil)
		f.Push(exec.Result{Stdout: "inactive\n", ExitCode: 3}, nil)
		st, err := mgr(t, f).Status(context.Background(), "tmp.mount")
		if err != nil {
			t.Fatal(err)
		}
		if !st.Masked || st.Enabled {
			t.Errorf("Status = %+v, want Masked", st)
		}
	})
}

// Weird/unrecognised query output must be a FAILURE, not silently "disabled".
func TestQuery_UnrecognisedOutputFailsClosed(t *testing.T) {
	for _, out := range []string{"not-found", "", "could not be found", "Failed to get unit"} {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{Stdout: out + "\n", ExitCode: 4}, nil)
		if _, err := mgr(t, f).IsEnabled(context.Background(), "ghost.service"); err == nil {
			t.Errorf("IsEnabled with output %q returned nil error; want fail-closed (must not collapse to 'disabled')", out)
		}
	}
}

// An exec failure (systemctl missing, ctx cancelled) on a query is surfaced.
func TestQuery_ExecErrorSurfaces(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{}, exec.ErrEscalationUnavailable) // stand-in exec error
	if _, err := mgr(t, f).IsActive(context.Background(), "nginx.service"); err == nil {
		t.Error("IsActive returned nil error on an exec failure")
	}
}

func TestMutation_NonZeroExitIsCommandError(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{ExitCode: 1, Stderr: "Failed to enable unit: Unit file ghost.service does not exist."}, nil)
	err := mgr(t, f).Enable(context.Background(), "ghost.service")
	var ce *exec.CommandError
	if !errors.As(err, &ce) || ce.ExitCode != 1 {
		t.Errorf("Enable err = %v, want *exec.CommandError exit 1", err)
	}
}

func TestMutation_ExecErrorPropagates(t *testing.T) {
	f := exectest.New(exec.Sudo)
	f.Push(exec.Result{}, exec.ErrEscalationUnavailable)
	if err := mgr(t, f).Start(context.Background(), "nginx.service"); !errors.Is(err, exec.ErrEscalationUnavailable) {
		t.Errorf("Start err = %v, want ErrEscalationUnavailable", err)
	}
}

// TestEveryMethodRejectsUnsafeUnitNameBeforeRunner: self-discovering per-parameter
// guard — for every Manager method, a flag-shaped unit name "-rf" never reaches
// the Runner. (fs seams are no-op'd so WriteUnit's content sub-case is hermetic.)
func TestEveryMethodRejectsUnsafeUnitNameBeforeRunner(t *testing.T) {
	const unsafe = "-rf"
	const safe = "nginx.service" // a valid unit name for the non-target string params

	defer swapFSSeams(t)()

	mt := reflect.TypeOf((*Manager)(nil)).Elem()
	if mt.NumMethod() == 0 {
		t.Fatal("matches-zero guard: Manager has no methods")
	}
	ctxType := reflect.TypeOf((*context.Context)(nil)).Elem()
	checked := 0

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
				default:
					args[p] = reflect.Zero(pt)
				}
			}
			fn.Call(args)
			if n := len(f.Calls()); n != 0 {
				t.Errorf("%s ran %d command(s) when string param #%d was unsafe (%q) — validate the unit name before the Runner", name, n, target, unsafe)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("matches-zero guard: no unit-name-taking methods were exercised")
	}
}

// swapFSSeams replaces the fs seams with no-ops for the duration of a test,
// returning a restore func. Keeps WriteUnit/RemoveUnit reflection cases hermetic.
func swapFSSeams(t *testing.T) func() {
	t.Helper()
	w, r := writeFileAtomic, removeStrict
	writeFileAtomic = func(context.Context, string, string, string, string, string) error { return nil }
	removeStrict = func(context.Context, string) error { return nil }
	return func() { writeFileAtomic, removeStrict = w, r }
}
