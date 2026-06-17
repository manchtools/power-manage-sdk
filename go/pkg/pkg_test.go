package pkg

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

// --- shared test harness ---------------------------------------------------

// newFake returns a FakeRunner reporting the Direct backend. Escalate is still
// recorded on each Command, so escalation assertions work regardless.
func newFake() *exectest.FakeRunner { return exectest.New(pmexec.Direct) }

// argv renders a recorded Command as "name arg1 arg2 …" for substring asserts.
func argv(c pmexec.Command) string {
	return strings.Join(append([]string{c.Name}, c.Args...), " ")
}

// stubLookPath overrides the package lookPath seam so only the named binaries
// resolve on PATH. Restored at test end.
func stubLookPath(t *testing.T, present ...string) {
	t.Helper()
	set := make(map[string]bool, len(present))
	for _, p := range present {
		set[p] = true
	}
	orig := lookPath
	lookPath = func(name string) (string, error) {
		if set[name] {
			return "/usr/bin/" + name, nil
		}
		return "", errors.New("not found")
	}
	t.Cleanup(func() { lookPath = orig })
}

// mustNew builds a Manager over a fresh FakeRunner and fails the test on error.
func mustNew(t *testing.T, b Backend, opts ...Option) (Manager, *exectest.FakeRunner) {
	t.Helper()
	f := newFake()
	m, err := New(b, f, opts...)
	if err != nil {
		t.Fatalf("New(%v): %v", b, err)
	}
	return m, f
}

// ok scripts the next runner call as a clean success with the given stdout.
func ok(f *exectest.FakeRunner, stdout string) { f.Push(pmexec.Result{Stdout: stdout}, nil) }

// --- New -------------------------------------------------------------------

func TestNew_AllBackends(t *testing.T) {
	for _, b := range []Backend{Apt, Dnf, Pacman, Zypper, Flatpak} {
		m, err := New(b, newFake())
		if err != nil {
			t.Fatalf("New(%v) unexpected error: %v", b, err)
		}
		if m.Backend() != b {
			t.Errorf("New(%v).Backend() = %v, want %v", b, m.Backend(), b)
		}
	}
}

func TestNew_RejectsUnknownBackend(t *testing.T) {
	for _, b := range []Backend{0, Backend(99), Backend(-1)} {
		if _, err := New(b, newFake()); !errors.Is(err, ErrUnknownBackend) {
			t.Errorf("New(%d) error = %v, want ErrUnknownBackend", int(b), err)
		}
	}
}

func TestNew_RejectsNilRunner(t *testing.T) {
	_, err := New(Apt, nil)
	if err == nil || !strings.Contains(err.Error(), "runner is required") {
		t.Errorf("New(Apt, nil) error = %v, want 'runner is required'", err)
	}
}

func TestNew_FlatpakIsFlatpakManager(t *testing.T) {
	m, err := New(Flatpak, newFake())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.(FlatpakManager); !ok {
		t.Fatalf("New(Flatpak) is %T, want a FlatpakManager", m)
	}
}

func TestNew_NativeBackendsAreNotFlatpakManager(t *testing.T) {
	for _, b := range []Backend{Apt, Dnf, Pacman, Zypper} {
		m, _ := New(b, newFake())
		if _, ok := m.(FlatpakManager); ok {
			t.Errorf("%v unexpectedly satisfies FlatpakManager", b)
		}
	}
}

// WithUserScope must flip flatpak to --user and drop escalation; the default is
// --system and escalated.
func TestNew_FlatpakScopeOption(t *testing.T) {
	t.Run("default is system + escalated", func(t *testing.T) {
		m, f := mustNew(t, Flatpak)
		ok(f, "")
		if err := m.Update(context.Background()); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		if !c.Escalate {
			t.Error("system-scope flatpak must escalate")
		}
		if !strings.Contains(argv(c), "--system") {
			t.Errorf("argv = %q, want --system", argv(c))
		}
	})
	t.Run("WithUserScope is user + unescalated", func(t *testing.T) {
		m, f := mustNew(t, Flatpak, WithUserScope())
		ok(f, "")
		if err := m.Update(context.Background()); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		if c.Escalate {
			t.Error("user-scope flatpak must NOT escalate")
		}
		if !strings.Contains(argv(c), "--user") {
			t.Errorf("argv = %q, want --user", argv(c))
		}
	})
}

// WithUserScope is documented as flatpak-only; applying it to a native backend
// must not change its (always-escalated) behaviour.
func TestNew_UserScopeIgnoredByNativeBackends(t *testing.T) {
	m, f := mustNew(t, Apt, WithUserScope())
	stubLookPath(t, "apt")
	ok(f, "")
	if err := m.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := f.Calls()[0]; !c.Escalate {
		t.Error("native apt must escalate regardless of WithUserScope")
	}
}

// --- Backend.String --------------------------------------------------------

func TestBackend_String(t *testing.T) {
	cases := map[Backend]string{
		Apt:         "apt",
		Dnf:         "dnf",
		Pacman:      "pacman",
		Zypper:      "zypper",
		Flatpak:     "flatpak",
		Backend(0):  "Backend(0)",
		Backend(99): "Backend(99)",
	}
	for b, want := range cases {
		if got := b.String(); got != want {
			t.Errorf("Backend(%d).String() = %q, want %q", int(b), got, want)
		}
	}
}

// --- Detect ----------------------------------------------------------------

func TestDetect(t *testing.T) {
	cases := []struct {
		name    string
		present []string
		want    []Backend
	}{
		{"none", nil, nil},
		{"apt only", []string{"apt-get"}, []Backend{Apt}},
		{"dnf only", []string{"dnf"}, []Backend{Dnf}},
		{"pacman only", []string{"pacman"}, []Backend{Pacman}},
		{"zypper only", []string{"zypper"}, []Backend{Zypper}},
		{"flatpak only", []string{"flatpak"}, []Backend{Flatpak}},
		{"native + flatpak", []string{"dnf", "flatpak"}, []Backend{Dnf, Flatpak}},
		{"priority order", []string{"flatpak", "zypper", "apt-get"}, []Backend{Apt, Zypper, Flatpak}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubLookPath(t, tc.present...)
			got := Detect(context.Background())
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Detect() = %v, want %v", got, tc.want)
			}
		})
	}
}
