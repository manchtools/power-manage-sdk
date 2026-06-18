package timesync

import (
	"context"
	"errors"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

func TestNew_NilRunner(t *testing.T) {
	if _, err := New(Chrony, nil); !errors.Is(err, exec.ErrRunnerRequired) {
		t.Error("New(_, nil) returned nil error")
	}
}

func TestNew_UnknownBackend(t *testing.T) {
	for _, b := range []Backend{0, Backend(-1), Backend(99)} {
		if _, err := New(b, exectest.New(exec.Direct)); !errors.Is(err, ErrUnknownBackend) {
			t.Errorf("New(%d) err = %v, want ErrUnknownBackend", b, err)
		}
	}
}

func TestNew_Backends(t *testing.T) {
	if m, err := New(Timedatectl, exectest.New(exec.Direct)); err != nil {
		t.Errorf("New(Timedatectl): %v", err)
	} else if _, ok := m.(*timedatectlManager); !ok {
		t.Errorf("New(Timedatectl) = %T", m)
	}
	if m, err := New(Chrony, exectest.New(exec.Direct)); err != nil {
		t.Errorf("New(Chrony): %v", err)
	} else if _, ok := m.(*chronyManager); !ok {
		t.Errorf("New(Chrony) = %T", m)
	}
}

func TestBackendString(t *testing.T) {
	cases := map[Backend]string{Timedatectl: "timedatectl", Chrony: "chrony", Backend(0): "Backend(0)"}
	for b, want := range cases {
		if got := b.String(); got != want {
			t.Errorf("Backend(%d).String() = %q, want %q", int(b), got, want)
		}
	}
}

func TestDetect(t *testing.T) {
	cases := []struct {
		name    string
		present map[string]bool
		want    []Backend
	}{
		{"none", map[string]bool{}, nil},
		{"timedatectl only", map[string]bool{"timedatectl": true}, []Backend{Timedatectl}},
		{"chronyc only", map[string]bool{"chronyc": true}, []Backend{Chrony}},
		{"both", map[string]bool{"timedatectl": true, "chronyc": true}, []Backend{Timedatectl, Chrony}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prev := lookPath
			t.Cleanup(func() { lookPath = prev }) // restored even if an assertion fails
			lookPath = func(name string) (string, error) {
				if tc.present[name] {
					return "/usr/bin/" + name, nil
				}
				return "", errors.New("not found")
			}
			got := Detect(context.Background())
			if len(got) != len(tc.want) {
				t.Fatalf("Detect(%v) = %v, want %v", tc.present, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("Detect[%d] = %v, want %v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestRunRead_ErrorMapping(t *testing.T) {
	ctx := context.Background()
	r := exectest.New(exec.Direct)
	r.Push(exec.Result{ExitCode: 1, Stderr: "boom"}, nil)
	if _, err := runRead(ctx, r, "chronyc"); err == nil {
		t.Error("runRead must map a non-zero exit to an error")
	}
	r.Push(exec.Result{}, errors.New("gone"))
	if _, err := runRead(ctx, r, "chronyc"); err == nil {
		t.Error("runRead must surface an exec error")
	}
	// unprivileged
	r.Push(exec.Result{Stdout: "x"}, nil)
	if _, err := runRead(ctx, r, "chronyc"); err != nil {
		t.Fatal(err)
	}
	if r.Calls()[2].Escalate {
		t.Error("timesync reads must not escalate")
	}
}
