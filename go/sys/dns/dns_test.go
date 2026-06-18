package dns

import (
	"context"
	"errors"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
	"github.com/manchtools/power-manage/sdk/go/sys/fs"
)

// fakeFS records WriteFile/Mkdir calls and replays scripted errors, so the
// Resolved backend's drop-in path is testable without touching disk.
type fakeFS struct {
	writes   []fakeWrite
	mkdirs   []string
	writeErr error
	mkdirErr error
}

type fakeWrite struct {
	path string
	data []byte
	opts fs.WriteOptions
}

func (f *fakeFS) WriteFile(_ context.Context, path string, data []byte, opts fs.WriteOptions) error {
	f.writes = append(f.writes, fakeWrite{path, data, opts})
	return f.writeErr
}

func (f *fakeFS) Mkdir(_ context.Context, path string, _ fs.MkdirOptions) error {
	f.mkdirs = append(f.mkdirs, path)
	return f.mkdirErr
}

// withFakeFS swaps newFS to return ff for the duration of t.
func withFakeFS(t *testing.T, ff *fakeFS) {
	t.Helper()
	prev := newFS
	t.Cleanup(func() { newFS = prev })
	newFS = func(exec.Runner) (fsManager, error) { return ff, nil }
}

func TestNew_NilRunner(t *testing.T) {
	if _, err := New(Resolved, nil); !errors.Is(err, exec.ErrRunnerRequired) {
		t.Errorf("New(_, nil) error = %v, want ErrRunnerRequired", err)
	}
}

func TestNew_UnknownBackend(t *testing.T) {
	for _, b := range []Backend{0, Backend(-1), Backend(99)} {
		_, err := New(b, exectest.New(exec.Direct))
		if !errors.Is(err, ErrUnknownBackend) {
			t.Errorf("New(%d) err = %v, want ErrUnknownBackend", b, err)
		}
	}
}

func TestNew_ResolvedAndNetworkManager(t *testing.T) {
	withFakeFS(t, &fakeFS{})
	m, err := New(Resolved, exectest.New(exec.Direct))
	if err != nil {
		t.Fatalf("New(Resolved) err = %v", err)
	}
	if _, ok := m.(*resolvedManager); !ok {
		t.Errorf("New(Resolved) = %T, want *resolvedManager", m)
	}
	m, err = New(NetworkManager, exectest.New(exec.Direct))
	if err != nil {
		t.Fatalf("New(NetworkManager) err = %v", err)
	}
	if _, ok := m.(*nmManager); !ok {
		t.Errorf("New(NetworkManager) = %T, want *nmManager", m)
	}
}

// TestNew_ResolvedUsesRealFS exercises the production newFS closure (fs.New over
// the injected Runner) — the other Resolved tests stub newFS, so without this
// the real construction path is never run.
func TestNew_ResolvedUsesRealFS(t *testing.T) {
	m, err := New(Resolved, exectest.New(exec.Direct))
	if err != nil {
		t.Fatalf("New(Resolved) with the real fs.Manager: %v", err)
	}
	if _, ok := m.(*resolvedManager); !ok {
		t.Errorf("New(Resolved) = %T, want *resolvedManager", m)
	}
}

func TestNew_PropagatesFSError(t *testing.T) {
	prev := newFS
	t.Cleanup(func() { newFS = prev })
	sentinel := errors.New("fs construction failed")
	newFS = func(exec.Runner) (fsManager, error) { return nil, sentinel }
	if _, err := New(Resolved, exectest.New(exec.Direct)); !errors.Is(err, sentinel) {
		t.Errorf("New(Resolved) err = %v, want the fs construction error", err)
	}
}

func TestBackendString(t *testing.T) {
	cases := map[Backend]string{Resolved: "resolved", NetworkManager: "networkmanager", Backend(0): "Backend(0)", Backend(7): "Backend(7)"}
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
		{"resolvectl only", map[string]bool{"resolvectl": true}, []Backend{Resolved}},
		{"nmcli only", map[string]bool{"nmcli": true}, []Backend{NetworkManager}},
		{"both", map[string]bool{"resolvectl": true, "nmcli": true}, []Backend{Resolved, NetworkManager}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prev := lookPath
			t.Cleanup(func() { lookPath = prev })
			lookPath = func(name string) (string, error) {
				if tc.present[name] {
					return "/usr/bin/" + name, nil
				}
				return "", errors.New("not found")
			}
			got := Detect(context.Background())
			if len(got) != len(tc.want) {
				t.Fatalf("Detect = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("Detect[%d] = %v, want %v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// runPriv/runRead map a non-zero exit and an exec failure into an error; a clean
// exit returns nil / stdout.
func TestRunHelpers_ErrorMapping(t *testing.T) {
	ctx := context.Background()

	t.Run("runPriv non-zero exit", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{ExitCode: 1, Stderr: "boom"}, nil)
		var ce *exec.CommandError
		if err := runPriv(ctx, r, "resolvectl", "x"); !errors.As(err, &ce) {
			t.Errorf("err = %v, want *exec.CommandError", err)
		}
	})
	t.Run("runPriv exec error", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{}, errors.New("not executable"))
		if err := runPriv(ctx, r, "resolvectl"); err == nil {
			t.Error("runPriv swallowed an exec error")
		}
	})
	t.Run("runPriv escalates", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{}, nil)
		if err := runPriv(ctx, r, "systemctl", "restart", "x"); err != nil {
			t.Fatal(err)
		}
		if !r.Calls()[0].Escalate {
			t.Error("runPriv must escalate")
		}
	})
	t.Run("runRead returns stdout", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{Stdout: "value\n"}, nil)
		out, err := runRead(ctx, r, "nmcli", "-g", "X", "device", "show")
		if err != nil || out != "value\n" {
			t.Errorf("runRead = (%q,%v), want value", out, err)
		}
		if r.Calls()[0].Escalate {
			t.Error("runRead must NOT escalate")
		}
	})
	t.Run("runRead non-zero exit", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{ExitCode: 10, Stderr: "no"}, nil)
		if _, err := runRead(ctx, r, "nmcli"); err == nil {
			t.Error("runRead swallowed a non-zero exit")
		}
	})
	t.Run("runRead exec error", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{}, errors.New("gone"))
		if _, err := runRead(ctx, r, "nmcli"); err == nil {
			t.Error("runRead swallowed an exec error")
		}
	})
}
