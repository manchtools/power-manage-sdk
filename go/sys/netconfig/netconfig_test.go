package netconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
	"github.com/manchtools/power-manage/sdk/go/sys/fs"
)

// fakeFS records WriteFile calls and replays a scripted error.
type fakeFS struct {
	writes   []fakeWrite
	writeErr error
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

// withFakeFS swaps newFS to return ff for the duration of t.
func withFakeFS(t *testing.T, ff *fakeFS) {
	t.Helper()
	prev := newFS
	t.Cleanup(func() { newFS = prev })
	newFS = func(exec.Runner) (fsManager, error) { return ff, nil }
}

func TestNew_NilRunner(t *testing.T) {
	if _, err := New(NetworkManager, nil); !errors.Is(err, exec.ErrRunnerRequired) {
		t.Errorf("New(_, nil) error = %v, want ErrRunnerRequired", err)
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
	if m, err := New(NetworkManager, exectest.New(exec.Direct)); err != nil {
		t.Errorf("New(NetworkManager): %v", err)
	} else if _, ok := m.(*nmBackend); !ok {
		t.Errorf("New(NetworkManager) = %T, want *nmBackend", m)
	}
	withFakeFS(t, &fakeFS{})
	if m, err := New(SystemdNetworkd, exectest.New(exec.Direct)); err != nil {
		t.Errorf("New(SystemdNetworkd): %v", err)
	} else if _, ok := m.(*networkdBackend); !ok {
		t.Errorf("New(SystemdNetworkd) = %T, want *networkdBackend", m)
	}
}

func TestNew_PropagatesFSError(t *testing.T) {
	prev := newFS
	t.Cleanup(func() { newFS = prev })
	sentinel := errors.New("fs boom")
	newFS = func(exec.Runner) (fsManager, error) { return nil, sentinel }
	if _, err := New(SystemdNetworkd, exectest.New(exec.Direct)); !errors.Is(err, sentinel) {
		t.Errorf("New(SystemdNetworkd) err = %v, want the fs error", err)
	}
}

func TestNew_SystemdNetworkdUsesRealFS(t *testing.T) {
	// Exercise the production newFS closure (fs.New) — the other networkd tests
	// stub it.
	if _, err := New(SystemdNetworkd, exectest.New(exec.Direct)); err != nil {
		t.Errorf("New(SystemdNetworkd) with the real fs.Manager: %v", err)
	}
}

func TestBackendString(t *testing.T) {
	cases := map[Backend]string{NetworkManager: "networkmanager", SystemdNetworkd: "systemd-networkd", Backend(0): "Backend(0)"}
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
		{"nmcli only", map[string]bool{"nmcli": true}, []Backend{NetworkManager}},
		{"networkctl only", map[string]bool{"networkctl": true}, []Backend{SystemdNetworkd}},
		{"both", map[string]bool{"nmcli": true, "networkctl": true}, []Backend{NetworkManager, SystemdNetworkd}},
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

func TestRunHelpers_ErrorMapping(t *testing.T) {
	ctx := context.Background()
	t.Run("runPriv non-zero exit", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{ExitCode: 1, Stderr: "boom"}, nil)
		var ce *exec.CommandError
		if err := runPriv(ctx, r, "nmcli", "x"); !errors.As(err, &ce) {
			t.Errorf("err = %v, want *exec.CommandError", err)
		}
	})
	t.Run("runPriv exec error", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{}, errors.New("gone"))
		if err := runPriv(ctx, r, "nmcli"); err == nil {
			t.Error("runPriv swallowed an exec error")
		}
	})
	t.Run("runRead non-zero exit", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{ExitCode: 1}, nil)
		if _, err := runRead(ctx, r, "ip"); err == nil {
			t.Error("runRead swallowed a non-zero exit")
		}
	})
	t.Run("runRead exec error", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{}, errors.New("gone"))
		if _, err := runRead(ctx, r, "ip"); err == nil {
			t.Error("runRead swallowed an exec error")
		}
	})
}
