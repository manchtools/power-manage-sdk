package repo

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/manchtools/power-manage-sdk/pkg"
	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
	"github.com/manchtools/power-manage-sdk/sys/fs"
)

// fakeFS is a recording fsManager. It records every op (as "Op:path", in order),
// returns scripted contents/existence/entries per path, and can be forced to
// error on a given "op:path". It lets repo unit tests assert the exact file
// operations a backend performs without touching the real filesystem (the real
// fs.Manager's Direct WriteFile hits real syscalls; its Sudo path stats real
// parent dirs).
type fakeFS struct {
	mu      sync.Mutex
	calls   []string
	written map[string][]byte
	read    map[string][]byte
	present map[string]bool
	entries map[string][]fs.DirEntry
	errs    map[string]error
}

func newFakeFS() *fakeFS {
	return &fakeFS{
		written: map[string][]byte{},
		read:    map[string][]byte{},
		present: map[string]bool{},
		entries: map[string][]fs.DirEntry{},
		errs:    map[string]error{},
	}
}

func (f *fakeFS) record(s string) { f.mu.Lock(); f.calls = append(f.calls, s); f.mu.Unlock() }

func (f *fakeFS) ReadFile(_ context.Context, path string) ([]byte, error) {
	f.record("ReadFile:" + path)
	if e := f.errs["ReadFile:"+path]; e != nil {
		return nil, e
	}
	return f.read[path], nil
}

func (f *fakeFS) ReadDir(_ context.Context, path string) ([]fs.DirEntry, error) {
	f.record("ReadDir:" + path)
	if e := f.errs["ReadDir:"+path]; e != nil {
		return nil, e
	}
	return f.entries[path], nil
}

func (f *fakeFS) WriteFile(_ context.Context, path string, data []byte, _ fs.WriteOptions) error {
	f.record("WriteFile:" + path)
	if e := f.errs["WriteFile:"+path]; e != nil {
		return e
	}
	f.written[path] = data
	return nil
}

func (f *fakeFS) Remove(_ context.Context, path string) error {
	f.record("Remove:" + path)
	return f.errs["Remove:"+path]
}

func (f *fakeFS) Mkdir(_ context.Context, path string, _ fs.MkdirOptions) error {
	f.record("Mkdir:" + path)
	return f.errs["Mkdir:"+path]
}

func (f *fakeFS) Exists(_ context.Context, path string) (bool, error) {
	f.record("Exists:" + path)
	if e := f.errs["Exists:"+path]; e != nil {
		return false, e
	}
	return f.present[path], nil
}

func (f *fakeFS) wrote(path string) string { return string(f.written[path]) }

func (f *fakeFS) didCall(want string) bool {
	for _, c := range f.calls {
		if c == want {
			return true
		}
	}
	return false
}

// newTestManager builds a Manager for backend b with the fake fs injected via the
// newFS seam and a Direct FakeRunner for package-manager commands.
func newTestManager(t *testing.T, b pkg.Backend) (*manager, *fakeFS, *exectest.FakeRunner) {
	t.Helper()
	ff := newFakeFS()
	orig := newFS
	newFS = func(pmexec.Runner) (fsManager, error) { return ff, nil }
	t.Cleanup(func() { newFS = orig })
	fr := exectest.New(pmexec.Direct)
	m, err := New(b, fr)
	if err != nil {
		t.Fatalf("New(%s): %v", b, err)
	}
	return m.(*manager), ff, fr
}

// argvs renders each recorded runner Command as "name arg1 arg2 …".
func argvs(fr *exectest.FakeRunner) []string {
	calls := fr.Calls()
	out := make([]string, len(calls))
	for i, c := range calls {
		out[i] = strings.TrimSpace(c.Name + " " + strings.Join(c.Args, " "))
	}
	return out
}

// --- New -------------------------------------------------------------------

func TestNew_NilRunnerRejected(t *testing.T) {
	if _, err := New(pkg.Apt, nil); !errors.Is(err, pmexec.ErrRunnerRequired) {
		t.Fatalf("New(nil runner) err = %v, want ErrRunnerRequired", err)
	}
}

func TestNew_UnsupportedBackendRejected(t *testing.T) {
	fr := exectest.New(pmexec.Direct)
	for _, b := range []pkg.Backend{pkg.Flatpak, pkg.Backend(0), pkg.Backend(99)} {
		if _, err := New(b, fr); !errors.Is(err, ErrUnsupportedBackend) {
			t.Errorf("New(%v) err = %v, want ErrUnsupportedBackend", b, err)
		}
	}
}

func TestNew_SupportedBackends(t *testing.T) {
	fr := exectest.New(pmexec.Direct)
	for _, b := range []pkg.Backend{pkg.Apt, pkg.Dnf, pkg.Pacman, pkg.Zypper} {
		m, err := New(b, fr)
		if err != nil {
			t.Fatalf("New(%s): %v", b, err)
		}
		if m.Backend() != b {
			t.Errorf("Backend() = %s, want %s", m.Backend(), b)
		}
	}
}

func TestNew_FSConstructionErrorPropagates(t *testing.T) {
	orig := newFS
	sentinel := errors.New("fs boom")
	newFS = func(pmexec.Runner) (fsManager, error) { return nil, sentinel }
	t.Cleanup(func() { newFS = orig })
	if _, err := New(pkg.Apt, exectest.New(pmexec.Direct)); !errors.Is(err, sentinel) {
		t.Fatalf("New err = %v, want the fs construction error", err)
	}
}

// --- Apply / Remove dispatch defense-in-depth ------------------------------

// A Manager with an out-of-range backend (only constructable by bypassing New)
// must fail closed rather than silently no-op.
func TestApplyRemove_UnreachableBackendFailsClosed(t *testing.T) {
	m := &manager{b: pkg.Flatpak, r: exectest.New(pmexec.Direct), fsm: newFakeFS()}
	if _, err := m.Apply(context.Background(), Repository{Name: "x"}); !errors.Is(err, ErrUnsupportedBackend) {
		t.Errorf("Apply err = %v, want ErrUnsupportedBackend", err)
	}
	if _, err := m.Remove(context.Background(), "x"); !errors.Is(err, ErrUnsupportedBackend) {
		t.Errorf("Remove err = %v, want ErrUnsupportedBackend", err)
	}
}

// Apply with no sub-config for the Manager's backend is a caller bug, not a
// silent no-op.
func TestApply_MissingConfigForBackend(t *testing.T) {
	cases := []struct {
		b pkg.Backend
		r Repository
	}{
		{pkg.Apt, Repository{Name: "x"}},
		{pkg.Dnf, Repository{Name: "x"}},
		{pkg.Pacman, Repository{Name: "x"}},
		{pkg.Zypper, Repository{Name: "x"}},
	}
	for _, c := range cases {
		m, _, _ := newTestManager(t, c.b)
		if _, err := m.Apply(context.Background(), c.r); !errors.Is(err, ErrMissingConfig) {
			t.Errorf("%s Apply(no config) err = %v, want ErrMissingConfig", c.b, err)
		}
	}
}
