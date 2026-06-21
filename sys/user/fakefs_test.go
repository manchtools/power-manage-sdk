package user

import (
	"context"
	"os"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/fs"
)

// fakeFS is a hermetic fsManager for user tests: it records the
// AccountsService write/remove, the home-fixup recursive chown, and the
// EnsureHome probe/create/seed/mode calls, and returns scripted errors.
// install() points the newFS seam at it for the test.
type fakeFS struct {
	writes  map[string]string
	removes []string
	chown   struct {
		path, owner, group string
		called             bool
	}
	// EnsureHome surface.
	present map[string]bool // Exists() answers
	mkdirs  []string
	copies  []struct{ src, dst string }
	chmods  struct {
		path string
		mode os.FileMode
	}
	existsErr, mkdirErr, copyErr, chmodErr error
	writeErr, removeErr, chownErr          error
}

func newFakeFS() *fakeFS {
	return &fakeFS{writes: map[string]string{}, present: map[string]bool{}}
}

func (f *fakeFS) Exists(_ context.Context, path string) (bool, error) {
	return f.present[path], f.existsErr
}

func (f *fakeFS) Mkdir(_ context.Context, path string, _ fs.MkdirOptions) error {
	f.mkdirs = append(f.mkdirs, path)
	if f.mkdirErr != nil {
		return f.mkdirErr // a failed mkdir must NOT mark the dir present
	}
	f.present[path] = true
	return nil
}

func (f *fakeFS) CopyTree(_ context.Context, src, dst string, _ fs.WriteOptions) error {
	f.copies = append(f.copies, struct{ src, dst string }{src, dst})
	return f.copyErr
}

func (f *fakeFS) SetMode(_ context.Context, path string, mode os.FileMode) error {
	f.chmods.path, f.chmods.mode = path, mode
	return f.chmodErr
}

func (f *fakeFS) WriteFile(_ context.Context, path string, data []byte, _ fs.WriteOptions) error {
	f.writes[path] = string(data)
	return f.writeErr
}

func (f *fakeFS) Remove(_ context.Context, path string) error {
	f.removes = append(f.removes, path)
	return f.removeErr
}

func (f *fakeFS) SetOwnershipRecursive(_ context.Context, path, owner, group string) error {
	f.chown.path, f.chown.owner, f.chown.group, f.chown.called = path, owner, group, true
	return f.chownErr
}

func (f *fakeFS) install(t *testing.T) *fakeFS {
	t.Helper()
	prev := newFS
	newFS = func(exec.Runner) (fsManager, error) { return f, nil }
	t.Cleanup(func() { newFS = prev })
	return f
}
