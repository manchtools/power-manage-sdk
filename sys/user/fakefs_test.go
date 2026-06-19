package user

import (
	"context"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/fs"
)

// fakeFS is a hermetic fsManager for user tests: it records the
// AccountsService write/remove and the home-fixup recursive chown, and returns
// scripted errors. install() points the newFS seam at it for the test.
type fakeFS struct {
	writes  map[string]string
	removes []string
	chown   struct {
		path, owner, group string
		called             bool
	}
	writeErr, removeErr, chownErr error
}

func newFakeFS() *fakeFS { return &fakeFS{writes: map[string]string{}} }

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
