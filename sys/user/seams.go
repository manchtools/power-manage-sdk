package user

import (
	"context"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/fs"
)

// fsManager is the narrow slice of fs.Manager this package uses: the -M+chown
// home-fixup path and the AccountsService config write/remove. A small interface
// so tests inject a fake via the newFS seam instead of touching a real
// filesystem or privilege.
type fsManager interface {
	WriteFile(ctx context.Context, path string, data []byte, opts fs.WriteOptions) error
	Remove(ctx context.Context, path string) error
	SetOwnershipRecursive(ctx context.Context, path, owner, group string) error
}

// newFS builds the fs.Manager (over the same injected Runner) the Manager writes
// through. A package var so tests override it to return a fake.
var newFS = func(r exec.Runner) (fsManager, error) { return fs.New(r) }

// accountsServiceDir is the AccountsService per-user config directory. A var (not
// const) so tests can point it at a temp dir.
var accountsServiceDir = "/var/lib/AccountsService/users"
