package firewall

import (
	"context"
	"os"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/fs"
)

// fsManager is the narrow slice of fs.Manager the firewalld backend uses to
// materialise service XML. Keeping it minimal lets unit tests inject a tiny
// fake (via the newFS seam) without driving real privileged file ops.
type fsManager interface {
	WriteFile(ctx context.Context, path string, data []byte, opts fs.WriteOptions) error
	Remove(ctx context.Context, path string) error
}

// newFS builds the fs.Manager each Manager uses for privileged writes, over the
// same injected Runner. A package var so tests override it to return a fake.
var newFS = func(r exec.Runner) (fsManager, error) { return fs.New(r) }

// readFile reads a managed service XML body. It is a non-privileged read (the
// files live under /etc/firewalld/services, world-readable), so it stays a plain
// os.ReadFile seam rather than going through the escalated fs.Manager.ReadFile.
var readFile = os.ReadFile
