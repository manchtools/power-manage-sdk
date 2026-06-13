//go:build !unix

package fs

import (
	"context"
	"errors"
)

// removeDirSecure is unix-only: the fd-anchored, symlink-refusing
// recursive delete relies on openat/unlinkat semantics that do not exist
// on non-unix platforms. The agent targets Linux, so this stub merely
// keeps the package buildable elsewhere (e.g. cross-platform `go vet`).
func removeDirSecure(_ context.Context, _ string) error {
	return errors.New("fs: secure directory removal is not supported on this platform")
}
