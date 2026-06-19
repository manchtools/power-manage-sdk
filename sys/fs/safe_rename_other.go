//go:build unix && !linux

package fs

import (
	"fmt"
	"os"
)

// safeRename on non-Linux unixes: RENAME_NOREPLACE is Linux-specific
// (renameat2(2)), so we fall back to a best-effort Lstat + os.Rename.
// The fallback is documented as racy in the Linux variant; it's
// acceptable here because the SDK's sole production target is Linux
// — non-Linux Unix builds exist for `go test` portability only.
func safeRename(oldPath, newPath string, removeExisting bool) error {
	if !removeExisting {
		if _, err := os.Lstat(newPath); err == nil {
			return fmt.Errorf("rename %s -> %s: destination exists", oldPath, newPath)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("lstat %s: %w", newPath, err)
		}
	}
	if err := os.Rename(oldPath, newPath); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", oldPath, newPath, err)
	}
	return nil
}
