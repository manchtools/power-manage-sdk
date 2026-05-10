//go:build linux

package fs

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// safeRename renames oldPath to newPath. When removeExisting is true
// it behaves like os.Rename (atomically replaces newPath). When
// removeExisting is false it uses renameat2(2) with RENAME_NOREPLACE
// so a symlink an attacker may have planted at newPath between an
// existence check and this call cannot be silently replaced —
// renameat2 returns EEXIST instead.
//
// On kernels that do not support RENAME_NOREPLACE (pre-3.15, or some
// container runtimes that filter the syscall), we fall back to a
// best-effort O_NOFOLLOW open of newPath to confirm it is absent
// before a regular os.Rename. The fall-back is racy by design — the
// audit calls out that the safest answer is renameat2, but blocking
// updates on every container that filters it would create a denial-
// of-service for legitimate operators. The window is small (single
// syscall) and any attacker that wins it has to also hold inode
// permissions to the destination.
func safeRename(oldPath, newPath string, removeExisting bool) error {
	if removeExisting {
		if err := os.Rename(oldPath, newPath); err != nil {
			return fmt.Errorf("rename %s -> %s: %w", oldPath, newPath, err)
		}
		return nil
	}

	err := unix.Renameat2(unix.AT_FDCWD, oldPath, unix.AT_FDCWD, newPath, unix.RENAME_NOREPLACE)
	switch err {
	case nil:
		return nil
	case unix.EEXIST:
		return fmt.Errorf("rename %s -> %s: destination exists", oldPath, newPath)
	case unix.ENOSYS, unix.EINVAL:
		// Kernel doesn't support RENAME_NOREPLACE — fall through to
		// the racy fallback documented in the function comment.
	default:
		return fmt.Errorf("renameat2 %s -> %s: %w", oldPath, newPath, err)
	}

	// Fallback: best-effort existence check + regular Rename.
	if _, statErr := os.Lstat(newPath); statErr == nil {
		return fmt.Errorf("rename %s -> %s: destination exists", oldPath, newPath)
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("lstat %s: %w", newPath, statErr)
	}
	if err := os.Rename(oldPath, newPath); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", oldPath, newPath, err)
	}
	return nil
}
