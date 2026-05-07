//go:build unix

// Atomicity here depends on POSIX rename(2) (same-filesystem rename
// is atomic) and on the ability to fsync a directory file
// descriptor. Neither holds on Windows, where this function would
// still execute but lose the contract callers depend on. Restrict
// it to Unix targets so misuse fails at build time rather than
// silently producing non-atomic writes.

package fs

import (
	"fmt"
	"os"
	"path/filepath"
)

// AtomicWriteFile writes data to path via a same-directory temp file
// followed by chmod + fsync + rename + directory fsync. Use it for
// any file where a half-written state would corrupt downstream
// readers (credentials, secrets, durable state files, etc.).
//
// Behaviour notes:
//   - The temp file is created in the SAME directory as path so the
//     final os.Rename is a same-filesystem operation (atomic on
//     POSIX). Cross-filesystem renames degrade to copy+delete and
//     defeat the purpose.
//   - perm is applied to the temp file BEFORE the rename so the
//     final inode carries the intended mode from the first moment
//     it is reachable by name. Callers passing 0600 for secret
//     files therefore never observe a wider mode mid-write.
//   - The directory is fsync'd after the rename so a crash before
//     the next sync still recovers the new inode by name. The
//     directory-sync error is intentionally ignored — exotic
//     filesystems return ENOSYS for directory fsync, but the
//     rename itself has already completed.
//   - On any failure path the temp file is removed so callers do
//     not accumulate `.tmp-*` clutter in the data directory.
//
// Unlike the privileged operations elsewhere in this package, this
// function does NOT shell out to sudo — the caller's process must
// already have write permission on path's directory. That makes it
// suitable for agent-local data dirs and CLI-installed config
// files but not for system paths owned by root. For atomic writes
// to root-owned paths, use WriteFileAtomic in this package — it
// shells out to sudo tee + chmod + mv and accepts owner/group.
func AtomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = os.Remove(tmpPath)
	}

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("rename temp: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
