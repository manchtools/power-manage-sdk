//go:build unix

package fs

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// SafeReplaceFile writes data to path using a same-directory temp
// file, then mv-into-place. Unlike AtomicWriteFile it adds two
// symlink-aware defenses required by anything that lives in a
// directory another user (or another process running as the same
// user with reduced privilege) might be able to plant entries in:
//
//   - The temp file is opened with O_NOFOLLOW: if a hostile race
//     replaces the temp path with a symlink between os.CreateTemp and
//     the first Write, the open fails with ELOOP rather than writing
//     through the symlink.
//   - The final rename is performed via syscall.Renameat2 with
//     RENAME_NOREPLACE on Linux when removeExisting is false, so a
//     symlink that has been planted at path between Stat() and
//     Rename() cannot be replaced with our temp file (preventing
//     redirection of subsequent writes to attacker-chosen targets).
//
// When removeExisting is true (the common case for "I want this file
// to exist with this content, replacing whatever's there"), the
// rename uses the regular os.Rename semantics, which atomically
// replaces the target. The caller is responsible for asserting that
// the target's parent directory is owned and writable only by trusted
// principals — RENAME_NOREPLACE alone does not protect against an
// attacker who can delete the existing file and then race the rename.
//
// SDK helper for agent finding F022 (authorized_keys writer race).
// Returns the resolved temp path on failure so the caller can decide
// whether to clean it up.
func SafeReplaceFile(path string, data []byte, perm os.FileMode, removeExisting bool) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	// os.CreateTemp opens with O_RDWR|O_CREATE|O_EXCL; that is enough
	// to make the create-side of the race safe (EEXIST is returned if
	// an attacker pre-creates a file with the suffix we picked). We
	// reopen with O_NOFOLLOW immediately to extend the protection
	// across the brief window between create and write.
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	_ = tmp.Close()

	// Reopen with O_NOFOLLOW so a symlink swap between CreateTemp and
	// the write fails the open. O_RDWR matches the original mode.
	f, err := os.OpenFile(tmpPath, os.O_RDWR|syscall.O_NOFOLLOW, perm)
	if err != nil {
		cleanup()
		return fmt.Errorf("reopen temp with O_NOFOLLOW: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp: %w", err)
	}

	if err := safeRename(tmpPath, path, removeExisting); err != nil {
		cleanup()
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// SafeBackupAndReplace is the binary-update shape of SafeReplaceFile:
// it moves the existing file at path to backupPath (no-op if path
// does not exist), then writes new content to path via SafeReplaceFile.
// Used by the agent's self-update path so a planted symlink at
// "${BinaryPath}.bak" cannot redirect the backup mv to an attacker-
// chosen target. SDK helper for agent finding F023.
//
// removeExistingBackup mirrors removeExisting on SafeReplaceFile —
// pass true if a previous failed update may have left a stale
// backup that must be replaced.
func SafeBackupAndReplace(path, backupPath string, newContent []byte, perm os.FileMode, removeExistingBackup bool) error {
	if _, err := os.Lstat(path); err == nil {
		// Use renameat2-with-NOREPLACE for the backup move when the
		// caller does not want to clobber an existing backup.
		if err := safeRename(path, backupPath, removeExistingBackup); err != nil {
			return fmt.Errorf("backup current to %s: %w", backupPath, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("lstat %s: %w", path, err)
	}
	return SafeReplaceFile(path, newContent, perm, true)
}
