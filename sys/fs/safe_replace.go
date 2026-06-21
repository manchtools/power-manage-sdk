//go:build unix

package fs

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// safeReplaceFile writes data to path using a same-directory temp
// file, then mv-into-place. It adds two symlink-aware defenses
// required by anything that lives in a directory another user (or
// another process running as the same user with reduced privilege)
// might be able to plant entries in:
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
func safeReplaceFile(path string, data []byte, perm os.FileMode, removeExisting bool) error {
	return safeReplaceFromReader(path, bytes.NewReader(data), perm, removeExisting)
}

// safeReplaceFromReader is the streaming form of safeReplaceFile: it copies from
// src into the same-directory temp file (io.Copy, no buffering of the whole
// payload), keeping every symlink-aware defense — O_NOFOLLOW temp open,
// fsync, atomic rename — so an arbitrarily large source (a downloaded AppImage)
// is placed atomically without holding it all in memory. A failed or truncated
// copy never clobbers the existing file: the rename is the final step.
func safeReplaceFromReader(path string, src io.Reader, perm os.FileMode, removeExisting bool) error {
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

	if _, err := io.Copy(f, src); err != nil {
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

// safeBackupAndReplace is the binary-update shape of safeReplaceFile:
// it COPIES the existing file at path to backupPath (no-op if path does
// not exist), then writes new content to path via safeReplaceFile.
// Reached through Manager.WriteFile with WriteOptions.Backup set — the
// agent's self-update path — so a planted symlink at "${BinaryPath}.bak"
// cannot redirect the backup to an attacker-chosen target. SDK helper
// for agent finding F023.
//
// Crash-safety: the backup is a COPY, not a move, so `path` is never
// left absent. safeReplaceFile writes a temp file and atomically renames
// it over `path` as the final step, so on ANY failure — backup error,
// write error, fsync error, or a crash/power-loss at any point — `path`
// still holds the original content. (A previous version renamed `path`
// to the backup FIRST, so a failed write left no binary at `path` at
// all — a fleet-wide brick risk during self-update.)
//
// removeExistingBackup mirrors removeExisting on safeReplaceFile —
// pass true if a previous failed update may have left a stale
// backup that must be replaced.
func safeBackupAndReplace(path, backupPath string, newContent []byte, perm os.FileMode, removeExistingBackup bool) error {
	// Open the current file with O_NOFOLLOW and read THROUGH the fd, so
	// there is no lstat→read TOCTOU window in which the path could be
	// swapped for a symlink: O_NOFOLLOW makes the open itself fail
	// (ELOOP) on a symlink, and the subsequent Stat/Read operate on the
	// already-open inode. The backup is then a fresh copy written via
	// safeReplaceFile, leaving `path` itself untouched.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if os.IsNotExist(err) {
			// Nothing to back up; just write the new content.
			return safeReplaceFile(path, newContent, perm, true)
		}
		return fmt.Errorf("open current %s for backup: %w", path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("stat current %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return fmt.Errorf("refusing to back up non-regular file %s", path)
	}
	current, err := io.ReadAll(f)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("read current %s for backup: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close current %s: %w", path, err)
	}
	if err := safeReplaceFile(backupPath, current, perm, removeExistingBackup); err != nil {
		return fmt.Errorf("backup current to %s: %w", backupPath, err)
	}
	return safeReplaceFile(path, newContent, perm, true)
}
