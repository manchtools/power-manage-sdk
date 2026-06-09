//go:build unix

package fs

import (
	"os"
	"path/filepath"
	"testing"
)

// On success: path holds the new content, backup holds a copy of the
// old content, and both are regular files with the requested perm.
func TestSafeBackupAndReplace_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent")
	backup := filepath.Join(dir, "agent.bak")

	if err := os.WriteFile(path, []byte("OLD"), 0o755); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := SafeBackupAndReplace(path, backup, []byte("NEW"), 0o755, true); err != nil {
		t.Fatalf("SafeBackupAndReplace: %v", err)
	}

	if got, _ := os.ReadFile(path); string(got) != "NEW" {
		t.Errorf("path: got %q, want NEW", got)
	}
	if got, _ := os.ReadFile(backup); string(got) != "OLD" {
		t.Errorf("backup: got %q, want OLD (a copy of the original)", got)
	}
	// path must be a regular file, never absent or a symlink.
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("path must still exist: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Errorf("path must be a regular file, got mode %v", info.Mode())
	}
}

// A symlink at `path` must be rejected (O_NOFOLLOW) rather than
// dereferenced — otherwise the backup would copy, and the replace would
// clobber, the symlink's target. The target must be left untouched.
func TestSafeBackupAndReplace_RejectsSymlinkPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("TARGET"), 0o644); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	err := SafeBackupAndReplace(link, filepath.Join(dir, "link.bak"), []byte("NEW"), 0o644, true)
	if err == nil {
		t.Fatal("expected an error for a symlinked path")
	}
	if got, _ := os.ReadFile(target); string(got) != "TARGET" {
		t.Errorf("symlink target must be untouched, got %q", got)
	}
}

// The load-bearing crash-safety property: a failure in the new-content
// write step must leave `path` holding the ORIGINAL content (never
// absent). Here the backup lands in a writable dir (so the copy
// succeeds) while `path` lives in a read-only dir (so SafeReplaceFile's
// temp create fails) — and `path` must still hold the old binary. The
// previous rename-first shape moved `path` away before this step, so a
// failure here left no binary at all.
func TestSafeBackupAndReplace_WriteFailureLeavesPathIntact(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions; cannot force the write failure")
	}
	root := t.TempDir()
	pathDir := filepath.Join(root, "bin")
	backupDir := filepath.Join(root, "backups")
	for _, d := range []string{pathDir, backupDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	path := filepath.Join(pathDir, "agent")
	backup := filepath.Join(backupDir, "agent.bak")
	if err := os.WriteFile(path, []byte("ORIGINAL"), 0o755); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Make path's directory read-only so SafeReplaceFile(path) fails at
	// temp creation; restore perms on cleanup so TempDir can be removed.
	if err := os.Chmod(pathDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(pathDir, 0o755) })

	err := SafeBackupAndReplace(path, backup, []byte("NEW"), 0o755, true)
	if err == nil {
		t.Fatal("expected an error when the path write step fails")
	}

	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("path must still exist after a failed update, got: %v", readErr)
	}
	if string(got) != "ORIGINAL" {
		t.Errorf("path must still hold the original binary after a failed update, got %q", got)
	}
}
