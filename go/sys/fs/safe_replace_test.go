//go:build unix

package fs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// SafeReplaceFile must produce a file with the requested content and
// mode, atomically (no half-written intermediate state visible to a
// concurrent reader). Same-directory temp file → fsync → rename.
func TestSafeReplaceFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "creds")

	if err := SafeReplaceFile(target, []byte("hello"), 0o600, true); err != nil {
		t.Fatalf("SafeReplaceFile: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("content = %q, want %q", string(got), "hello")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %v, want 0600", mode)
	}
}

// removeExisting=true must replace the existing file in place.
func TestSafeReplaceFile_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "f")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := SafeReplaceFile(target, []byte("new"), 0o600, true); err != nil {
		t.Fatalf("SafeReplaceFile: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "new" {
		t.Errorf("content = %q, want %q", string(got), "new")
	}
}

// removeExisting=false must refuse to clobber an existing file at the
// destination — this is the symlink-swap defense from agent F022.
// On Linux this is enforced by RENAME_NOREPLACE; the fallback path is
// a Lstat+rename window which still rejects existing files.
func TestSafeReplaceFile_RefusesExistingWhenNoReplace(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "f")
	if err := os.WriteFile(target, []byte("existing"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	err := SafeReplaceFile(target, []byte("new"), 0o600, false)
	if err == nil {
		t.Fatalf("SafeReplaceFile: want error, got nil")
	}
	if !strings.Contains(err.Error(), "destination exists") {
		t.Errorf("error = %v, want substring 'destination exists'", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "existing" {
		t.Errorf("content = %q, want existing file untouched", string(got))
	}
}

// SafeBackupAndReplace must move the existing binary aside, then
// install the new one. Verifies the agent self-update flow.
func TestSafeBackupAndReplace_MovesExistingThenWrites(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "agent")
	bak := filepath.Join(dir, "agent.bak")
	if err := os.WriteFile(bin, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := SafeBackupAndReplace(bin, bak, []byte("new-binary"), 0o755, true); err != nil {
		t.Fatalf("SafeBackupAndReplace: %v", err)
	}

	got, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("ReadFile bin: %v", err)
	}
	if string(got) != "new-binary" {
		t.Errorf("bin = %q, want new-binary", string(got))
	}
	gotBak, err := os.ReadFile(bak)
	if err != nil {
		t.Fatalf("ReadFile bak: %v", err)
	}
	if string(gotBak) != "old-binary" {
		t.Errorf("bak = %q, want old-binary", string(gotBak))
	}
}

// When the existing binary is absent, SafeBackupAndReplace must skip
// the backup move and just install the new content. Covers the
// first-install case.
func TestSafeBackupAndReplace_NoExistingFile(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "agent")
	bak := filepath.Join(dir, "agent.bak")

	if err := SafeBackupAndReplace(bin, bak, []byte("first"), 0o755, false); err != nil {
		t.Fatalf("SafeBackupAndReplace: %v", err)
	}
	got, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("ReadFile bin: %v", err)
	}
	if string(got) != "first" {
		t.Errorf("bin = %q, want first", string(got))
	}
	if _, err := os.Stat(bak); !os.IsNotExist(err) {
		t.Errorf("backup file unexpectedly exists: %v", err)
	}
}
