//go:build unix

// Mirrors the build tag on atomic_write.go — the test references
// AtomicWriteFile directly, so it would fail to compile on
// non-Unix targets.

package fs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestAtomicWriteFile_WritesAndReplaces covers the success paths: first
// write creates the file; a subsequent write replaces it
// atomically without leaving behind the temp file.
func TestAtomicWriteFile_WritesAndReplaces(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "creds.enc")

	if err := AtomicWriteFile(target, []byte("v1"), 0600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, []byte("v1")) {
		t.Fatalf("got %q, want %q", got, "v1")
	}

	if err := AtomicWriteFile(target, []byte("v2"), 0600); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, err = os.ReadFile(target)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, []byte("v2")) {
		t.Fatalf("got %q, want %q", got, "v2")
	}

	// No leftover temp files.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "creds.enc" {
			t.Errorf("unexpected leftover: %q", e.Name())
		}
	}
}

// TestAtomicWriteFile_AppliesMode asserts the final file carries the
// requested permissions — secret-bearing files must be 0600 the
// moment they become visible under the target name, not briefly
// world-readable.
func TestAtomicWriteFile_AppliesMode(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "salt")

	if err := AtomicWriteFile(target, []byte("secret"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("mode = %o, want 0600", mode)
	}
}

// TestAtomicWriteFile_WriteFailsNoLeftover is the reliability guarantee:
// a failed write into a nonexistent directory must NOT leave a
// temp file somewhere for a future operator to stumble over.
func TestAtomicWriteFile_WriteFailsNoLeftover(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist", "creds.enc")
	if err := AtomicWriteFile(missing, []byte("x"), 0600); err == nil {
		t.Fatal("expected error writing into nonexistent directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	for _, e := range entries {
		t.Errorf("unexpected artifact in %s: %s", dir, e.Name())
	}
}
