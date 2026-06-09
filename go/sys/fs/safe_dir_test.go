//go:build unix

package fs

import (
	"os"
	"path/filepath"
	"testing"
)

// AssertRealDir is the guard callers use before running a privileged,
// path-based chmod/chown on a directory that an untrusted user may
// control (canonical case: ~/.ssh, owned by the target user). It must
// accept a real directory and reject a symlink — even one resolving to
// a valid directory — because a path-based chmod/chown would otherwise
// dereference the symlink and act on its target (TOCTOU privesc). It
// must also reject non-directories.
func TestAssertRealDir(t *testing.T) {
	tmp := t.TempDir()

	realDir := filepath.Join(tmp, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := AssertRealDir(realDir); err != nil {
		t.Errorf("real directory must be accepted, got: %v", err)
	}

	// Symlink to a directory: the attack shape. Must be rejected even
	// though it resolves to a valid dir.
	target := filepath.Join(tmp, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	symlink := filepath.Join(tmp, "symlink")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := AssertRealDir(symlink); err == nil {
		t.Error("a symlink to a directory must be rejected (dereference is the TOCTOU vector)")
	}

	// Regular file.
	file := filepath.Join(tmp, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := AssertRealDir(file); err == nil {
		t.Error("a regular file must be rejected")
	}

	// Missing path.
	if err := AssertRealDir(filepath.Join(tmp, "nope")); err == nil {
		t.Error("a missing path must be rejected")
	}
}
