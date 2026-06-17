package remote

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

// selfOwner returns the current process's user/group names for chown-to-self
// (permitted without privilege), so applyMode's ownership branch can be exercised
// in the unprivileged unit sweep.
func selfOwner(t *testing.T) (owner, group string) {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skipf("current user: %v", err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skipf("current group: %v", err)
	}
	return u.Username, g.Name
}

// TestApplyMode_DirectoryOwnership pins the fix for the regression where applyMode
// used FchownNoFollow for every target. That helper refuses non-regular files, so
// owner/group on a DIRECTORY destination (archive extract, git clone, S3 prefix)
// failed even with valid inputs. The dir path now goes through OpenRealDir+Chown.
func TestApplyMode_DirectoryOwnership(t *testing.T) {
	owner, group := selfOwner(t)
	dir := filepath.Join(t.TempDir(), "extracted")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := applyMode(dir, "0750", owner, group); err != nil {
		t.Fatalf("applyMode on a directory must succeed, got: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Errorf("dir mode = %v, want 0750", info.Mode().Perm())
	}
}

// TestApplyMode_RegularFileOwnership covers the regular-file branch (FchownNoFollow).
func TestApplyMode_RegularFileOwnership(t *testing.T) {
	owner, group := selfOwner(t)
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := applyMode(f, "0600", owner, group); err != nil {
		t.Fatalf("applyMode on a regular file: %v", err)
	}
	if info, _ := os.Stat(f); info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", info.Mode().Perm())
	}
}

// TestApplyMode_NoOpWhenAllEmpty verifies applyMode skips work entirely.
func TestApplyMode_NoOpWhenAllEmpty(t *testing.T) {
	if err := applyMode(filepath.Join(t.TempDir(), "nope"), "", "", ""); err != nil {
		t.Errorf("applyMode with no fields set = %v, want nil (no-op)", err)
	}
}
