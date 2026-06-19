package encryption

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteKeyFile_TmpfsModeAndContent(t *testing.T) {
	path, err := writeKeyFile(mustSecret(t, "the-passphrase"))
	if err != nil {
		t.Fatalf("writeKeyFile: %v", err)
	}
	defer cleanupKeyFile(path)

	if !strings.HasPrefix(path, keyFileDir+"/") {
		t.Errorf("key file %q not under %q (must be RAM-backed tmpfs)", path, keyFileDir)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 0600", perm)
	}
	if dirInfo, err := os.Stat(keyFileDir); err == nil {
		if perm := dirInfo.Mode().Perm(); perm != 0o700 {
			t.Errorf("key file dir mode = %o, want 0700", perm)
		}
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if string(content) != "the-passphrase" {
		t.Errorf("key file content = %q, want the passphrase plaintext", content)
	}
}

func TestCleanupKeyFile_Removes(t *testing.T) {
	path, err := writeKeyFile(mustSecret(t, "x"))
	if err != nil {
		t.Fatal(err)
	}
	cleanupKeyFile(path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("key file still present after cleanup (err=%v)", err)
	}
}

func TestCleanupKeyFile_EmptyAndMissingAreNoops(t *testing.T) {
	cleanupKeyFile("") // must not panic
	cleanupKeyFile(filepath.Join(t.TempDir(), "never-existed"))
}

// cleanupKeyFile must NOT follow a symlink that replaced the path (TOCTOU): it
// removes the symlink itself, leaving the target untouched (not zeroed).
func TestCleanupKeyFile_RefusesToFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("sensitive-target"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	cleanupKeyFile(link)

	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Errorf("symlink should be removed, lstat err=%v", err)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("target should be untouched: %v", err)
	}
	if string(content) != "sensitive-target" {
		t.Errorf("target was modified through the symlink: %q (TOCTOU not prevented)", content)
	}
}
