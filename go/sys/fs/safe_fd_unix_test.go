//go:build unix

package fs

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// OpenRealDir is the TOCTOU-closing replacement for "AssertRealDir then
// path-based chmod/chown". It must accept a real directory and return a
// handle whose fd-based Chmod/Chown act on the opened inode; it must
// reject a symlink (even one resolving to a valid dir — that dereference
// is the privesc vector) and a non-directory, at open time, so there is
// no check-then-use gap.
func TestOpenRealDir(t *testing.T) {
	tmp := t.TempDir()

	realDir := filepath.Join(tmp, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	f, err := OpenRealDir(realDir)
	if err != nil {
		t.Fatalf("real directory must be accepted: %v", err)
	}
	// The fd must be usable for fd-based metadata changes; this is the
	// whole point — the operation acts on the opened inode, not a
	// re-resolved path.
	if err := f.Chmod(0o750); err != nil {
		t.Errorf("fchmod via the returned fd must work: %v", err)
	}
	if err := f.Chown(os.Getuid(), os.Getgid()); err != nil {
		t.Errorf("fchown via the returned fd must work: %v", err)
	}
	_ = f.Close()
	if got := mustMode(t, realDir); got.Perm() != 0o750 {
		t.Errorf("fchmod did not land on the directory: perm=%v", got.Perm())
	}

	// Symlink to a directory: the attack shape. The O_NOFOLLOW open must
	// fail rather than hand back a handle to the target.
	target := filepath.Join(tmp, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	link := filepath.Join(tmp, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if f, err := OpenRealDir(link); err == nil {
		_ = f.Close()
		t.Error("a symlink to a directory must be rejected (dereference is the TOCTOU vector)")
	}
	if got := mustMode(t, target); got.Perm() != 0o700 {
		t.Errorf("symlink target must be untouched, perm=%v", got.Perm())
	}

	// Regular file: O_DIRECTORY must reject it.
	file := filepath.Join(tmp, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if f, err := OpenRealDir(file); err == nil {
		_ = f.Close()
		t.Error("a regular file must be rejected by O_DIRECTORY")
	}

	// Missing path.
	if f, err := OpenRealDir(filepath.Join(tmp, "nope")); err == nil {
		_ = f.Close()
		t.Error("a missing path must be rejected")
	}
}

// FchownNoFollow must chown a real regular file through its fd and refuse
// a symlinked path (leaving the target untouched) and a non-regular
// file. Without root we can only chown to our own ids, which is enough to
// prove the success path; the security properties (symlink + non-regular
// rejection) need no privilege.
func TestFchownNoFollow(t *testing.T) {
	tmp := t.TempDir()

	file := filepath.Join(tmp, "authorized_keys")
	if err := os.WriteFile(file, []byte("ssh-ed25519 AAAA"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := FchownNoFollow(file, os.Getuid(), os.Getgid()); err != nil {
		t.Errorf("a real regular file must be chown-able: %v", err)
	}

	// Symlink: the planted-link attack on a freshly written file. Must be
	// rejected, and the target's ownership/content must be untouched.
	target := filepath.Join(tmp, "shadow")
	if err := os.WriteFile(target, []byte("root:!"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(tmp, "planted")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := FchownNoFollow(link, os.Getuid(), os.Getgid()); err == nil {
		t.Error("a symlinked path must be rejected, not dereferenced")
	}

	// Directory: non-regular, must be refused (use OpenRealDir for dirs).
	dir := filepath.Join(tmp, "dir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := FchownNoFollow(dir, os.Getuid(), os.Getgid()); err == nil {
		t.Error("a directory must be refused by FchownNoFollow")
	}

	// FIFO: a user could plant one in place of the freshly written file.
	// A blocking O_RDONLY open on a FIFO hangs forever (local DoS); the
	// O_NONBLOCK open must return promptly and the non-regular check must
	// reject it. The deadline guards against a regression to a blocking
	// open: a hang fails the test instead of wedging the suite.
	fifo := filepath.Join(tmp, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	fifoDone := make(chan error, 1)
	go func() { fifoDone <- FchownNoFollow(fifo, os.Getuid(), os.Getgid()) }()
	select {
	case err := <-fifoDone:
		if err == nil {
			t.Error("a FIFO must be refused by FchownNoFollow")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FchownNoFollow hung on a FIFO — O_NONBLOCK regression (blocking O_RDONLY open)")
	}

	// Missing path.
	if err := FchownNoFollow(filepath.Join(tmp, "nope"), os.Getuid(), os.Getgid()); err == nil {
		t.Error("a missing path must be rejected")
	}
}

func mustMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	return info.Mode()
}
