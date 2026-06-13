//go:build unix

package fs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// WS6 #12: RemoveDir guarded recursive `rm -rf` with a TOP-LEVEL-ONLY
// denylist (an exact-match map of `/etc`, `/home`, …). A path one level
// down — `/etc/sudoers.d`, `/home/alice`, `/var/lib/anything` — slipped
// straight through to a root `rm -rf`. The fix is deny-by-default across
// the whole subtree of every security-relevant prefix.
//
// The must-refuse set below is sourced from INTENT (the security-relevant
// system prefixes a managed directory action must never be able to wipe),
// NOT from the implementation's list — so a prefix silently dropped from
// the code fails this test.
func TestIsUnderProtectedPrefix(t *testing.T) {
	refuse := []string{
		"/",
		"/etc", "/etc/sudoers.d", "/etc/sudoers.d/power-manage",
		"/etc/cron.d", "/etc/cron.d/job", "/etc/systemd/system",
		"/boot", "/boot/efi", "/boot/efi/EFI",
		"/var", "/var/lib", "/var/lib/anything", "/var/lib/postgresql/data",
		"/home", "/home/alice", "/home/alice/.ssh",
		"/root", "/root/.ssh",
		"/usr", "/usr/bin", "/usr/lib/systemd",
		"/bin", "/sbin", "/lib", "/lib64",
		"/proc", "/sys", "/dev", "/run",
		// non-clean inputs must normalise before the check
		"/etc/../etc/sudoers.d", "/home/./bob",
	}
	for _, p := range refuse {
		if !IsUnderProtectedPrefix(p) {
			t.Errorf("IsUnderProtectedPrefix(%q) = false, want true (protected)", p)
		}
	}

	allow := []string{
		"/tmp/managed", "/tmp/foo/bar",
		"/srv/app/data",
		"/opt/myapp/cache",
		"/var/log/myapp", // /var itself is protected but /var/log/* is not
		"/data/managed",
	}
	for _, p := range allow {
		if IsUnderProtectedPrefix(p) {
			t.Errorf("IsUnderProtectedPrefix(%q) = true, want false (deletable)", p)
		}
	}
}

// RemoveDir must refuse a protected path BEFORE touching the filesystem.
// Using real system paths is safe precisely because the refusal happens
// in the predicate, before any unlink.
func TestRemoveDir_RefusesProtectedPrefixes(t *testing.T) {
	useRootBackend(t)
	for _, p := range []string{
		"/etc/sudoers.d/power-manage",
		"/etc/cron.d",
		"/boot/efi",
		"/var/lib/anything",
		"/home/alice",
		"/root/.ssh",
		"/usr/local",
	} {
		err := RemoveDir(context.Background(), p)
		if err == nil {
			t.Errorf("RemoveDir(%q) = nil, want refusal", p)
		}
	}
}

// Positive path: a managed tree under a non-protected prefix is removed
// recursively. Runs as the test user against t.TempDir(); no root needed.
func TestRemoveDir_DeletesManagedTree(t *testing.T) {
	useRootBackend(t)
	root := t.TempDir()
	target := filepath.Join(root, "managed")
	sub := filepath.Join(target, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdirall: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := RemoveDir(context.Background(), target); err != nil {
		t.Fatalf("RemoveDir: %v", err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Errorf("target still exists after RemoveDir: %v", err)
	}
	// The parent (the non-protected managed root) is left intact.
	if _, err := os.Stat(root); err != nil {
		t.Errorf("RemoveDir removed more than its target: %v", err)
	}
}

// WS6 #4: a symlinked INTERMEDIATE component must abort the delete — the
// fd-anchored walk opens each component O_NOFOLLOW, so a swapped-in
// symlink fails the open instead of redirecting `rm -rf` into another
// tree.
func TestRemoveDir_RefusesSymlinkedComponent(t *testing.T) {
	useRootBackend(t)
	root := t.TempDir()

	// A victim tree the attacker hopes RemoveDir will descend into.
	victim := filepath.Join(root, "victim")
	if err := os.MkdirAll(filepath.Join(victim, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir victim: %v", err)
	}
	victimFile := filepath.Join(victim, "sub", "keep.txt")
	if err := os.WriteFile(victimFile, []byte("KEEP"), 0o644); err != nil {
		t.Fatalf("seed victim: %v", err)
	}

	// `link` is a symlink standing in for what should be a real dir.
	link := filepath.Join(root, "link")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	err := RemoveDir(context.Background(), filepath.Join(link, "sub"))
	if err == nil {
		t.Fatalf("RemoveDir through a symlinked component: want error, got nil")
	}
	if _, statErr := os.Stat(victimFile); statErr != nil {
		t.Errorf("victim was deleted through a symlinked component: %v", statErr)
	}
}

// The leaf target being a symlink must also be refused — RemoveDir is
// asked to delete a DIRECTORY; a symlink is not one and must not be
// dereferenced (nor silently unlinked as if it were the target dir).
func TestRemoveDir_RefusesSymlinkTarget(t *testing.T) {
	useRootBackend(t)
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatalf("mkdir victim: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if err := RemoveDir(context.Background(), link); err == nil {
		t.Fatalf("RemoveDir on a symlink target: want error, got nil")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Errorf("victim removed via symlink leaf: %v", err)
	}
}
