//go:build unix

package fs

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

// WS6 #5: directory chmod/chown was path-based, so it re-resolved the
// path on every call and dereferenced a final-component symlink. A user
// who controls a managed directory could swap it for a symlink between a
// check and the chmod/chown, redirecting a root-run permission change
// onto the symlink's target (e.g. /etc, /root). SetDirPermissionsNoFollow
// closes the class: it opens the directory with O_NOFOLLOW|O_DIRECTORY
// and applies fchmod/fchown through the fd, so a symlink at the path
// fails the open (ELOOP) instead of being dereferenced.
//
// Contract:
//   - correct: a real directory → mode and ownership applied via the fd;
//   - present-but-wrong: the path is a symlink → ELOOP, NOTHING applied
//     to the symlink's target;
//   - absent: the path does not exist → error.
func TestSetDirPermissionsNoFollow_RealDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "managed")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := SetDirPermissionsNoFollow(dir, 0o750, -1, -1); err != nil {
		t.Fatalf("SetDirPermissionsNoFollow: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o750 {
		t.Errorf("mode = %v, want 0750", perm)
	}
}

func TestSetDirPermissionsNoFollow_AppliesOwnershipToSelf(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "owned")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	u, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)

	if err := SetDirPermissionsNoFollow(dir, 0o700, uid, gid); err != nil {
		t.Fatalf("SetDirPermissionsNoFollow: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fileUID(t, info); got != uid {
		t.Errorf("uid = %d, want %d", got, uid)
	}
}

func TestSetDirPermissionsNoFollow_RefusesSymlink(t *testing.T) {
	root := t.TempDir()

	// The victim directory whose mode an attacker hopes to change by
	// planting a symlink where a managed dir is expected.
	victim := filepath.Join(root, "victim")
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatalf("mkdir victim: %v", err)
	}
	link := filepath.Join(root, "managed")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	err := SetDirPermissionsNoFollow(link, 0o777, -1, -1)
	if err == nil {
		t.Fatalf("SetDirPermissionsNoFollow on a symlink: want error, got nil")
	}

	// The victim's mode must be unchanged — the symlink was not followed.
	info, statErr := os.Stat(victim)
	if statErr != nil {
		t.Fatalf("stat victim: %v", statErr)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("victim mode = %v, want 0700 (unchanged) — symlink was dereferenced", perm)
	}
}

func TestSetDirPermissionsNoFollow_RefusesNonDir(t *testing.T) {
	// A regular file is not a directory: O_DIRECTORY must reject it
	// rather than chmod'ing it.
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := SetDirPermissionsNoFollow(f, 0o700, -1, -1); err == nil {
		t.Fatalf("SetDirPermissionsNoFollow on a regular file: want error, got nil")
	}
}

func TestSetDirPermissionsNoFollow_Missing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	if err := SetDirPermissionsNoFollow(missing, 0o700, -1, -1); err == nil {
		t.Fatalf("SetDirPermissionsNoFollow on a missing path: want error, got nil")
	}
}
