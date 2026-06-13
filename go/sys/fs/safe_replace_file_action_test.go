//go:build unix

package fs

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

// WS6 #2: WriteFileAtomic used a PREDICTABLE temp name (path+".pm-tmp")
// and wrote it with a privilege-backend `tee`, which FOLLOWS symlinks.
// A local attacker who can create entries in the target directory could
// pre-plant `<target>.pm-tmp` as a symlink to any root-writable file and
// redirect the root agent's write there — an arbitrary-file-write → root
// privesc. The fix routes the write through SafeReplaceFile: a
// RANDOM-suffix same-directory temp opened O_NOFOLLOW, fchmod'd, then
// renamed into place. The predictable name is gone entirely, so a planted
// symlink at the old name is never touched.
//
// Design intent pinned here:
//   - the predictable `<target>.pm-tmp` path is NEVER written through;
//   - no leftover temp (`.<base>.tmp-*`) lingers on success;
//   - the final inode is a real regular file with the requested content
//     and mode.
func TestWriteFileAtomic_RefusesSymlinkPlantedTempTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "managed.conf")

	// Sentinel in a separate tree that the attacker hopes to clobber by
	// planting a symlink at the OLD predictable temp path.
	sentinelDir := t.TempDir()
	sentinel := filepath.Join(sentinelDir, "sentinel")
	if err := os.WriteFile(sentinel, []byte("ORIGINAL"), 0o644); err != nil {
		t.Fatalf("seed sentinel: %v", err)
	}
	planted := target + ".pm-tmp"
	if err := os.Symlink(sentinel, planted); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}

	const content = "managed content\n"
	if err := WriteFileAtomic(context.Background(), target, content, "0644", "", ""); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	// The planted symlink target must be untouched — the write must not
	// have followed `<target>.pm-tmp`.
	got, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("read sentinel: %v", err)
	}
	if string(got) != "ORIGINAL" {
		t.Fatalf("sentinel was modified through the planted .pm-tmp symlink: %q", string(got))
	}

	// The real target holds the new content as a regular file.
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("lstat target: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("target is a symlink, want a regular file")
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("target is not a regular file: %v", info.Mode())
	}
	gotTarget, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(gotTarget) != content {
		t.Errorf("target content = %q, want %q", string(gotTarget), content)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("target mode = %v, want 0644", perm)
	}

	// No predictable name was created and no random temp lingers.
	matches, _ := filepath.Glob(filepath.Join(dir, ".managed.conf.tmp-*"))
	if len(matches) != 0 {
		t.Errorf("leftover temp files: %v", matches)
	}
}

// WriteFileAtomic must refuse to write THROUGH a symlink planted at the
// final target path: a symlink at `target` must be replaced by the real
// regular file (rename-over), never dereferenced so the write lands on
// the symlink's victim. Pins that the new inode is real and the victim
// is untouched.
func TestWriteFileAtomic_TargetSymlinkNotDereferenced(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "managed.conf")

	victimDir := t.TempDir()
	victim := filepath.Join(victimDir, "victim")
	if err := os.WriteFile(victim, []byte("VICTIM"), 0o644); err != nil {
		t.Fatalf("seed victim: %v", err)
	}
	if err := os.Symlink(victim, target); err != nil {
		t.Fatalf("plant target symlink: %v", err)
	}

	if err := WriteFileAtomic(context.Background(), target, "new\n", "0644", "", ""); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	if got, _ := os.ReadFile(victim); string(got) != "VICTIM" {
		t.Fatalf("victim modified through target symlink deref: %q", string(got))
	}
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("lstat target: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("target still a symlink after write")
	}
}

// The correct path with explicit ownership: resolving the owner/group
// NAMES to ids and applying them through an fd (no path-based chown that
// could follow a swapped symlink). Run against the current user so it
// works without root.
func TestWriteFileAtomic_AppliesOwnershipToSelf(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "owned.conf")

	u, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skipf("cannot resolve current group: %v", err)
	}

	if err := WriteFileAtomic(context.Background(), target, "x\n", "0640", u.Username, g.Name); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o640 {
		t.Errorf("mode = %v, want 0640", perm)
	}
	wantUID, _ := strconv.Atoi(u.Uid)
	if uid := fileUID(t, info); uid != wantUID {
		t.Errorf("uid = %d, want %d", uid, wantUID)
	}
}
