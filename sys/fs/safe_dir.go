package fs

import (
	"fmt"
	"os"
)

// AssertRealDir verifies that path is a real directory and not a
// symlink (or any other non-directory). It is a CHEAP PRE-FLIGHT
// PREDICATE, not a TOCTOU-proof guard: it answers "is this a real dir
// right now?" via a single Lstat. Because the answer is about the path
// (not an open handle), any privileged operation a caller runs
// afterwards re-resolves the path in a separate syscall — leaving a
// check-then-use window in which a user who controls the directory (the
// canonical case being ~/.ssh, owned by the target user) can swap it for
// a symlink between this check and the operation. A path-based chmod/
// chown would then dereference it and act on the target (e.g. /etc) — a
// TOCTOU privilege escalation.
//
// To actually CLOSE that class, do not pair this with path-based
// chmod/chown. Use OpenRealDir to obtain an O_NOFOLLOW directory handle
// and apply ownership/mode through the fd (f.Chown/f.Chmod →
// fchown(2)/fchmod(2)), so the operation acts on the inode that was
// opened and a later path swap cannot redirect it. Keep AssertRealDir
// for cheap, non-privileged checks (logging, early rejection) where the
// re-resolution window is not a concern.
//
// It uses Lstat, so the symlink itself — not its target — is inspected.
// It does not escalate privileges: a stat is read-only, and the agent
// already runs with enough privilege to read the path's metadata.
func AssertRealDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat dir %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path %s is a symlink; refusing to dereference it", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("path %s is not a directory", path)
	}
	return nil
}
