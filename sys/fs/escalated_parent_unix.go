//go:build unix

package fs

import (
	"fmt"
	"os"
	"syscall"
)

// escalatedParentSafe reports whether dir is safe to host an escalated write —
// i.e. a non-root user cannot plant a symlink in it during the write. The check
// is done unprivileged in Go (directory metadata is world-readable) BEFORE any
// sudo/doas invocation, so an unsafe target is refused without escalating.
//
// A directory is safe when it is owned by root AND either has no group/other
// write bit OR is sticky. The sticky case (e.g. /tmp, mode 1777) is genuinely
// safe: the sticky bit restricts deletion/rename within the directory to each
// file's owner, so an attacker cannot delete or replace root's mktemp'd file.
// For any directory this accepts, only root can change its ownership/mode, so
// the gap between this check and the subsequent root write cannot be widened by
// an attacker.
//
// Note: this guards the IMMEDIATE parent. Defending every path component against
// a symlinked-directory swap requires fd-anchored opens, which the shell-based
// escalated path cannot do without a root helper; the Direct (root agent) path
// is fd-anchored and is the one used for security-sensitive writes.
func escalatedParentSafe(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("escalated write: stat parent %s: %w", dir, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: %s: cannot determine ownership", ErrUnsafeParentDir, dir)
	}
	groupOrOtherWritable := fi.Mode().Perm()&0o022 != 0
	sticky := fi.Mode()&os.ModeSticky != 0
	if st.Uid != 0 || (groupOrOtherWritable && !sticky) {
		return fmt.Errorf("%w: %s (uid=%d, mode=%#o, sticky=%v) — a non-root user could plant a symlink here",
			ErrUnsafeParentDir, dir, st.Uid, fi.Mode().Perm(), sticky)
	}
	return nil
}
