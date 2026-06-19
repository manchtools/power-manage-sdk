//go:build unix

package fs

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// OpenRealDir opens path as a real directory WITHOUT following a final
// symlink and returns the *os.File, so callers can apply privileged
// metadata changes through the fd — f.Chown / f.Chmod, which are
// fchown(2) / fchmod(2) on the open descriptor — instead of path-based
// chmod/chown.
//
// This is the TOCTOU-closing counterpart to AssertRealDir. A path-based
// chmod/chown re-resolves the path on every call, so a user who controls
// the directory (e.g. ~/.ssh, owned by the target user) can swap it for
// a symlink between a prior check and the operation, redirecting a
// root-run chmod/chown onto the symlink's target. Operating through the
// returned fd removes the whole class: the descriptor is bound to the
// inode that was opened, and a later swap of the path cannot redirect
// operations on it.
//
//   - O_NOFOLLOW makes the open itself fail (ELOOP) if the final path
//     component is a symlink — there is no window to swap one in, because
//     the check and the handle are the same syscall.
//   - O_DIRECTORY makes the open fail (ENOTDIR) if the path is not a
//     directory, subsuming AssertRealDir's non-dir rejection.
//
// The caller MUST Close the returned file.
func OpenRealDir(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open real dir %s: %w", path, err)
	}
	return f, nil
}

// FchownNoFollow sets ownership on a regular file via an O_NOFOLLOW open
// followed by an fd-based chown (fchown(2)). A symlink at path is
// rejected — the open fails (ELOOP) rather than dereferencing — so a
// user who can plant a symlink where a privileged file was just written
// (e.g. ~/.ssh/authorized_keys inside their own 0700 dir) cannot
// redirect the chown onto an arbitrary target (e.g. /etc/shadow). Unlike
// `chown -h`, which would silently chown the planted symlink itself, this
// surfaces the tampering as an error.
//
// It refuses non-regular files (a directory, device, fifo, …) so it
// cannot be misused as a directory chown — use OpenRealDir for those.
//
// O_NONBLOCK is set because O_NOFOLLOW only guards symlinks: a user who
// can plant a path could plant a FIFO instead, and a blocking O_RDONLY
// open on a FIFO hangs until a writer appears (a local DoS on the root
// agent). With O_NONBLOCK the open returns immediately for a FIFO (and
// avoids blocking/side effects on a device node too); the subsequent
// IsRegular check then rejects it.
func FchownNoFollow(path string, uid, gid int) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open %s without following symlinks: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to chown non-regular file %s", path)
	}
	if err := f.Chown(uid, gid); err != nil {
		return fmt.Errorf("fchown %s: %w", path, err)
	}
	return nil
}

// SetDirPermissionsNoFollow applies mode and ownership to a DIRECTORY
// through an O_NOFOLLOW|O_DIRECTORY fd, so the operation acts on the
// inode that was opened and a later path swap cannot redirect it. This is
// the TOCTOU-closing replacement for path-based dir chmod/chown (WS6 #5).
//
//   - A symlink at path fails the open (ELOOP) instead of being
//     dereferenced — a user who can swap a managed directory for a
//     symlink to /etc or /root cannot redirect a root-run chmod/chown
//     onto the target.
//   - A non-directory fails the open (ENOTDIR).
//   - uid and/or gid of -1 leaves that id unchanged (chown(2) sentinel);
//     when both are -1 the chown is skipped entirely.
//
// The mode is always applied; callers that do not want to change the mode
// should pass the directory's existing mode.
func SetDirPermissionsNoFollow(path string, mode os.FileMode, uid, gid int) error {
	f, err := OpenRealDir(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("fchmod dir %s: %w", path, err)
	}
	if uid != -1 || gid != -1 {
		if err := f.Chown(uid, gid); err != nil {
			return fmt.Errorf("fchown dir %s: %w", path, err)
		}
	}
	return nil
}

// ResolveOwnership maps owner/group NAMES to numeric uid/gid for the
// fd-based fchown helpers. An empty name yields -1 ("leave unchanged",
// the chown(2) sentinel). A name is resolved against the user/group
// database first and falls back to a numeric id (matching chown(1), which
// accepts raw ids); a value that is neither a known name nor a number is
// an error. Callers MUST fail closed on that error rather than silently
// widening or narrowing ownership.
func ResolveOwnership(owner, group string) (uid, gid int, err error) {
	uid, gid = -1, -1
	if owner != "" {
		uid, err = resolveID(owner, func(name string) (string, error) {
			u, lookupErr := user.Lookup(name)
			if lookupErr != nil {
				return "", lookupErr
			}
			return u.Uid, nil
		})
		if err != nil {
			return -1, -1, fmt.Errorf("resolve owner %q: %w", owner, err)
		}
	}
	if group != "" {
		gid, err = resolveID(group, func(name string) (string, error) {
			g, lookupErr := user.LookupGroup(name)
			if lookupErr != nil {
				return "", lookupErr
			}
			return g.Gid, nil
		})
		if err != nil {
			return -1, -1, fmt.Errorf("resolve group %q: %w", group, err)
		}
	}
	return uid, gid, nil
}

// resolveID resolves a name to a numeric id via lookup, falling back to
// parsing the name as a raw numeric id.
func resolveID(name string, lookup func(string) (string, error)) (int, error) {
	if idStr, lookupErr := lookup(name); lookupErr == nil {
		id, parseErr := strconv.Atoi(idStr)
		if parseErr != nil {
			return -1, fmt.Errorf("parse id %q: %w", idStr, parseErr)
		}
		return id, nil
	}
	if id, parseErr := strconv.Atoi(name); parseErr == nil {
		return id, nil
	}
	return -1, fmt.Errorf("unknown name and not a numeric id")
}
