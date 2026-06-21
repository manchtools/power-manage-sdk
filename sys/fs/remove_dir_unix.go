//go:build unix

package fs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// removeDirSecure removes the directory at path (already validated,
// cleaned, absolute, and confirmed NOT under a protected prefix by
// RemoveDir) without ever following a symlink — neither an intermediate
// path component nor the leaf nor any descendant. This closes the
// resolve-then-string-reopen TOCTOU that a plain `rm -rf <path>` left
// open (WS6 #4): a `rm -rf` re-resolves the whole path, so a component
// swapped for a symlink after validation could redirect the recursive
// delete into another tree (e.g. /etc, a user's home).
//
// The approach is openat-anchored:
//   - walk the parent's components from "/" with O_NOFOLLOW|O_DIRECTORY,
//     so a symlinked intermediate component fails the open (ELOOP);
//   - require the leaf to be a real directory (a symlinked leaf is
//     refused, not unlinked-as-if-the-dir and not dereferenced);
//   - recurse with unlinkat/openat anchored on directory fds, so every
//     descendant is reached by handle, not by re-resolved path.
func removeDirSecure(ctx context.Context, path string) error {
	parent := filepath.Dir(path)
	base := filepath.Base(path)

	pfd, err := openNoFollowChain(parent)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(pfd) }()

	var st unix.Stat_t
	if err := unix.Fstatat(pfd, base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFLNK:
		return fmt.Errorf("refusing to remove symlink %s", path)
	case unix.S_IFDIR:
		// ok
	default:
		return fmt.Errorf("refusing to remove non-directory %s", path)
	}

	return removeAtRecursive(ctx, pfd, base)
}

// openNoFollowChain opens dir by walking its components from the
// filesystem root, opening each with O_NOFOLLOW|O_DIRECTORY so no
// symlinked component is ever traversed. The caller must Close the fd.
func openNoFollowChain(dir string) (int, error) {
	clean := filepath.Clean(dir)

	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open /: %w", err)
	}
	if clean == "/" {
		return fd, nil
	}

	rest := strings.TrimPrefix(clean, "/")
	for _, comp := range strings.Split(rest, "/") {
		if comp == "" || comp == "." {
			continue
		}
		next, openErr := unix.Openat(fd, comp, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, fmt.Errorf("open component %q of %s without following symlinks: %w", comp, dir, openErr)
		}
		fd = next
	}
	return fd, nil
}

// removeAtRecursive removes name under dirfd. A directory is recursed
// into via an O_NOFOLLOW openat and rmdir'd; anything else — including a
// symlink — is unlinkat'd WITHOUT being followed.
func removeAtRecursive(ctx context.Context, dirfd int, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		// Regular file, symlink, device, fifo, … — unlink the entry
		// itself; never traverse into it.
		if err := unix.Unlinkat(dirfd, name, 0); err != nil {
			return fmt.Errorf("unlink %s: %w", name, err)
		}
		return nil
	}

	cfd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open dir %s: %w", name, err)
	}
	// os.NewFile takes ownership of cfd for the Readdirnames call; we keep
	// using cfd for unlinkat on the children BEFORE closing f, then close
	// f exactly once (which closes cfd).
	f := os.NewFile(uintptr(cfd), name)
	children, readErr := f.Readdirnames(-1)
	if readErr != nil {
		_ = f.Close()
		return fmt.Errorf("read dir %s: %w", name, readErr)
	}
	for _, child := range children {
		if child == "." || child == ".." {
			continue
		}
		if err := removeAtRecursive(ctx, cfd, child); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close dir %s: %w", name, err)
	}
	if err := unix.Unlinkat(dirfd, name, unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("rmdir %s: %w", name, err)
	}
	return nil
}
