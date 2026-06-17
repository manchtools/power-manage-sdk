package fs

import (
	"context"
	"fmt"
	"path/filepath"
)

// Mkdir creates a directory per opts. opts.Recursive adds -p; opts.Mode and
// opts.Owner/Group, when set, are applied after creation. A zero opts.Mode
// leaves mkdir's default (mode minus umask) in place.
func (m *manager) Mkdir(ctx context.Context, path string, opts MkdirOptions) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	args := make([]string, 0, 3)
	if opts.Recursive {
		args = append(args, "-p")
	}
	args = append(args, "--", path)
	if err := m.runChecked(ctx, "mkdir", args...); err != nil {
		return err
	}
	if opts.Mode != 0 {
		if err := m.SetMode(ctx, path, opts.Mode); err != nil {
			return err
		}
	}
	if opts.Owner != "" || opts.Group != "" {
		if err := m.SetOwnership(ctx, path, opts.Owner, opts.Group); err != nil {
			return err
		}
	}
	return nil
}

// Remove deletes a single file (rm -f) and returns any error. The `--`
// end-of-options separator and ValidatePath both refuse a leading-`-` path.
func (m *manager) Remove(ctx context.Context, path string) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	return m.runChecked(ctx, "rm", "-f", "--", path)
}

// RemoveDir removes a directory and its contents WITHOUT following any symlink
// (intermediate component, leaf, or descendant) and refuses any target at or
// under a security-relevant system prefix.
//
// Two hardenings over a plain `rm -rf`:
//
//   - Deny-by-default (WS6 #12): IsUnderProtectedPrefix refuses the whole
//     subtree of every protected root, so /etc/sudoers.d, /home/alice,
//     /var/lib/anything no longer slip through to a root delete.
//   - Symlink-refusing fd-anchored delete (WS6 #4): on the Direct backend
//     removeDirSecure walks the path by openat(O_NOFOLLOW) handles, never
//     re-resolving a string, so a component swapped for a symlink aborts the
//     operation. Non-root callers cannot openat as root and fall back to the
//     privilege-backend `rm -rf` (not symlink-safe, but not the root agent's
//     path).
//
// The deny-by-default refusal applies regardless of backend.
func (m *manager) RemoveDir(ctx context.Context, path string) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("path must be absolute: %s", path)
	}
	if IsUnderProtectedPrefix(clean) {
		return fmt.Errorf("refusing to remove protected path: %s", clean)
	}
	if m.direct() {
		return removeDirSecure(ctx, clean)
	}
	return m.runChecked(ctx, "rm", "-rf", "--", clean)
}
