package fs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile writes data to path atomically, applying opts (mode/ownership, and
// an optional backup of the prior contents).
//
// When the Runner's backend is Direct — the deployed root agent — the write
// takes the TOCTOU-safe, fd-anchored path: a random-suffix same-directory temp
// opened O_NOFOLLOW, fchmod'd, fsync'd, renamed into place, then chowned through
// an O_NOFOLLOW fd. This closes the root arbitrary-file-write privesc class
// (WS6 #2): a predictable, symlink-followable temp could otherwise let a local
// attacker redirect the root agent's write to an arbitrary file.
//
// Under Sudo/Doas (a non-root caller, e.g. CI or a dev tool) the escalated path
// is used: it cannot openat as root, so it is also made symlink-safe by refusing
// any target whose parent directory a non-root user could write to (the only
// place a symlink could be planted) and then writing atomically in a single root
// shell — mktemp + write + `mv -T` over the target (a rename replaces a symlinked
// target, never follows it). See writeEscalated.
func (m *manager) WriteFile(ctx context.Context, path string, data []byte, opts WriteOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidatePath(path); err != nil {
		return err
	}
	if opts.Backup != "" {
		if err := ValidatePath(opts.Backup); err != nil {
			return err
		}
		// Backing a file up to itself is meaningless and behaves differently per
		// backend (Direct silently no-ops; the escalated cp errors "same file"),
		// so reject it up front for deterministic, intent-preserving behavior.
		if filepath.Clean(opts.Backup) == filepath.Clean(path) {
			return fmt.Errorf("%w: backup path must differ from the target path", ErrInvalidPath)
		}
	}
	if m.direct() {
		return writeDirect(path, data, opts)
	}
	return m.writeEscalated(ctx, path, data, opts)
}

// writeDirect is the fd-based, symlink-safe path (WS6 #2). It runs the syscalls
// directly with the process's own (root) privilege — no Runner round trip.
func writeDirect(path string, data []byte, opts WriteOptions) error {
	perm := opts.Mode
	if perm == 0 {
		perm = 0o644
	}
	if opts.Backup != "" {
		if err := safeBackupAndReplace(path, opts.Backup, data, perm, true); err != nil {
			return fmt.Errorf("write file %s: %w", path, err)
		}
	} else if err := safeReplaceFile(path, data, perm, true); err != nil {
		return fmt.Errorf("write file %s: %w", path, err)
	}
	if opts.Owner != "" || opts.Group != "" {
		uid, gid, err := ResolveOwnership(opts.Owner, opts.Group)
		if err != nil {
			return err
		}
		if err := FchownNoFollow(path, uid, gid); err != nil {
			return fmt.Errorf("set ownership on %s: %w", path, err)
		}
	}
	return nil
}

// writeEscalated is the privilege-backend (sudo/doas) path for non-root callers.
// It is symlink-safe. First it refuses, unprivileged, any target whose parent
// directory a non-root user could write to (escalatedParentSafe) — the only
// place an attacker could plant a symlink. Then it performs the entire write in
// a SINGLE root shell: mktemp a random temp in the target's directory (O_EXCL,
// nothing to follow), write it from stdin, set mode/owner, and atomically
// `mv -T` it over the target (a rename REPLACES a symlinked target, it does not
// follow it). The Direct/root path (writeDirect) is fd-anchored and is preferred
// for security-sensitive writes; this shell path serves non-root callers that
// cannot openat the target as root.
func (m *manager) writeEscalated(ctx context.Context, path string, data []byte, opts WriteOptions) error {
	perm := opts.Mode
	if perm == 0 {
		perm = 0o644
	}
	if err := escalatedParentSafe(filepath.Dir(path)); err != nil {
		return err
	}
	res, err := m.runPrivStdin(ctx, string(data), "sh", "-c", escalatedWriteScript,
		"sh", path, modeArg(perm), Ownership(opts.Owner, opts.Group), opts.Backup)
	if err != nil {
		return fmt.Errorf("write file %s: %w", path, err)
	}
	if cerr := cmdError("write file", res); cerr != nil {
		return fmt.Errorf("write file %s: %w", path, cerr)
	}
	return nil
}

// escalatedWriteScript performs an atomic, symlink-safe write entirely as root in
// one process, so there is no cross-process TOCTOU window. Positional args:
// $1=target, $2=chmod mode, $3=chown owner (":group" form, "" to skip),
// $4=backup path ("" to skip). The file content is read from stdin. The parent
// directory's safety is vetted in Go (escalatedParentSafe) before this runs, so
// only root can have influenced the directory this writes into.
const escalatedWriteScript = `set -eu
target=$1; mode=$2; owner=$3; backup=$4
dir=$(dirname -- "$target")
if [ -n "$backup" ] && [ -e "$target" ]; then
	cp -f -- "$target" "$backup"
fi
tmp=$(mktemp "$dir/.pm-XXXXXXXXXX")
trap 'rm -f -- "$tmp"' EXIT
cat > "$tmp"
chmod "$mode" -- "$tmp"
if [ -n "$owner" ]; then
	chown "$owner" -- "$tmp"
fi
mv -T -- "$tmp" "$target"
trap - EXIT
`

// runChecked runs an escalated command and folds a runner error and a non-zero
// exit into a single error (nil only on a clean exit).
func (m *manager) runChecked(ctx context.Context, name string, args ...string) error {
	res, err := m.runPriv(ctx, name, args...)
	if err != nil {
		return err
	}
	return cmdError(name, res)
}

// Copy copies src to dst (plain cp, no -p) and applies opts to dst. opts.Mode of
// 0 leaves cp's default destination mode (the source mode with the process umask
// applied) in place; set opts.Mode to fix the mode explicitly. This differs from
// WriteFile, which defaults a zero mode to 0644.
func (m *manager) Copy(ctx context.Context, src, dst string, opts WriteOptions) error {
	if err := ValidatePath(src); err != nil {
		return err
	}
	if err := ValidatePath(dst); err != nil {
		return err
	}
	if err := m.runChecked(ctx, "cp", "--", src, dst); err != nil {
		return fmt.Errorf("copy file: %w", err)
	}
	if opts.Mode != 0 {
		if err := m.SetMode(ctx, dst, opts.Mode); err != nil {
			return err
		}
	}
	if opts.Owner != "" || opts.Group != "" {
		if err := m.SetOwnership(ctx, dst, opts.Owner, opts.Group); err != nil {
			return err
		}
	}
	return nil
}

// SetMode sets the file mode (chmod). The mode is applied exactly as given
// (a zero mode means 0000); callers that want a default for a fresh file use
// WriteOptions.Mode, which defaults 0 to 0644.
func (m *manager) SetMode(ctx context.Context, path string, mode os.FileMode) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	return m.runChecked(ctx, "chmod", modeArg(mode), "--", path)
}

// SetOwnership sets the file owner and group (chown). Both empty is a no-op.
func (m *manager) SetOwnership(ctx context.Context, path, owner, group string) error {
	ownership := Ownership(owner, group)
	if ownership == "" {
		return nil
	}
	if err := ValidatePath(path); err != nil {
		return err
	}
	return m.runChecked(ctx, "chown", "--", ownership, path)
}

// SetOwnershipRecursive changes ownership of a path and all its contents
// (chown -R). Both empty is a no-op. The `--` separator and ValidatePath both
// refuse an ownership or path value that begins with `-`.
func (m *manager) SetOwnershipRecursive(ctx context.Context, path, owner, group string) error {
	ownership := Ownership(owner, group)
	if ownership == "" {
		return nil
	}
	if err := ValidatePath(path); err != nil {
		return err
	}
	return m.runChecked(ctx, "chown", "-R", "--", ownership, path)
}
