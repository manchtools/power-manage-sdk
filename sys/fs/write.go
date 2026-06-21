package fs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
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
	if err := validateMode(opts.Mode); err != nil {
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

// WriteReader streams the bytes from r to path, applying opts, WITHOUT buffering
// the whole payload in memory — for a large artifact (e.g. a downloaded AppImage
// of tens-to-hundreds of MB) that WriteFile([]byte) would risk OOM on. The stream
// lands in a same-directory temp file that is renamed into place only after it is
// written, so at no instant does a crash or power-loss leave the destination
// holding a partial file: it always holds either the prior content or the new
// content in full. On the Direct backend the temp open is O_NOFOLLOW (symlink-
// safe) and an io.Copy error aborts BEFORE the rename, so a mid-stream READER
// error also leaves the destination untouched. Under Sudo/Doas the stream is
// piped through a single root shell that `cat`s stdin into the temp and `mv -T`s
// it over the target; a reader that errors mid-stream is surfaced as an error,
// but because the shell renames on its own stdin-EOF the truncated temp may
// already have been placed — so callers stream a COMPLETE source (the AppImage
// flow streams a checksum-verified file, where a read error means disk failure).
//
// opts.Backup is NOT supported (WriteReader targets a fresh large artifact, not an
// in-place config edit with a kept backup); setting it is an error. A zero
// opts.Mode defaults to 0644, as WriteFile does.
func (m *manager) WriteReader(ctx context.Context, path string, r io.Reader, opts WriteOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidatePath(path); err != nil {
		return err
	}
	if err := validateMode(opts.Mode); err != nil {
		return err
	}
	if r == nil {
		return fmt.Errorf("%w: WriteReader requires a non-nil reader", ErrInvalidPath)
	}
	if opts.Backup != "" {
		return fmt.Errorf("%w: WriteReader does not support a backup (use WriteFile for in-place edits)", ErrInvalidPath)
	}
	if m.direct() {
		return writeReaderDirect(path, r, opts)
	}
	return m.writeReaderEscalated(ctx, path, r, opts)
}

// writeReaderDirect is the fd-anchored streaming path (root agent): it streams r
// into an O_NOFOLLOW temp and atomically renames into place, then chowns through
// an O_NOFOLLOW fd — the symlink-safe Direct write, sourced from a reader.
func writeReaderDirect(path string, r io.Reader, opts WriteOptions) error {
	perm := opts.Mode
	if perm == 0 {
		perm = 0o644
	}
	if err := safeReplaceFromReader(path, r, perm, true); err != nil {
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

// writeReaderEscalated streams r through the escalatedWriteScript: the root shell
// `cat`s stdin into a same-directory temp and `mv -T`s it over the target, so the
// payload never lands in this (non-root) process's memory. Same parent-safety
// vetting and single-root-shell atomicity as writeEscalated; backup is always
// empty (WriteReader rejects Backup up front).
func (m *manager) writeReaderEscalated(ctx context.Context, path string, r io.Reader, opts WriteOptions) error {
	perm := opts.Mode
	if perm == 0 {
		perm = 0o644
	}
	if err := escalatedParentSafe(filepath.Dir(path)); err != nil {
		return err
	}
	res, err := m.r.Run(ctx, pmexec.Command{
		Name:     "sh",
		Args:     []string{"-c", escalatedWriteScript, "sh", path, modeArg(perm), Ownership(opts.Owner, opts.Group), ""},
		Stdin:    r,
		Escalate: true,
	})
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
	if err := validateMode(opts.Mode); err != nil {
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

// CopyTree recursively copies the tree at src to dst, preserving mode, ownership,
// and timestamps (cp -a), and merges into dst rather than nesting under it: it
// runs `cp -a -T -- src dst`, where -T (--no-target-directory) makes cp treat dst
// as the literal destination. So `CopyTree(ctx, "/etc/skel", "/home/alice", …)`
// makes /home/alice a copy of skel's contents whether or not /home/alice already
// exists — never /home/alice/skel. cp -a OVERWRITES files that already exist at
// dst (it does not delete dst-only files); a caller that must not clobber existing
// content (e.g. a user's customised dotfiles) checks Exists first.
//
// opts applies to dst AFTER the copy: a non-zero Mode chmods the destination ROOT
// only (not recursively — the per-file modes from the archive copy are kept),
// while Owner/Group, if set, are applied RECURSIVELY (the common intent when
// re-homing a tree copied as root — e.g. skel → a user's home). Both are skipped
// when unset, leaving the archive-preserved metadata.
func (m *manager) CopyTree(ctx context.Context, src, dst string, opts WriteOptions) error {
	if err := ValidatePath(src); err != nil {
		return err
	}
	if err := ValidatePath(dst); err != nil {
		return err
	}
	if err := validateMode(opts.Mode); err != nil {
		return err
	}
	if err := m.runChecked(ctx, "cp", "-a", "-T", "--", src, dst); err != nil {
		return fmt.Errorf("copy tree: %w", err)
	}
	if opts.Mode != 0 {
		if err := m.SetMode(ctx, dst, opts.Mode); err != nil {
			return err
		}
	}
	if opts.Owner != "" || opts.Group != "" {
		if err := m.SetOwnershipRecursive(ctx, dst, opts.Owner, opts.Group); err != nil {
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
	if err := validateMode(mode); err != nil {
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
	// A recursive chown of a whole system tree (`/`, `/etc`, `/usr`, `/home`,
	// `/root`, …) hands an attacker ownership of every file beneath it — a
	// privilege-escalation and data-destruction vector. Refuse any top-level
	// system directory (the same set RemoveDir protects) before chown. A managed
	// subdirectory (e.g. /home/alice, /var/lib/app) remains re-ownable.
	if IsProtectedPath(path) {
		return fmt.Errorf("%w: %s", ErrProtectedTarget, filepath.Clean(path))
	}
	return m.runChecked(ctx, "chown", "-R", "--", ownership, path)
}
