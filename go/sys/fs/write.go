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
// is used: it cannot openat as root, so it shells the write through the
// privilege backend (tee → chmod → chown → mv). That path is NOT symlink-safe,
// but the security-relevant consumer — the root agent — never takes it.
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
// Predictable temp + tee/mv; not symlink-safe (see WriteFile's doc for why that
// is acceptable).
func (m *manager) writeEscalated(ctx context.Context, path string, data []byte, opts WriteOptions) error {
	perm := opts.Mode
	if perm == 0 {
		perm = 0o644
	}
	if opts.Backup != "" {
		if err := m.backupEscalated(ctx, path, opts.Backup); err != nil {
			return err
		}
	}
	tmpPath := path + ".pm-tmp"
	if err := m.writeTee(ctx, tmpPath, data); err != nil {
		m.bestEffortRemove(ctx, tmpPath)
		return fmt.Errorf("write file %s: %w", tmpPath, err)
	}
	if err := m.applyModeOwner(ctx, tmpPath, perm, opts.Owner, opts.Group); err != nil {
		m.bestEffortRemove(ctx, tmpPath)
		return err
	}
	if err := m.runChecked(ctx, "mv", "-f", "--", tmpPath, path); err != nil {
		m.bestEffortRemove(ctx, tmpPath)
		return fmt.Errorf("move file into place: %w", err)
	}
	return nil
}

// writeTee streams data to path through an escalated `tee`. A non-zero tee exit
// (e.g. the parent directory does not exist) is surfaced as an error.
func (m *manager) writeTee(ctx context.Context, path string, data []byte) error {
	res, err := m.runPrivStdin(ctx, string(data), "tee", "--", path)
	if err != nil {
		return err
	}
	return cmdError("tee", res)
}

// applyModeOwner chmods (always) and chowns (when owner/group set) a path
// through the escalated backend.
func (m *manager) applyModeOwner(ctx context.Context, path string, perm os.FileMode, owner, group string) error {
	if err := m.runChecked(ctx, "chmod", modeArg(perm), "--", path); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	if owner != "" || group != "" {
		if err := m.runChecked(ctx, "chown", "--", Ownership(owner, group), path); err != nil {
			return fmt.Errorf("chown: %w", err)
		}
	}
	return nil
}

// backupEscalated copies the existing file at path to backup before it is
// replaced. A path that does not yet exist is a no-op (nothing to back up).
func (m *manager) backupEscalated(ctx context.Context, path, backup string) error {
	exists, err := m.Exists(ctx, path)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if err := m.runChecked(ctx, "cp", "-f", "--", path, backup); err != nil {
		return fmt.Errorf("backup %s to %s: %w", path, backup, err)
	}
	return nil
}

// runChecked runs an escalated command and folds a runner error and a non-zero
// exit into a single error (nil only on a clean exit).
func (m *manager) runChecked(ctx context.Context, name string, args ...string) error {
	res, err := m.runPriv(ctx, name, args...)
	if err != nil {
		return err
	}
	return cmdError(name, res)
}

// bestEffortRemove deletes path through the escalated backend, ignoring the
// outcome — used to clean up a temp file on a failure path.
func (m *manager) bestEffortRemove(ctx context.Context, path string) {
	_, _ = m.runPriv(ctx, "rm", "-f", "--", path)
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
