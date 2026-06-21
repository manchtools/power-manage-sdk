package fs

import (
	"context"
	"fmt"
	"strings"
)

// MountInfo describes one mounted filesystem, as reported by findmnt.
type MountInfo struct {
	Source   string // backing device or pseudo-source (e.g. /dev/sda1, tmpfs, proc)
	Target   string // mountpoint
	FSType   string // filesystem type (ext4, xfs, tmpfs, ...)
	ReadOnly bool   // the mount carries the "ro" VFS option
}

// IsReadOnly reports whether the filesystem mounted at path is read-only, by
// examining the mount options via findmnt (unprivileged). The caller controls
// timeout/cancellation through ctx.
func (m *manager) IsReadOnly(ctx context.Context, path string) (bool, error) {
	if err := ValidatePath(path); err != nil {
		return false, err
	}
	res, err := m.runQuery(ctx, "findmnt", "-n", "-o", "OPTIONS", "--target", path)
	if err != nil {
		return false, err
	}
	if res.ExitCode != 0 {
		return false, cmdError("findmnt", res)
	}
	return mountOptionsReadOnly(strings.TrimSpace(res.Stdout)), nil
}

// mountOptionsReadOnly reports whether a comma-separated findmnt OPTIONS value
// carries the "ro" VFS flag (an exact token, never a substring of e.g.
// "errors=remount-ro").
func mountOptionsReadOnly(options string) bool {
	for _, opt := range strings.Split(options, ",") {
		if opt == "ro" {
			return true
		}
	}
	return false
}

// ListMounts enumerates every currently mounted filesystem via findmnt (an
// unprivileged read). It is the enumeration counterpart to the per-path
// IsReadOnly/RemountRW: a caller that must act on EVERY matching mount — e.g.
// remounting all read-only on-disk mounts during a repair, since /usr can go
// read-only independently of / — lists them here, filters as it needs (typically
// Source has a "/dev/" prefix and ReadOnly is true), and RemountRWs each.
//
// Output is the raw `findmnt -rn` form: one row per mount, SOURCE/TARGET/FSTYPE/
// OPTIONS. A row that does not split into at least four fields is skipped rather
// than aborting the whole enumeration.
func (m *manager) ListMounts(ctx context.Context) ([]MountInfo, error) {
	res, err := m.runQuery(ctx, "findmnt", "-rn", "-o", "SOURCE,TARGET,FSTYPE,OPTIONS")
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, cmdError("findmnt", res)
	}
	var mounts []MountInfo
	for _, line := range strings.Split(strings.TrimRight(res.Stdout, "\n"), "\n") {
		if line == "" {
			continue
		}
		// -r escapes any whitespace inside a value (\x20 etc.), so the four
		// columns are always space-separated and Fields recovers them exactly.
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		mounts = append(mounts, MountInfo{
			Source:   f[0],
			Target:   f[1],
			FSType:   f[2],
			ReadOnly: mountOptionsReadOnly(f[3]),
		})
	}
	return mounts, nil
}

// RemountRW remounts the filesystem at path read-write through the privilege
// backend: mount -o remount,rw.
func (m *manager) RemountRW(ctx context.Context, path string) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	if err := m.runChecked(ctx, "mount", "-o", "remount,rw", "--", path); err != nil {
		return fmt.Errorf("remount %s read-write: %w", path, err)
	}
	return nil
}
