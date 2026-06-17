package fs

import (
	"context"
	"fmt"
	"strings"
)

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
	for _, opt := range strings.Split(strings.TrimSpace(res.Stdout), ",") {
		if opt == "ro" {
			return true, nil
		}
	}
	return false, nil
}

// RemountRW remounts the filesystem at path read-write through the privilege
// backend: mount -o remount,rw.
func (m *manager) RemountRW(ctx context.Context, path string) error {
	if err := m.runChecked(ctx, "mount", "-o", "remount,rw", path); err != nil {
		return fmt.Errorf("remount %s read-write: %w", path, err)
	}
	return nil
}
