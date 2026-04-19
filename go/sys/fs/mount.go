package fs

import (
	"context"
	"fmt"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// IsReadOnly checks if the filesystem at path is mounted read-only
// by examining mount options via findmnt.
func IsReadOnly(path string) (bool, error) {
	out, err := exec.Query("findmnt", "-n", "-o", "OPTIONS", "--target", path)
	if err != nil {
		return false, err
	}
	for _, opt := range strings.Split(strings.TrimSpace(out), ",") {
		if opt == "ro" {
			return true, nil
		}
	}
	return false, nil
}

// RemountRW attempts to remount the filesystem at path as read-write
// via the configured privilege backend: mount -o remount,rw.
func RemountRW(ctx context.Context, path string) error {
	_, err := exec.Privileged(ctx, "mount", "-o", "remount,rw", path)
	if err != nil {
		return fmt.Errorf("remount %s read-write: %w", path, err)
	}
	return nil
}
