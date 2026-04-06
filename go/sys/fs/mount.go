package fs

import (
	"context"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// IsReadOnly checks if the filesystem at path is mounted read-only
// by examining /proc/mounts.
func IsReadOnly(path string) bool {
	out, err := exec.Query("findmnt", "-n", "-o", "OPTIONS", "--target", path)
	if err != nil {
		return false
	}
	for _, opt := range strings.Split(strings.TrimSpace(out), ",") {
		if opt == "ro" {
			return true
		}
	}
	return false
}

// RemountRW attempts to remount the filesystem at path as read-write
// via sudo mount -o remount,rw.
func RemountRW(ctx context.Context, path string) error {
	_, err := exec.Sudo(ctx, "mount", "-o", "remount,rw", path)
	return err
}
