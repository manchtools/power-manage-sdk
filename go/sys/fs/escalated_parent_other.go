//go:build !unix

package fs

import "fmt"

// escalatedParentSafe is unix-only (it relies on syscall.Stat_t to read the
// directory's numeric owner). On non-unix platforms — kept buildable for
// cross-platform `go vet` — the escalated path is unsupported, so it fails
// closed.
func escalatedParentSafe(dir string) error {
	return fmt.Errorf("%w: %s: escalated writes are unsupported on this platform", ErrUnsafeParentDir, dir)
}
