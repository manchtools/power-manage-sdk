//go:build unix

package fs

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// TestEscalatedParentSafe pins the parent-directory safety rule the escalated
// WriteFile depends on: a directory is safe only when root-owned AND either not
// group/other-writable OR sticky.
func TestEscalatedParentSafe(t *testing.T) {
	// A root-owned, non-group/other-writable system dir is safe.
	if err := escalatedParentSafe("/usr"); err != nil {
		t.Errorf("escalatedParentSafe(/usr) = %v, want nil (root-owned, 0755)", err)
	}

	// A world-writable, non-sticky directory is refused — regardless of who runs
	// the test (0777-non-sticky is unsafe whether owned by root or the test user).
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := escalatedParentSafe(dir); !errors.Is(err, ErrUnsafeParentDir) {
		t.Errorf("escalatedParentSafe(0777 non-sticky) = %v, want ErrUnsafeParentDir", err)
	}

	// A non-existent directory is an error (cannot be vetted, so cannot be used).
	if err := escalatedParentSafe(dir + "/does-not-exist"); err == nil {
		t.Error("escalatedParentSafe(missing) = nil, want an error")
	}

	// The sticky exception: a root-owned sticky dir (e.g. /tmp) IS safe — the
	// sticky bit stops a non-root user from deleting/replacing root's temp file.
	if fi, err := os.Stat("/tmp"); err == nil {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if ok && st.Uid == 0 && fi.Mode()&os.ModeSticky != 0 {
			if err := escalatedParentSafe("/tmp"); err != nil {
				t.Errorf("escalatedParentSafe(/tmp, root-owned sticky) = %v, want nil (sticky exception)", err)
			}
		}
	}
}
