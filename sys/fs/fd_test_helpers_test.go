//go:build unix

package fs

import (
	"os"
	"syscall"
	"testing"
)

// fileUID returns the owning uid of info, failing the test if the
// platform stat shape is unavailable.
func fileUID(t *testing.T, info os.FileInfo) int {
	t.Helper()
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("FileInfo.Sys() is not *syscall.Stat_t")
	}
	return int(st.Uid)
}
