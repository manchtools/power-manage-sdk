//go:build unix

package fs

import (
	"os"
	"syscall"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
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

// useRootBackend forces the Root privilege backend for the duration of a
// test (restored on cleanup) so the fd-based, symlink-safe code paths in
// WriteFileAtomic / RemoveDir are exercised even though the test process
// is not actually root. The operations themselves run against
// test-user-owned temp dirs, so they succeed without real privilege; only
// the path SELECTION (fd vs sudo escalation) is what the backend gates.
func useRootBackend(t *testing.T) {
	t.Helper()
	prev := exec.CurrentPrivilegeBackend()
	exec.SetPrivilegeBackend(exec.Direct)
	t.Cleanup(func() {
		switch prev {
		case exec.Sudo, exec.Doas, exec.Direct:
			exec.SetPrivilegeBackend(prev)
		default:
			// Pre-rework the unset zero value resolved to sudo, so the captured
			// "prev" round-tripped cleanly. The fail-closed enum now makes the
			// zero value invalid, which SetPrivilegeBackend ignores — leaving the
			// global stuck on Direct and breaking later non-root sudo-path tests.
			// Restore the historical default (sudo) explicitly.
			exec.SetPrivilegeBackend(exec.Sudo)
		}
	})
}
