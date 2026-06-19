//go:build container

// Container-based real-execution tests for the package-manager stale-lock
// repair path. Unlike the fake-runner unit tests (which feed fabricated fuser
// exit codes), these run INSIDE a container against the REAL fuser binary and a
// REAL lock file on the container filesystem — so a shell-quoting change, a
// fuser behaviour difference, or a wrong lock path is caught, not assumed.
//
// The test process runs in the container, so os.Stat (the statFile seam) and
// the Runner-driven fuser/rm hit the SAME filesystem. A host-side proxy Runner
// would break this: removeStaleLock's os.Stat would probe the host while fuser
// probed the container.
//
// Each test owns its precondition: it self-skips when the expected container
// state (a baked stale lock) is absent, so `go test -tags=container ./pkg/`
// against any image is correct.
package pkg

import (
	"context"
	"os"
	"testing"
	"time"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

const containerDpkgLock = "/var/lib/dpkg/lock"

func containerRunner(t *testing.T) pmexec.Runner {
	t.Helper()
	// The container runs the test as root (matching the production agent:
	// systemd User=root), so the Direct backend runs commands without a
	// privilege wrapper.
	r, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	return r
}

// TestRepair_RemovesStaleLock_Container pins the success path against a REAL
// fuser: a lock file that NO process holds open is removed.
func TestRepair_RemovesStaleLock_Container(t *testing.T) {
	if _, err := os.Stat(containerDpkgLock); os.IsNotExist(err) {
		t.Skip("precondition absent: not a state-locked-apt container")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := removeStaleLock(ctx, containerRunner(t), containerDpkgLock); err != nil {
		t.Fatalf("removeStaleLock on an unheld lock returned error: %v", err)
	}
	if _, err := os.Stat(containerDpkgLock); !os.IsNotExist(err) {
		t.Fatalf("stale (unheld) lock was not removed; stat err = %v", err)
	}
}

// TestRepair_KeepsHeldLock_Container pins the safety-critical REJECTION path
// against a REAL fuser: a lock a process is actively holding open MUST NOT be
// removed (fuser reports it in use → removeStaleLock leaves it).
//
// It is a two-phase check so it cannot pass for the wrong reason: a broken or
// missing fuser would ALSO leave the lock (removeStaleLock returns nil on a
// probe error), which looks identical to "correctly kept". So we assert
// held→KEPT, then release the fd and assert released→REMOVED. Only a fuser that
// genuinely discriminates a held fd from an unheld one passes both.
func TestRepair_KeepsHeldLock_Container(t *testing.T) {
	dir := t.TempDir()
	lock := dir + "/held.lock"
	f, err := os.OpenFile(lock, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("create held lock: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := containerRunner(t)

	// Phase 1: the fd is held → fuser sees this process → lock must remain.
	if err := removeStaleLock(ctx, r, lock); err != nil {
		t.Fatalf("removeStaleLock(held) returned error: %v", err)
	}
	if _, err := os.Stat(lock); err != nil {
		t.Fatalf("a HELD lock was removed (or stat failed): %v — never delete a live lock", err)
	}

	// Phase 2: release the fd → fuser sees no holder → lock must now be removed.
	// If fuser were broken, this would still leave the lock and fail here,
	// proving phase 1 wasn't a false positive.
	if err := f.Close(); err != nil {
		t.Fatalf("close held lock fd: %v", err)
	}
	if err := removeStaleLock(ctx, r, lock); err != nil {
		t.Fatalf("removeStaleLock(released) returned error: %v", err)
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatalf("released lock not removed; stat err = %v — fuser did not discriminate held vs unheld", err)
	}
}
