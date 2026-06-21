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
	osexec "os/exec"
	"strconv"
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

// TestRepair_ZyppLockLiveness_Container pins the zypp.pid PID-liveness path
// against a REAL kill -0: a PID file naming a LIVE process must be kept, one
// naming a DEAD process must be removed. fuser is deliberately NOT the probe
// here — zypp.pid has no open holder, so fuser would report "no holder" and
// wrongly green-light removal even while zypper runs; this proves the PID-based
// probe is what discriminates.
//
// Two-phase so it cannot pass for the wrong reason (mirrors the held-lock test):
// a kill -0 that always failed would remove in BOTH phases (failing phase 1); one
// that always succeeded would keep in BOTH (failing phase 2). Only a probe that
// genuinely discriminates a live PID from a dead one passes both.
func TestRepair_ZyppLockLiveness_Container(t *testing.T) {
	dir := t.TempDir()
	pidFile := dir + "/zypp.pid"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := containerRunner(t)

	// Phase 1: a LIVE pid (this test process) → the lock must remain.
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
		t.Fatalf("write live pid file: %v", err)
	}
	if err := removeStaleZyppLock(ctx, r, pidFile); err != nil {
		t.Fatalf("removeStaleZyppLock(live) returned error: %v", err)
	}
	if _, err := os.Stat(pidFile); err != nil {
		t.Fatalf("a PID file naming a LIVE process was removed (or stat failed): %v — never delete a live lock", err)
	}

	// Phase 2: a DEAD pid (a child run to completion and reaped — not a zombie,
	// which would still answer kill -0) → the lock must now be removed.
	done := osexec.Command("true")
	if err := done.Run(); err != nil {
		t.Fatalf("run throwaway child: %v", err)
	}
	deadPID := done.Process.Pid
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(deadPID)+"\n"), 0o644); err != nil {
		t.Fatalf("write dead pid file: %v", err)
	}
	if err := removeStaleZyppLock(ctx, r, pidFile); err != nil {
		t.Fatalf("removeStaleZyppLock(dead) returned error: %v", err)
	}
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Fatalf("a PID file naming a DEAD process was not removed; stat err = %v — kill -0 did not discriminate live vs dead", err)
	}
}
