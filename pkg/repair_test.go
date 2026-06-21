package pkg

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// stubStatFile overrides the statFile seam: paths in exist resolve, all others
// report os.ErrNotExist. onCall, if non-nil, runs before returning (used to
// cancel the context between statFile and the fuser probe).
func stubStatFile(t *testing.T, onCall func(), exist ...string) {
	t.Helper()
	set := make(map[string]bool, len(exist))
	for _, p := range exist {
		set[p] = true
	}
	orig := statFile
	statFile = func(p string) (fs.FileInfo, error) {
		if onCall != nil {
			onCall()
		}
		if set[p] {
			return nil, nil
		}
		return nil, fs.ErrNotExist
	}
	t.Cleanup(func() { statFile = orig })
}

func TestRemoveStaleLock_FileAbsent(t *testing.T) {
	stubStatFile(t, nil) // nothing exists
	f := newFake()
	if err := removeStaleLock(context.Background(), f, "/var/lib/dpkg/lock"); err != nil {
		t.Fatalf("absent lock should be a no-op, got %v", err)
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("absent lock must run no commands, ran %d", n)
	}
}

// NOTE: the in-use ("fuser reports a holder → keep") and stale-removed
// ("fuser reports no holder → escalated rm") behaviours were previously
// asserted here by FEEDING the FakeRunner a fabricated fuser exit code — i.e.
// the test scripted the exact tool behaviour it then "verified", proving only
// that the Go branch on a hand-chosen exit code works, never that real fuser
// emits that code for a real held/unheld fd. Those two cases now run against
// the REAL fuser binary on a REAL lock file in pkg/repair_container_test.go
// (build tag `container`), so they are removed here as the first step of the
// container-only migration. The fake-runner tests BELOW are kept: they cover
// error/edge LOGIC (inconclusive probe, exec failure, stat error, context
// cancellation) that is about the Go code path, not fabricated tool behaviour.

func TestRemoveStaleLock_InconclusiveProbeKeepsLock(t *testing.T) {
	stubStatFile(t, nil, "/lock")
	f := newFake()
	f.Push(pmexec.Result{ExitCode: 3}, nil) // fuser: probe failure, not the "stale" 1
	if err := removeStaleLock(context.Background(), f, "/lock"); err != nil {
		t.Fatal(err)
	}
	if n := len(f.Calls()); n != 1 {
		t.Errorf("inconclusive probe must NOT remove, ran %d commands", n)
	}
}

func TestRemoveStaleLock_FuserExecErrorKeepsLock(t *testing.T) {
	stubStatFile(t, nil, "/lock")
	f := newFake()
	f.Push(pmexec.Result{}, errors.New("fuser: command not found"))
	if err := removeStaleLock(context.Background(), f, "/lock"); err != nil {
		t.Fatalf("a failed probe must be tolerated, got %v", err)
	}
	if n := len(f.Calls()); n != 1 {
		t.Errorf("failed probe must not remove, ran %d", n)
	}
}

func TestRemoveStaleLock_RmExecErrorTolerated(t *testing.T) {
	stubStatFile(t, nil, "/lock")
	f := newFake()
	f.Push(pmexec.Result{ExitCode: 1}, nil)           // stale
	f.Push(pmexec.Result{}, errors.New("rm: denied")) // removal fails
	if err := removeStaleLock(context.Background(), f, "/lock"); err != nil {
		t.Fatalf("a failed removal is best-effort, got %v", err)
	}
}

// A stat failure that is NOT "file does not exist" (e.g. permission denied) is
// not proof of absence: leave the lock untouched and run nothing.
func TestRemoveStaleLock_StatErrorLeavesLock(t *testing.T) {
	orig := statFile
	statFile = func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }
	t.Cleanup(func() { statFile = orig })
	f := newFake()
	if err := removeStaleLock(context.Background(), f, "/lock"); err != nil {
		t.Fatalf("a non-not-exist stat error is best-effort, got %v", err)
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("a stat error must leave the lock untouched (no probe/rm), ran %d", n)
	}
}

// A stat failure concurrent with a cancellation reports the cancellation, not a
// best-effort skip.
func TestRemoveStaleLock_StatErrorWithCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	orig := statFile
	statFile = func(string) (fs.FileInfo, error) {
		cancel()
		return nil, fs.ErrPermission
	}
	t.Cleanup(func() { statFile = orig })
	if err := removeStaleLock(ctx, newFake(), "/lock"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestRemoveStaleLock_CtxCancelledAtEntry(t *testing.T) {
	stubStatFile(t, nil, "/lock")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := newFake()
	if err := removeStaleLock(ctx, f, "/lock"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("cancelled-at-entry must run nothing, ran %d", n)
	}
}

// When the context is cancelled between the stat and the probe, the probe's
// fail-closed ctx.Err() is distinguished from a genuine probe failure and
// returned as the cancellation.
func TestRemoveStaleLock_CtxCancelledAfterStat(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stubStatFile(t, cancel, "/lock") // cancel fires when statFile is called
	f := newFake()
	if err := removeStaleLock(ctx, f, "/lock"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// cancelAfterRunner wraps a Runner and cancels the context once the nth Run has
// completed, letting a test drive a capability into a mid-sequence cancellation
// (e.g. cancelled between the fuser probe and the rm).
type cancelAfterRunner struct {
	inner  pmexec.Runner
	n      int
	cancel context.CancelFunc
	calls  int
}

func (c *cancelAfterRunner) Run(ctx context.Context, cmd pmexec.Command) (pmexec.Result, error) {
	res, err := c.inner.Run(ctx, cmd)
	c.calls++
	if c.calls == c.n {
		c.cancel()
	}
	return res, err
}

func (c *cancelAfterRunner) Stream(ctx context.Context, cmd pmexec.Command, onLine pmexec.OutputCallback) (pmexec.Result, error) {
	return c.inner.Stream(ctx, cmd, onLine)
}

func (c *cancelAfterRunner) Backend() pmexec.PrivilegeBackend { return c.inner.Backend() }

// When the context is cancelled after a stale probe but before the rm, the rm's
// fail-closed ctx.Err() is reported as the cancellation, not swallowed.
func TestRemoveStaleLock_CtxCancelledDuringRemoval(t *testing.T) {
	stubStatFile(t, nil, "/lock")
	ctx, cancel := context.WithCancel(context.Background())
	inner := newFake()
	inner.Push(pmexec.Result{ExitCode: 1}, nil) // fuser: stale
	r := &cancelAfterRunner{inner: inner, n: 1, cancel: cancel}
	if err := removeStaleLock(ctx, r, "/lock"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled from the rm step", err)
	}
}

func TestBestEffortStep(t *testing.T) {
	t.Run("nil error passes", func(t *testing.T) {
		if err := bestEffortStep(context.Background(), "step", nil); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})
	t.Run("genuine failure is swallowed", func(t *testing.T) {
		if err := bestEffortStep(context.Background(), "step", errors.New("wedged")); err != nil {
			t.Errorf("a genuine step failure must be swallowed, got %v", err)
		}
	})
	t.Run("cancellation stops the chain", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		// A cancelled context makes the step fail closed; bestEffortStep must
		// report the cancellation rather than swallow it.
		err := bestEffortStep(ctx, "step", context.Canceled)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	})
}

func TestRepairErr(t *testing.T) {
	t.Run("wraps the cause", func(t *testing.T) {
		cause := &pmexec.CommandError{Name: "apt", ExitCode: 1, Stderr: "boom"}
		err := repairErr(context.Background(), "apt update failed", cause)
		if err == nil || !errors.As(err, new(*pmexec.CommandError)) {
			t.Fatalf("repairErr must wrap the cause, got %v", err)
		}
	})
	t.Run("cancellation wins over the message", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := repairErr(ctx, "apt update failed", errors.New("orig"))
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})
}

// stubReadFile overrides the readFile seam used by removeStaleZyppLock.
func stubReadFile(t *testing.T, content string, err error) {
	t.Helper()
	orig := readFile
	readFile = func(string) ([]byte, error) {
		if err != nil {
			return nil, err
		}
		return []byte(content), nil
	}
	t.Cleanup(func() { readFile = orig })
}

// /run/zypp.pid is a PID FILE, not an flock: zypper writes its PID and closes
// the descriptor, so fuser always reports "no holder" and would green-light
// removal while zypper runs. removeStaleZyppLock must instead probe the named
// PID's liveness and only remove the lock when the process is gone.

func TestRemoveStaleZyppLock_FileAbsent(t *testing.T) {
	stubStatFile(t, nil) // nothing exists
	f := newFake()
	if err := removeStaleZyppLock(context.Background(), f, "/run/zypp.pid"); err != nil {
		t.Fatalf("absent pid file must be a no-op, got %v", err)
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("absent pid file must run nothing, ran %d", n)
	}
}

func TestRemoveStaleZyppLock_LivePIDKept(t *testing.T) {
	stubStatFile(t, nil, "/run/zypp.pid")
	stubReadFile(t, "4242\n", nil)
	f := newFake()
	f.Push(pmexec.Result{ExitCode: 0}, nil) // kill -0: process is alive
	if err := removeStaleZyppLock(context.Background(), f, "/run/zypp.pid"); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	if len(calls) != 1 {
		t.Fatalf("a live PID must be probed but NOT removed, ran %d commands", len(calls))
	}
	if argv(calls[0]) != "kill -0 4242" {
		t.Errorf("probe argv = %q, want \"kill -0 4242\"", argv(calls[0]))
	}
	// The probe MUST escalate: probed unprivileged, a root-owned zypper would
	// return EPERM (non-zero) and be misread as dead.
	if !calls[0].Escalate {
		t.Error("kill -0 liveness probe must escalate so EPERM cannot be confused with ESRCH")
	}
}

func TestRemoveStaleZyppLock_DeadPIDRemoved(t *testing.T) {
	stubStatFile(t, nil, "/run/zypp.pid")
	stubReadFile(t, "4242\n", nil)
	f := newFake()
	f.Push(pmexec.Result{ExitCode: 1}, nil) // kill -0: ESRCH, the process is gone
	f.Push(pmexec.Result{}, nil)            // rm -f
	if err := removeStaleZyppLock(context.Background(), f, "/run/zypp.pid"); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	if len(calls) != 2 {
		t.Fatalf("a dead PID must be probed then removed, ran %d commands", len(calls))
	}
	if calls[1].Name != "rm" || argv(calls[1]) != "rm -f /run/zypp.pid" || !calls[1].Escalate {
		t.Errorf("removal = %q (escalate=%v), want escalated \"rm -f /run/zypp.pid\"", argv(calls[1]), calls[1].Escalate)
	}
}

func TestRemoveStaleZyppLock_EmptyFileRemoved(t *testing.T) {
	stubStatFile(t, nil, "/run/zypp.pid")
	stubReadFile(t, "  \n", nil) // empty/whitespace: no live holder to harm
	f := newFake()
	f.Push(pmexec.Result{}, nil) // rm -f
	if err := removeStaleZyppLock(context.Background(), f, "/run/zypp.pid"); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	if len(calls) != 1 || calls[0].Name != "rm" {
		t.Fatalf("an empty PID file must be removed without a kill probe, calls=%v", calls)
	}
}

// A PID file whose content is not purely numeric — including a leading-dash
// value that kill would treat as a flag / process group — must NEVER be spliced
// into kill and must NOT trigger removal. Leave the lock; surface nothing.
func TestRemoveStaleZyppLock_NonNumericRefused(t *testing.T) {
	for _, content := range []string{"-1\n", "12 34", "abc", "0x10", "12;rm"} {
		stubStatFile(t, nil, "/run/zypp.pid")
		stubReadFile(t, content, nil)
		f := newFake()
		if err := removeStaleZyppLock(context.Background(), f, "/run/zypp.pid"); err != nil {
			t.Fatalf("content %q: %v", content, err)
		}
		if n := len(f.Calls()); n != 0 {
			t.Errorf("content %q: a non-numeric PID must run nothing (no kill, no rm), ran %d", content, n)
		}
	}
}

func TestRemoveStaleZyppLock_ReadErrorKeepsLock(t *testing.T) {
	stubStatFile(t, nil, "/run/zypp.pid")
	stubReadFile(t, "", errors.New("permission denied"))
	f := newFake()
	if err := removeStaleZyppLock(context.Background(), f, "/run/zypp.pid"); err != nil {
		t.Fatalf("a read failure is best-effort, got %v", err)
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("a read error must leave the lock untouched, ran %d", n)
	}
}

func TestRemoveStaleZyppLock_LivenessProbeExecErrorKeepsLock(t *testing.T) {
	stubStatFile(t, nil, "/run/zypp.pid")
	stubReadFile(t, "4242\n", nil)
	f := newFake()
	f.Push(pmexec.Result{}, errors.New("kill: not found")) // probe could not run
	if err := removeStaleZyppLock(context.Background(), f, "/run/zypp.pid"); err != nil {
		t.Fatalf("an inconclusive probe is best-effort, got %v", err)
	}
	if n := len(f.Calls()); n != 1 {
		t.Errorf("a failed probe must NOT remove (1 call), ran %d", n)
	}
}

func TestRemoveStaleZyppLock_Cancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := newFake()
	if err := removeStaleZyppLock(ctx, f, "/run/zypp.pid"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("cancelled-at-entry must run nothing, ran %d", n)
	}
}
