package pkg

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
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

func TestRemoveStaleLock_InUse(t *testing.T) {
	stubStatFile(t, nil, "/lock")
	f := newFake()
	f.Push(pmexec.Result{ExitCode: 0}, nil) // fuser: a process holds it
	if err := removeStaleLock(context.Background(), f, "/lock"); err != nil {
		t.Fatal(err)
	}
	if n := len(f.Calls()); n != 1 {
		t.Fatalf("in-use lock must probe but not remove, ran %d", n)
	}
}

func TestRemoveStaleLock_StaleRemoved(t *testing.T) {
	stubStatFile(t, nil, "/lock")
	f := newFake()
	f.Push(pmexec.Result{ExitCode: 1}, nil) // fuser: nobody holds it (stale)
	f.Push(pmexec.Result{ExitCode: 0}, nil) // rm -f
	if err := removeStaleLock(context.Background(), f, "/lock"); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	if len(calls) != 2 {
		t.Fatalf("stale lock must probe then remove, ran %d", len(calls))
	}
	if argv(calls[1]) != "rm -f /lock" || !calls[1].Escalate {
		t.Errorf("removal call = %q (escalate=%v), want escalated rm -f", argv(calls[1]), calls[1].Escalate)
	}
}

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
