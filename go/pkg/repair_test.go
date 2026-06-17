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
