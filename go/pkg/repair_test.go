package pkg

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestRepairErr_PassesThroughCtxErr verifies that when the context is
// cancelled, repairErr returns the raw ctx.Err() so callers can detect
// it via errors.Is, instead of wrapping the subprocess error.
func TestRepairErr_PassesThroughCtxErr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	subErr := errors.New("sudo: command timed out")
	got := repairErr(ctx, "apt update failed", "stderr output", subErr)

	if !errors.Is(got, context.Canceled) {
		t.Errorf("expected errors.Is(err, context.Canceled) = true, got err = %v", got)
	}
	// Must be the raw ctx.Err() — not wrapped — so the message stays clean.
	if got.Error() != context.Canceled.Error() {
		t.Errorf("expected raw context.Canceled, got %q", got.Error())
	}
}

// TestRepairErr_PassesThroughDeadlineExceeded verifies the same for
// DeadlineExceeded so callers using errors.Is can match either form.
func TestRepairErr_PassesThroughDeadlineExceeded(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()

	subErr := errors.New("sudo: command timed out")
	got := repairErr(ctx, "apt update failed", "stderr output", subErr)

	if !errors.Is(got, context.DeadlineExceeded) {
		t.Errorf("expected errors.Is(err, context.DeadlineExceeded) = true, got err = %v", got)
	}
}

// TestRepairErr_WrapsSubprocessError verifies that when the context is
// healthy, repairErr wraps the subprocess error with the message and
// stderr, AND keeps the original error reachable via errors.Is.
func TestRepairErr_WrapsSubprocessError(t *testing.T) {
	ctx := context.Background()
	subErr := errors.New("exit status 100")

	got := repairErr(ctx, "apt update failed", "E: Could not get lock", subErr)

	if got == nil {
		t.Fatal("expected error, got nil")
	}
	// The original error must remain reachable for callers using errors.Is.
	if !errors.Is(got, subErr) {
		t.Errorf("expected errors.Is(err, subErr) = true, got err = %v", got)
	}
	// The message and stderr must appear for debuggability.
	msg := got.Error()
	if !strings.Contains(msg, "apt update failed") {
		t.Errorf("expected error message to contain 'apt update failed', got %q", msg)
	}
	if !strings.Contains(msg, "E: Could not get lock") {
		t.Errorf("expected error message to contain stderr, got %q", msg)
	}
}

// TestRemoveStaleLock_CancelledCtx verifies that removeStaleLock returns
// ctx.Err() immediately on a pre-cancelled context, before stat'ing the
// path or spawning fuser/sudo subprocesses.
func TestRemoveStaleLock_CancelledCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Use a path that definitely exists so we know the early return is
	// from the ctx check, not from the os.Stat ENOENT branch.
	err := removeStaleLock(ctx, "/etc/hostname")

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected errors.Is(err, context.Canceled) = true, got err = %v", err)
	}
}

// TestRemoveStaleLock_NonExistentPathHealthyCtx verifies the happy path:
// a healthy context plus a non-existent path returns nil silently
// (preserving the pre-existing best-effort behavior).
func TestRemoveStaleLock_NonExistentPathHealthyCtx(t *testing.T) {
	err := removeStaleLock(context.Background(), "/nonexistent/path/does/not/exist")
	if err != nil {
		t.Errorf("expected nil for non-existent path, got %v", err)
	}
}

// TestAptRepair_PreflightCancellation verifies that Apt.Repair short-circuits
// on a pre-cancelled context without spawning any subprocesses. The very
// first thing it does is iterate lockFiles calling removeStaleLock, which
// itself preflights ctx.Err().
func TestAptRepair_PreflightCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	a := NewAptWithContext(context.Background())
	err := a.Repair(ctx)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected errors.Is(err, context.Canceled) = true, got err = %v", err)
	}
}
