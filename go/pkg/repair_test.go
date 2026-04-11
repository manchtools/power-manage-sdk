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
