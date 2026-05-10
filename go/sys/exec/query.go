package exec

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-cmd/cmd"
)

// Query runs a simple command and returns stdout.
// This is for quick queries that don't need context or detailed error handling.
//
// Deprecated: Query blocks indefinitely if the underlying tool hangs (e.g. a
// stuck `systemctl is-active` on a wedged unit will pin the calling goroutine
// for the lifetime of the agent). Prefer QueryCtx so callers can apply a
// timeout via context.WithTimeout. The non-Ctx form is preserved for source
// compatibility with one-off scripts and tests where blocking is acceptable.
func Query(name string, args ...string) (string, error) {
	return QueryCtx(context.Background(), name, args...)
}

// QueryCtx is like Query but respects context cancellation. If the context
// is cancelled before the command completes, the command is stopped and
// ctx.Err() is returned.
func QueryCtx(ctx context.Context, name string, args ...string) (string, error) {
	c := cmd.NewCmd(name, args...)
	statusChan := c.Start()
	select {
	case status := <-statusChan:
		if status.Error != nil {
			return "", status.Error
		}
		if status.Exit != 0 {
			return "", fmt.Errorf("exit code %d", status.Exit)
		}
		return strings.Join(status.Stdout, "\n"), nil
	case <-ctx.Done():
		c.Stop()
		<-statusChan
		return "", ctx.Err()
	}
}

// QueryOutput runs a command and returns stdout, exit code, and any error.
// Returns stdout even on non-zero exit for commands where exit code matters.
//
// Deprecated: prefer QueryOutputCtx — see Query for the rationale. Same
// indefinite-hang hazard.
func QueryOutput(name string, args ...string) (stdout string, exitCode int, err error) {
	return QueryOutputCtx(context.Background(), name, args...)
}

// QueryOutputCtx is like QueryOutput but respects context cancellation.
// On cancellation it returns whatever stdout has been buffered so far,
// the underlying exit code (or -1 if the process was killed), and ctx.Err().
func QueryOutputCtx(ctx context.Context, name string, args ...string) (stdout string, exitCode int, err error) {
	c := cmd.NewCmd(name, args...)
	statusChan := c.Start()
	select {
	case status := <-statusChan:
		return strings.Join(status.Stdout, "\n"), status.Exit, status.Error
	case <-ctx.Done():
		c.Stop()
		status := <-statusChan
		return strings.Join(status.Stdout, "\n"), status.Exit, ctx.Err()
	}
}

// Check runs a command and returns true if it succeeds (exit 0, no error).
//
// Deprecated: prefer CheckCtx. See Query for the rationale.
func Check(name string, args ...string) bool {
	return CheckCtx(context.Background(), name, args...)
}

// CheckCtx is like Check but respects context cancellation.
func CheckCtx(ctx context.Context, name string, args ...string) bool {
	_, err := Run(ctx, name, args...)
	return err == nil
}

// FormatError formats a command error with stderr output for better diagnostics.
func FormatError(err error, result *Result) string {
	if result != nil && result.Stderr != "" {
		return fmt.Sprintf("%v: %s", err, strings.TrimSpace(result.Stderr))
	}
	return err.Error()
}
