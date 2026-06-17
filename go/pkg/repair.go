package pkg

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	pmexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// statFile is the os.Stat seam used by removeStaleLock so the lock-file probe
// can be exercised hermetically in tests.
var statFile = os.Stat

// bestEffortStep classifies the outcome of one best-effort repair step. A nil
// err means success. A cancelled context returns ctx.Err() so the caller stops
// the chain; any other failure is logged and swallowed (returns nil) so a single
// wedged step does not abort the whole repair. The step is run by the caller
// (its err is passed in), so a cancelled context still fails the step closed —
// runPriv refuses to spawn — and is reported here as the cancellation.
func bestEffortStep(ctx context.Context, what string, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	slog.Warn(what+" failed", "error", err)
	return nil
}

// repairErr returns ctx.Err() when the context has been cancelled, otherwise it
// wraps err with msg. err is typically an *exec.CommandError, which already
// carries the subprocess stderr. The returned error stays detectable via
// errors.Is(err, context.Canceled / context.DeadlineExceeded).
func repairErr(ctx context.Context, msg string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return fmt.Errorf("%s: %w", msg, err)
}

// removeStaleLock removes a package-manager lock file when no process holds it
// open. It probes with fuser (read-side, unprivileged) and only deletes when
// fuser reports the canonical "no process holds it" exit (1); any other probe
// outcome is treated as inconclusive and the lock is left in place — we must
// never delete a live lock based on a failed probe. The actual removal runs
// escalated through the Runner (rm -f).
//
// Returns ctx.Err() the moment the context is cancelled so callers short-circuit
// cleanly; a failure to remove the file is logged (best-effort) and does not
// return an error, but a context cancellation always wins over the warning path.
func removeStaleLock(ctx context.Context, r pmexec.Runner, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := statFile(path); err != nil {
		if os.IsNotExist(err) {
			return nil // file doesn't exist — nothing to remove
		}
		// A permission/I/O stat failure is not proof of absence; leave the lock
		// untouched rather than risk removing a live one, and surface it.
		slog.Warn("failed to stat lock file; leaving it in place", "path", path, "error", err)
		return nil
	}

	// fuser exits 0 if a process is using the file, 1 if not, and other codes
	// for probe failures (binary missing, permission denied). Treat anything
	// other than the canonical "no process holds it" exit (1) as inconclusive.
	res, err := runRead(ctx, r, "fuser", path)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		slog.Warn("fuser probe failed; skipping stale lock removal", "path", path, "error", err)
		return nil
	}
	if res.ExitCode == 0 {
		return nil // file is actively in use
	}
	if res.ExitCode != 1 {
		slog.Warn("fuser probe inconclusive; skipping stale lock removal", "path", path, "exit", res.ExitCode)
		return nil
	}

	// rm is best-effort. A cancelled context makes runPriv fail closed with
	// ctx.Err(); distinguish that from a genuine removal failure and propagate
	// the cancellation promptly (matching the fuser-probe and bestEffortStep
	// handling), rather than logging a spurious warning and relying on a later
	// caller check.
	if _, err := runPriv(ctx, r, true, nil, "rm", "-f", path); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		slog.Warn("failed to remove stale lock", "path", path, "error", err)
	}
	return nil
}
