package pkg

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// statFile is the os.Stat seam used by removeStaleLock so the lock-file probe
// can be exercised hermetically in tests.
var statFile = os.Stat

// readFile is the os.ReadFile seam used by removeStaleZyppLock so the PID-file
// read can be exercised hermetically in tests.
var readFile = os.ReadFile

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
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
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

// removeStaleZyppLock removes a zypp PID file (/run/zypp.pid) only when the PID
// it names is dead. Unlike the flock-style lockfiles removeStaleLock handles
// (apt/dpkg/pacman hold the descriptor open for the lock's lifetime, so fuser
// sees a live holder), zypp.pid is a PID FILE: zypper writes its PID and closes
// the descriptor, so NO process holds it open and fuser would always report "no
// holder" — wrongly green-lighting removal while zypper still runs. Probe the
// named PID's liveness directly instead.
//
// The liveness probe (kill -0) runs ESCALATED so a non-zero exit reliably means
// ESRCH (the process is gone): probed unprivileged, a root-owned zypper process
// would return EPERM (non-zero) and be misread as dead. Non-numeric content —
// including a leading-dash value kill would treat as a flag/process group — is
// never spliced into kill and never triggers removal. An empty file has no live
// holder and is removed. Like removeStaleLock, a cancelled context wins over the
// best-effort warning paths, and a failed probe/read leaves the lock in place
// (never delete on an inconclusive result).
func removeStaleZyppLock(ctx context.Context, r pmexec.Runner, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := statFile(path); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if os.IsNotExist(err) {
			return nil // file doesn't exist — nothing to remove
		}
		slog.Warn("failed to stat zypp PID file; leaving it in place", "path", path, "error", err)
		return nil
	}

	content, err := readFile(path)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		// A read failure is not proof of absence; leave the lock untouched.
		slog.Warn("cannot read zypp PID file; leaving it in place", "path", path, "error", err)
		return nil
	}

	pid := strings.TrimSpace(string(content))
	if pid != "" && !isAllDigits(pid) {
		// Non-numeric content (garbage, or a leading-dash value kill would
		// interpret as a flag/process group): never probe with it, never remove.
		slog.Warn("zypp PID file is non-numeric; leaving it in place", "path", path, "content", pid)
		return nil
	}

	if pid != "" {
		res, err := runPriv(ctx, r, true, nil, "kill", "-0", pid)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			slog.Warn("zypp PID liveness probe failed; leaving the lock in place", "path", path, "pid", pid, "error", err)
			return nil
		}
		if res.ExitCode == 0 {
			return nil // process is alive — keep the lock
		}
	}

	// Empty file or a dead PID: no live holder. Remove (escalated, best-effort).
	if _, err := runPriv(ctx, r, true, nil, "rm", "-f", path); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		slog.Warn("failed to remove stale zypp PID file", "path", path, "error", err)
	}
	return nil
}

// isAllDigits reports whether s is non-empty and every rune is an ASCII digit.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// verifyOrRebuildRPMDB runs `rpm --verifydb` (an unprivileged read) and, ONLY
// when it reports corruption (a non-zero exit — a genuine rpmdb verdict, as
// opposed to a runner failure where rpm could not run at all), escalates to a
// full `rpm --rebuilddb`. Shared by the rpm-based managers (dnf, zypper). A
// runner failure (binary missing, context cancelled) yields no corruption
// verdict, so no rebuild. The rebuild's result/error is returned for the
// caller's best-effort handling.
func verifyOrRebuildRPMDB(ctx context.Context, r pmexec.Runner) (pmexec.Result, error) {
	res, err := runRead(ctx, r, "rpm", "--verifydb")
	if err != nil {
		return res, err
	}
	if res.ExitCode == 0 {
		return res, nil // database is clean — no rebuild
	}
	rebuilt, rerr := runPriv(ctx, r, true, nil, "rpm", "--rebuilddb")
	if rerr != nil {
		return rebuilt, rerr
	}
	return rebuilt, asCommandError("rpm", rebuilt)
}
