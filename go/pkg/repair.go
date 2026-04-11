package pkg

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

// Repair attempts to fix common package manager issues.
//
// The ctx parameter is propagated through to the underlying subprocess
// invocations, so deadlines and cancellations from the caller are honored.
// Repair methods short-circuit and return ctx.Err() the moment ctx is
// cancelled, so a cancelled caller does not cause additional sudo
// subprocesses to be spawned.

// repairErr returns ctx.Err() if the context has been cancelled, otherwise
// it wraps err with the given message and the subprocess stderr. The
// returned error is detectable via errors.Is(err, context.Canceled) /
// errors.Is(err, context.DeadlineExceeded).
func repairErr(ctx context.Context, msg, stderr string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return fmt.Errorf("%s: %s: %w", msg, stderr, err)
}

// Repair for Apt: removes stale lock files, runs dpkg --configure -a,
// apt --fix-broken install -y, and apt update.
func (a *Apt) Repair(ctx context.Context) error {
	// Remove stale lock files
	lockFiles := []string{
		"/var/lib/dpkg/lock",
		"/var/lib/dpkg/lock-frontend",
		"/var/lib/apt/lists/lock",
		"/var/cache/apt/archives/lock",
	}
	for _, lf := range lockFiles {
		if err := removeStaleLock(ctx, lf); err != nil {
			return err
		}
	}

	// dpkg --configure -a
	if err := ctx.Err(); err != nil {
		return err
	}
	if result, err := a.run(ctx, "dpkg", "--configure", "-a"); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		slog.Warn("dpkg --configure -a failed", "error", err, "stderr", result.Stderr)
	}

	// apt --fix-broken install -y
	if err := ctx.Err(); err != nil {
		return err
	}
	if result, err := a.fixBroken(ctx); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		slog.Warn("apt --fix-broken install failed", "error", err, "stderr", result.Stderr)
	}

	// apt update
	if err := ctx.Err(); err != nil {
		return err
	}
	if result, err := a.run(ctx, "apt", "update"); err != nil {
		return repairErr(ctx, "apt update failed", result.Stderr, err)
	}

	return nil
}

// Repair for Dnf: runs dnf history redo last, dnf remove --duplicates, rpm --verifydb.
func (d *Dnf) Repair(ctx context.Context) error {
	// dnf -y history redo last
	if err := ctx.Err(); err != nil {
		return err
	}
	if result, err := d.run(ctx, "history", "redo", "last", "-y"); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		slog.Warn("dnf history redo last failed", "error", err, "stderr", result.Stderr)
	}

	// dnf -y remove --duplicates
	if err := ctx.Err(); err != nil {
		return err
	}
	if result, err := d.run(ctx, "remove", "--duplicates", "-y"); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		slog.Warn("dnf remove --duplicates failed", "error", err, "stderr", result.Stderr)
	}

	// rpm --verifydb (read-only, no sudo needed)
	if err := ctx.Err(); err != nil {
		return err
	}
	c := exec.CommandContext(ctx, "rpm", "--verifydb")
	c.Env = append(os.Environ(), "LANG=C", "LC_ALL=C")
	if out, err := c.CombinedOutput(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		slog.Warn("rpm --verifydb failed", "error", err, "output", string(out))
	}

	return nil
}

// Repair for Pacman: removes stale db.lck, runs pacman -Syy --noconfirm.
func (p *Pacman) Repair(ctx context.Context) error {
	// Remove stale lock file
	if err := removeStaleLock(ctx, "/var/lib/pacman/db.lck"); err != nil {
		return err
	}

	// pacman -Syy --noconfirm (force refresh all databases)
	if err := ctx.Err(); err != nil {
		return err
	}
	if result, err := p.run(ctx, "-Syy", "--noconfirm"); err != nil {
		return repairErr(ctx, "pacman -Syy failed", result.Stderr, err)
	}

	return nil
}

// Repair for Zypper: removes stale zypp.pid, runs zypper refresh.
func (z *Zypper) Repair(ctx context.Context) error {
	// Remove stale lock file
	if err := removeStaleLock(ctx, "/run/zypp.pid"); err != nil {
		return err
	}

	// zypper --non-interactive refresh
	if err := ctx.Err(); err != nil {
		return err
	}
	if result, err := z.run(ctx, "--non-interactive", "refresh"); err != nil {
		return repairErr(ctx, "zypper refresh failed", result.Stderr, err)
	}

	return nil
}

// Repair for Flatpak: runs flatpak repair --system.
func (f *Flatpak) Repair(ctx context.Context) error {
	args := []string{"repair"}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if result, err := f.run(ctx, args...); err != nil {
		return repairErr(ctx, "flatpak repair failed", result.Stderr, err)
	}

	return nil
}

// removeStaleLock removes a lock file if the owning package manager process
// is not running. Uses fuser to check if any process has the file open,
// which is more reliable than pgrep for detecting active locks.
//
// Returns ctx.Err() if the context is cancelled at any point so callers
// can short-circuit cleanly. A failure to actually remove the file is
// logged via slog.Warn (best-effort) and does not return an error, but
// a context cancellation always wins over the warning path.
func removeStaleLock(ctx context.Context, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		return nil // file doesn't exist
	}

	// Check if any process has this specific file open.
	// fuser exits 0 if processes are using the file, 1 if not.
	if err := exec.CommandContext(ctx, "fuser", path).Run(); err == nil {
		return nil // file is actively in use
	} else if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}

	// No process has the file open — lock is stale. Remove it.
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := exec.CommandContext(ctx, "sudo", "-n", "rm", "-f", path).Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		slog.Warn("failed to remove stale lock", "path", path, "error", err)
	}
	return nil
}
