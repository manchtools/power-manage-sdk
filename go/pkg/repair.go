package pkg

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

// Repair attempts to fix common package manager issues.

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
		removeStaleLock(lf)
	}

	// dpkg --configure -a
	if result, err := a.run("dpkg", "--configure", "-a"); err != nil {
		slog.Warn("dpkg --configure -a failed", "error", err, "stderr", result.Stderr)
	}

	// apt --fix-broken install -y
	if result, err := a.FixBroken(); err != nil {
		slog.Warn("apt --fix-broken install failed", "error", err, "stderr", result.Stderr)
	}

	// apt update
	if result, err := a.run("apt", "update"); err != nil {
		return fmt.Errorf("apt update failed: %s", result.Stderr)
	}

	return nil
}

// Repair for Dnf: runs dnf history redo last, dnf remove --duplicates, rpm --verifydb.
func (d *Dnf) Repair(ctx context.Context) error {
	// dnf -y history redo last
	if result, err := d.run("history", "redo", "last", "-y"); err != nil {
		slog.Warn("dnf history redo last failed", "error", err, "stderr", result.Stderr)
	}

	// dnf -y remove --duplicates
	if result, err := d.run("remove", "--duplicates", "-y"); err != nil {
		slog.Warn("dnf remove --duplicates failed", "error", err, "stderr", result.Stderr)
	}

	// rpm --verifydb
	c := exec.CommandContext(ctx, "rpm", "--verifydb")
	if out, err := c.CombinedOutput(); err != nil {
		slog.Warn("rpm --verifydb failed", "error", err, "output", string(out))
	}

	return nil
}

// Repair for Pacman: removes stale db.lck, runs pacman -Syy --noconfirm.
func (p *Pacman) Repair(ctx context.Context) error {
	// Remove stale lock file
	removeStaleLock("/var/lib/pacman/db.lck")

	// pacman -Syy --noconfirm (force refresh all databases)
	if result, err := p.run("-Syy", "--noconfirm"); err != nil {
		return fmt.Errorf("pacman -Syy failed: %s", result.Stderr)
	}

	return nil
}

// Repair for Zypper: removes stale zypp.pid, runs zypper refresh.
func (z *Zypper) Repair(ctx context.Context) error {
	// Remove stale lock file
	removeStaleLock("/run/zypp.pid")

	// zypper --non-interactive refresh
	if result, err := z.run("--non-interactive", "refresh"); err != nil {
		return fmt.Errorf("zypper refresh failed: %s", result.Stderr)
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
	if result, err := f.run(args...); err != nil {
		return fmt.Errorf("flatpak repair failed: %s", result.Stderr)
	}

	return nil
}

// removeStaleLock removes a lock file if no package manager process is running.
// Rather than trying to detect lock types (apt/dpkg use fcntl, pacman uses
// O_CREAT|O_EXCL), we simply check whether the owning process is still alive.
func removeStaleLock(path string) {
	if _, err := os.Stat(path); err != nil {
		return // file doesn't exist
	}

	// Check if any package manager process is running.
	// If so, the lock is probably legitimate — don't touch it.
	for _, proc := range []string{"apt", "apt-get", "dpkg", "pacman", "zypper", "dnf"} {
		if err := exec.Command("pgrep", "-x", proc).Run(); err == nil {
			return // process is running, lock may be active
		}
	}

	// No package manager process running — lock is stale. Remove it.
	if err := exec.Command("sudo", "-n", "rm", "-f", path).Run(); err != nil {
		slog.Warn("failed to remove stale lock", "path", path, "error", err)
	}
}

// dpkgRun is a helper for running dpkg commands through the apt run() method.
// The Apt.run() method handles sudo and apt-get fallback, but for dpkg we
// need the command name passed through directly.
func (a *Apt) dpkgRun(args ...string) (*CommandResult, error) {
	_ = strings.Join(args, " ") // unused, just to keep strings imported
	return a.run("dpkg", args...)
}
