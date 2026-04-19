// Package reboot provides system reboot detection and scheduling utilities.
package reboot

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// Injectable seams for testing. Production code uses the defaults.
var (
	statFunc     = os.Stat
	lookPathFunc = exec.LookPath
	runCmdFunc   = func(name string, args ...string) error {
		return exec.Command(name, args...).Run()
	}
)

// IsRequired checks if the system requires a reboot after updates.
//
// Detection methods:
//   - Debian/Ubuntu: checks /var/run/reboot-required (created by update-notifier)
//   - Fedora/RHEL: runs needs-restarting -r (exit 1 = reboot needed)
//
// Returns false on unsupported systems or if detection fails. Unexpected
// errors (permission denied on stat, exec failure on needs-restarting) are
// logged via slog.Debug rather than returned, since callers treat this as a
// best-effort hint.
func IsRequired() bool {
	// Debian/Ubuntu: file-based detection. A successful stat means the
	// file exists and reboot is required. ErrNotExist is the expected
	// "no reboot needed" path; any other error is unexpected and logged.
	if _, err := statFunc("/var/run/reboot-required"); err == nil {
		return true
	} else if !errors.Is(err, os.ErrNotExist) {
		slog.Debug("stat /var/run/reboot-required failed", "error", err)
	}

	// Fedora/RHEL: needs-restarting (from dnf-utils/yum-utils).
	// Look up the binary; if absent, we silently fall through (no detection
	// available on this system).
	path, err := lookPathFunc("needs-restarting")
	if err != nil {
		return false
	}

	runErr := runCmdFunc(path, "-r")
	if runErr == nil {
		return false // exit 0 = no reboot needed
	}
	// needs-restarting exits 1 when a reboot IS needed.
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		return exitErr.ExitCode() == 1
	}
	// Couldn't even run needs-restarting (e.g. *exec.Error wrapping ENOENT
	// or a permission error). Log and report no reboot rather than guess.
	slog.Debug("needs-restarting -r failed to run", "error", runErr)
	return false
}

// Schedule schedules a system reboot via shutdown -r.
//
// Parameters:
//   - ctx: context for the sudo command
//   - delay: shutdown delay (e.g. "+1" for 1 minute, "+5" for 5 minutes, "now" for immediate)
//   - message: broadcast message shown to logged-in users (omitted when empty)
//
// An empty delay defaults to "+1" since shutdown(8) requires a time argument.
func Schedule(ctx context.Context, delay, message string) error {
	if delay == "" {
		delay = "+1"
	}
	args := []string{"-r", delay}
	if message != "" {
		args = append(args, message)
	}
	if _, err := sysexec.Privileged(ctx, "shutdown", args...); err != nil {
		return fmt.Errorf("schedule reboot: %w", err)
	}
	return nil
}

// Cancel cancels a pending scheduled reboot.
func Cancel(ctx context.Context) error {
	if _, err := sysexec.Privileged(ctx, "shutdown", "-c"); err != nil {
		return fmt.Errorf("cancel reboot: %w", err)
	}
	return nil
}
