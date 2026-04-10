// Package reboot provides system reboot detection and scheduling utilities.
package reboot

import (
	"context"
	"errors"
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
// Returns false on unsupported systems or if detection fails.
func IsRequired() bool {
	// Debian/Ubuntu: file-based detection
	if _, err := statFunc("/var/run/reboot-required"); err == nil {
		return true
	}

	// Fedora/RHEL: needs-restarting (from dnf-utils/yum-utils)
	if path, err := lookPathFunc("needs-restarting"); err == nil {
		if err := runCmdFunc(path, "-r"); err != nil {
			// needs-restarting exits 1 when reboot is needed
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return exitErr.ExitCode() == 1
			}
		}
		return false // exit 0 = no reboot needed
	}

	return false
}

// Schedule schedules a system reboot via shutdown -r.
//
// Parameters:
//   - ctx: context for the sudo command
//   - delay: shutdown delay (e.g. "+1" for 1 minute, "+5" for 5 minutes, "now" for immediate)
//   - message: broadcast message shown to logged-in users
func Schedule(ctx context.Context, delay, message string) error {
	_, err := sysexec.Sudo(ctx, "shutdown", "-r", delay, message)
	return err
}

// Cancel cancels a pending scheduled reboot.
func Cancel(ctx context.Context) error {
	_, err := sysexec.Sudo(ctx, "shutdown", "-c")
	return err
}
