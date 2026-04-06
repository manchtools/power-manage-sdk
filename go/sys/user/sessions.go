package user

import (
	"context"
	"errors"
	"fmt"
	"os/exec"

	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// KillSessions terminates all sessions for a user.
// Uses loginctl terminate-user if available, falls back to pkill -KILL -u.
func KillSessions(ctx context.Context, username string) error {
	if !IsValidName(username) {
		return fmt.Errorf("invalid username: %s", username)
	}

	// Try loginctl first (systemd).
	var loginctlErr error
	if _, err := exec.LookPath("loginctl"); err == nil {
		_, loginctlErr = sysexec.Sudo(ctx, "loginctl", "terminate-user", username)
		if loginctlErr == nil {
			return nil
		}
		// Fall through to pkill on failure.
	}

	// Fallback: pkill -KILL -u.
	// pkill exits 1 if no processes matched, which is fine.
	result, err := sysexec.Sudo(ctx, "pkill", "-KILL", "-u", username)
	if err != nil {
		// Exit code 1 means no processes found — not an error.
		if result != nil && result.ExitCode == 1 {
			return nil
		}
		// Combine both errors if loginctl also failed.
		if loginctlErr != nil {
			return fmt.Errorf("kill sessions for %s: %w", username, errors.Join(loginctlErr, err))
		}
		return fmt.Errorf("kill sessions for %s: %w", username, err)
	}
	return nil
}
