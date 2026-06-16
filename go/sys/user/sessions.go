package user

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// KillSessions terminates all of a user's sessions. It prefers systemd's
// loginctl terminate-user and falls back to pkill -KILL -u. A pkill exit of 1
// (no matching processes) is treated as success.
func (u *shadowUtils) KillSessions(ctx context.Context, name string) error {
	if err := validateUsername(name); err != nil {
		return err
	}
	// loginctl first; the Runner resolves and runs it, reporting "not found" if
	// systemd-logind is absent, in which case we fall through to pkill.
	if res, err := u.r.Run(ctx, exec.Command{Name: "loginctl", Args: []string{"terminate-user", name}, Escalate: true}); err == nil && res.ExitCode == 0 {
		return nil
	}
	res, err := u.r.Run(ctx, exec.Command{Name: "pkill", Args: []string{"-KILL", "-u", name}, Escalate: true})
	if err != nil {
		return fmt.Errorf("kill sessions for %s: %w", name, err)
	}
	// pkill exits 1 when no processes matched — not an error here.
	if res.ExitCode != 0 && res.ExitCode != 1 {
		return &exec.CommandError{Name: "pkill", ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return nil
}
