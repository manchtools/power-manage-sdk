// Package reboot provides system reboot detection and scheduling through an
// injected exec.Runner.
//
// Build a Manager with a Runner and call its methods. Scheduling escalates
// through the Runner; the reboot-required probe runs unprivileged.
//
//	r, _ := exec.NewRunner(exec.Sudo)
//	rb, _ := reboot.New(r)
//	if need, _ := rb.IsRequired(ctx); need { _ = rb.Schedule(ctx, "+5", "patching") }
//
// Status: SDK-resident, single-consumer today (the agent's reboot-required +
// scheduled-reboot pipeline). Sits in the SDK because the planned server-side
// maintenance-window simulator needs the same "next reboot window" math. F027 in
// TECH_DEBT_AUDIT.md.
package reboot

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// rebootRequiredPath is the Debian/Ubuntu reboot-required marker (created by
// update-notifier). A var so tests can redirect it.
var rebootRequiredPath = "/var/run/reboot-required"

// statFunc seams the marker-file check for tests.
var statFunc = os.Stat

// Manager detects and schedules system reboots.
type Manager interface {
	// IsRequired reports whether the system needs a reboot after updates. It is
	// best-effort: an unsupported host or a detection failure yields (false, nil);
	// the returned error is reserved for a genuinely unexpected condition the
	// caller may want to surface (e.g. a non-ENOENT stat error on the marker).
	IsRequired(ctx context.Context) (bool, error)
	// Schedule schedules a reboot via shutdown -r. An empty delay defaults to
	// "+1"; a non-empty message is broadcast to logged-in users.
	Schedule(ctx context.Context, delay, message string) error
	// Cancel cancels a pending scheduled reboot (shutdown -c).
	Cancel(ctx context.Context) error
}

// New returns a Manager driven by runner. A nil runner is rejected.
func New(runner exec.Runner) (Manager, error) {
	if runner == nil {
		return nil, fmt.Errorf("reboot: %w", exec.ErrRunnerRequired)
	}
	return &rebooter{r: runner}, nil
}

type rebooter struct {
	r exec.Runner
}

// IsRequired checks the Debian/Ubuntu marker file, then falls back to
// `needs-restarting -r` (Fedora/RHEL; exit 1 = reboot needed) run unprivileged
// through the Runner. A binary that isn't installed, or any execution failure, is
// treated as "not required" — this is a hint, not an authority.
func (rb *rebooter) IsRequired(ctx context.Context) (bool, error) {
	if _, err := statFunc(rebootRequiredPath); err == nil {
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		// A stat error other than "not found" (e.g. permission) is the one
		// genuinely unexpected condition worth surfacing.
		return false, fmt.Errorf("stat %s: %w", rebootRequiredPath, err)
	}

	res, err := rb.r.Run(ctx, exec.Command{Name: "needs-restarting", Args: []string{"-r"}})
	if err != nil {
		// needs-restarting absent or unrunnable → no detection available here.
		slog.Debug("needs-restarting -r could not run", "error", err)
		return false, nil
	}
	// Exit 1 = a reboot is needed; 0 = not; anything else = indeterminate.
	return res.ExitCode == 1, nil
}

// Schedule schedules a system reboot via shutdown -r (escalated).
func (rb *rebooter) Schedule(ctx context.Context, delay, message string) error {
	if delay == "" {
		delay = "+1"
	}
	args := []string{"-r", delay}
	if message != "" {
		args = append(args, message)
	}
	return rb.shutdown(ctx, "schedule reboot", args...)
}

// Cancel cancels a pending scheduled reboot (escalated).
func (rb *rebooter) Cancel(ctx context.Context) error {
	return rb.shutdown(ctx, "cancel reboot", "-c")
}

func (rb *rebooter) shutdown(ctx context.Context, op string, args ...string) error {
	res, err := rb.r.Run(ctx, exec.Command{Name: "shutdown", Args: args, Escalate: true})
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s: %w", op, &exec.CommandError{Name: "shutdown", ExitCode: res.ExitCode, Stderr: res.Stderr})
	}
	return nil
}
