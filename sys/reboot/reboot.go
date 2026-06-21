// Package reboot provides system reboot detection and scheduling through an
// injected exec.Runner.
//
// Build a Manager with a Runner and call its methods. Scheduling escalates
// through the Runner; the reboot-required probe runs unprivileged.
//
//	r, _ := exec.NewRunner(exec.Sudo)
//	rb, _ := reboot.New(r)
//	if need, _ := rb.IsRequired(ctx); need {
//		_ = rb.Schedule(ctx, reboot.ScheduleOptions{Delay: "+5", Message: "patching"})
//	}
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
	"strconv"
	"strings"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// rebootRequiredPath is the Debian/Ubuntu reboot-required marker (created by
// update-notifier). A var so tests can redirect it.
var rebootRequiredPath = "/var/run/reboot-required"

// statFunc seams the marker-file check for tests.
var statFunc = os.Stat

// Manager detects and schedules system reboots.
type Manager interface {
	// IsRequired reports whether the system needs a reboot after updates. An
	// unsupported host (no marker file and no needs-restarting binary) yields
	// (false, nil) — absence of detection is not a failure. A genuinely
	// unexpected condition IS surfaced as an error: a non-ENOENT stat error on
	// the marker, or a needs-restarting run failure that isn't "tool absent"
	// (e.g. a cancelled/timed-out context).
	IsRequired(ctx context.Context) (bool, error)
	// Schedule schedules a reboot via shutdown -r using opts. An empty
	// opts.Delay defaults to "+1"; a non-empty opts.Message is broadcast to
	// logged-in users.
	Schedule(ctx context.Context, opts ScheduleOptions) error
	// Cancel cancels a pending scheduled reboot (shutdown -c).
	Cancel(ctx context.Context) error
}

// ScheduleOptions configures a scheduled reboot. Fields are named so callers
// can't transpose the (delay, message) pair, and so future knobs (e.g. a
// kexec fast-reboot) can be added without breaking the signature.
type ScheduleOptions struct {
	// Delay is the reboot grace time, constrained to a positive relative minute
	// offset "+N" (N >= minRebootGraceMinutes). This is deliberately narrower
	// than shutdown(8)'s full TIME grammar: "now", "+0", a negative offset, and
	// absolute clock times (e.g. "23:00") are rejected so a reboot always leaves
	// a grace window for logged-in users. Empty defaults to "+1" (one minute).
	Delay string
	// Message, when non-empty, is the wall message broadcast to logged-in
	// users by shutdown.
	Message string
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
// through the Runner. A binary that isn't installed is treated as "not required"
// (no detection available, not a failure); a genuine run failure is surfaced.
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
		if errors.Is(err, exec.ErrBackendUnavailable) {
			// needs-restarting isn't installed → no detection available on this
			// host. That's expected on non-RHEL systems, not a failure.
			slog.Debug("needs-restarting not available, skipping reboot probe", "error", err)
			return false, nil
		}
		// Any other failure (e.g. context cancelled/timed out) is genuinely
		// unexpected: we were asked and couldn't answer. Surface it rather than
		// silently reporting "no reboot needed".
		return false, fmt.Errorf("run needs-restarting: %w", err)
	}
	// Exit 1 = a reboot is needed; 0 = not; anything else = indeterminate.
	return res.ExitCode == 1, nil
}

// minRebootGraceMinutes is the smallest accepted grace window. A reboot must
// give logged-in users at least one minute of warning — "now"/"+0" would reboot
// instantly, which is a denial-of-service against active sessions and exactly
// what this Manager exists to schedule *around*, not trigger.
const minRebootGraceMinutes = 1

// Schedule schedules a system reboot via shutdown -r (escalated).
func (rb *rebooter) Schedule(ctx context.Context, opts ScheduleOptions) error {
	delay := opts.Delay
	if delay == "" {
		delay = "+1"
	}
	if err := validateDelay(delay); err != nil {
		return err
	}
	if err := validateMessage(opts.Message); err != nil {
		return err
	}
	args := []string{"-r", delay}
	if opts.Message != "" {
		args = append(args, opts.Message)
	}
	return rb.shutdown(ctx, "schedule reboot", args...)
}

// validateDelay constrains the shutdown TIME spec to a positive relative
// minute offset ("+N", N >= minRebootGraceMinutes). This is deliberately
// narrower than shutdown(8)'s full grammar: "now", "+0", a negative offset, an
// absolute clock time, or any control-character-bearing value is rejected
// BEFORE the escalated shutdown runs. The reboot must always leave a grace
// window for logged-in users, and a control character (e.g. "+5\nnow") must
// never reach the privileged command line.
func validateDelay(delay string) error {
	digits, ok := strings.CutPrefix(delay, "+")
	if !ok || digits == "" {
		return fmt.Errorf("invalid reboot delay %q: must be a relative offset of the form \"+N\" minutes", delay)
	}
	// strconv.Atoi accepts a leading sign, so an all-digits check is required
	// to reject smuggled forms like "++5" or "+-1" before parsing.
	for _, r := range digits {
		if r < '0' || r > '9' {
			return fmt.Errorf("invalid reboot delay %q: must be a relative offset of the form \"+N\" minutes", delay)
		}
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return fmt.Errorf("invalid reboot delay %q: must be a relative offset of the form \"+N\" minutes", delay)
	}
	if n < minRebootGraceMinutes {
		return fmt.Errorf("invalid reboot delay %q: grace window must be at least %d minute(s)", delay, minRebootGraceMinutes)
	}
	return nil
}

// validateMessage rejects a wall message carrying a control character before it
// reaches the escalated shutdown command. shutdown broadcasts the message
// verbatim to every logged-in user's terminal, so a newline or ESC sequence
// could inject terminal-control codes into other users' sessions. A space is
// fine; only control characters and DEL are refused.
func validateMessage(message string) error {
	for _, r := range message {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("invalid reboot message: must not contain control characters")
		}
	}
	return nil
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
