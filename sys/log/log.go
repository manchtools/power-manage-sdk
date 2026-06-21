// Package log reads system logs through an injected exec.Runner.
//
//	r, _ := exec.NewRunner(exec.Direct) // the system journal needs root
//	s, err := log.New(log.Journald, r)
//	if err != nil { ... }
//	lines, _ := s.Query(ctx, log.Query{Unit: "sshd.service", Lines: 200, Priority: "warning"})
//
// Two backends are implemented: Journald (journalctl) and Syslog
// (/var/log/{syslog,messages}). The query filters and their hardening — line
// cap, priority allow-list, grep length cap, and the structural ReDoS guard —
// are shared and applied before any tool runs (validate-then-execute). Reads
// escalate through the Runner (system logs are root-readable). Detect lists the
// backends usable on the host.
//
// The signing/authorization of a remote log request is the consumer's concern
// (the agent verifies a CA signature before calling this); this package is the
// reader.
package log

import (
	"context"
	"errors"
	"fmt"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// Backend selects the log source. The zero value is invalid; only implemented
// backends exist.
type Backend int

const (
	// Journald reads the systemd journal via journalctl.
	Journald Backend = iota + 1
	// Syslog reads the classic /var/log/{syslog,messages} files.
	Syslog
)

// String renders the backend as its canonical name.
func (b Backend) String() string {
	switch b {
	case Journald:
		return "journald"
	case Syslog:
		return "syslog"
	default:
		return fmt.Sprintf("Backend(%d)", int(b))
	}
}

// ErrUnknownBackend is returned by New for the zero value or any unimplemented
// backend.
var ErrUnknownBackend = errors.New("log: unknown backend")

// ErrInvalidQuery is returned when a Query field is unsafe or out of range (bad
// priority, an over-long or catastrophic-backtracking grep pattern).
var ErrInvalidQuery = errors.New("log: invalid query")

// Query selects which log entries to return.
type Query struct {
	// Unit filters by systemd unit (Journald only; ignored by Syslog).
	Unit string
	// Since and Until bound the time range (journalctl's --since/--until forms;
	// Journald only).
	Since, Until string
	// Priority filters by syslog priority (Journald only). Allowed values:
	// 0-7 or emerg/alert/crit/err/warning/notice/info/debug.
	Priority string
	// Grep keeps only entries matching this pattern. Capped at 256 chars and
	// refused if it is a catastrophic-backtracking shape (ReDoS guard).
	Grep string
	// Kernel restricts the result to kernel-ring messages (journalctl -k;
	// Journald only, ignored by Syslog).
	Kernel bool
	// Lines caps the number of entries returned. <=0 means 100; values above
	// 10000 are clamped to 10000.
	Lines int
}

const (
	defaultLines = 100
	maxLines     = 10000
	maxGrepLen   = 256
)

// Source is the log read surface.
type Source interface {
	// Query returns the matching log lines, most-recent-last, after validating
	// the query (validate-then-execute: an invalid query runs no command).
	Query(ctx context.Context, q Query) ([]string, error)
}

// New returns a Source for the named backend, driven by runner. Pure: validates
// the backend; does not probe (use Detect). Nil runner and unknown backend are
// rejected.
func New(b Backend, runner exec.Runner) (Source, error) {
	if runner == nil {
		return nil, fmt.Errorf("log: %w", exec.ErrRunnerRequired)
	}
	switch b {
	case Journald:
		return &journaldSource{r: runner}, nil
	case Syslog:
		return &syslogSource{r: runner}, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownBackend, int(b))
	}
}

// cappedLines applies the default/clamp policy to Query.Lines.
func cappedLines(n int) int {
	if n <= 0 {
		return defaultLines
	}
	if n > maxLines {
		return maxLines
	}
	return n
}

// validPriorities is the journald priority allow-list (names + numeric levels).
var validPriorities = map[string]bool{
	"0": true, "1": true, "2": true, "3": true, "4": true, "5": true, "6": true, "7": true,
	"emerg": true, "alert": true, "crit": true, "err": true,
	"warning": true, "notice": true, "info": true, "debug": true,
}

// validateQuery enforces the shared, security-relevant query constraints before
// any backend builds a command. Priority is validated whenever set (even for
// Syslog, which ignores it) so a bad value is never silently accepted.
func validateQuery(q Query) error {
	if q.Priority != "" && !validPriorities[q.Priority] {
		return fmt.Errorf("%w: priority %q is not a valid syslog priority", ErrInvalidQuery, q.Priority)
	}
	if q.Grep != "" {
		if len(q.Grep) > maxGrepLen {
			return fmt.Errorf("%w: grep pattern too long (%d > %d)", ErrInvalidQuery, len(q.Grep), maxGrepLen)
		}
		if reason := isPathologicalGrepPattern(q.Grep); reason != "" {
			return fmt.Errorf("%w: grep pattern rejected: %s", ErrInvalidQuery, reason)
		}
	}
	return nil
}

// runEscalated runs a read that needs root (system logs) and returns stdout. A
// non-zero exit becomes a *CommandError unless it is in okExitCodes (some tools,
// e.g. grep, use a non-zero exit to mean "no matches", which is not a failure).
func runEscalated(ctx context.Context, r exec.Runner, okExitCodes map[int]bool, name string, args ...string) (string, error) {
	res, err := r.Run(ctx, exec.Command{Name: name, Args: args, Escalate: true})
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 && !okExitCodes[res.ExitCode] {
		return "", &exec.CommandError{Name: name, ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return res.Stdout, nil
}
