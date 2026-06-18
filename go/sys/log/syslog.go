package log

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// syslogPaths are the classic plain-text log files, in preference order.
var syslogPaths = []string{"/var/log/syslog", "/var/log/messages"}

// statFile is a seam (os.Stat) so backend-selection is testable; existence only
// needs a traversable /var/log, not read access to the file.
var statFile = os.Stat

// syslogSource reads the classic /var/log/{syslog,messages} files. Unlike
// Journald it has no unit/priority concept — those Query fields are validated
// (so a bad value still errors) but ignored. Grep is applied as a Go RE2 regex
// over the most-recent Lines entries (limit-then-filter), so it filters within
// the tail window rather than the whole file.
type syslogSource struct {
	r exec.Runner
}

// Query tails the active syslog file and applies the grep filter.
func (s *syslogSource) Query(ctx context.Context, q Query) ([]string, error) {
	if err := validateQuery(q); err != nil {
		return nil, err
	}
	// Compile the grep pattern BEFORE any privileged read, so a malformed
	// pattern fails closed without triggering an escalated tail. The structural
	// guard already ran in validateQuery; RE2 is linear-time, so this is DoS-safe.
	var re *regexp.Regexp
	if q.Grep != "" {
		var err error
		if re, err = regexp.Compile(q.Grep); err != nil {
			return nil, fmt.Errorf("%w: grep pattern: %v", ErrInvalidQuery, err)
		}
	}
	path, err := syslogPath()
	if err != nil {
		return nil, err
	}
	// Bounded read: tail the last N lines (`--` ends options so a path can't be
	// read as a flag — though our paths are constants).
	out, err := runEscalated(ctx, s.r, nil, "tail", "-n", strconv.Itoa(cappedLines(q.Lines)), "--", path)
	if err != nil {
		return nil, err
	}
	lines := splitLines(out)
	if re == nil {
		return lines, nil
	}
	matched := make([]string, 0, len(lines))
	for _, l := range lines {
		if re.MatchString(l) {
			matched = append(matched, l)
		}
	}
	return matched, nil
}

// syslogPath returns the first existing syslog file.
func syslogPath() (string, error) {
	for _, p := range syslogPaths {
		if _, err := statFile(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("log: no syslog file found (looked in %v)", syslogPaths)
}
