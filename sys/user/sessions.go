package user

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/manchtools/power-manage-sdk/sys/exec"
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
	if res, err := u.exec(ctx, exec.Command{Name: "loginctl", Args: []string{"terminate-user", name}, Escalate: true}); err == nil && res.ExitCode == 0 {
		return nil
	}
	res, err := u.exec(ctx, exec.Command{Name: "pkill", Args: []string{"-KILL", "-u", name}, Escalate: true})
	if err != nil {
		return fmt.Errorf("kill sessions for %s: %w", name, err)
	}
	// pkill exits 1 when no processes matched — not an error here.
	if res.ExitCode != 0 && res.ExitCode != 1 {
		return &exec.CommandError{Name: "pkill", ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return nil
}

// lastTimeLayout is the timestamp `last -F` emits under the C locale the Runner
// forces — Go's reference time in the `Mon Jan _2 15:04:05 2006` shape (the day-
// of-month is space-padded for single digits). No zone token: `last` prints in
// the host's local time without a zone name, so the timestamp is parsed in the
// local location.
const lastTimeLayout = "Mon Jan _2 15:04:05 2006"

// LastLogin returns the most recent login time for the named user. It shells
// `last -1 -F <name>` (an unprivileged read; the Runner forces the C locale so
// the timestamp is always the stable English form) and parses the single record.
//
// A user that has never logged in has no record: `last` then prints only its
// "wtmp begins …" footer (or nothing), and LastLogin returns the zero time.Time
// with a nil error — never logging in is a legitimate state, not a failure. A
// genuine execution failure (the `last` binary missing, a cancelled context)
// propagates so it is never mistaken for "never logged in".
func (u *shadowUtils) LastLogin(ctx context.Context, name string) (time.Time, error) {
	if err := validateUsername(name); err != nil {
		return time.Time{}, err
	}
	res, err := u.exec(ctx, exec.Command{Name: "last", Args: []string{"-1", "-F", name}})
	if err != nil {
		return time.Time{}, fmt.Errorf("last login for %s: %w", name, err)
	}
	if res.ExitCode != 0 {
		return time.Time{}, &exec.CommandError{Name: "last", ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return parseLastLogin(res.Stdout), nil
}

// parseLastLogin extracts the login instant from `last -1 -F` output. A record
// line has the form
//
//	<user> <tty> [<host>] Mon Jun 16 14:23:01 2025 - <logout/duration trailer>
//
// The login timestamp is the five whitespace-separated fields ending in the year
// — found by scanning each line for a `Mon Jan _2 15:04:05 2006` match. Lines
// that carry no such timestamp ("wtmp begins …", blanks) are skipped, so a
// user with no record yields the zero time.
func parseLastLogin(out string) time.Time {
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "wtmp begins") {
			continue
		}
		if t, ok := extractLastTimestamp(line); ok {
			return t
		}
	}
	return time.Time{}
}

// extractLastTimestamp finds the 5-field `Mon Jan _2 15:04:05 2006` timestamp
// embedded in a `last` record line. The leading <user>/<tty>/<host> columns and
// the trailing logout/duration columns vary in count, so it slides a 5-field
// window across the line rather than assuming a fixed offset, and returns the
// FIRST parse that succeeds (the login time always precedes the logout time).
func extractLastTimestamp(line string) (time.Time, bool) {
	fields := strings.Fields(line)
	for i := 0; i+5 <= len(fields); i++ {
		candidate := strings.Join(fields[i:i+5], " ")
		if t, err := time.ParseInLocation(lastTimeLayout, candidate, time.Local); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
