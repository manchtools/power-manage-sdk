// Package maintenance hosts the canonical parser, validator, union
// resolver and evaluator for pm.v1.MaintenanceWindow. The package is
// shared so server (handler validation, union computation across the
// device's groups) and agent (per-tick gate in the scheduler) agree
// bit-for-bit on what counts as an allowed dispatch time.
//
// Window semantics:
//
//   - Empty schedule = "always allowed". The feature is opt-in and a
//     group with no window contributes nothing to the device-side
//     gate.
//   - Each entry is (weekdays, allow-range). The allow-range uses
//     24-hour HH:MM-HH:MM. start > end means the range crosses
//     midnight and continues into the next weekday.
//   - Multiple entries combine as OR within a single window: any
//     matching entry allows the moment.
//   - Union across windows applies the same OR. The device is allowed
//     when *any* of its reaching groups allows the moment. If any
//     reaching group is empty, the union collapses to "always
//     allowed" — empty already means unconstrained, so adding it to
//     the union cannot tighten the result.
//
// All evaluation runs against time.Time.Local at the agent. The
// server never computes IsAllowed — the device is the only authority
// on its own wall-clock.
package maintenance

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// Allowed weekday tokens. Order matches time.Weekday so we can index
// into it directly when matching entries.
var weekdayTokens = [7]string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

// ErrInvalidEntry is returned by Validate when the schedule contains
// a malformed entry. Callers wrap this in a Connect-RPC
// CodeInvalidArgument so the web UI can surface a precise message.
var ErrInvalidEntry = errors.New("invalid maintenance window entry")

// Validate reports whether the window is syntactically well-formed.
// A nil window or an empty schedule is valid (= always allowed).
func Validate(w *pmv1.MaintenanceWindow) error {
	if w == nil {
		return nil
	}
	for i, e := range w.GetSchedule() {
		if err := validateEntry(e); err != nil {
			return fmt.Errorf("%w: entry %d: %v", ErrInvalidEntry, i, err)
		}
	}
	return nil
}

// IsAllowed reports whether the moment t falls inside the window. A
// nil window or empty schedule allows every moment. The check uses
// t.Weekday() and t.Hour()/t.Minute() — callers that want
// device-local semantics must pass an already-Local'd time.
func IsAllowed(w *pmv1.MaintenanceWindow, t time.Time) bool {
	if w == nil || len(w.GetSchedule()) == 0 {
		return true
	}
	for _, e := range w.GetSchedule() {
		if entryAllows(e, t) {
			return true
		}
	}
	return false
}

// Union combines windows the most-permissive way: if any input is
// empty (nil or zero schedule), the result is empty (= always
// allowed). Otherwise the result is the concatenation of every
// input's entries — IsAllowed already ORs entries within a single
// window, so concatenation gives OR across windows for free.
//
// The returned window aliases input entry pointers; callers that
// mutate the result must clone first. Server-side resolvers don't
// mutate, so the alias is safe in practice.
func Union(windows ...*pmv1.MaintenanceWindow) *pmv1.MaintenanceWindow {
	for _, w := range windows {
		if w == nil || len(w.GetSchedule()) == 0 {
			return &pmv1.MaintenanceWindow{}
		}
	}
	out := &pmv1.MaintenanceWindow{}
	for _, w := range windows {
		out.Schedule = append(out.Schedule, w.GetSchedule()...)
	}
	return out
}

// validateEntry checks a single MaintenanceWindowEntry for shape.
// Returns the underlying parse error so Validate can wrap it with
// the entry index for a useful operator-facing message.
func validateEntry(e *pmv1.MaintenanceWindowEntry) error {
	if e == nil {
		return errors.New("nil entry")
	}
	if len(e.Days) == 0 {
		return errors.New("days must list at least one weekday")
	}
	seen := make(map[string]struct{}, len(e.Days))
	for _, d := range e.Days {
		if !isWeekdayToken(d) {
			return fmt.Errorf("day %q must be one of mon|tue|wed|thu|fri|sat|sun", d)
		}
		if _, dup := seen[d]; dup {
			return fmt.Errorf("day %q listed twice", d)
		}
		seen[d] = struct{}{}
	}
	if _, _, err := parseRange(e.Allow); err != nil {
		return err
	}
	return nil
}

// entryAllows checks t against one (days, range) entry. Crosses
// midnight when the range's start is after its end: in that case
// "match before midnight today" OR "match after midnight on the
// previous-day-listed-in-days".
func entryAllows(e *pmv1.MaintenanceWindowEntry, t time.Time) bool {
	if e == nil {
		return false
	}
	startMin, endMin, err := parseRange(e.Allow)
	if err != nil {
		// A malformed entry that slipped past Validate should never
		// allow dispatch — fail-closed beats fail-open here because
		// the operator's intent was a constraint and an unparseable
		// constraint is never "allow everything".
		return false
	}
	tMin := t.Hour()*60 + t.Minute()
	today := weekdayTokens[t.Weekday()]
	// Same-day branch — including the crossing-midnight case where
	// the active piece on `today` runs from startMin to end-of-day.
	if entryListsDay(e, today) {
		if startMin <= endMin {
			if tMin >= startMin && tMin < endMin {
				return true
			}
		} else {
			// crosses midnight: today the range is startMin .. 23:59
			if tMin >= startMin {
				return true
			}
		}
	}
	// Crossing-midnight tail — the early-morning hours belong to the
	// previous day's range. Check whether `yesterday` is listed and
	// the current minute is before that range's end.
	if startMin > endMin {
		yesterday := weekdayTokens[(int(t.Weekday())+6)%7]
		if entryListsDay(e, yesterday) && tMin < endMin {
			return true
		}
	}
	return false
}

func entryListsDay(e *pmv1.MaintenanceWindowEntry, day string) bool {
	for _, d := range e.Days {
		if d == day {
			return true
		}
	}
	return false
}

// parseRange parses "HH:MM-HH:MM" into start/end minute-of-day. Both
// must be 24h, and start may equal end (degenerate empty range that
// allows nothing). start > end means the range crosses midnight.
func parseRange(s string) (int, int, error) {
	if len(s) != 11 || s[5] != '-' {
		return 0, 0, fmt.Errorf("allow %q must be HH:MM-HH:MM", s)
	}
	start, err := parseClock(s[:5])
	if err != nil {
		return 0, 0, fmt.Errorf("allow start: %w", err)
	}
	end, err := parseClock(s[6:])
	if err != nil {
		return 0, 0, fmt.Errorf("allow end: %w", err)
	}
	if start == end {
		return 0, 0, fmt.Errorf("allow %q is a zero-length range", s)
	}
	return start, end, nil
}

func parseClock(s string) (int, error) {
	if len(s) != 5 || s[2] != ':' {
		return 0, fmt.Errorf("clock %q must be HH:MM", s)
	}
	// strconv.Atoi accepts a leading sign ("+9", "-1"), so a signed hour or
	// minute ("+9:00") would slip through the range check below. Require both
	// fields to be exactly two ASCII digits before parsing — the wire format is
	// fixed-width zero-padded HH:MM, never a signed integer.
	if !isTwoDigits(s[:2]) {
		return 0, fmt.Errorf("hour %q must be two digits", s[:2])
	}
	if !isTwoDigits(s[3:]) {
		return 0, fmt.Errorf("minute %q must be two digits", s[3:])
	}
	h, err := strconv.Atoi(s[:2])
	if err != nil || h < 0 || h > 23 {
		return 0, fmt.Errorf("hour %q out of range 00-23", s[:2])
	}
	m, err := strconv.Atoi(s[3:])
	if err != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("minute %q out of range 00-59", s[3:])
	}
	return h*60 + m, nil
}

// isTwoDigits reports whether s is exactly two ASCII digits (0-9). Used to
// reject signed/non-numeric clock fields that strconv.Atoi would otherwise
// accept (a leading '+' or '-').
func isTwoDigits(s string) bool {
	if len(s) != 2 {
		return false
	}
	return s[0] >= '0' && s[0] <= '9' && s[1] >= '0' && s[1] <= '9'
}

// isWeekdayToken accepts only the canonical lowercase tokens the
// projector and entryListsDay agree on. ToLower'ing here would
// validate "MON" but then `entryListsDay` would silently never match
// it at runtime — fail-fast at validation time keeps the two sites
// honest. Callers that want case-insensitive input must canonicalize
// before calling Validate.
func isWeekdayToken(d string) bool {
	if len(d) != 3 {
		return false
	}
	for _, t := range weekdayTokens {
		if d == t {
			return true
		}
	}
	return false
}
