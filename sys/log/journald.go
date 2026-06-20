package log

import (
	"context"
	"strconv"
	"strings"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// journaldSource reads the systemd journal via journalctl.
type journaldSource struct {
	r exec.Runner
}

// Query builds and runs a journalctl invocation. Every dynamic value is an
// option-ARGUMENT (`-u <unit>`, `--grep <pat>`, …), never a positional operand,
// so none can be reinterpreted as a flag. Filters are validated first.
func (s *journaldSource) Query(ctx context.Context, q Query) ([]string, error) {
	if err := validateQuery(q); err != nil {
		return nil, err
	}
	args := []string{"--no-pager", "-n", strconv.Itoa(cappedLines(q.Lines))}
	if q.Unit != "" {
		args = append(args, "-u", q.Unit)
	}
	if q.Since != "" {
		args = append(args, "--since", q.Since)
	}
	if q.Until != "" {
		args = append(args, "--until", q.Until)
	}
	if q.Priority != "" {
		args = append(args, "-p", q.Priority)
	}
	if q.Grep != "" {
		args = append(args, "--grep", q.Grep)
	}
	res, err := s.r.Run(ctx, exec.Command{Name: "journalctl", Args: args, Escalate: true})
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		// journalctl --grep exits 1 (grep-like) when it matches NOTHING — an empty
		// result, not a failure. A genuine fault writes a diagnostic to stderr,
		// whereas a no-match leaves stderr empty (only "-- No entries --" on
		// stdout). Treat that exact shape — a Grep query, exit 1, empty stderr — as
		// the empty result so a caller can tell "no logs matched" from "journalctl
		// broke"; anything else (other exit codes, any stderr, no Grep) stays an
		// error, fail-closed.
		if q.Grep != "" && res.ExitCode == 1 && strings.TrimSpace(res.Stderr) == "" {
			return []string{}, nil
		}
		return nil, &exec.CommandError{Name: "journalctl", ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return dropStatusMarkers(splitLines(res.Stdout)), nil
}

// dropStatusMarkers removes journalctl's status MARKERS — the "-- ... --"
// wrapped lines it prints on stdout that are NOT log entries: "-- No entries --"
// (a non-matching query), "-- Boot <id> --" / "-- Reboot --" boot delimiters,
// and "-- Logs begin at ..., end at ... --". In the default short output every
// real entry begins with a timestamp, so a line wrapped in "-- ... --" is always
// a marker. Returns a non-nil empty slice when every line was a marker, matching
// splitLines' contract.
func dropStatusMarkers(lines []string) []string {
	kept := make([]string, 0, len(lines))
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "-- ") && strings.HasSuffix(t, " --") {
			continue
		}
		kept = append(kept, ln)
	}
	return kept
}

// splitLines splits captured stdout into lines, dropping a single trailing
// empty line (the final newline). Returns a non-nil empty slice for empty input.
func splitLines(out string) []string {
	out = strings.TrimSuffix(out, "\n")
	if out == "" {
		return []string{}
	}
	return strings.Split(out, "\n")
}
