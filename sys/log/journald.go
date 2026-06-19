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
	out, err := runEscalated(ctx, s.r, nil, "journalctl", args...)
	if err != nil {
		return nil, err
	}
	return splitLines(out), nil
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
