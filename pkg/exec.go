package pkg

import (
	"bytes"
	"context"
	"io"
	"strings"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// runRead executes an unprivileged read-side query (Info / Search / List /
// Show / version + status probes) through the injected Runner. The Runner forces
// the C locale on every command, so the output parser always sees the stable
// English form regardless of the host locale. A non-zero exit is reported in
// Result.ExitCode (NOT as an error) — read callers branch on specific codes (e.g.
// dnf check-update's 100, dpkg -s's 1) — so the returned error is non-nil only
// when the command could not be executed at all.
func runRead(ctx context.Context, r pmexec.Runner, name string, args ...string) (pmexec.Result, error) {
	return r.Run(ctx, pmexec.Command{Name: name, Args: args})
}

// probe runs an unprivileged read whose non-zero exit is a benign domain signal
// — "not installed" / "not pinned" / "not in repo" / "no such subcommand" —
// rather than a failure, while a runner error (binary missing, blocked env,
// context cancellation) propagates. It returns (stdout, ok, err): ok is true
// only on a clean (exit 0) run. This is the seam that keeps tolerant lookups
// from masking cancellations and executor failures as a benign miss.
func probe(ctx context.Context, r pmexec.Runner, name string, args ...string) (string, bool, error) {
	res, err := runRead(ctx, r, name, args...)
	if err != nil {
		return "", false, err
	}
	return res.Stdout, res.ExitCode == 0, nil
}

// runPriv executes a privileged write-side command (Install / Remove / Update /
// …) through the Runner. escalate is true for every native-manager mutation and
// for system-scope flatpak; it is false for user-scope flatpak. env carries any
// backend-specific variables (e.g. apt's DEBIAN_FRONTEND=noninteractive) on top
// of the forced C locale. Like runRead, a non-zero exit is in Result.ExitCode,
// not the error; callers convert it via asCommandError when a non-zero exit
// means failure (most do; dnf check-update does not).
func runPriv(ctx context.Context, r pmexec.Runner, escalate bool, env []string, name string, args ...string) (pmexec.Result, error) {
	return r.Run(ctx, pmexec.Command{
		Name:     name,
		Args:     args,
		Env:      env,
		Escalate: escalate,
	})
}

// readOut runs an unprivileged read whose non-zero exit is itself a failure
// (List/Show/Version/… — a garbled or error exit means the parse can't proceed),
// returning stdout on a clean exit and an *exec.CommandError otherwise. Reads
// that branch on a specific exit code (dpkg -s's 1, dnf check-update's 100,
// search's "no matches" codes) call runRead directly and inspect Result.ExitCode.
func readOut(ctx context.Context, r pmexec.Runner, name string, args ...string) (string, error) {
	res, err := runRead(ctx, r, name, args...)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", &pmexec.CommandError{Name: name, ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return res.Stdout, nil
}

// runPrivStdin is the stdin-bearing companion of runPriv (pacman.conf rewrite
// via tee). An empty stdin sends no input.
func runPrivStdin(ctx context.Context, r pmexec.Runner, escalate bool, env []string, stdin, name string, args ...string) (pmexec.Result, error) {
	var in io.Reader
	if stdin != "" {
		in = strings.NewReader(stdin)
	}
	return r.Run(ctx, pmexec.Command{
		Name:     name,
		Args:     args,
		Env:      env,
		Stdin:    in,
		Escalate: escalate,
	})
}

// asCommandError turns a completed command's Result into a typed error when its
// exit code is non-zero, mirroring the old "non-zero exit ⇒ failure" contract
// the mutating methods rely on. A clean exit returns nil. The exit code and
// stderr are preserved on *exec.CommandError so callers can branch via
// errors.As.
func asCommandError(name string, res pmexec.Result) error {
	if res.ExitCode == 0 {
		return nil
	}
	return &pmexec.CommandError{Name: name, ExitCode: res.ExitCode, Stderr: res.Stderr}
}

// countNonEmptyLines counts non-blank lines in command output.
func countNonEmptyLines(data string) int {
	count := 0
	for _, line := range bytes.Split([]byte(data), []byte("\n")) {
		if len(strings.TrimSpace(string(line))) > 0 {
			count++
		}
	}
	return count
}
