package repo

import (
	"context"
	"fmt"
	"strings"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// applyZypper configures a zypper repository with `zypper addrepo` (preceded by a
// best-effort removerepo so a reconfigure replaces cleanly), then applies the
// description / enable / autorefresh modifiers, imports the GPG key, and
// refreshes. addrepo is command-based with no cheap idempotency probe, so a
// successful Apply reports Changed=true.
//
// The repository URL is https-validated and the name is alphanumeric-validated
// (validateZypper), so neither can be flag-shaped; the description is passed as
// `--name=<value>` (glued) so a leading '-' cannot be reparsed as an option.
func (m *manager) applyZypper(ctx context.Context, name string, c *ZypperConfig) (Outcome, error) {
	var log strings.Builder

	// Autorefresh is set atomically at add time via the --refresh flag, so a
	// repo created with Autorefresh=false is never left auto-refreshing (a
	// separate modifyrepo would have to actively *disable* it otherwise).
	args := []string{"--non-interactive", "addrepo"}
	if c.Autorefresh {
		args = append(args, "--refresh")
	}
	if !c.GPGCheck {
		args = append(args, "--no-gpgcheck")
	}
	if c.Type != "" {
		args = append(args, "--type", c.Type)
	}

	// Best-effort pre-removal so a reconfigure of an existing alias succeeds.
	if _, err := m.runPriv(ctx, "zypper", "--non-interactive", "removerepo", name); err != nil {
		fmt.Fprintf(&log, "note: pre-add removerepo failed (expected if the repo is absent): %v\n", err)
	}

	args = append(args, c.URL, name)
	res, err := m.runPriv(ctx, "zypper", args...)
	if res.Stdout != "" {
		log.WriteString(res.Stdout)
	}
	if err != nil {
		if res.Stderr != "" {
			log.WriteString(res.Stderr)
		}
		return Outcome{
			Result:  pmexec.Result{ExitCode: 1, Stdout: log.String(), Stderr: res.Stderr},
			Changed: false,
		}, fmt.Errorf("add repository: %w", err)
	}
	fmt.Fprintf(&log, "configured repository: %s\n", name)

	// Description / enable / autorefresh diverge from operator intent silently if
	// they fail, so they are fatal.
	if c.Description != "" {
		if _, err := m.runPriv(ctx, "zypper", "--non-interactive", "modifyrepo", "--name="+c.Description, name); err != nil {
			return Outcome{}, fmt.Errorf("set repo description: %w", err)
		}
	}
	if c.Enabled {
		if _, err := m.runPriv(ctx, "zypper", "--non-interactive", "modifyrepo", "--enable", name); err != nil {
			return Outcome{}, fmt.Errorf("enable repo: %w", err)
		}
	} else {
		if _, err := m.runPriv(ctx, "zypper", "--non-interactive", "modifyrepo", "--disable", name); err != nil {
			return Outcome{}, fmt.Errorf("disable repo: %w", err)
		}
	}
	// Key import + refresh are non-fatal (the repo is configured).
	if c.GPGKey != "" {
		m.runNonFatal(ctx, &log, "warning: failed to import GPG key", "rpm", pmexec.SeparatePositionals([]string{"--import"}, c.GPGKey)...)
	}
	m.runNonFatal(ctx, &log, "warning: failed to refresh repo", "zypper", "--non-interactive", "refresh", name)

	return out(log.String(), true), nil
}

// removeZypper removes a zypper repository by alias. zypper `removerepo` EXITS 0
// whether or not the alias existed — it reports an absent repo with a "not found"
// message on stderr rather than a non-zero exit. So idempotency is keyed off that
// message (a no-op → Changed=false), NOT the exit code; a genuine failure still
// exits non-zero and surfaces as an error. The Runner forces LC_ALL=C, so the
// English "not found" match is locale-stable.
func (m *manager) removeZypper(ctx context.Context, name string) (Outcome, error) {
	var log strings.Builder
	res, err := m.runPriv(ctx, "zypper", "--non-interactive", "removerepo", name)
	if err != nil {
		return Outcome{}, fmt.Errorf("remove repository: %w", err)
	}
	if strings.Contains(res.Stdout+res.Stderr, "not found") {
		fmt.Fprintf(&log, "repository %s not found, nothing to remove\n", name)
		return out(log.String(), false), nil
	}
	fmt.Fprintf(&log, "removed repository: %s\n", name)
	return out(log.String(), true), nil
}
