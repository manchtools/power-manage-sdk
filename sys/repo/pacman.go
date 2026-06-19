package repo

import (
	"context"
	"fmt"
	"strings"

	"github.com/manchtools/power-manage-sdk/sys/fs"
)

// pacmanConf is the pacman configuration file edited in place.
const pacmanConf = "/etc/pacman.conf"

// removePacmanSection removes a [name] section from pacman.conf content. A
// section extends from its [name] header to the next [section] header (exclusive)
// or end of file. Done in Go (no sed) so there is no shell/regex injection risk.
func removePacmanSection(content, name string) string {
	sectionHeader := "[" + name + "]"
	lines := strings.Split(content, "\n")
	var result []string
	inSection := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == sectionHeader {
			inSection = true
			continue
		}
		if inSection && strings.HasPrefix(trimmed, "[") {
			inSection = false
		}
		if !inSection {
			result = append(result, line)
		}
	}
	return strings.Join(result, "\n")
}

// applyPacman appends (or replaces) the repository's [name] section in
// /etc/pacman.conf and synchronizes the package database. The conf is rewritten
// atomically; the db sync is non-fatal (surfaced as a warning).
//
// A missing /etc/pacman.conf is treated as empty content (fs.Manager.ReadFile
// reports absence as empty); on a real pacman host the file always exists.
func (m *manager) applyPacman(ctx context.Context, name string, c *PacmanConfig) (Outcome, error) {
	var log strings.Builder
	confBytes, err := m.fsm.ReadFile(ctx, pacmanConf)
	if err != nil {
		return Outcome{}, fmt.Errorf("read pacman.conf: %w", err)
	}
	confStr := string(confBytes)

	var section strings.Builder
	fmt.Fprintf(&section, "\n[%s]\n", name)
	if c.SigLevel != "" {
		fmt.Fprintf(&section, "SigLevel = %s\n", c.SigLevel)
	}
	fmt.Fprintf(&section, "Server = %s\n", c.Server)

	newConf := confStr
	if strings.Contains(confStr, "["+name+"]") {
		newConf = removePacmanSection(confStr, name)
	}
	newConf += section.String()

	// Idempotency: skip the write + db sync when the conf already matches.
	if newConf == confStr {
		fmt.Fprintf(&log, "repository %s already configured\n", name)
		return out(log.String(), false), nil
	}

	if err := m.fsm.WriteFile(ctx, pacmanConf, []byte(newConf), fs.WriteOptions{Mode: 0o644}); err != nil {
		return Outcome{}, fmt.Errorf("write pacman.conf: %w", err)
	}
	fmt.Fprintf(&log, "configured repository: %s\n", name)

	res, serr := m.runPriv(ctx, "pacman", "-Sy", "--noconfirm")
	if res.Stdout != "" {
		log.WriteString(res.Stdout)
	}
	if serr != nil {
		fmt.Fprintf(&log, "warning: failed to sync repository database: %v\n", serr)
	}
	return out(log.String(), true), nil
}

// removePacman removes the repository's section from /etc/pacman.conf. Removing
// an absent section is an idempotent no-op.
func (m *manager) removePacman(ctx context.Context, name string) (Outcome, error) {
	var log strings.Builder
	confBytes, err := m.fsm.ReadFile(ctx, pacmanConf)
	if err != nil {
		return Outcome{}, fmt.Errorf("read pacman.conf: %w", err)
	}
	confStr := string(confBytes)
	if !strings.Contains(confStr, "["+name+"]") {
		fmt.Fprintf(&log, "repository %s not found, nothing to remove\n", name)
		return out(log.String(), false), nil
	}
	newConf := removePacmanSection(confStr, name)
	if err := m.fsm.WriteFile(ctx, pacmanConf, []byte(newConf), fs.WriteOptions{Mode: 0o644}); err != nil {
		return Outcome{}, fmt.Errorf("write pacman.conf: %w", err)
	}
	fmt.Fprintf(&log, "removed repository: %s\n", name)
	return out(log.String(), true), nil
}
