package pkg

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
)

// HasUpdates checks whether package updates are available.
// When securityOnly is true, only security updates are considered (where supported).

// HasUpdates for Apt: runs `apt -s upgrade` (simulated) and checks for "Inst " lines.
func (a *Apt) HasUpdates(ctx context.Context, securityOnly bool) bool {
	cmd := a.getAptCmd()
	args := []string{"-s", "upgrade"}
	// NOTE: securityOnly filtering for apt is not yet implemented correctly.
	// Approaches like overriding Dir::Etc::SourceList do not reliably filter
	// to security-only updates. A proper implementation would need to parse
	// the origin/label of each upgradable package.
	_ = securityOnly

	c := exec.CommandContext(ctx, cmd, args...)
	c.Env = append(os.Environ(), "LANG=C", "LC_ALL=C")
	out, err := c.Output()
	if err != nil {
		return false
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "Inst ") {
			return true
		}
	}
	return false
}

// HasUpdates for Dnf: runs `dnf check-update`. Exit code 100 means updates available.
func (d *Dnf) HasUpdates(ctx context.Context, securityOnly bool) bool {
	args := []string{"check-update", "-q"}
	if securityOnly {
		args = append(args, "--security")
	}

	c := exec.CommandContext(ctx, "dnf", args...)
	c.Env = append(os.Environ(), "LANG=C", "LC_ALL=C")
	err := c.Run()
	if err != nil {
		if c.ProcessState != nil && c.ProcessState.ExitCode() == 100 {
			return true
		}
	}
	return false
}

// HasUpdates for Pacman: runs `pacman -Qu`. Exit code 0 with output means updates available.
func (p *Pacman) HasUpdates(ctx context.Context, _ bool) bool {
	out, err := exec.CommandContext(ctx, "pacman", "-Qu").Output()
	if err != nil {
		return false
	}
	return len(strings.TrimSpace(string(out))) > 0
}

// HasUpdates for Zypper: runs `zypper list-updates`. Exit code 100 means updates available.
func (z *Zypper) HasUpdates(ctx context.Context, securityOnly bool) bool {
	args := []string{"--non-interactive", "list-updates"}
	if securityOnly {
		args = append(args, "--type", "patch", "--category", "security")
	}

	c := exec.CommandContext(ctx, "zypper", args...)
	c.Env = append(os.Environ(), "LANG=C", "LC_ALL=C")
	var stdout bytes.Buffer
	c.Stdout = &stdout
	err := c.Run()
	if err != nil {
		// zypper returns 100 when updates are available
		if c.ProcessState != nil && c.ProcessState.ExitCode() == 100 {
			return true
		}
		return false
	}
	// Exit 0: parse stdout for update table rows (contain "v |" or "i |").
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "v |") || strings.Contains(line, "i |") {
			return true
		}
	}
	return false
}

// HasUpdates for Flatpak: checks if any updates are available via remote-ls --updates.
func (f *Flatpak) HasUpdates(ctx context.Context, _ bool) bool {
	args := []string{"remote-ls", "--updates", "--columns=application"}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}

	out, err := exec.CommandContext(ctx, "flatpak", args...).Output()
	if err != nil {
		return false
	}
	return len(strings.TrimSpace(string(out))) > 0
}
