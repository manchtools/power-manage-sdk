package pkg

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"strings"
)

// HasUpdates checks whether package updates are available.
// When securityOnly is true, only security updates are considered (where supported).

// HasUpdates for Apt: runs `apt -s upgrade` (simulated) and checks for "Inst " lines.
func (a *Apt) HasUpdates(ctx context.Context, securityOnly bool) bool {
	cmd := a.getAptCmd()
	args := []string{"-s", "upgrade"}
	if securityOnly {
		args = append(args, "-o", "Dir::Etc::SourceList=/etc/apt/sources.list",
			"-o", "Dir::Etc::SourceParts=/dev/null")
	}

	out, err := exec.CommandContext(ctx, cmd, args...).Output()
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
	c.Env = append([]string{"LANG=C", "LC_ALL=C"})
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
	c.Env = append([]string{"LANG=C", "LC_ALL=C"})
	err := c.Run()
	if err != nil {
		// zypper returns 100 when updates are available
		if c.ProcessState != nil && c.ProcessState.ExitCode() == 100 {
			return true
		}
		return false
	}
	// Exit 0 with table content also means updates — check output
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
