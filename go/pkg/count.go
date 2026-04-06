package pkg

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// InstalledCount returns the number of installed packages.

// InstalledCount for Apt: counts lines from `dpkg-query -f ".\n" -W`.
func (a *Apt) InstalledCount() (int, error) {
	out, err := exec.CommandContext(a.ctx, "dpkg-query", "-f", ".\n", "-W").Output()
	if err != nil {
		return 0, fmt.Errorf("dpkg-query: %w", err)
	}
	return countNonEmptyLines(out), nil
}

// InstalledCount for Dnf: counts lines from `rpm -qa --qf ".\n"`.
func (d *Dnf) InstalledCount() (int, error) {
	out, err := exec.CommandContext(d.ctx, "rpm", "-qa", "--qf", ".\n").Output()
	if err != nil {
		return 0, fmt.Errorf("rpm -qa: %w", err)
	}
	return countNonEmptyLines(out), nil
}

// InstalledCount for Pacman: counts lines from `pacman -Qq`.
func (p *Pacman) InstalledCount() (int, error) {
	out, err := exec.CommandContext(p.ctx, "pacman", "-Qq").Output()
	if err != nil {
		return 0, fmt.Errorf("pacman -Qq: %w", err)
	}
	return countNonEmptyLines(out), nil
}

// InstalledCount for Zypper: counts lines from `rpm -qa --qf ".\n"` (rpm-based).
func (z *Zypper) InstalledCount() (int, error) {
	out, err := exec.CommandContext(z.ctx, "rpm", "-qa", "--qf", ".\n").Output()
	if err != nil {
		return 0, fmt.Errorf("rpm -qa: %w", err)
	}
	return countNonEmptyLines(out), nil
}

// InstalledCount for Flatpak: counts installed applications.
func (f *Flatpak) InstalledCount() (int, error) {
	args := []string{"list", "--columns=application"}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}

	out, err := exec.CommandContext(f.ctx, "flatpak", args...).Output()
	if err != nil {
		return 0, fmt.Errorf("flatpak list: %w", err)
	}
	return countNonEmptyLines(out), nil
}

// countNonEmptyLines counts non-empty lines in output.
func countNonEmptyLines(data []byte) int {
	count := 0
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(strings.TrimSpace(string(line))) > 0 {
			count++
		}
	}
	return count
}
