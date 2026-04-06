package pkg

import (
	"bytes"
	"os/exec"
	"strings"
)

// InstalledCount returns the number of installed packages.

// InstalledCount for Apt: counts lines from `dpkg-query -f ".\n" -W`.
func (a *Apt) InstalledCount() int {
	out, err := exec.CommandContext(a.ctx, "dpkg-query", "-f", ".\n", "-W").Output()
	if err != nil {
		return 0
	}
	return countNonEmptyLines(out)
}

// InstalledCount for Dnf: counts lines from `rpm -qa --qf ".\n"`.
func (d *Dnf) InstalledCount() int {
	out, err := exec.CommandContext(d.ctx, "rpm", "-qa", "--qf", ".\n").Output()
	if err != nil {
		return 0
	}
	return countNonEmptyLines(out)
}

// InstalledCount for Pacman: counts lines from `pacman -Qq`.
func (p *Pacman) InstalledCount() int {
	out, err := exec.CommandContext(p.ctx, "pacman", "-Qq").Output()
	if err != nil {
		return 0
	}
	return countNonEmptyLines(out)
}

// InstalledCount for Zypper: counts lines from `rpm -qa --qf ".\n"` (rpm-based).
func (z *Zypper) InstalledCount() int {
	out, err := exec.CommandContext(z.ctx, "rpm", "-qa", "--qf", ".\n").Output()
	if err != nil {
		return 0
	}
	return countNonEmptyLines(out)
}

// InstalledCount for Flatpak: counts installed applications.
func (f *Flatpak) InstalledCount() int {
	args := []string{"list", "--columns=application"}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}

	out, err := exec.CommandContext(f.ctx, "flatpak", args...).Output()
	if err != nil {
		return 0
	}
	return countNonEmptyLines(out)
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
