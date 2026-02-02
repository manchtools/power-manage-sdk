package pkg

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Pacman implements the Manager interface for Arch Linux-based systems.
type Pacman struct {
	ctx     context.Context
	useSudo bool
}

// NewPacman creates a new Pacman package manager.
// By default, sudo is enabled for privileged operations.
func NewPacman() *Pacman {
	return &Pacman{ctx: context.Background(), useSudo: true}
}

// NewPacmanWithContext creates a new Pacman package manager with context.
// By default, sudo is enabled for privileged operations.
func NewPacmanWithContext(ctx context.Context) *Pacman {
	return &Pacman{ctx: ctx, useSudo: true}
}

// WithSudo sets whether to use sudo for privileged operations.
func (p *Pacman) WithSudo(useSudo bool) *Pacman {
	p.useSudo = useSudo
	return p
}

// Info returns pacman version information.
func (p *Pacman) Info() (name, version string, err error) {
	out, err := exec.CommandContext(p.ctx, "pacman", "--version").Output()
	if err != nil {
		return "", "", err
	}
	// Output format: " Pacman v6.0.2 - ..."
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Pacman v") {
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.HasPrefix(part, "v") {
					return "pacman", strings.TrimPrefix(part, "v"), nil
				}
			}
		}
	}
	return "pacman", "", nil
}

// Install installs packages (latest version).
func (p *Pacman) Install(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	// -S: sync, --noconfirm: non-interactive, --needed: don't reinstall if up to date
	args := append([]string{"-S", "--noconfirm", "--needed"}, packages...)
	return p.run(args...)
}

// InstallVersion installs a package with specific version options.
// Note: Pacman doesn't natively support installing specific versions.
// This requires the package to be available in the repos or using downgrade tools.
func (p *Pacman) InstallVersion(name string, opts InstallOptions) (*CommandResult, error) {
	if opts.Version == "" {
		return p.Install(name)
	}

	// Try to install with version specification (name=version format)
	// This works if the version is available in the repos
	pkgSpec := fmt.Sprintf("%s=%s", name, opts.Version)

	args := []string{"-S", "--noconfirm"}
	if opts.AllowDowngrade {
		args = append(args, "--overwrite", "*")
	}
	args = append(args, pkgSpec)

	return p.run(args...)
}

// Remove removes packages.
func (p *Pacman) Remove(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	// -R: remove, --noconfirm: non-interactive
	args := append([]string{"-R", "--noconfirm"}, packages...)
	return p.run(args...)
}

// Purge removes packages including configuration files.
func (p *Pacman) Purge(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	// -Rns: remove with dependencies and config files
	args := append([]string{"-Rns", "--noconfirm"}, packages...)
	return p.run(args...)
}

// Update updates the package database.
func (p *Pacman) Update() (*CommandResult, error) {
	// -Sy: sync database
	return p.run("-Sy", "--noconfirm")
}

// Upgrade upgrades packages.
func (p *Pacman) Upgrade(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		// -Syu: sync, refresh, upgrade all
		return p.run("-Syu", "--noconfirm")
	}
	// Upgrade specific packages
	args := append([]string{"-S", "--noconfirm"}, packages...)
	return p.run(args...)
}

// Search searches for packages.
func (p *Pacman) Search(query string) ([]SearchResult, error) {
	out, err := exec.CommandContext(p.ctx, "pacman", "-Ss", query).Output()
	if err != nil {
		// pacman returns exit code 1 if no results
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, err
	}

	var results []SearchResult
	scanner := bufio.NewScanner(bytes.NewReader(out))
	var currentResult *SearchResult

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, " ") {
			// Description line (indented)
			if currentResult != nil {
				currentResult.Description = strings.TrimSpace(line)
				results = append(results, *currentResult)
				currentResult = nil
			}
		} else if line != "" {
			// Package line: repo/name version
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				nameParts := strings.Split(parts[0], "/")
				name := nameParts[len(nameParts)-1]
				repo := ""
				if len(nameParts) > 1 {
					repo = nameParts[0]
				}
				currentResult = &SearchResult{
					Name:       name,
					Version:    parts[1],
					Repository: repo,
				}
			}
		}
	}

	return results, nil
}

// List lists installed packages.
func (p *Pacman) List() ([]Package, error) {
	// -Q: query installed, -i: info format
	out, err := exec.CommandContext(p.ctx, "pacman", "-Q").Output()
	if err != nil {
		return nil, err
	}

	pinnedPkgs, _ := p.getPinnedSet()

	var packages []Package
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		pkg := Package{
			Name:    fields[0],
			Version: fields[1],
			Status:  "installed",
			Pinned:  pinnedPkgs[fields[0]],
		}
		packages = append(packages, pkg)
	}
	return packages, nil
}

// ListUpgradable lists packages with available upgrades.
func (p *Pacman) ListUpgradable() ([]PackageUpdate, error) {
	// -Qu: query upgradable
	out, err := exec.CommandContext(p.ctx, "pacman", "-Qu").Output()
	if err != nil {
		// Exit code 1 means no updates available
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, err
	}

	var updates []PackageUpdate
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		// Format: name current_version -> new_version
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[2] == "->" {
			updates = append(updates, PackageUpdate{
				Name:           fields[0],
				CurrentVersion: fields[1],
				NewVersion:     fields[3],
			})
		} else if len(fields) >= 2 {
			// Simple format: name new_version
			currentVersion, _ := p.GetInstalledVersion(fields[0])
			updates = append(updates, PackageUpdate{
				Name:           fields[0],
				CurrentVersion: currentVersion,
				NewVersion:     fields[1],
			})
		}
	}
	return updates, nil
}

// Show returns detailed information about a package.
func (p *Pacman) Show(name string) (*Package, error) {
	// Try installed first (-Qi), then sync database (-Si)
	var out []byte
	var err error
	var status string

	out, err = exec.CommandContext(p.ctx, "pacman", "-Qi", name).Output()
	if err == nil {
		status = "installed"
	} else {
		out, err = exec.CommandContext(p.ctx, "pacman", "-Si", name).Output()
		if err != nil {
			return nil, err
		}
		status = "available"
	}

	pkg := &Package{Name: name, Status: status}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Version") {
			pkg.Version = parsePacmanValue(line)
		} else if strings.HasPrefix(line, "Architecture") {
			pkg.Architecture = parsePacmanValue(line)
		} else if strings.HasPrefix(line, "Description") {
			pkg.Description = parsePacmanValue(line)
		} else if strings.HasPrefix(line, "Installed Size") {
			pkg.Size = parsePacmanSize(parsePacmanValue(line))
		} else if strings.HasPrefix(line, "Repository") {
			pkg.Repository = parsePacmanValue(line)
		}
	}

	pkg.Pinned, _ = p.IsPinned(name)

	return pkg, nil
}

// ListVersions lists all available versions of a package.
// Note: Pacman typically only keeps the latest version in repos.
func (p *Pacman) ListVersions(name string) (*VersionInfo, error) {
	info := &VersionInfo{Name: name}
	info.Installed, _ = p.GetInstalledVersion(name)

	// Get version from sync database
	out, err := exec.CommandContext(p.ctx, "pacman", "-Si", name).Output()
	if err != nil {
		return info, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Version") {
			version := parsePacmanValue(line)
			repo := ""
			// Try to get repo from package info
			for scanner.Scan() {
				l := scanner.Text()
				if strings.HasPrefix(l, "Repository") {
					repo = parsePacmanValue(l)
					break
				}
			}
			info.Versions = append(info.Versions, AvailableVersion{
				Version:    version,
				Repository: repo,
			})
			break
		}
	}

	return info, nil
}

// IsInstalled checks if a package is installed.
func (p *Pacman) IsInstalled(name string) (bool, error) {
	err := exec.CommandContext(p.ctx, "pacman", "-Q", name).Run()
	return err == nil, nil
}

// GetInstalledVersion returns the installed version of a package.
func (p *Pacman) GetInstalledVersion(name string) (string, error) {
	out, err := exec.CommandContext(p.ctx, "pacman", "-Q", name).Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	if len(fields) >= 2 {
		return fields[1], nil
	}
	return "", nil
}

// Pin prevents a package from being upgraded using IgnorePkg in pacman.conf.
// Note: This modifies /etc/pacman.conf which requires root privileges.
func (p *Pacman) Pin(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}

	// Read current pacman.conf
	confContent, err := exec.CommandContext(p.ctx, "cat", "/etc/pacman.conf").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to read pacman.conf: %w", err)
	}

	// Get currently ignored packages
	ignoredPkgs := p.getIgnoredPackages(string(confContent))

	// Add new packages to ignore list
	for _, pkg := range packages {
		if !contains(ignoredPkgs, pkg) {
			ignoredPkgs = append(ignoredPkgs, pkg)
		}
	}

	// Update pacman.conf
	return p.updateIgnorePkg(string(confContent), ignoredPkgs)
}

// Unpin allows a package to be upgraded again by removing from IgnorePkg.
func (p *Pacman) Unpin(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}

	// Read current pacman.conf
	confContent, err := exec.CommandContext(p.ctx, "cat", "/etc/pacman.conf").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to read pacman.conf: %w", err)
	}

	// Get currently ignored packages
	ignoredPkgs := p.getIgnoredPackages(string(confContent))

	// Remove packages from ignore list
	var newIgnored []string
	for _, pkg := range ignoredPkgs {
		if !contains(packages, pkg) {
			newIgnored = append(newIgnored, pkg)
		}
	}

	// Update pacman.conf
	return p.updateIgnorePkg(string(confContent), newIgnored)
}

// ListPinned lists all pinned (IgnorePkg) packages.
func (p *Pacman) ListPinned() ([]Package, error) {
	confContent, err := exec.CommandContext(p.ctx, "cat", "/etc/pacman.conf").Output()
	if err != nil {
		return nil, err
	}

	ignoredPkgs := p.getIgnoredPackages(string(confContent))

	var packages []Package
	for _, name := range ignoredPkgs {
		version, _ := p.GetInstalledVersion(name)
		packages = append(packages, Package{
			Name:    name,
			Version: version,
			Status:  "installed",
			Pinned:  true,
		})
	}
	return packages, nil
}

// IsPinned checks if a package is pinned (in IgnorePkg).
func (p *Pacman) IsPinned(name string) (bool, error) {
	confContent, err := exec.CommandContext(p.ctx, "cat", "/etc/pacman.conf").Output()
	if err != nil {
		return false, err
	}
	ignoredPkgs := p.getIgnoredPackages(string(confContent))
	return contains(ignoredPkgs, name), nil
}

func (p *Pacman) getPinnedSet() (map[string]bool, error) {
	confContent, err := exec.CommandContext(p.ctx, "cat", "/etc/pacman.conf").Output()
	if err != nil {
		return nil, err
	}

	pinned := make(map[string]bool)
	for _, pkg := range p.getIgnoredPackages(string(confContent)) {
		pinned[pkg] = true
	}
	return pinned, nil
}

func (p *Pacman) getIgnoredPackages(confContent string) []string {
	var ignored []string
	scanner := bufio.NewScanner(strings.NewReader(confContent))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "IgnorePkg") {
			// Format: IgnorePkg = pkg1 pkg2 pkg3
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				pkgs := strings.Fields(strings.TrimSpace(parts[1]))
				ignored = append(ignored, pkgs...)
			}
		}
	}
	return ignored
}

func (p *Pacman) updateIgnorePkg(confContent string, ignoredPkgs []string) (*CommandResult, error) {
	var newConf strings.Builder
	foundIgnorePkg := false
	scanner := bufio.NewScanner(strings.NewReader(confContent))

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "IgnorePkg") {
			if !foundIgnorePkg {
				foundIgnorePkg = true
				if len(ignoredPkgs) > 0 {
					newConf.WriteString(fmt.Sprintf("IgnorePkg = %s\n", strings.Join(ignoredPkgs, " ")))
				}
				// Skip the old line
				continue
			}
		}
		newConf.WriteString(line + "\n")
	}

	// If IgnorePkg wasn't found and we have packages to ignore, add it
	if !foundIgnorePkg && len(ignoredPkgs) > 0 {
		// Insert after [options] section
		content := newConf.String()
		optionsIdx := strings.Index(content, "[options]")
		if optionsIdx != -1 {
			// Find next newline after [options]
			nextNewline := strings.Index(content[optionsIdx:], "\n")
			if nextNewline != -1 {
				insertPos := optionsIdx + nextNewline + 1
				content = content[:insertPos] + fmt.Sprintf("IgnorePkg = %s\n", strings.Join(ignoredPkgs, " ")) + content[insertPos:]
			}
		}
		newConf.Reset()
		newConf.WriteString(content)
	}

	// Write the new config using sudo tee
	return p.runWithStdin("tee", "/etc/pacman.conf", newConf.String())
}

func (p *Pacman) run(args ...string) (*CommandResult, error) {
	start := time.Now()

	var c *exec.Cmd
	if p.useSudo {
		sudoArgs := append([]string{"-n", "pacman"}, args...)
		c = exec.CommandContext(p.ctx, "sudo", sudoArgs...)
	} else {
		c = exec.CommandContext(p.ctx, "pacman", args...)
	}

	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr

	err := c.Run()
	result := &CommandResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: time.Since(start),
	}

	if c.ProcessState != nil {
		result.ExitCode = c.ProcessState.ExitCode()
	}
	result.Success = err == nil

	return result, err
}

func (p *Pacman) runWithStdin(cmd, arg, stdin string) (*CommandResult, error) {
	start := time.Now()

	var c *exec.Cmd
	if p.useSudo {
		c = exec.CommandContext(p.ctx, "sudo", "-n", cmd, arg)
	} else {
		c = exec.CommandContext(p.ctx, cmd, arg)
	}

	c.Stdin = strings.NewReader(stdin)

	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr

	err := c.Run()
	result := &CommandResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: time.Since(start),
	}

	if c.ProcessState != nil {
		result.ExitCode = c.ProcessState.ExitCode()
	}
	result.Success = err == nil

	return result, err
}

func parsePacmanValue(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func parsePacmanSize(s string) int64 {
	s = strings.TrimSpace(s)
	multiplier := int64(1)

	if strings.HasSuffix(s, " KiB") {
		multiplier = 1024
		s = strings.TrimSuffix(s, " KiB")
	} else if strings.HasSuffix(s, " MiB") {
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, " MiB")
	} else if strings.HasSuffix(s, " GiB") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, " GiB")
	} else if strings.HasSuffix(s, " B") {
		s = strings.TrimSuffix(s, " B")
	}

	size, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return int64(size * float64(multiplier))
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
