package pkg

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// nevraVersionRe matches the first dash followed by a digit in an NEVRA string,
// marking the boundary between the package name and version.
var nevraVersionRe = regexp.MustCompile(`-\d`)

// parseNEVRAName extracts the package name from an NEVRA string
// (Name-[Epoch:]Version-Release[.Arch]). It finds the first dash
// followed by a digit, which marks the start of the version portion.
func parseNEVRAName(nevra string) string {
	loc := nevraVersionRe.FindStringIndex(nevra)
	if loc == nil {
		return nevra
	}
	return nevra[:loc[0]]
}

// Dnf implements the Manager interface for Fedora/RHEL-based systems.
type Dnf struct {
	ctx     context.Context
	useSudo bool
}

// NewDnf creates a new Dnf package manager.
// By default, sudo is enabled for privileged operations.
func NewDnf() *Dnf {
	return &Dnf{ctx: context.Background(), useSudo: true}
}

// NewDnfWithContext creates a new Dnf package manager with context.
// By default, sudo is enabled for privileged operations.
func NewDnfWithContext(ctx context.Context) *Dnf {
	return &Dnf{ctx: ctx, useSudo: true}
}

// WithSudo sets whether to use sudo for privileged operations.
func (d *Dnf) WithSudo(useSudo bool) *Dnf {
	d.useSudo = useSudo
	return d
}

// Info returns dnf version information.
func (d *Dnf) Info() (name, version string, err error) {
	out, err := exec.CommandContext(d.ctx, "dnf", "--version").Output()
	if err != nil {
		return "", "", err
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) > 0 {
		return "dnf", strings.TrimSpace(lines[0]), nil
	}
	return "dnf", "", nil
}

// Install installs packages (latest version).
func (d *Dnf) Install(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	args := append([]string{"install", "-y"}, packages...)
	return d.run(d.ctx, args...)
}

// InstallVersion installs a package with specific version options.
func (d *Dnf) InstallVersion(name string, opts InstallOptions) (*CommandResult, error) {
	pkgSpec := name
	if opts.Version != "" {
		pkgSpec = fmt.Sprintf("%s-%s", name, opts.Version)
	}

	args := []string{"install", "-y"}
	if opts.AllowDowngrade {
		args = append(args, "--allowerasing")
	}
	args = append(args, pkgSpec)

	result, err := d.run(d.ctx, args...)

	// If downgrade is allowed and install failed, try explicit downgrade
	if opts.AllowDowngrade && err != nil && opts.Version != "" {
		return d.run(d.ctx, "downgrade", "-y", pkgSpec)
	}

	return result, err
}

// Remove removes packages.
func (d *Dnf) Remove(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	args := append([]string{"remove", "-y"}, packages...)
	return d.run(d.ctx, args...)
}

// Update updates the package database (dnf check-update).
// dnf check-update returns exit code 100 when updates are available,
// which is a success case, not an error.
func (d *Dnf) Update() (*CommandResult, error) {
	result, err := d.run(d.ctx, "check-update")
	if err != nil && result != nil && result.ExitCode == 100 {
		result.Success = true
		return result, nil
	}
	return result, err
}

// Upgrade upgrades packages.
func (d *Dnf) Upgrade(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return d.run(d.ctx, "upgrade", "-y")
	}
	args := append([]string{"upgrade", "-y"}, packages...)
	return d.run(d.ctx, args...)
}

// Search searches for packages.
func (d *Dnf) Search(query string) ([]SearchResult, error) {
	out, err := exec.CommandContext(d.ctx, "dnf", "search", "-q", query).Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, err
	}

	var results []SearchResult
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "=") || line == "" {
			continue
		}
		parts := strings.SplitN(line, " : ", 2)
		if len(parts) < 2 {
			continue
		}
		nameParts := strings.Split(parts[0], ".")
		name := nameParts[0]
		results = append(results, SearchResult{
			Name:        name,
			Description: strings.TrimSpace(parts[1]),
		})
	}
	return results, nil
}

// List lists installed packages.
func (d *Dnf) List() ([]Package, error) {
	out, err := exec.CommandContext(d.ctx, "rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SIZE}\t%{SUMMARY}\n").Output()
	if err != nil {
		return nil, err
	}

	pinnedPkgs, _ := d.getPinnedSet()

	var packages []Package
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 4 {
			continue
		}
		size, _ := strconv.ParseInt(fields[3], 10, 64)
		desc := ""
		if len(fields) > 4 {
			desc = fields[4]
		}
		packages = append(packages, Package{
			Name:         fields[0],
			Version:      fields[1],
			Architecture: fields[2],
			Status:       "installed",
			Size:         size,
			Description:  desc,
			Pinned:       pinnedPkgs[fields[0]],
		})
	}
	return packages, nil
}

// ListUpgradable lists packages with available upgrades.
func (d *Dnf) ListUpgradable() ([]PackageUpdate, error) {
	out, err := exec.CommandContext(d.ctx, "dnf", "check-update", "-q").Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() != 100 {
			return nil, err
		}
	}

	var updates []PackageUpdate
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		nameParts := strings.Split(fields[0], ".")
		name := nameParts[0]
		arch := ""
		if len(nameParts) > 1 {
			arch = nameParts[len(nameParts)-1]
		}

		currentVersion, _ := d.GetInstalledVersion(name)

		updates = append(updates, PackageUpdate{
			Name:           name,
			Architecture:   arch,
			NewVersion:     fields[1],
			Repository:     fields[2],
			CurrentVersion: currentVersion,
		})
	}
	return updates, nil
}

// Show returns detailed information about a package.
func (d *Dnf) Show(name string) (*Package, error) {
	out, err := exec.CommandContext(d.ctx, "dnf", "info", "-q", name).Output()
	if err != nil {
		return nil, err
	}

	pkg := &Package{Name: name, Status: "available"}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Version") {
			pkg.Version = parseValue(line)
		} else if strings.HasPrefix(line, "Release") {
			if pkg.Version != "" {
				pkg.Version += "-" + parseValue(line)
			}
		} else if strings.HasPrefix(line, "Architecture") {
			pkg.Architecture = parseValue(line)
		} else if strings.HasPrefix(line, "Size") {
			pkg.Size = parseSize(parseValue(line))
		} else if strings.HasPrefix(line, "Summary") {
			pkg.Description = parseValue(line)
		} else if strings.HasPrefix(line, "Repository") {
			pkg.Repository = parseValue(line)
		}
	}

	installed, _ := d.IsInstalled(name)
	if installed {
		pkg.Status = "installed"
	}

	if pinned, err := d.IsPinned(name); err != nil {
		slog.Debug("failed to check pin status", "package", name, "error", err)
	} else {
		pkg.Pinned = pinned
	}

	return pkg, nil
}

// ListVersions lists all available versions of a package.
func (d *Dnf) ListVersions(name string) (*VersionInfo, error) {
	out, err := exec.CommandContext(d.ctx, "dnf", "list", "--showduplicates", "-q", name).Output()
	if err != nil {
		return nil, err
	}

	info := &VersionInfo{Name: name}
	if installed, err := d.GetInstalledVersion(name); err != nil {
		slog.Debug("failed to get installed version", "package", name, "error", err)
	} else {
		info.Installed = installed
	}

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "Installed") || strings.HasPrefix(line, "Available") {
			continue
		}
		// format: name.arch  version  repo
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		version := fields[1]
		repo := fields[2]

		if seen[version] {
			continue
		}
		seen[version] = true

		info.Versions = append(info.Versions, AvailableVersion{
			Version:    version,
			Repository: repo,
		})
	}

	return info, nil
}

// IsInstalled checks if a package is installed.
func (d *Dnf) IsInstalled(name string) (bool, error) {
	err := exec.CommandContext(d.ctx, "rpm", "-q", name).Run()
	return err == nil, nil
}

// GetInstalledVersion returns the installed version of a package.
func (d *Dnf) GetInstalledVersion(name string) (string, error) {
	out, err := exec.CommandContext(d.ctx, "rpm", "-q", "--queryformat", "%{VERSION}-%{RELEASE}", name).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// ensureVersionLock installs the versionlock plugin if not already installed.
func (d *Dnf) ensureVersionLock() error {
	// Check if versionlock command works
	err := exec.CommandContext(d.ctx, "dnf", "versionlock", "--help").Run()
	if err == nil {
		return nil // plugin already installed
	}

	// Install the plugin
	_, err = d.run(d.ctx, "install", "-y", "python3-dnf-plugin-versionlock")
	return err
}

// Pin prevents a package from being upgraded (dnf versionlock).
// Automatically installs the versionlock plugin if not present.
func (d *Dnf) Pin(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	if err := d.ensureVersionLock(); err != nil {
		return nil, err
	}
	args := append([]string{"versionlock", "add"}, packages...)
	return d.run(d.ctx, args...)
}

// Unpin allows a package to be upgraded again (dnf versionlock delete).
// Automatically installs the versionlock plugin if not present.
func (d *Dnf) Unpin(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	if err := d.ensureVersionLock(); err != nil {
		return nil, err
	}
	args := append([]string{"versionlock", "delete"}, packages...)
	return d.run(d.ctx, args...)
}

// ListPinned lists all pinned (versionlocked) packages.
// Automatically installs the versionlock plugin if not present.
func (d *Dnf) ListPinned() ([]Package, error) {
	if err := d.ensureVersionLock(); err != nil {
		return nil, err
	}
	out, err := exec.CommandContext(d.ctx, "dnf", "versionlock", "list", "-q").Output()
	if err != nil {
		return nil, err
	}

	var packages []Package
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		name := parseNEVRAName(line)
		version, _ := d.GetInstalledVersion(name)
		packages = append(packages, Package{
			Name:    name,
			Version: version,
			Status:  "installed",
			Pinned:  true,
		})
	}
	return packages, nil
}

// IsPinned checks if a package is pinned (versionlocked).
func (d *Dnf) IsPinned(name string) (bool, error) {
	out, err := exec.CommandContext(d.ctx, "dnf", "versionlock", "list", "-q").Output()
	if err != nil {
		return false, nil // versionlock plugin might not be installed
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && parseNEVRAName(line) == name {
			return true, nil
		}
	}
	return false, nil
}

func (d *Dnf) getPinnedSet() (map[string]bool, error) {
	out, err := exec.CommandContext(d.ctx, "dnf", "versionlock", "list", "-q").Output()
	if err != nil {
		return nil, nil
	}

	pinned := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		pinned[parseNEVRAName(line)] = true
	}
	return pinned, nil
}

func (d *Dnf) run(ctx context.Context, args ...string) (*CommandResult, error) {
	start := time.Now()

	var c *exec.Cmd
	if d.useSudo {
		// Prepend sudo -n (non-interactive) to avoid password prompts
		sudoArgs := append([]string{"-n", "dnf"}, args...)
		c = exec.CommandContext(ctx, "sudo", sudoArgs...)
	} else {
		c = exec.CommandContext(ctx, "dnf", args...)
	}

	// Force English locale for reliable output parsing.
	c.Env = append(os.Environ(), "LANG=C", "LC_ALL=C")

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

func parseValue(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func parseSize(s string) int64 {
	s = strings.TrimSpace(s)
	multiplier := int64(1)

	if strings.HasSuffix(s, " k") || strings.HasSuffix(s, " K") {
		multiplier = 1024
		s = strings.TrimSuffix(strings.TrimSuffix(s, " k"), " K")
	} else if strings.HasSuffix(s, " M") {
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, " M")
	} else if strings.HasSuffix(s, " G") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, " G")
	}

	size, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return int64(size * float64(multiplier))
}
