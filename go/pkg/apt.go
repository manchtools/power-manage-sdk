package pkg

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Apt implements the Manager interface for Debian-based systems.
type Apt struct {
	ctx     context.Context
	useSudo bool
	aptCmd  string // cached apt command (apt or apt-get)
}

// NewApt creates a new Apt package manager.
// By default, sudo is enabled for privileged operations.
func NewApt() *Apt {
	return &Apt{ctx: context.Background(), useSudo: true}
}

// NewAptWithContext creates a new Apt package manager with context.
// By default, sudo is enabled for privileged operations.
func NewAptWithContext(ctx context.Context) *Apt {
	return &Apt{ctx: ctx, useSudo: true}
}

// WithSudo sets whether to use sudo for privileged operations.
func (a *Apt) WithSudo(useSudo bool) *Apt {
	a.useSudo = useSudo
	return a
}

// Info returns apt version information.
func (a *Apt) Info() (name, version string, err error) {
	out, err := exec.CommandContext(a.ctx, "apt", "--version").Output()
	if err != nil {
		return "", "", err
	}
	parts := strings.Fields(string(out))
	if len(parts) >= 2 {
		return "apt", parts[1], nil
	}
	return "apt", "", nil
}

// Install installs packages (latest version).
// Uses --fix-broken to automatically resolve dependency issues.
func (a *Apt) Install(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	args := append([]string{"install", "-y", "--fix-broken"}, packages...)
	return a.run("apt", args...)
}

// InstallVersion installs a package with specific version options.
// Uses --fix-broken to automatically resolve dependency issues.
func (a *Apt) InstallVersion(name string, opts InstallOptions) (*CommandResult, error) {
	pkgSpec := name
	if opts.Version != "" {
		pkgSpec = fmt.Sprintf("%s=%s", name, opts.Version)
	}

	args := []string{"install", "-y", "--fix-broken"}
	if opts.AllowDowngrade {
		args = append(args, "--allow-downgrades")
	}
	args = append(args, pkgSpec)

	return a.run("apt", args...)
}

// Remove removes packages.
func (a *Apt) Remove(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	args := append([]string{"remove", "-y"}, packages...)
	return a.run("apt", args...)
}

// Purge removes packages including configuration files.
func (a *Apt) Purge(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	args := append([]string{"purge", "-y"}, packages...)
	return a.run("apt", args...)
}

// Update updates the package database.
func (a *Apt) Update() (*CommandResult, error) {
	return a.run("apt", "update")
}

// Upgrade upgrades packages.
func (a *Apt) Upgrade(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return a.run("apt", "upgrade", "-y")
	}
	args := append([]string{"install", "-y", "--only-upgrade"}, packages...)
	return a.run("apt", args...)
}

// Search searches for packages.
func (a *Apt) Search(query string) ([]SearchResult, error) {
	var cmd string
	var args []string
	if a.hasApt() {
		cmd = "apt"
		args = []string{"search", "--names-only", query}
	} else {
		cmd = "apt-cache"
		args = []string{"search", query}
	}

	out, err := exec.CommandContext(a.ctx, cmd, args...).Output()
	if err != nil {
		return nil, err
	}

	var results []SearchResult
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) < 2 {
			continue
		}
		results = append(results, SearchResult{
			Name:        strings.TrimSpace(parts[0]),
			Description: strings.TrimSpace(parts[1]),
		})
	}
	return results, nil
}

// List lists installed packages.
func (a *Apt) List() ([]Package, error) {
	out, err := exec.CommandContext(a.ctx, "dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${Status}\t${Installed-Size}\t${Description}\n").Output()
	if err != nil {
		return nil, err
	}

	pinnedPkgs, _ := a.getPinnedSet()

	var packages []Package
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 5 {
			continue
		}
		if !strings.Contains(fields[3], "installed") {
			continue
		}
		size, _ := strconv.ParseInt(fields[4], 10, 64)
		desc := ""
		if len(fields) > 5 {
			desc = fields[5]
		}
		pkg := Package{
			Name:         fields[0],
			Version:      fields[1],
			Architecture: fields[2],
			Status:       "installed",
			Size:         size * 1024,
			Description:  desc,
			Pinned:       pinnedPkgs[fields[0]],
		}
		packages = append(packages, pkg)
	}
	return packages, nil
}

// ListUpgradable lists packages with available upgrades.
func (a *Apt) ListUpgradable() ([]PackageUpdate, error) {
	out, err := exec.CommandContext(a.ctx, "apt", "list", "--upgradable").Output()
	if err != nil {
		return nil, err
	}

	var updates []PackageUpdate
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Scan() // Skip header

	re := regexp.MustCompile(`^([^/]+)/(\S+)\s+(\S+)\s+(\S+)\s+\[upgradable from: ([^\]]+)\]`)
	for scanner.Scan() {
		matches := re.FindStringSubmatch(scanner.Text())
		if len(matches) < 6 {
			continue
		}
		updates = append(updates, PackageUpdate{
			Name:           matches[1],
			Repository:     matches[2],
			NewVersion:     matches[3],
			Architecture:   matches[4],
			CurrentVersion: matches[5],
		})
	}
	return updates, nil
}

// Show returns detailed information about a package.
func (a *Apt) Show(name string) (*Package, error) {
	var cmd string
	if a.hasApt() {
		cmd = "apt"
	} else {
		cmd = "apt-cache"
	}

	out, err := exec.CommandContext(a.ctx, cmd, "show", name).Output()
	if err != nil {
		return nil, err
	}

	pkg := &Package{Name: name}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Version:") {
			pkg.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		} else if strings.HasPrefix(line, "Architecture:") {
			pkg.Architecture = strings.TrimSpace(strings.TrimPrefix(line, "Architecture:"))
		} else if strings.HasPrefix(line, "Description:") {
			pkg.Description = strings.TrimSpace(strings.TrimPrefix(line, "Description:"))
		} else if strings.HasPrefix(line, "Installed-Size:") {
			sizeStr := strings.TrimSpace(strings.TrimPrefix(line, "Installed-Size:"))
			if size, err := strconv.ParseInt(sizeStr, 10, 64); err == nil {
				pkg.Size = size * 1024
			}
		}
	}

	installed, _ := a.IsInstalled(name)
	if installed {
		pkg.Status = "installed"
	} else {
		pkg.Status = "available"
	}

	pkg.Pinned, _ = a.IsPinned(name)

	return pkg, nil
}

// ListVersions lists all available versions of a package.
func (a *Apt) ListVersions(name string) (*VersionInfo, error) {
	out, err := exec.CommandContext(a.ctx, "apt-cache", "madison", name).Output()
	if err != nil {
		return nil, err
	}

	info := &VersionInfo{Name: name}
	info.Installed, _ = a.GetInstalledVersion(name)

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		// format: package | version | repository
		fields := strings.Split(scanner.Text(), "|")
		if len(fields) < 3 {
			continue
		}
		version := strings.TrimSpace(fields[1])
		repo := strings.TrimSpace(fields[2])

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
func (a *Apt) IsInstalled(name string) (bool, error) {
	err := exec.CommandContext(a.ctx, "dpkg", "-s", name).Run()
	return err == nil, nil
}

// GetInstalledVersion returns the installed version of a package.
func (a *Apt) GetInstalledVersion(name string) (string, error) {
	out, err := exec.CommandContext(a.ctx, "dpkg-query", "-W", "-f=${Version}", name).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// Pin prevents a package from being upgraded (apt-mark hold).
func (a *Apt) Pin(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	args := append([]string{"hold"}, packages...)
	return a.run("apt-mark", args...)
}

// Unpin allows a package to be upgraded again (apt-mark unhold).
func (a *Apt) Unpin(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	args := append([]string{"unhold"}, packages...)
	return a.run("apt-mark", args...)
}

// ListPinned lists all pinned (held) packages.
func (a *Apt) ListPinned() ([]Package, error) {
	out, err := exec.CommandContext(a.ctx, "apt-mark", "showhold").Output()
	if err != nil {
		return nil, err
	}

	var packages []Package
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		name := strings.TrimSpace(scanner.Text())
		if name == "" {
			continue
		}
		version, _ := a.GetInstalledVersion(name)
		packages = append(packages, Package{
			Name:    name,
			Version: version,
			Status:  "installed",
			Pinned:  true,
		})
	}
	return packages, nil
}

// IsPinned checks if a package is pinned (held).
func (a *Apt) IsPinned(name string) (bool, error) {
	out, err := exec.CommandContext(a.ctx, "apt-mark", "showhold", name).Output()
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) == name, nil
}

func (a *Apt) getPinnedSet() (map[string]bool, error) {
	out, err := exec.CommandContext(a.ctx, "apt-mark", "showhold").Output()
	if err != nil {
		return nil, err
	}

	pinned := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		name := strings.TrimSpace(scanner.Text())
		if name != "" {
			pinned[name] = true
		}
	}
	return pinned, nil
}

// getAptCmd returns the preferred apt command (apt if available, apt-get as fallback).
// The result is cached for subsequent calls.
func (a *Apt) getAptCmd() string {
	if a.aptCmd != "" {
		return a.aptCmd
	}
	// Prefer apt if available
	if _, err := exec.LookPath("apt"); err == nil {
		a.aptCmd = "apt"
	} else {
		a.aptCmd = "apt-get"
	}
	return a.aptCmd
}

// hasApt returns true if the apt command is available.
func (a *Apt) hasApt() bool {
	return a.getAptCmd() == "apt"
}

func (a *Apt) run(cmd string, args ...string) (*CommandResult, error) {
	start := time.Now()

	// Use preferred apt command for apt/apt-get operations
	if cmd == "apt" || cmd == "apt-get" {
		cmd = a.getAptCmd()
	}

	var c *exec.Cmd
	if a.useSudo {
		// Prepend sudo -n (non-interactive) to avoid password prompts
		sudoArgs := append([]string{"-n", cmd}, args...)
		c = exec.CommandContext(a.ctx, "sudo", sudoArgs...)
	} else {
		c = exec.CommandContext(a.ctx, cmd, args...)
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
