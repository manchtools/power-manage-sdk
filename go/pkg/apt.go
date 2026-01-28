package pkg

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Apt implements the Manager interface for Debian-based systems.
type Apt struct {
	ctx context.Context
}

// NewApt creates a new Apt package manager.
func NewApt() *Apt {
	return &Apt{ctx: context.Background()}
}

// NewAptWithContext creates a new Apt package manager with context.
func NewAptWithContext(ctx context.Context) *Apt {
	return &Apt{ctx: ctx}
}

// Info returns apt version information.
func (a *Apt) Info() (name, version string, err error) {
	out, err := exec.CommandContext(a.ctx, "apt", "--version").Output()
	if err != nil {
		return "", "", err
	}
	// apt 2.6.1 (amd64)
	parts := strings.Fields(string(out))
	if len(parts) >= 2 {
		return "apt", parts[1], nil
	}
	return "apt", "", nil
}

// Install installs packages.
func (a *Apt) Install(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	args := append([]string{"install", "-y"}, packages...)
	return a.run("apt-get", args...)
}

// Remove removes packages.
func (a *Apt) Remove(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	args := append([]string{"remove", "-y"}, packages...)
	return a.run("apt-get", args...)
}

// Update updates the package database.
func (a *Apt) Update() (*CommandResult, error) {
	return a.run("apt-get", "update")
}

// Upgrade upgrades packages.
func (a *Apt) Upgrade(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return a.run("apt-get", "upgrade", "-y")
	}
	args := append([]string{"install", "-y", "--only-upgrade"}, packages...)
	return a.run("apt-get", args...)
}

// Search searches for packages.
func (a *Apt) Search(query string) ([]SearchResult, error) {
	out, err := exec.CommandContext(a.ctx, "apt-cache", "search", query).Output()
	if err != nil {
		return nil, err
	}

	var results []SearchResult
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		// format: package-name - description
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

	var packages []Package
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 5 {
			continue
		}
		// Only include installed packages
		if !strings.Contains(fields[3], "installed") {
			continue
		}
		size, _ := strconv.ParseInt(fields[4], 10, 64)
		desc := ""
		if len(fields) > 5 {
			desc = fields[5]
		}
		packages = append(packages, Package{
			Name:         fields[0],
			Version:      fields[1],
			Architecture: fields[2],
			Status:       "installed",
			Size:         size * 1024, // dpkg reports in KB
			Description:  desc,
		})
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
	// Skip header line "Listing..."
	scanner.Scan()

	// format: package/repo version arch [upgradable from: old-version]
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
	out, err := exec.CommandContext(a.ctx, "apt-cache", "show", name).Output()
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

	return pkg, nil
}

// IsInstalled checks if a package is installed.
func (a *Apt) IsInstalled(name string) (bool, error) {
	err := exec.CommandContext(a.ctx, "dpkg", "-s", name).Run()
	return err == nil, nil
}

func (a *Apt) run(cmd string, args ...string) (*CommandResult, error) {
	start := time.Now()
	c := exec.CommandContext(a.ctx, cmd, args...)

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
