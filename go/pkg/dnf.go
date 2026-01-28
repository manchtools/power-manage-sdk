package pkg

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Dnf implements the Manager interface for Fedora/RHEL-based systems.
type Dnf struct {
	ctx context.Context
}

// NewDnf creates a new Dnf package manager.
func NewDnf() *Dnf {
	return &Dnf{ctx: context.Background()}
}

// NewDnfWithContext creates a new Dnf package manager with context.
func NewDnfWithContext(ctx context.Context) *Dnf {
	return &Dnf{ctx: ctx}
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

// Install installs packages.
func (d *Dnf) Install(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	args := append([]string{"install", "-y"}, packages...)
	return d.run(args...)
}

// Remove removes packages.
func (d *Dnf) Remove(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	args := append([]string{"remove", "-y"}, packages...)
	return d.run(args...)
}

// Update updates the package database (dnf check-update).
func (d *Dnf) Update() (*CommandResult, error) {
	return d.run("check-update")
}

// Upgrade upgrades packages.
func (d *Dnf) Upgrade(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return d.run("upgrade", "-y")
	}
	args := append([]string{"upgrade", "-y"}, packages...)
	return d.run(args...)
}

// Search searches for packages.
func (d *Dnf) Search(query string) ([]SearchResult, error) {
	out, err := exec.CommandContext(d.ctx, "dnf", "search", "-q", query).Output()
	if err != nil {
		// dnf search returns exit code 1 if no results
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, err
	}

	var results []SearchResult
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		// Skip header lines
		if strings.HasPrefix(line, "=") || line == "" {
			continue
		}
		// format: name.arch : description
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
		})
	}
	return packages, nil
}

// ListUpgradable lists packages with available upgrades.
func (d *Dnf) ListUpgradable() ([]PackageUpdate, error) {
	out, err := exec.CommandContext(d.ctx, "dnf", "check-update", "-q").Output()
	if err != nil {
		// exit code 100 means updates available, 0 means no updates
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
		// format: name.arch  version  repo
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

		// Get current version
		currentVersion := ""
		if installed, _ := d.getInstalledVersion(name); installed != "" {
			currentVersion = installed
		}

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

	return pkg, nil
}

// IsInstalled checks if a package is installed.
func (d *Dnf) IsInstalled(name string) (bool, error) {
	err := exec.CommandContext(d.ctx, "rpm", "-q", name).Run()
	return err == nil, nil
}

func (d *Dnf) getInstalledVersion(name string) (string, error) {
	out, err := exec.CommandContext(d.ctx, "rpm", "-q", "--queryformat", "%{VERSION}-%{RELEASE}", name).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (d *Dnf) run(args ...string) (*CommandResult, error) {
	start := time.Now()
	c := exec.CommandContext(d.ctx, "dnf", args...)

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
