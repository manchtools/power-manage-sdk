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

// Zypper implements the Manager interface for openSUSE/SLES-based systems.
type Zypper struct {
	ctx     context.Context
	useSudo bool
}

// NewZypper creates a new Zypper package manager.
// By default, sudo is enabled for privileged operations.
func NewZypper() *Zypper {
	return &Zypper{ctx: context.Background(), useSudo: true}
}

// NewZypperWithContext creates a new Zypper package manager with context.
// By default, sudo is enabled for privileged operations.
func NewZypperWithContext(ctx context.Context) *Zypper {
	return &Zypper{ctx: ctx, useSudo: true}
}

// WithSudo sets whether to use sudo for privileged operations.
func (z *Zypper) WithSudo(useSudo bool) *Zypper {
	z.useSudo = useSudo
	return z
}

// Info returns zypper version information.
func (z *Zypper) Info() (name, version string, err error) {
	out, err := exec.CommandContext(z.ctx, "zypper", "--version").Output()
	if err != nil {
		return "", "", err
	}
	// Output format: "zypper 1.14.59"
	parts := strings.Fields(string(out))
	if len(parts) >= 2 {
		return "zypper", parts[1], nil
	}
	return "zypper", "", nil
}

// Install installs packages (latest version).
func (z *Zypper) Install(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	// --non-interactive: non-interactive mode
	args := append([]string{"--non-interactive", "install"}, packages...)
	return z.run(args...)
}

// InstallVersion installs a package with specific version options.
func (z *Zypper) InstallVersion(name string, opts InstallOptions) (*CommandResult, error) {
	pkgSpec := name
	if opts.Version != "" {
		// Zypper uses = for version specification
		pkgSpec = fmt.Sprintf("%s=%s", name, opts.Version)
	}

	args := []string{"--non-interactive", "install"}
	if opts.AllowDowngrade {
		args = append(args, "--oldpackage")
	}
	args = append(args, pkgSpec)

	return z.run(args...)
}

// Remove removes packages.
func (z *Zypper) Remove(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	args := append([]string{"--non-interactive", "remove"}, packages...)
	return z.run(args...)
}

// Purge removes packages (zypper doesn't distinguish purge from remove).
func (z *Zypper) Purge(packages ...string) (*CommandResult, error) {
	return z.Remove(packages...)
}

// Update updates the package database (refresh repositories).
func (z *Zypper) Update() (*CommandResult, error) {
	return z.run("--non-interactive", "refresh")
}

// Upgrade upgrades packages.
func (z *Zypper) Upgrade(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		// Upgrade all packages
		return z.run("--non-interactive", "update")
	}
	// Upgrade specific packages
	args := append([]string{"--non-interactive", "update"}, packages...)
	return z.run(args...)
}

// DistUpgrade performs a distribution upgrade.
func (z *Zypper) DistUpgrade() (*CommandResult, error) {
	return z.run("--non-interactive", "dist-upgrade")
}

// Search searches for packages.
func (z *Zypper) Search(query string) ([]SearchResult, error) {
	out, err := exec.CommandContext(z.ctx, "zypper", "--non-interactive", "search", query).Output()
	if err != nil {
		// zypper returns 104 if no matches found
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 104 {
			return nil, nil
		}
		return nil, err
	}

	var results []SearchResult
	scanner := bufio.NewScanner(bytes.NewReader(out))

	// Skip header lines (until we see a line starting with ---)
	headerPassed := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+-") {
			headerPassed = true
			continue
		}
		if !headerPassed {
			continue
		}

		// Format: S | Name | Summary | Type
		// or: i | name | version | arch | repo
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}

		name := strings.TrimSpace(parts[1])
		summary := strings.TrimSpace(parts[2])

		if name == "" {
			continue
		}

		results = append(results, SearchResult{
			Name:        name,
			Description: summary,
		})
	}
	return results, nil
}

// List lists installed packages.
func (z *Zypper) List() ([]Package, error) {
	// Use rpm query for installed packages
	out, err := exec.CommandContext(z.ctx, "rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SIZE}\t%{SUMMARY}\n").Output()
	if err != nil {
		return nil, err
	}

	pinnedPkgs, _ := z.getPinnedSet()

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
func (z *Zypper) ListUpgradable() ([]PackageUpdate, error) {
	out, err := exec.CommandContext(z.ctx, "zypper", "--non-interactive", "list-updates").Output()
	if err != nil {
		return nil, err
	}

	var updates []PackageUpdate
	scanner := bufio.NewScanner(bytes.NewReader(out))

	// Skip header lines
	headerPassed := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+-") {
			headerPassed = true
			continue
		}
		if !headerPassed {
			continue
		}

		// Format: S | Repository | Name | Current Version | Available Version | Arch
		parts := strings.Split(line, "|")
		if len(parts) < 5 {
			continue
		}

		repo := strings.TrimSpace(parts[1])
		name := strings.TrimSpace(parts[2])
		currentVersion := strings.TrimSpace(parts[3])
		newVersion := strings.TrimSpace(parts[4])
		arch := ""
		if len(parts) > 5 {
			arch = strings.TrimSpace(parts[5])
		}

		if name == "" {
			continue
		}

		updates = append(updates, PackageUpdate{
			Name:           name,
			Repository:     repo,
			CurrentVersion: currentVersion,
			NewVersion:     newVersion,
			Architecture:   arch,
		})
	}
	return updates, nil
}

// Show returns detailed information about a package.
func (z *Zypper) Show(name string) (*Package, error) {
	out, err := exec.CommandContext(z.ctx, "zypper", "--non-interactive", "info", name).Output()
	if err != nil {
		return nil, err
	}

	pkg := &Package{Name: name, Status: "available"}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Version") {
			pkg.Version = parseZypperValue(line)
		} else if strings.HasPrefix(line, "Arch") {
			pkg.Architecture = parseZypperValue(line)
		} else if strings.HasPrefix(line, "Summary") {
			pkg.Description = parseZypperValue(line)
		} else if strings.HasPrefix(line, "Installed Size") {
			pkg.Size = parseZypperSize(parseZypperValue(line))
		} else if strings.HasPrefix(line, "Repository") {
			pkg.Repository = parseZypperValue(line)
		} else if strings.HasPrefix(line, "Status") {
			status := parseZypperValue(line)
			if strings.Contains(strings.ToLower(status), "installed") {
				pkg.Status = "installed"
			}
		}
	}

	// Double-check installation status
	installed, _ := z.IsInstalled(name)
	if installed {
		pkg.Status = "installed"
	}

	pkg.Pinned, _ = z.IsPinned(name)

	return pkg, nil
}

// ListVersions lists all available versions of a package.
func (z *Zypper) ListVersions(name string) (*VersionInfo, error) {
	// Use --match-exact to get exact package name matches
	out, err := exec.CommandContext(z.ctx, "zypper", "--non-interactive", "search", "-s", "--match-exact", name).Output()
	if err != nil {
		return nil, err
	}

	info := &VersionInfo{Name: name}
	info.Installed, _ = z.GetInstalledVersion(name)

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(out))

	// Skip header lines
	headerPassed := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+-") {
			headerPassed = true
			continue
		}
		if !headerPassed {
			continue
		}

		// Format: S | Name | Type | Version | Arch | Repository
		parts := strings.Split(line, "|")
		if len(parts) < 6 {
			continue
		}

		pkgName := strings.TrimSpace(parts[1])
		if pkgName != name {
			continue
		}

		version := strings.TrimSpace(parts[3])
		repo := strings.TrimSpace(parts[5])

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
func (z *Zypper) IsInstalled(name string) (bool, error) {
	err := exec.CommandContext(z.ctx, "rpm", "-q", name).Run()
	return err == nil, nil
}

// GetInstalledVersion returns the installed version of a package.
func (z *Zypper) GetInstalledVersion(name string) (string, error) {
	out, err := exec.CommandContext(z.ctx, "rpm", "-q", "--queryformat", "%{VERSION}-%{RELEASE}", name).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// Pin prevents a package from being upgraded using package locks.
func (z *Zypper) Pin(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	args := append([]string{"--non-interactive", "addlock"}, packages...)
	return z.run(args...)
}

// Unpin allows a package to be upgraded again by removing the lock.
func (z *Zypper) Unpin(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	args := append([]string{"--non-interactive", "removelock"}, packages...)
	return z.run(args...)
}

// ListPinned lists all pinned (locked) packages.
func (z *Zypper) ListPinned() ([]Package, error) {
	out, err := exec.CommandContext(z.ctx, "zypper", "--non-interactive", "locks").Output()
	if err != nil {
		return nil, err
	}

	var packages []Package
	scanner := bufio.NewScanner(bytes.NewReader(out))

	// Skip header lines
	headerPassed := false
	// Match pattern like: "  1 | vim | package"
	lockPattern := regexp.MustCompile(`^\s*\d+\s*\|\s*(\S+)`)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+-") {
			headerPassed = true
			continue
		}
		if !headerPassed {
			continue
		}

		matches := lockPattern.FindStringSubmatch(line)
		if len(matches) >= 2 {
			name := matches[1]
			version, _ := z.GetInstalledVersion(name)
			packages = append(packages, Package{
				Name:    name,
				Version: version,
				Status:  "installed",
				Pinned:  true,
			})
		}
	}
	return packages, nil
}

// IsPinned checks if a package is pinned (locked).
func (z *Zypper) IsPinned(name string) (bool, error) {
	out, err := exec.CommandContext(z.ctx, "zypper", "--non-interactive", "locks").Output()
	if err != nil {
		return false, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	lockPattern := regexp.MustCompile(`^\s*\d+\s*\|\s*` + regexp.QuoteMeta(name) + `\s*\|`)

	for scanner.Scan() {
		if lockPattern.MatchString(scanner.Text()) {
			return true, nil
		}
	}
	return false, nil
}

func (z *Zypper) getPinnedSet() (map[string]bool, error) {
	out, err := exec.CommandContext(z.ctx, "zypper", "--non-interactive", "locks").Output()
	if err != nil {
		return nil, nil
	}

	pinned := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	lockPattern := regexp.MustCompile(`^\s*\d+\s*\|\s*(\S+)`)

	for scanner.Scan() {
		matches := lockPattern.FindStringSubmatch(scanner.Text())
		if len(matches) >= 2 {
			pinned[matches[1]] = true
		}
	}
	return pinned, nil
}

func (z *Zypper) run(args ...string) (*CommandResult, error) {
	start := time.Now()

	var c *exec.Cmd
	if z.useSudo {
		sudoArgs := append([]string{"-n", "zypper"}, args...)
		c = exec.CommandContext(z.ctx, "sudo", sudoArgs...)
	} else {
		c = exec.CommandContext(z.ctx, "zypper", args...)
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

func parseZypperValue(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func parseZypperSize(s string) int64 {
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
