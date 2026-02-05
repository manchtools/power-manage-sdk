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

// Flatpak implements the Manager interface for Flatpak applications.
// Note: Flatpak is a universal package format that works across distributions.
// It can coexist with traditional package managers like apt, dnf, pacman, etc.
type Flatpak struct {
	ctx     context.Context
	useSudo bool
}

// NewFlatpak creates a new Flatpak package manager.
// By default, sudo is enabled for system-wide installations.
func NewFlatpak() *Flatpak {
	return &Flatpak{ctx: context.Background(), useSudo: true}
}

// NewFlatpakWithContext creates a new Flatpak package manager with context.
// By default, sudo is enabled for system-wide installations.
func NewFlatpakWithContext(ctx context.Context) *Flatpak {
	return &Flatpak{ctx: ctx, useSudo: true}
}

// WithSudo sets whether to use sudo for privileged operations.
// When false, operates on user installations only.
func (f *Flatpak) WithSudo(useSudo bool) *Flatpak {
	f.useSudo = useSudo
	return f
}

// Info returns flatpak version information.
func (f *Flatpak) Info() (name, version string, err error) {
	out, err := exec.CommandContext(f.ctx, "flatpak", "--version").Output()
	if err != nil {
		return "", "", err
	}
	// Output format: "Flatpak 1.14.4"
	parts := strings.Fields(string(out))
	if len(parts) >= 2 {
		return "flatpak", parts[1], nil
	}
	return "flatpak", "", nil
}

// Install installs packages (latest version).
// Package names should be in the format: remote/app-id or just app-id (uses flathub by default).
func (f *Flatpak) Install(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	// -y: assume yes, --noninteractive: non-interactive mode
	args := []string{"install", "-y", "--noninteractive"}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}
	args = append(args, packages...)
	return f.run(args...)
}

// InstallVersion installs a package with specific version options.
// Note: Flatpak doesn't support installing specific versions directly.
// The version field is ignored; use commits or refs for version control.
func (f *Flatpak) InstallVersion(name string, opts InstallOptions) (*CommandResult, error) {
	// Flatpak doesn't support version pinning in the traditional sense
	// You would need to use specific commits, which is advanced usage
	return f.Install(name)
}

// Remove removes packages.
func (f *Flatpak) Remove(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	args := []string{"uninstall", "-y", "--noninteractive"}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}
	args = append(args, packages...)
	return f.run(args...)
}

// Purge removes packages and their data.
func (f *Flatpak) Purge(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}
	args := []string{"uninstall", "-y", "--noninteractive", "--delete-data"}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}
	args = append(args, packages...)
	return f.run(args...)
}

// Update updates the Flatpak remote metadata.
func (f *Flatpak) Update() (*CommandResult, error) {
	args := []string{"update", "--appstream", "-y", "--noninteractive"}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}
	return f.run(args...)
}

// Upgrade upgrades packages.
func (f *Flatpak) Upgrade(packages ...string) (*CommandResult, error) {
	args := []string{"update", "-y", "--noninteractive"}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}
	if len(packages) > 0 {
		args = append(args, packages...)
	}
	return f.run(args...)
}

// Search searches for packages in configured remotes.
func (f *Flatpak) Search(query string) ([]SearchResult, error) {
	out, err := exec.CommandContext(f.ctx, "flatpak", "search", query).Output()
	if err != nil {
		// flatpak search returns exit code 1 if no results
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, err
	}

	var results []SearchResult
	scanner := bufio.NewScanner(bytes.NewReader(out))

	// Skip header line if present
	if scanner.Scan() {
		// Check if first line is a header (contains "Application ID" or similar)
		firstLine := scanner.Text()
		if !strings.Contains(firstLine, "\t") {
			// Not a data line, skip it
		} else {
			// It's a data line, process it
			if result := parseFlatpakSearchLine(firstLine); result != nil {
				results = append(results, *result)
			}
		}
	}

	for scanner.Scan() {
		if result := parseFlatpakSearchLine(scanner.Text()); result != nil {
			results = append(results, *result)
		}
	}
	return results, nil
}

// List lists installed Flatpak applications.
func (f *Flatpak) List() ([]Package, error) {
	args := []string{"list", "--columns=application,version,arch,size,description,origin"}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}

	out, err := exec.CommandContext(f.ctx, "flatpak", args...).Output()
	if err != nil {
		return nil, err
	}

	pinnedPkgs, _ := f.getPinnedSet()

	var packages []Package
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 4 {
			continue
		}
		size := parseFlatpakSize(fields[3])
		desc := ""
		if len(fields) > 4 {
			desc = fields[4]
		}
		repo := ""
		if len(fields) > 5 {
			repo = fields[5]
		}
		packages = append(packages, Package{
			Name:         fields[0],
			Version:      fields[1],
			Architecture: fields[2],
			Status:       "installed",
			Size:         size,
			Description:  desc,
			Repository:   repo,
			Pinned:       pinnedPkgs[fields[0]],
		})
	}
	return packages, nil
}

// ListUpgradable lists Flatpak applications with available updates.
func (f *Flatpak) ListUpgradable() ([]PackageUpdate, error) {
	args := []string{"remote-ls", "--updates", "--columns=application,version,origin"}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}

	out, err := exec.CommandContext(f.ctx, "flatpak", args...).Output()
	if err != nil {
		return nil, err
	}

	var updates []PackageUpdate
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 2 {
			continue
		}

		appID := fields[0]
		newVersion := fields[1]
		repo := ""
		if len(fields) > 2 {
			repo = fields[2]
		}

		// Get current installed version
		currentVersion, _ := f.GetInstalledVersion(appID)

		updates = append(updates, PackageUpdate{
			Name:           appID,
			NewVersion:     newVersion,
			CurrentVersion: currentVersion,
			Repository:     repo,
		})
	}
	return updates, nil
}

// Show returns detailed information about a Flatpak application.
func (f *Flatpak) Show(name string) (*Package, error) {
	args := []string{"info", name}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}

	out, err := exec.CommandContext(f.ctx, "flatpak", args...).Output()
	if err != nil {
		// Try searching in remotes if not installed
		return f.showFromRemote(name)
	}

	pkg := &Package{Name: name, Status: "installed"}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Version:") {
			pkg.Version = parseFlatpakValue(line)
		} else if strings.HasPrefix(line, "Arch:") {
			pkg.Architecture = parseFlatpakValue(line)
		} else if strings.HasPrefix(line, "Description:") {
			pkg.Description = parseFlatpakValue(line)
		} else if strings.HasPrefix(line, "Installed:") || strings.HasPrefix(line, "Size:") {
			pkg.Size = parseFlatpakSize(parseFlatpakValue(line))
		} else if strings.HasPrefix(line, "Origin:") {
			pkg.Repository = parseFlatpakValue(line)
		}
	}

	pkg.Pinned, _ = f.IsPinned(name)

	return pkg, nil
}

func (f *Flatpak) showFromRemote(name string) (*Package, error) {
	out, err := exec.CommandContext(f.ctx, "flatpak", "remote-info", "flathub", name).Output()
	if err != nil {
		return nil, fmt.Errorf("package not found: %s", name)
	}

	pkg := &Package{Name: name, Status: "available"}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Version:") {
			pkg.Version = parseFlatpakValue(line)
		} else if strings.HasPrefix(line, "Arch:") {
			pkg.Architecture = parseFlatpakValue(line)
		} else if strings.HasPrefix(line, "Description:") {
			pkg.Description = parseFlatpakValue(line)
		} else if strings.HasPrefix(line, "Download:") || strings.HasPrefix(line, "Size:") {
			pkg.Size = parseFlatpakSize(parseFlatpakValue(line))
		}
	}
	pkg.Repository = "flathub"

	return pkg, nil
}

// ListVersions lists available versions of a Flatpak application.
// Note: Flatpak typically only has one version per branch in remotes.
func (f *Flatpak) ListVersions(name string) (*VersionInfo, error) {
	info := &VersionInfo{Name: name}
	info.Installed, _ = f.GetInstalledVersion(name)

	// Get available version from remote
	out, err := exec.CommandContext(f.ctx, "flatpak", "remote-info", "flathub", name).Output()
	if err != nil {
		return info, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Version:") {
			version := parseFlatpakValue(line)
			info.Versions = append(info.Versions, AvailableVersion{
				Version:    version,
				Repository: "flathub",
			})
			break
		}
	}

	return info, nil
}

// IsInstalled checks if a Flatpak application is installed.
func (f *Flatpak) IsInstalled(name string) (bool, error) {
	args := []string{"info", name}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}
	err := exec.CommandContext(f.ctx, "flatpak", args...).Run()
	return err == nil, nil
}

// GetInstalledVersion returns the installed version of a Flatpak application.
func (f *Flatpak) GetInstalledVersion(name string) (string, error) {
	args := []string{"info", "--show-version", name}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}
	out, err := exec.CommandContext(f.ctx, "flatpak", args...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// Pin prevents a Flatpak application from being upgraded using mask.
func (f *Flatpak) Pin(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}

	var allOutput strings.Builder
	var lastErr error

	for _, pkg := range packages {
		args := []string{"mask", pkg}
		if f.useSudo {
			args = append(args, "--system")
		} else {
			args = append(args, "--user")
		}
		result, err := f.run(args...)
		if result != nil {
			allOutput.WriteString(result.Stdout)
			allOutput.WriteString(result.Stderr)
		}
		if err != nil {
			lastErr = err
		}
	}

	return &CommandResult{
		Success: lastErr == nil,
		Stdout:  allOutput.String(),
	}, lastErr
}

// Unpin allows a Flatpak application to be upgraded again by removing the mask.
func (f *Flatpak) Unpin(packages ...string) (*CommandResult, error) {
	if len(packages) == 0 {
		return &CommandResult{Success: true}, nil
	}

	var allOutput strings.Builder
	var lastErr error

	for _, pkg := range packages {
		args := []string{"mask", "--remove", pkg}
		if f.useSudo {
			args = append(args, "--system")
		} else {
			args = append(args, "--user")
		}
		result, err := f.run(args...)
		if result != nil {
			allOutput.WriteString(result.Stdout)
			allOutput.WriteString(result.Stderr)
		}
		if err != nil {
			lastErr = err
		}
	}

	return &CommandResult{
		Success: lastErr == nil,
		Stdout:  allOutput.String(),
	}, lastErr
}

// ListPinned lists all masked (pinned) Flatpak applications.
func (f *Flatpak) ListPinned() ([]Package, error) {
	args := []string{"mask"}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}

	out, err := exec.CommandContext(f.ctx, "flatpak", args...).Output()
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
		version, _ := f.GetInstalledVersion(name)
		packages = append(packages, Package{
			Name:    name,
			Version: version,
			Status:  "installed",
			Pinned:  true,
		})
	}
	return packages, nil
}

// IsPinned checks if a Flatpak application is masked (pinned).
func (f *Flatpak) IsPinned(name string) (bool, error) {
	args := []string{"mask"}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}

	out, err := exec.CommandContext(f.ctx, "flatpak", args...).Output()
	if err != nil {
		return false, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == name {
			return true, nil
		}
	}
	return false, nil
}

func (f *Flatpak) getPinnedSet() (map[string]bool, error) {
	args := []string{"mask"}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}

	out, err := exec.CommandContext(f.ctx, "flatpak", args...).Output()
	if err != nil {
		return nil, nil
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

// AddRemote adds a Flatpak remote repository.
func (f *Flatpak) AddRemote(name, url string) (*CommandResult, error) {
	args := []string{"remote-add", "--if-not-exists", name, url}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}
	return f.run(args...)
}

// RemoveRemote removes a Flatpak remote repository.
func (f *Flatpak) RemoveRemote(name string) (*CommandResult, error) {
	args := []string{"remote-delete", "--force", name}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}
	return f.run(args...)
}

// ListRemotes lists configured Flatpak remotes.
func (f *Flatpak) ListRemotes() ([]string, error) {
	args := []string{"remotes", "--columns=name"}
	if f.useSudo {
		args = append(args, "--system")
	} else {
		args = append(args, "--user")
	}

	out, err := exec.CommandContext(f.ctx, "flatpak", args...).Output()
	if err != nil {
		return nil, err
	}

	var remotes []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		name := strings.TrimSpace(scanner.Text())
		if name != "" {
			remotes = append(remotes, name)
		}
	}
	return remotes, nil
}

func (f *Flatpak) run(args ...string) (*CommandResult, error) {
	start := time.Now()

	var c *exec.Cmd
	if f.useSudo {
		sudoArgs := append([]string{"-n", "flatpak"}, args...)
		c = exec.CommandContext(f.ctx, "sudo", sudoArgs...)
	} else {
		c = exec.CommandContext(f.ctx, "flatpak", args...)
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

func parseFlatpakSearchLine(line string) *SearchResult {
	// Format: Name\tDescription\tApplication ID\tVersion\tBranch\tRemotes
	fields := strings.Split(line, "\t")
	if len(fields) < 3 {
		return nil
	}

	return &SearchResult{
		Name:        fields[2], // Application ID
		Description: fields[1], // Description
		Version:     "",
		Repository:  "",
	}
}

func parseFlatpakValue(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func parseFlatpakSize(s string) int64 {
	s = strings.TrimSpace(s)
	multiplier := int64(1)

	// Handle formats like "1.2 GB", "500 MB", "100 kB", "1.5 GiB"
	s = strings.ReplaceAll(s, ",", "")

	if strings.HasSuffix(s, " kB") || strings.HasSuffix(s, " KB") {
		multiplier = 1000
		s = strings.TrimSuffix(strings.TrimSuffix(s, " kB"), " KB")
	} else if strings.HasSuffix(s, " KiB") {
		multiplier = 1024
		s = strings.TrimSuffix(s, " KiB")
	} else if strings.HasSuffix(s, " MB") {
		multiplier = 1000 * 1000
		s = strings.TrimSuffix(s, " MB")
	} else if strings.HasSuffix(s, " MiB") {
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, " MiB")
	} else if strings.HasSuffix(s, " GB") {
		multiplier = 1000 * 1000 * 1000
		s = strings.TrimSuffix(s, " GB")
	} else if strings.HasSuffix(s, " GiB") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, " GiB")
	} else if strings.HasSuffix(s, " bytes") {
		s = strings.TrimSuffix(s, " bytes")
	}

	size, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return int64(size * float64(multiplier))
}
