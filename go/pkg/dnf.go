package pkg

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	pmexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// dnf drives the Fedora/RHEL package manager (dnf / rpm) over an injected Runner.
type dnf struct {
	r pmexec.Runner
}

var _ Manager = (*dnf)(nil)

// nevraVersionRe matches the first dash-then-digit in an NEVRA string, marking
// the boundary between the package name and its version.
var nevraVersionRe = regexp.MustCompile(`-\d`)

// parseNEVRAName extracts the package name from an NEVRA string
// (Name-[Epoch:]Version-Release[.Arch]).
func parseNEVRAName(nevra string) string {
	loc := nevraVersionRe.FindStringIndex(nevra)
	if loc == nil {
		return nevra
	}
	return nevra[:loc[0]]
}

func (d *dnf) Backend() Backend { return Dnf }

// write runs a privileged dnf command and maps a non-zero exit to an error.
func (d *dnf) write(ctx context.Context, args ...string) error {
	res, err := runPriv(ctx, d.r, true, nil, "dnf", args...)
	if err != nil {
		return err
	}
	return asCommandError("dnf", res)
}

// Version returns the dnf version string.
func (d *dnf) Version(ctx context.Context) (string, error) {
	out, err := readOut(ctx, d.r, "dnf", "--version")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]), nil
}

// Install installs packages. opts.Version pins a single package (dnf name-version
// form); opts.AllowDowngrade adds --allowerasing and, on failure, retries an
// explicit `dnf downgrade`.
func (d *dnf) Install(ctx context.Context, opts InstallOptions, packages ...string) error {
	if err := ValidatePackageNames(packages); err != nil {
		return err
	}
	if err := ValidatePackageVersion(opts.Version); err != nil {
		return err
	}
	if opts.Version != "" && len(packages) != 1 {
		return fmt.Errorf("pkg: InstallOptions.Version requires exactly one package, got %d", len(packages))
	}
	if len(packages) == 0 {
		return nil
	}
	args := []string{"install", "-y"}
	if opts.AllowDowngrade {
		args = append(args, "--allowerasing")
	}
	var pkgSpec string
	if opts.Version != "" {
		pkgSpec = fmt.Sprintf("%s-%s", packages[0], opts.Version)
		args = append(args, pkgSpec)
	} else {
		args = append(args, packages...)
	}

	err := d.write(ctx, args...)
	// Only retry as an explicit downgrade when dnf itself rejected the install
	// (a non-zero exit). An exec/escalation/context failure must not trigger a
	// second escalated command.
	var ce *pmexec.CommandError
	if errors.As(err, &ce) && opts.AllowDowngrade && opts.Version != "" {
		return d.write(ctx, "downgrade", "-y", pkgSpec)
	}
	return err
}

// Remove removes packages. dnf has no purge concept, so opts.Purge is a no-op.
func (d *dnf) Remove(ctx context.Context, _ RemoveOptions, packages ...string) error {
	if err := ValidatePackageNames(packages); err != nil {
		return err
	}
	if len(packages) == 0 {
		return nil
	}
	return d.write(ctx, append([]string{"remove", "-y"}, packages...)...)
}

// Update refreshes metadata via `dnf check-update` (exit 100 = updates available
// is a success, not an error).
func (d *dnf) Update(ctx context.Context) error {
	res, err := runPriv(ctx, d.r, true, nil, "dnf", "check-update")
	if err != nil {
		return err
	}
	if res.ExitCode == 0 || res.ExitCode == 100 {
		return nil
	}
	return asCommandError("dnf", res)
}

// Upgrade upgrades the named packages, or all packages with no names.
func (d *dnf) Upgrade(ctx context.Context, packages ...string) error {
	if err := ValidatePackageNames(packages); err != nil {
		return err
	}
	if len(packages) == 0 {
		return nil // empty is a no-op; UpgradeAll does a full upgrade
	}
	return d.write(ctx, append([]string{"upgrade", "-y"}, packages...)...)
}

// UpgradeAll performs a full system upgrade (dnf upgrade).
func (d *dnf) UpgradeAll(ctx context.Context) error {
	return d.write(ctx, "upgrade", "-y")
}

// ensureVersionLock installs the versionlock plugin if its subcommand is absent.
func (d *dnf) ensureVersionLock(ctx context.Context) error {
	_, ok, err := probe(ctx, d.r, "dnf", "versionlock", "--help")
	if err != nil {
		return err // runner/context failure — do not escalate into a plugin install
	}
	if ok {
		return nil // plugin already present
	}
	return d.write(ctx, "install", "-y", "python3-dnf-plugin-versionlock")
}

// Pin holds packages back (dnf versionlock add), installing the plugin if needed.
func (d *dnf) Pin(ctx context.Context, packages ...string) error {
	if err := ValidatePackageNames(packages); err != nil {
		return err
	}
	if len(packages) == 0 {
		return nil
	}
	if err := d.ensureVersionLock(ctx); err != nil {
		return err
	}
	return d.write(ctx, append([]string{"versionlock", "add"}, packages...)...)
}

// Unpin releases held packages (dnf versionlock delete).
func (d *dnf) Unpin(ctx context.Context, packages ...string) error {
	if err := ValidatePackageNames(packages); err != nil {
		return err
	}
	if len(packages) == 0 {
		return nil
	}
	if err := d.ensureVersionLock(ctx); err != nil {
		return err
	}
	return d.write(ctx, append([]string{"versionlock", "delete"}, packages...)...)
}

// Autoremove removes packages installed only as now-unneeded dependencies.
func (d *dnf) Autoremove(ctx context.Context) error {
	return d.write(ctx, "autoremove", "-y")
}

// Repair re-runs the last transaction, drops duplicate packages, and verifies
// the rpm database. Every step is best-effort (logged, not fatal) except a
// context cancellation, which short-circuits.
func (d *dnf) Repair(ctx context.Context) error {
	steps := []struct {
		what string
		run  func() error
	}{
		{"dnf history redo last", func() error { return d.write(ctx, "history", "redo", "last", "-y") }},
		{"dnf remove --duplicates", func() error { return d.write(ctx, "remove", "--duplicates", "-y") }},
		{"rpm --verifydb", func() error { _, err := readOut(ctx, d.r, "rpm", "--verifydb"); return err }},
	}
	for _, s := range steps {
		if err := bestEffortStep(ctx, s.what, s.run()); err != nil {
			return err
		}
	}
	return nil
}

// Search searches package names/summaries (exit 1 = no matches).
func (d *dnf) Search(ctx context.Context, query string) ([]SearchResult, error) {
	res, err := runRead(ctx, d.r, "dnf", "search", "-q", query)
	if err != nil {
		return nil, err
	}
	if res.ExitCode == 1 {
		return nil, nil
	}
	if res.ExitCode != 0 {
		return nil, asCommandError("dnf", res)
	}

	var results []SearchResult
	scanner := bufio.NewScanner(strings.NewReader(res.Stdout))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "=") || line == "" {
			continue
		}
		parts := strings.SplitN(line, " : ", 2)
		if len(parts) < 2 {
			continue
		}
		name := strings.SplitN(parts[0], ".", 2)[0]
		results = append(results, SearchResult{
			Name:        name,
			Description: strings.TrimSpace(parts[1]),
		})
	}
	return results, nil
}

// List lists installed packages.
func (d *dnf) List(ctx context.Context) ([]Package, error) {
	out, err := readOut(ctx, d.r, "rpm", "-qa", "--queryformat",
		"%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SIZE}\t%{SUMMARY}\n")
	if err != nil {
		return nil, err
	}

	pinned, err := d.getPinnedSet(ctx)
	if err != nil {
		return nil, err
	}

	var packages []Package
	scanner := bufio.NewScanner(strings.NewReader(out))
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
			Pinned:       pinned[fields[0]],
		})
	}
	return packages, nil
}

// ListUpgradable lists packages with an available upgrade (check-update exit 100).
func (d *dnf) ListUpgradable(ctx context.Context) ([]PackageUpdate, error) {
	res, err := runRead(ctx, d.r, "dnf", "check-update", "-q")
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 && res.ExitCode != 100 {
		return nil, asCommandError("dnf", res)
	}

	var updates []PackageUpdate
	scanner := bufio.NewScanner(strings.NewReader(res.Stdout))
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
		current, err := d.InstalledVersion(ctx, name)
		if err != nil {
			return nil, err
		}
		updates = append(updates, PackageUpdate{
			Name:           name,
			Architecture:   arch,
			NewVersion:     fields[1],
			Repository:     fields[2],
			CurrentVersion: current,
		})
	}
	return updates, nil
}

// Show returns detailed information about a package.
func (d *dnf) Show(ctx context.Context, name string) (*Package, error) {
	if err := ValidatePackageName(name); err != nil {
		return nil, err
	}
	out, err := readOut(ctx, d.r, "dnf", "info", "-q", name)
	if err != nil {
		return nil, err
	}

	pkg := &Package{Name: name, Status: "available"}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Version"):
			pkg.Version = parseValue(line)
		case strings.HasPrefix(line, "Release"):
			if pkg.Version != "" {
				pkg.Version += "-" + parseValue(line)
			}
		case strings.HasPrefix(line, "Architecture"):
			pkg.Architecture = parseValue(line)
		case strings.HasPrefix(line, "Size"):
			pkg.Size = parseSize(parseValue(line))
		case strings.HasPrefix(line, "Summary"):
			pkg.Description = parseValue(line)
		case strings.HasPrefix(line, "Repository"):
			pkg.Repository = parseValue(line)
		}
	}

	installed, err := d.IsInstalled(ctx, name)
	if err != nil {
		return nil, err
	}
	if installed {
		pkg.Status = "installed"
	}
	pinned, err := d.IsPinned(ctx, name)
	if err != nil {
		return nil, err
	}
	pkg.Pinned = pinned
	return pkg, nil
}

// ListVersions lists the versions available for a package.
func (d *dnf) ListVersions(ctx context.Context, name string) (*VersionInfo, error) {
	if err := ValidatePackageName(name); err != nil {
		return nil, err
	}
	out, err := readOut(ctx, d.r, "dnf", "list", "--showduplicates", "-q", name)
	if err != nil {
		return nil, err
	}

	info := &VersionInfo{Name: name}
	installed, err := d.InstalledVersion(ctx, name)
	if err != nil {
		return nil, err
	}
	info.Installed = installed

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "Installed") || strings.HasPrefix(line, "Available") {
			continue
		}
		fields := strings.Fields(line) // name.arch  version  repo
		if len(fields) < 3 {
			continue
		}
		version := fields[1]
		if seen[version] {
			continue
		}
		seen[version] = true
		info.Versions = append(info.Versions, AvailableVersion{
			Version:    version,
			Repository: fields[2],
		})
	}
	return info, nil
}

// IsInstalled reports whether a package is installed (rpm -q exits 0).
func (d *dnf) IsInstalled(ctx context.Context, name string) (bool, error) {
	if err := ValidatePackageName(name); err != nil {
		return false, err
	}
	res, err := runRead(ctx, d.r, "rpm", "-q", name)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// InstalledVersion returns the installed version of a package, or "" if absent.
func (d *dnf) InstalledVersion(ctx context.Context, name string) (string, error) {
	if err := ValidatePackageName(name); err != nil {
		return "", err
	}
	res, err := runRead(ctx, d.r, "rpm", "-q", "--queryformat", "%{VERSION}-%{RELEASE}", name)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", nil // not installed
	}
	return strings.TrimSpace(res.Stdout), nil
}

// InstalledCount returns the number of installed packages.
func (d *dnf) InstalledCount(ctx context.Context) (int, error) {
	out, err := readOut(ctx, d.r, "rpm", "-qa", "--qf", ".\n")
	if err != nil {
		return 0, err
	}
	return countNonEmptyLines(out), nil
}

// HasUpdates reports whether updates are available (dnf check-update exit 100).
func (d *dnf) HasUpdates(ctx context.Context, securityOnly bool) (bool, error) {
	args := []string{"check-update", "-q"}
	if securityOnly {
		args = append(args, "--security")
	}
	res, err := runRead(ctx, d.r, "dnf", args...)
	if err != nil {
		return false, err
	}
	switch res.ExitCode {
	case 0:
		return false, nil
	case 100:
		return true, nil
	default:
		return false, asCommandError("dnf", res)
	}
}

// IsPinned reports whether a package is versionlocked. Tolerant of an absent
// plugin (reports false rather than erroring).
func (d *dnf) IsPinned(ctx context.Context, name string) (bool, error) {
	if err := ValidatePackageName(name); err != nil {
		return false, err
	}
	out, ok, err := probe(ctx, d.r, "dnf", "versionlock", "list", "-q")
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil // versionlock plugin absent → not pinned
	}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" && parseNEVRAName(line) == name {
			return true, nil
		}
	}
	return false, nil
}

// ListPinned lists versionlocked packages (installing the plugin if needed).
func (d *dnf) ListPinned(ctx context.Context) ([]Package, error) {
	if err := d.ensureVersionLock(ctx); err != nil {
		return nil, err
	}
	out, err := readOut(ctx, d.r, "dnf", "versionlock", "list", "-q")
	if err != nil {
		return nil, err
	}

	var packages []Package
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		name := parseNEVRAName(line)
		version, err := d.InstalledVersion(ctx, name)
		if err != nil {
			return nil, err
		}
		packages = append(packages, Package{
			Name:    name,
			Version: version,
			Status:  "installed",
			Pinned:  true,
		})
	}
	return packages, nil
}

func (d *dnf) getPinnedSet(ctx context.Context) (map[string]bool, error) {
	out, ok, err := probe(ctx, d.r, "dnf", "versionlock", "list", "-q")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil // versionlock plugin absent → nothing pinned
	}
	pinned := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			pinned[parseNEVRAName(line)] = true
		}
	}
	return pinned, nil
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
	switch {
	case strings.HasSuffix(s, " k"), strings.HasSuffix(s, " K"):
		multiplier = 1024
		s = strings.TrimSuffix(strings.TrimSuffix(s, " k"), " K")
	case strings.HasSuffix(s, " M"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, " M")
	case strings.HasSuffix(s, " G"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, " G")
	}
	size, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return int64(size * float64(multiplier))
}
