package pkg

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"

	pmexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// apt drives the Debian/Ubuntu package manager (apt / apt-get / dpkg / apt-mark)
// over an injected Runner.
type apt struct {
	r       pmexec.Runner
	cmdOnce sync.Once
	aptCmd  string // cached "apt" or "apt-get"
}

var _ Manager = (*apt)(nil)

// aptWriteEnv prevents debconf from attempting an interactive frontend when
// there is no terminal. The C locale is forced separately via Command.CLocale.
var aptWriteEnv = []string{"DEBIAN_FRONTEND=noninteractive"}

// dpkgConfOptions keep dpkg non-interactive when a postinst would otherwise
// prompt about a changed conffile (kernel/grub upgrades):
//   - --force-confdef: take the default action for new conffiles
//   - --force-confold: keep the currently-installed version if user-modified
var dpkgConfOptions = []string{
	"-o", "Dpkg::Options::=--force-confdef",
	"-o", "Dpkg::Options::=--force-confold",
}

func (a *apt) Backend() Backend { return Apt }

// aptCommand returns "apt" when available, else "apt-get" (cached).
func (a *apt) aptCommand() string {
	a.cmdOnce.Do(func() {
		if _, err := lookPath("apt"); err == nil {
			a.aptCmd = "apt"
		} else {
			a.aptCmd = "apt-get"
		}
	})
	return a.aptCmd
}

func (a *apt) hasApt() bool { return a.aptCommand() == "apt" }

// write runs a privileged apt-family command and maps a non-zero exit to an
// *exec.CommandError. "apt"/"apt-get" are resolved to the preferred binary;
// other commands (dpkg, apt-mark) run as named.
func (a *apt) write(ctx context.Context, cmd string, args ...string) error {
	if cmd == "apt" || cmd == "apt-get" {
		cmd = a.aptCommand()
	}
	res, err := runPriv(ctx, a.r, true, aptWriteEnv, cmd, args...)
	if err != nil {
		return err
	}
	return asCommandError(cmd, res)
}

// Version returns the apt version string.
func (a *apt) Version(ctx context.Context) (string, error) {
	out, err := readOut(ctx, a.r, "apt", "--version")
	if err != nil {
		return "", err
	}
	parts := strings.Fields(out)
	if len(parts) >= 2 {
		return parts[1], nil
	}
	return "", nil
}

// Install installs packages, using --fix-broken to resolve dependency issues.
func (a *apt) Install(ctx context.Context, opts InstallOptions, packages ...string) error {
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
	args := []string{"install", "-y", "--fix-broken"}
	if opts.AllowDowngrade {
		args = append(args, "--allow-downgrades")
	}
	if opts.Version != "" {
		args = append(args, fmt.Sprintf("%s=%s", packages[0], opts.Version))
	} else {
		args = append(args, packages...)
	}
	return a.write(ctx, "apt", args...)
}

// Remove removes packages; opts.Purge deletes configuration files too.
func (a *apt) Remove(ctx context.Context, opts RemoveOptions, packages ...string) error {
	if err := ValidatePackageNames(packages); err != nil {
		return err
	}
	if len(packages) == 0 {
		return nil
	}
	verb := "remove"
	if opts.Purge {
		verb = "purge"
	}
	args := append([]string{verb, "-y"}, packages...)
	return a.write(ctx, "apt", args...)
}

// Update refreshes the package index.
func (a *apt) Update(ctx context.Context) error {
	return a.write(ctx, "apt", "update")
}

// Upgrade upgrades the named packages; with no names it runs a full
// dist-upgrade (which can add/remove packages to satisfy held-back deps).
func (a *apt) Upgrade(ctx context.Context, packages ...string) error {
	if err := ValidatePackageNames(packages); err != nil {
		return err
	}
	if len(packages) == 0 {
		args := append([]string{"dist-upgrade", "-y"}, dpkgConfOptions...)
		return a.write(ctx, "apt", args...)
	}
	args := append([]string{"install", "-y", "--only-upgrade"}, dpkgConfOptions...)
	args = append(args, packages...)
	return a.write(ctx, "apt", args...)
}

// Pin holds packages (apt-mark hold).
func (a *apt) Pin(ctx context.Context, packages ...string) error {
	if err := ValidatePackageNames(packages); err != nil {
		return err
	}
	if len(packages) == 0 {
		return nil
	}
	return a.write(ctx, "apt-mark", append([]string{"hold"}, packages...)...)
}

// Unpin releases held packages (apt-mark unhold).
func (a *apt) Unpin(ctx context.Context, packages ...string) error {
	if err := ValidatePackageNames(packages); err != nil {
		return err
	}
	if len(packages) == 0 {
		return nil
	}
	return a.write(ctx, "apt-mark", append([]string{"unhold"}, packages...)...)
}

// Autoremove removes packages installed only as now-unneeded dependencies.
func (a *apt) Autoremove(ctx context.Context) error {
	return a.write(ctx, "apt", "autoremove", "-y")
}

// Repair clears stale dpkg/apt locks, reconfigures interrupted packages, fixes
// broken dependencies, and refreshes the index.
func (a *apt) Repair(ctx context.Context) error {
	for _, lf := range []string{
		"/var/lib/dpkg/lock",
		"/var/lib/dpkg/lock-frontend",
		"/var/lib/apt/lists/lock",
		"/var/cache/apt/archives/lock",
	} {
		if err := removeStaleLock(ctx, a.r, lf); err != nil {
			return err
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.write(ctx, "dpkg", "--configure", "-a"); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		slog.Warn("dpkg --configure -a failed", "error", err)
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	args := append([]string{"--fix-broken", "install", "-y"}, dpkgConfOptions...)
	if err := a.write(ctx, "apt", args...); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		slog.Warn("apt --fix-broken install failed", "error", err)
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.write(ctx, "apt", "update"); err != nil {
		return repairErr(ctx, "apt update failed", err)
	}
	return nil
}

// Search searches package names.
func (a *apt) Search(ctx context.Context, query string) ([]SearchResult, error) {
	var out string
	var err error
	if a.hasApt() {
		out, err = readOut(ctx, a.r, "apt", "search", "--names-only", query)
	} else {
		out, err = readOut(ctx, a.r, "apt-cache", "search", query)
	}
	if err != nil {
		return nil, err
	}

	var results []SearchResult
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), " - ", 2)
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
func (a *apt) List(ctx context.Context) ([]Package, error) {
	out, err := readOut(ctx, a.r, "dpkg-query", "-W",
		"-f=${Package}\t${Version}\t${Architecture}\t${Status}\t${Installed-Size}\t${Description}\n")
	if err != nil {
		return nil, err
	}

	pinned, _ := a.getPinnedSet(ctx)

	var packages []Package
	scanner := bufio.NewScanner(strings.NewReader(out))
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
		packages = append(packages, Package{
			Name:         fields[0],
			Version:      fields[1],
			Architecture: fields[2],
			Status:       "installed",
			Size:         size * 1024,
			Description:  desc,
			Pinned:       pinned[fields[0]],
		})
	}
	return packages, nil
}

var aptUpgradableRe = regexp.MustCompile(`^([^/]+)/(\S+)\s+(\S+)\s+(\S+)\s+\[upgradable from: ([^\]]+)\]`)

// ListUpgradable lists packages with an available upgrade.
func (a *apt) ListUpgradable(ctx context.Context) ([]PackageUpdate, error) {
	out, err := readOut(ctx, a.r, "apt", "list", "--upgradable")
	if err != nil {
		return nil, err
	}

	var updates []PackageUpdate
	scanner := bufio.NewScanner(strings.NewReader(out))
	scanner.Scan() // skip header
	for scanner.Scan() {
		m := aptUpgradableRe.FindStringSubmatch(scanner.Text())
		if len(m) < 6 {
			continue
		}
		updates = append(updates, PackageUpdate{
			Name:           m[1],
			Repository:     m[2],
			NewVersion:     m[3],
			Architecture:   m[4],
			CurrentVersion: m[5],
		})
	}
	return updates, nil
}

// Show returns detailed information about a package.
func (a *apt) Show(ctx context.Context, name string) (*Package, error) {
	if err := ValidatePackageName(name); err != nil {
		return nil, err
	}
	cmd := "apt-cache"
	if a.hasApt() {
		cmd = "apt"
	}
	out, err := readOut(ctx, a.r, cmd, "show", name)
	if err != nil {
		return nil, err
	}

	pkg := &Package{Name: name}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Version:"):
			pkg.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		case strings.HasPrefix(line, "Architecture:"):
			pkg.Architecture = strings.TrimSpace(strings.TrimPrefix(line, "Architecture:"))
		case strings.HasPrefix(line, "Description:"):
			pkg.Description = strings.TrimSpace(strings.TrimPrefix(line, "Description:"))
		case strings.HasPrefix(line, "Installed-Size:"):
			if size, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "Installed-Size:")), 10, 64); err == nil {
				pkg.Size = size * 1024
			}
		}
	}

	if installed, _ := a.IsInstalled(ctx, name); installed {
		pkg.Status = "installed"
	} else {
		pkg.Status = "available"
	}
	if pinned, err := a.IsPinned(ctx, name); err != nil {
		slog.Debug("failed to check pin status", "package", name, "error", err)
	} else {
		pkg.Pinned = pinned
	}
	return pkg, nil
}

// ListVersions lists the versions available for a package.
func (a *apt) ListVersions(ctx context.Context, name string) (*VersionInfo, error) {
	if err := ValidatePackageName(name); err != nil {
		return nil, err
	}
	out, err := readOut(ctx, a.r, "apt-cache", "madison", name)
	if err != nil {
		return nil, err
	}

	info := &VersionInfo{Name: name}
	if installed, err := a.InstalledVersion(ctx, name); err != nil {
		slog.Debug("failed to get installed version", "package", name, "error", err)
	} else {
		info.Installed = installed
	}

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "|") // package | version | repository
		if len(fields) < 3 {
			continue
		}
		version := strings.TrimSpace(fields[1])
		if seen[version] {
			continue
		}
		seen[version] = true
		info.Versions = append(info.Versions, AvailableVersion{
			Version:    version,
			Repository: strings.TrimSpace(fields[2]),
		})
	}
	return info, nil
}

// IsInstalled reports whether a package is installed (dpkg -s exits 0).
func (a *apt) IsInstalled(ctx context.Context, name string) (bool, error) {
	if err := ValidatePackageName(name); err != nil {
		return false, err
	}
	res, err := runRead(ctx, a.r, "dpkg", "-s", name)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// InstalledVersion returns the installed version of a package, or "" if absent.
func (a *apt) InstalledVersion(ctx context.Context, name string) (string, error) {
	if err := ValidatePackageName(name); err != nil {
		return "", err
	}
	out, err := readOut(ctx, a.r, "dpkg-query", "-W", "-f=${Version}", name)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// InstalledCount returns the number of installed packages.
func (a *apt) InstalledCount(ctx context.Context) (int, error) {
	out, err := readOut(ctx, a.r, "dpkg-query", "-f", ".\n", "-W")
	if err != nil {
		return 0, err
	}
	return countNonEmptyLines(out), nil
}

// HasUpdates reports whether any package can be upgraded. apt has no reliable
// security-only filter, so securityOnly is accepted but not honored here.
func (a *apt) HasUpdates(ctx context.Context, securityOnly bool) (bool, error) {
	_ = securityOnly
	out, err := readOut(ctx, a.r, a.aptCommand(), "-s", "upgrade")
	if err != nil {
		return false, err
	}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "Inst ") {
			return true, nil
		}
	}
	return false, nil
}

// IsPinned reports whether a package is held (apt-mark showhold <name>).
func (a *apt) IsPinned(ctx context.Context, name string) (bool, error) {
	if err := ValidatePackageName(name); err != nil {
		return false, err
	}
	out, err := readOut(ctx, a.r, "apt-mark", "showhold", name)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == name, nil
}

// ListPinned lists held packages.
func (a *apt) ListPinned(ctx context.Context) ([]Package, error) {
	out, err := readOut(ctx, a.r, "apt-mark", "showhold")
	if err != nil {
		return nil, err
	}

	var packages []Package
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		name := strings.TrimSpace(scanner.Text())
		if name == "" {
			continue
		}
		version, _ := a.InstalledVersion(ctx, name)
		packages = append(packages, Package{
			Name:    name,
			Version: version,
			Status:  "installed",
			Pinned:  true,
		})
	}
	return packages, nil
}

func (a *apt) getPinnedSet(ctx context.Context) (map[string]bool, error) {
	out, err := readOut(ctx, a.r, "apt-mark", "showhold")
	if err != nil {
		return nil, err
	}
	pinned := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		if name := strings.TrimSpace(scanner.Text()); name != "" {
			pinned[name] = true
		}
	}
	return pinned, nil
}
