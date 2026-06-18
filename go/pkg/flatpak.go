package pkg

import (
	"bufio"
	"context"
	"fmt"
	"strconv"
	"strings"

	pmexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// flatpak drives the cross-distro application bundle manager over an injected
// Runner. system selects the --system installation (escalated) over --user
// (unprivileged); see WithUserScope.
type flatpak struct {
	r      pmexec.Runner
	system bool
}

var (
	_ Manager        = (*flatpak)(nil)
	_ FlatpakManager = (*flatpak)(nil)
)

func (f *flatpak) Backend() Backend { return Flatpak }

// scope returns the installation-scope flag for the configured mode.
func (f *flatpak) scope() string {
	if f.system {
		return "--system"
	}
	return "--user"
}

// write runs a privileged flatpak command. It escalates only in system scope;
// --user operations run unprivileged.
func (f *flatpak) write(ctx context.Context, args ...string) error {
	res, err := runPriv(ctx, f.r, f.system, nil, "flatpak", args...)
	if err != nil {
		return err
	}
	return asCommandError("flatpak", res)
}

// Version returns the flatpak version string ("Flatpak 1.14.4").
func (f *flatpak) Version(ctx context.Context) (string, error) {
	out, err := readOut(ctx, f.r, "flatpak", "--version")
	if err != nil {
		return "", err
	}
	parts := strings.Fields(out)
	if len(parts) >= 2 {
		return parts[1], nil
	}
	return "", nil
}

// Install installs application bundles. Flatpak does not support traditional
// version pinning, so opts.Version is validated but ignored (use commits/refs
// for exact version control). All named bundles are installed at latest.
func (f *flatpak) Install(ctx context.Context, opts InstallOptions, packages ...string) error {
	if err := ValidatePackageNames(packages); err != nil {
		return err
	}
	if err := ValidatePackageVersion(opts.Version); err != nil {
		return err
	}
	if len(packages) == 0 {
		return nil
	}
	args := append([]string{"install", "-y", "--noninteractive", f.scope()}, packages...)
	return f.write(ctx, args...)
}

// Remove uninstalls bundles; opts.Purge also deletes per-app data (--delete-data).
func (f *flatpak) Remove(ctx context.Context, opts RemoveOptions, packages ...string) error {
	if err := ValidatePackageNames(packages); err != nil {
		return err
	}
	if len(packages) == 0 {
		return nil
	}
	args := []string{"uninstall", "-y", "--noninteractive"}
	if opts.Purge {
		args = append(args, "--delete-data")
	}
	args = append(args, f.scope())
	args = append(args, packages...)
	return f.write(ctx, args...)
}

// Update refreshes appstream metadata for the configured remotes.
func (f *flatpak) Update(ctx context.Context) error {
	return f.write(ctx, "update", "--appstream", "-y", "--noninteractive", f.scope())
}

// Upgrade updates the named bundles, or all installed bundles with no names.
func (f *flatpak) Upgrade(ctx context.Context, packages ...string) error {
	if err := ValidatePackageNames(packages); err != nil {
		return err
	}
	if len(packages) == 0 {
		return nil // empty is a no-op; UpgradeAll updates everything (flatpak update with no refs)
	}
	args := append([]string{"update", "-y", "--noninteractive", f.scope()}, packages...)
	return f.write(ctx, args...)
}

// UpgradeAll updates every installed app/runtime (flatpak update with no refs).
func (f *flatpak) UpgradeAll(ctx context.Context) error {
	return f.write(ctx, "update", "-y", "--noninteractive", f.scope())
}

// Autoremove removes unused runtimes/extensions (flatpak uninstall --unused).
func (f *flatpak) Autoremove(ctx context.Context) error {
	return f.write(ctx, "uninstall", "--unused", "-y", "--noninteractive", f.scope())
}

// Repair runs `flatpak repair`, restoring a consistent installation state.
func (f *flatpak) Repair(ctx context.Context) error {
	if err := f.write(ctx, "repair", f.scope()); err != nil {
		return repairErr(ctx, "flatpak repair failed", err)
	}
	return nil
}

// Search searches configured remotes (exit 1 = no matches).
func (f *flatpak) Search(ctx context.Context, query string) ([]SearchResult, error) {
	res, err := runRead(ctx, f.r, "flatpak", "search", query)
	if err != nil {
		return nil, err
	}
	if res.ExitCode == 1 {
		return nil, nil
	}
	if res.ExitCode != 0 {
		return nil, asCommandError("flatpak", res)
	}

	var results []SearchResult
	scanner := bufio.NewScanner(strings.NewReader(res.Stdout))
	// The first line is a header iff it has no tab; otherwise it is data.
	if scanner.Scan() {
		first := scanner.Text()
		if strings.Contains(first, "\t") {
			if r := parseFlatpakSearchLine(first); r != nil {
				results = append(results, *r)
			}
		}
	}
	for scanner.Scan() {
		if r := parseFlatpakSearchLine(scanner.Text()); r != nil {
			results = append(results, *r)
		}
	}
	return results, nil
}

// List lists installed application bundles.
func (f *flatpak) List(ctx context.Context) ([]Package, error) {
	out, err := readOut(ctx, f.r, "flatpak", "list",
		"--columns=application,version,arch,size,description,origin", f.scope())
	if err != nil {
		return nil, err
	}

	pinned, err := f.getPinnedSet(ctx)
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
			Size:         parseFlatpakSize(fields[3]),
			Description:  desc,
			Repository:   repo,
			Pinned:       pinned[fields[0]],
		})
	}
	return packages, nil
}

// ListUpgradable lists bundles with an available update.
func (f *flatpak) ListUpgradable(ctx context.Context) ([]PackageUpdate, error) {
	out, err := readOut(ctx, f.r, "flatpak", "remote-ls", "--updates",
		"--columns=application,version,origin", f.scope())
	if err != nil {
		return nil, err
	}

	var updates []PackageUpdate
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 2 {
			continue
		}
		repo := ""
		if len(fields) > 2 {
			repo = fields[2]
		}
		current, err := f.InstalledVersion(ctx, fields[0])
		if err != nil {
			return nil, err
		}
		updates = append(updates, PackageUpdate{
			Name:           fields[0],
			NewVersion:     fields[1],
			CurrentVersion: current,
			Repository:     repo,
		})
	}
	return updates, nil
}

// Show returns detailed information about a bundle, falling back to the flathub
// remote when the bundle is not installed.
func (f *flatpak) Show(ctx context.Context, name string) (*Package, error) {
	if err := ValidatePackageName(name); err != nil {
		return nil, err
	}
	// A non-zero `flatpak info` exit means the bundle is not installed locally —
	// fall back to the remote. A runner/context failure propagates.
	out, ok, err := probe(ctx, f.r, "flatpak", "info", name, f.scope())
	if err != nil {
		return nil, err
	}
	if !ok {
		return f.showFromRemote(ctx, name)
	}

	pkg := &Package{Name: name, Status: "installed"}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Version:"):
			pkg.Version = parseFlatpakValue(line)
		case strings.HasPrefix(line, "Arch:"):
			pkg.Architecture = parseFlatpakValue(line)
		case strings.HasPrefix(line, "Description:"):
			pkg.Description = parseFlatpakValue(line)
		case strings.HasPrefix(line, "Installed:"), strings.HasPrefix(line, "Size:"):
			pkg.Size = parseFlatpakSize(parseFlatpakValue(line))
		case strings.HasPrefix(line, "Origin:"):
			pkg.Repository = parseFlatpakValue(line)
		}
	}

	pinned, err := f.IsPinned(ctx, name)
	if err != nil {
		return nil, err
	}
	pkg.Pinned = pinned
	return pkg, nil
}

func (f *flatpak) showFromRemote(ctx context.Context, name string) (*Package, error) {
	// A runner/context failure propagates; a non-zero exit means the bundle is
	// not offered by the remote.
	out, ok, err := probe(ctx, f.r, "flatpak", "remote-info", "flathub", name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("package not found: %s", name)
	}

	pkg := &Package{Name: name, Status: "available", Repository: "flathub"}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Version:"):
			pkg.Version = parseFlatpakValue(line)
		case strings.HasPrefix(line, "Arch:"):
			pkg.Architecture = parseFlatpakValue(line)
		case strings.HasPrefix(line, "Description:"):
			pkg.Description = parseFlatpakValue(line)
		case strings.HasPrefix(line, "Download:"), strings.HasPrefix(line, "Size:"):
			pkg.Size = parseFlatpakSize(parseFlatpakValue(line))
		}
	}
	return pkg, nil
}

// ListVersions reports the single remote (flathub) version for a bundle.
func (f *flatpak) ListVersions(ctx context.Context, name string) (*VersionInfo, error) {
	if err := ValidatePackageName(name); err != nil {
		return nil, err
	}
	info := &VersionInfo{Name: name}
	installed, err := f.InstalledVersion(ctx, name)
	if err != nil {
		return nil, err
	}
	info.Installed = installed

	out, ok, err := probe(ctx, f.r, "flatpak", "remote-info", "flathub", name)
	if err != nil {
		return nil, err // runner/context failure
	}
	if !ok {
		return info, nil // not available on flathub
	}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		if line := scanner.Text(); strings.HasPrefix(line, "Version:") {
			info.Versions = append(info.Versions, AvailableVersion{
				Version:    parseFlatpakValue(line),
				Repository: "flathub",
			})
			break
		}
	}
	return info, nil
}

// IsInstalled reports whether a bundle is installed (flatpak info exits 0).
func (f *flatpak) IsInstalled(ctx context.Context, name string) (bool, error) {
	if err := ValidatePackageName(name); err != nil {
		return false, err
	}
	res, err := runRead(ctx, f.r, "flatpak", "info", name, f.scope())
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// InstalledVersion returns the installed version of a bundle, or "" if absent.
func (f *flatpak) InstalledVersion(ctx context.Context, name string) (string, error) {
	if err := ValidatePackageName(name); err != nil {
		return "", err
	}
	res, err := runRead(ctx, f.r, "flatpak", "info", "--show-version", name, f.scope())
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", nil
	}
	return strings.TrimSpace(res.Stdout), nil
}

// InstalledCount returns the number of installed bundles.
func (f *flatpak) InstalledCount(ctx context.Context) (int, error) {
	out, err := readOut(ctx, f.r, "flatpak", "list", "--columns=application", f.scope())
	if err != nil {
		return 0, err
	}
	return countNonEmptyLines(out), nil
}

// HasUpdates reports whether any bundle has an available update. Flatpak has no
// security-only feed, so securityOnly is ignored.
func (f *flatpak) HasUpdates(ctx context.Context, securityOnly bool) (bool, error) {
	_ = securityOnly
	out, err := readOut(ctx, f.r, "flatpak", "remote-ls", "--updates", "--columns=application", f.scope())
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) != "", nil
}

// Pin masks bundles so they are held back from updates. Best-effort across the
// set: every bundle is attempted and the last error (if any) is returned.
func (f *flatpak) Pin(ctx context.Context, packages ...string) error {
	if err := ValidatePackageNames(packages); err != nil {
		return err
	}
	var lastErr error
	for _, name := range packages {
		if err := f.write(ctx, "mask", name, f.scope()); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// Unpin removes the mask so bundles update again.
func (f *flatpak) Unpin(ctx context.Context, packages ...string) error {
	if err := ValidatePackageNames(packages); err != nil {
		return err
	}
	var lastErr error
	for _, name := range packages {
		if err := f.write(ctx, "mask", "--remove", name, f.scope()); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// ListPinned lists masked bundles.
func (f *flatpak) ListPinned(ctx context.Context) ([]Package, error) {
	out, err := readOut(ctx, f.r, "flatpak", "mask", f.scope())
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
		version, err := f.InstalledVersion(ctx, name)
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

// IsPinned reports whether a bundle is masked.
func (f *flatpak) IsPinned(ctx context.Context, name string) (bool, error) {
	if err := ValidatePackageName(name); err != nil {
		return false, err
	}
	out, ok, err := probe(ctx, f.r, "flatpak", "mask", f.scope())
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == name {
			return true, nil
		}
	}
	return false, nil
}

func (f *flatpak) getPinnedSet(ctx context.Context) (map[string]bool, error) {
	out, ok, err := probe(ctx, f.r, "flatpak", "mask", f.scope())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
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

// AddRemote registers a flatpak remote. name must be a valid remote alias and
// url an https repository URL (validated to keep flag/metacharacter and
// plaintext-transport inputs off the argv and out of the trust path).
func (f *flatpak) AddRemote(ctx context.Context, name, url string) error {
	if err := ValidateRemoteName(name); err != nil {
		return err
	}
	if err := ValidateRepoBaseURL(url); err != nil {
		return err
	}
	return f.write(ctx, "remote-add", "--if-not-exists", name, url, f.scope())
}

// RemoveRemote deletes a flatpak remote.
func (f *flatpak) RemoveRemote(ctx context.Context, name string) error {
	if err := ValidateRemoteName(name); err != nil {
		return err
	}
	return f.write(ctx, "remote-delete", "--force", name, f.scope())
}

// ListRemotes returns the configured flatpak remote names.
func (f *flatpak) ListRemotes(ctx context.Context) ([]string, error) {
	out, err := readOut(ctx, f.r, "flatpak", "remotes", "--columns=name", f.scope())
	if err != nil {
		return nil, err
	}
	var remotes []string
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		if name := strings.TrimSpace(scanner.Text()); name != "" {
			remotes = append(remotes, name)
		}
	}
	return remotes, nil
}

func parseFlatpakSearchLine(line string) *SearchResult {
	// Name\tDescription\tApplication ID\tVersion\tBranch\tRemotes
	fields := strings.Split(line, "\t")
	if len(fields) < 3 {
		return nil
	}
	return &SearchResult{
		Name:        fields[2], // application ID
		Description: fields[1],
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
	s = strings.ReplaceAll(strings.TrimSpace(s), ",", "")
	multiplier := int64(1)
	switch {
	case strings.HasSuffix(s, " kB"), strings.HasSuffix(s, " KB"):
		multiplier = 1000
		s = strings.TrimSuffix(strings.TrimSuffix(s, " kB"), " KB")
	case strings.HasSuffix(s, " KiB"):
		multiplier = 1024
		s = strings.TrimSuffix(s, " KiB")
	case strings.HasSuffix(s, " MB"):
		multiplier = 1000 * 1000
		s = strings.TrimSuffix(s, " MB")
	case strings.HasSuffix(s, " MiB"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, " MiB")
	case strings.HasSuffix(s, " GB"):
		multiplier = 1000 * 1000 * 1000
		s = strings.TrimSuffix(s, " GB")
	case strings.HasSuffix(s, " GiB"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, " GiB")
	case strings.HasSuffix(s, " bytes"):
		s = strings.TrimSuffix(s, " bytes")
	}
	size, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return int64(size * float64(multiplier))
}
