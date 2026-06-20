package pkg

import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// validPacmanPkgName restricts IgnorePkg values to safe characters, preventing
// config injection via pacman.conf even after ValidatePackageName has passed.
var validPacmanPkgName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+-]*$`)

// pacman drives the Arch Linux package manager over an injected Runner.
type pacman struct {
	r pmexec.Runner
}

var _ Manager = (*pacman)(nil)

func (p *pacman) Backend() Backend { return Pacman }

func (p *pacman) write(ctx context.Context, args ...string) (pmexec.Result, error) {
	res, err := runPriv(ctx, p.r, true, nil, "pacman", args...)
	if err != nil {
		return pmexec.Result{}, err
	}
	return res, asCommandError("pacman", res)
}

// Version returns the pacman version string (parsed from " Pacman v6.0.2 - …").
func (p *pacman) Version(ctx context.Context) (string, error) {
	out, err := readOut(ctx, p.r, "pacman", "--version")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Pacman v") {
			for _, field := range strings.Fields(line) {
				if strings.HasPrefix(field, "v") {
					return strings.TrimPrefix(field, "v"), nil
				}
			}
		}
	}
	return "", nil
}

// Install installs packages. With opts.Version it targets a single package via
// the name=version form (pacman can only satisfy this if the version is in a
// configured repo); opts.AllowDowngrade adds `--overwrite '*'`.
func (p *pacman) Install(ctx context.Context, opts InstallOptions, packages ...string) (pmexec.Result, error) {
	if err := ValidatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if err := ValidatePackageVersion(opts.Version); err != nil {
		return pmexec.Result{}, err
	}
	if opts.Version != "" && len(packages) != 1 {
		return pmexec.Result{}, fmt.Errorf("pkg: InstallOptions.Version requires exactly one package, got %d", len(packages))
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil
	}
	if opts.Version == "" {
		return p.write(ctx, append([]string{"-S", "--noconfirm", "--needed"}, packages...)...)
	}
	// A pinned `name=version` install also performs a downgrade when the target
	// version is lower and still available in a sync repo, so AllowDowngrade
	// needs no extra flag. We deliberately do NOT pass `--overwrite '*'`: it
	// force-overwrites every conflicting file on disk (data-loss risk) and is not
	// a correct downgrade mechanism.
	return p.write(ctx, "-S", "--noconfirm", fmt.Sprintf("%s=%s", packages[0], opts.Version))
}

// InstallLocal installs a local package file through `pacman -U`, which resolves
// its dependencies from the sync repositories and downgrades naturally when the
// file is older than the installed version — so opts.AllowDowngrade needs no
// extra flag and is ignored. ValidateLocalPackagePath requires an absolute path,
// so the operand can never be flag-shaped.
func (p *pacman) InstallLocal(ctx context.Context, path string, _ InstallLocalOptions) (pmexec.Result, error) {
	if err := ValidateLocalPackagePath(path); err != nil {
		return pmexec.Result{}, err
	}
	return p.write(ctx, "-U", "--noconfirm", path)
}

// Remove removes packages; opts.Purge uses -Rns (with deps + config files).
func (p *pacman) Remove(ctx context.Context, opts RemoveOptions, packages ...string) (pmexec.Result, error) {
	if err := ValidatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil
	}
	flag := "-R"
	if opts.Purge {
		flag = "-Rns"
	}
	return p.write(ctx, append([]string{flag, "--noconfirm"}, packages...)...)
}

// Update syncs the package databases (-Sy).
func (p *pacman) Update(ctx context.Context) (pmexec.Result, error) {
	return p.write(ctx, "-Sy", "--noconfirm")
}

// Upgrade upgrades the named packages, or the whole system (-Syu) with no names.
func (p *pacman) Upgrade(ctx context.Context, packages ...string) (pmexec.Result, error) {
	if err := ValidatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil // empty is a no-op; UpgradeAll does a full upgrade
	}
	return p.write(ctx, append([]string{"-S", "--noconfirm"}, packages...)...)
}

// UpgradeAll performs a full system upgrade (pacman -Syu).
func (p *pacman) UpgradeAll(ctx context.Context, opts UpgradeOptions) (pmexec.Result, error) {
	if opts.SecurityOnly {
		// Arch is a rolling release with no security/non-security split — there
		// is no way to apply only security updates. Fail closed rather than
		// silently run a full upgrade.
		return pmexec.Result{}, ErrSecurityOnlyUnsupported
	}
	return p.write(ctx, "-Syu", "--noconfirm")
}

// Autoremove removes orphaned packages (installed as deps, no longer required).
func (p *pacman) Autoremove(ctx context.Context) (pmexec.Result, error) {
	res, err := runRead(ctx, p.r, "pacman", "-Qtdq")
	if err != nil {
		return pmexec.Result{}, err
	}
	if res.ExitCode == 1 {
		return pmexec.Result{}, nil // no orphans
	}
	if res.ExitCode != 0 {
		return res, asCommandError("pacman", res)
	}
	var orphans []string
	for _, line := range strings.Split(res.Stdout, "\n") {
		if name := strings.TrimSpace(line); name != "" {
			orphans = append(orphans, name)
		}
	}
	if len(orphans) == 0 {
		return pmexec.Result{}, nil
	}
	return p.write(ctx, append([]string{"-Rns", "--noconfirm"}, orphans...)...)
}

// Repair clears a stale db lock and force-refreshes all databases.
func (p *pacman) Repair(ctx context.Context) (pmexec.Result, error) {
	if err := removeStaleLock(ctx, p.r, "/var/lib/pacman/db.lck"); err != nil {
		return pmexec.Result{}, err
	}
	res, err := p.write(ctx, "-Syy", "--noconfirm")
	if err != nil {
		return res, repairErr(ctx, "pacman -Syy failed", err)
	}
	return res, nil
}

// Search searches packages (-Ss; exit 1 = no matches).
func (p *pacman) Search(ctx context.Context, query string) ([]SearchResult, error) {
	if err := ValidateSearchQuery(query); err != nil {
		return nil, err
	}
	res, err := runRead(ctx, p.r, "pacman", "-Ss", query)
	if err != nil {
		return nil, err
	}
	if res.ExitCode == 1 {
		return nil, nil
	}
	if res.ExitCode != 0 {
		return nil, asCommandError("pacman", res)
	}

	var results []SearchResult
	var current *SearchResult
	scanner := bufio.NewScanner(strings.NewReader(res.Stdout))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, " ") { // indented description line
			if current != nil {
				current.Description = strings.TrimSpace(line)
				results = append(results, *current)
				current = nil
			}
			continue
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line) // repo/name version …
		if len(fields) >= 2 {
			nameParts := strings.Split(fields[0], "/")
			name := nameParts[len(nameParts)-1]
			repo := ""
			if len(nameParts) > 1 {
				repo = nameParts[0]
			}
			current = &SearchResult{Name: name, Version: fields[1], Repository: repo}
		}
	}
	return results, nil
}

// List lists installed packages (-Q).
func (p *pacman) List(ctx context.Context) ([]Package, error) {
	out, err := readOut(ctx, p.r, "pacman", "-Q")
	if err != nil {
		return nil, err
	}

	pinned, err := p.getPinnedSet(ctx)
	if err != nil {
		return nil, err
	}

	var packages []Package
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		packages = append(packages, Package{
			Name:    fields[0],
			Version: fields[1],
			Status:  "installed",
			Pinned:  pinned[fields[0]],
		})
	}
	return packages, nil
}

// ListUpgradable lists packages with an available upgrade (-Qu; exit 1 = none).
func (p *pacman) ListUpgradable(ctx context.Context) ([]PackageUpdate, error) {
	res, err := runRead(ctx, p.r, "pacman", "-Qu")
	if err != nil {
		return nil, err
	}
	if res.ExitCode == 1 {
		return nil, nil
	}
	if res.ExitCode != 0 {
		return nil, asCommandError("pacman", res)
	}

	var updates []PackageUpdate
	scanner := bufio.NewScanner(strings.NewReader(res.Stdout))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		switch {
		case len(fields) >= 4 && fields[2] == "->": // name current -> new
			updates = append(updates, PackageUpdate{
				Name:           fields[0],
				CurrentVersion: fields[1],
				NewVersion:     fields[3],
			})
		case len(fields) >= 2: // name new
			current, err := p.InstalledVersion(ctx, fields[0])
			if err != nil {
				return nil, err
			}
			updates = append(updates, PackageUpdate{
				Name:           fields[0],
				CurrentVersion: current,
				NewVersion:     fields[1],
			})
		}
	}
	return updates, nil
}

// Show returns detailed information about a package (-Qi installed, else -Si).
func (p *pacman) Show(ctx context.Context, name string) (*Package, error) {
	if err := ValidatePackageName(name); err != nil {
		return nil, err
	}
	// -Qi reports an installed package; a non-zero exit means "not installed"
	// (try the sync DB), while a runner/context failure propagates.
	out, ok, err := probe(ctx, p.r, "pacman", "-Qi", name)
	if err != nil {
		return nil, err
	}
	status := "installed"
	if !ok {
		out, ok, err = probe(ctx, p.r, "pacman", "-Si", name)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("package not found: %s", name)
		}
		status = "available"
	}

	pkg := &Package{Name: name, Status: status}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Version"):
			pkg.Version = parsePacmanValue(line)
		case strings.HasPrefix(line, "Architecture"):
			pkg.Architecture = parsePacmanValue(line)
		case strings.HasPrefix(line, "Description"):
			pkg.Description = parsePacmanValue(line)
		case strings.HasPrefix(line, "Installed Size"):
			pkg.Size = parsePacmanSize(parsePacmanValue(line))
		case strings.HasPrefix(line, "Repository"):
			pkg.Repository = parsePacmanValue(line)
		}
	}

	pinned, err := p.IsPinned(ctx, name)
	if err != nil {
		return nil, err
	}
	pkg.Pinned = pinned
	return pkg, nil
}

// ListVersions reports the single repo version pacman keeps for a package.
func (p *pacman) ListVersions(ctx context.Context, name string) (*VersionInfo, error) {
	if err := ValidatePackageName(name); err != nil {
		return nil, err
	}
	info := &VersionInfo{Name: name}
	installed, err := p.InstalledVersion(ctx, name)
	if err != nil {
		return nil, err
	}
	info.Installed = installed

	out, ok, err := probe(ctx, p.r, "pacman", "-Si", name)
	if err != nil {
		return nil, err // runner/context failure
	}
	if !ok {
		return info, nil // not in any sync repo
	}

	// Parse Version and Repository order-independently (do not assume Repository
	// follows Version in the -Si output).
	var version, repo string
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Version"):
			version = parsePacmanValue(line)
		case strings.HasPrefix(line, "Repository"):
			repo = parsePacmanValue(line)
		}
	}
	if version != "" {
		info.Versions = append(info.Versions, AvailableVersion{Version: version, Repository: repo})
	}
	return info, nil
}

// IsInstalled reports whether a package is installed (pacman -Q exits 0).
func (p *pacman) IsInstalled(ctx context.Context, name string) (bool, error) {
	if err := ValidatePackageName(name); err != nil {
		return false, err
	}
	res, err := runRead(ctx, p.r, "pacman", "-Q", name)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// InstalledVersion returns the installed version of a package, or "" if absent.
func (p *pacman) InstalledVersion(ctx context.Context, name string) (string, error) {
	if err := ValidatePackageName(name); err != nil {
		return "", err
	}
	res, err := runRead(ctx, p.r, "pacman", "-Q", name)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", nil
	}
	fields := strings.Fields(res.Stdout)
	if len(fields) >= 2 {
		return fields[1], nil
	}
	return "", nil
}

// InstalledCount returns the number of installed packages (-Qq).
func (p *pacman) InstalledCount(ctx context.Context) (int, error) {
	out, err := readOut(ctx, p.r, "pacman", "-Qq")
	if err != nil {
		return 0, err
	}
	return countNonEmptyLines(out), nil
}

// HasUpdates reports whether any update is available (-Qu: exit 0 + output).
// pacman has no security-only feed, so securityOnly is ignored.
func (p *pacman) HasUpdates(ctx context.Context, securityOnly bool) (bool, error) {
	_ = securityOnly
	res, err := runRead(ctx, p.r, "pacman", "-Qu")
	if err != nil {
		return false, err
	}
	if res.ExitCode == 1 {
		return false, nil
	}
	if res.ExitCode != 0 {
		return false, asCommandError("pacman", res)
	}
	return strings.TrimSpace(res.Stdout) != "", nil
}

// Pin holds packages by adding them to IgnorePkg in /etc/pacman.conf. Pinning is
// a config-file edit, not a package transaction, so it has no command output to
// surface — the returned Result is the zero Result.
func (p *pacman) Pin(ctx context.Context, packages ...string) (pmexec.Result, error) {
	if err := ValidatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil
	}
	// Second, stricter gate: IgnorePkg values land in pacman.conf, so reject any
	// name that could inject a config directive even though ValidatePackageNames
	// already passed.
	for _, name := range packages {
		if !validPacmanPkgName.MatchString(name) {
			return pmexec.Result{}, fmt.Errorf("invalid package name %q: must match [a-zA-Z0-9][a-zA-Z0-9._+-]*", name)
		}
	}

	conf, err := p.readConf(ctx)
	if err != nil {
		return pmexec.Result{}, err
	}
	ignored := getIgnoredPackages(conf)
	for _, name := range packages {
		if !contains(ignored, name) {
			ignored = append(ignored, name)
		}
	}
	return pmexec.Result{}, p.writeIgnorePkg(ctx, conf, ignored)
}

// Unpin releases packages by removing them from IgnorePkg. Like Pin, this is a
// config-file edit with no command output (zero Result).
func (p *pacman) Unpin(ctx context.Context, packages ...string) (pmexec.Result, error) {
	if err := ValidatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil
	}
	conf, err := p.readConf(ctx)
	if err != nil {
		return pmexec.Result{}, err
	}
	var kept []string
	for _, name := range getIgnoredPackages(conf) {
		if !contains(packages, name) {
			kept = append(kept, name)
		}
	}
	return pmexec.Result{}, p.writeIgnorePkg(ctx, conf, kept)
}

// ListPinned lists IgnorePkg-held packages.
func (p *pacman) ListPinned(ctx context.Context) ([]Package, error) {
	conf, err := p.readConf(ctx)
	if err != nil {
		return nil, err
	}
	var packages []Package
	for _, name := range getIgnoredPackages(conf) {
		version, err := p.InstalledVersion(ctx, name)
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

// IsPinned reports whether a package is in IgnorePkg.
func (p *pacman) IsPinned(ctx context.Context, name string) (bool, error) {
	if err := ValidatePackageName(name); err != nil {
		return false, err
	}
	conf, err := p.readConf(ctx)
	if err != nil {
		return false, err
	}
	return contains(getIgnoredPackages(conf), name), nil
}

func (p *pacman) getPinnedSet(ctx context.Context) (map[string]bool, error) {
	conf, err := p.readConf(ctx)
	if err != nil {
		return nil, err
	}
	pinned := make(map[string]bool)
	for _, name := range getIgnoredPackages(conf) {
		pinned[name] = true
	}
	return pinned, nil
}

// readConf reads /etc/pacman.conf (world-readable, so unprivileged) via cat,
// matching the privilege-wrapper discipline the writes use.
func (p *pacman) readConf(ctx context.Context) (string, error) {
	out, err := readOut(ctx, p.r, "cat", "/etc/pacman.conf")
	if err != nil {
		return "", fmt.Errorf("failed to read pacman.conf: %w", err)
	}
	return out, nil
}

// writeIgnorePkg rewrites pacman.conf with the given IgnorePkg set and installs
// it via an escalated `tee`.
func (p *pacman) writeIgnorePkg(ctx context.Context, conf string, ignored []string) error {
	out := buildIgnorePkgConf(conf, ignored)
	res, err := runPrivStdin(ctx, p.r, true, nil, out, "tee", "/etc/pacman.conf")
	if err != nil {
		return err
	}
	return asCommandError("tee", res)
}

func getIgnoredPackages(conf string) []string {
	var ignored []string
	scanner := bufio.NewScanner(strings.NewReader(conf))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "IgnorePkg") {
			continue
		}
		if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
			ignored = append(ignored, strings.Fields(strings.TrimSpace(parts[1]))...)
		}
	}
	return ignored
}

// buildIgnorePkgConf returns conf with its IgnorePkg line replaced (or inserted
// after [options]) to reflect ignored. An empty set drops the directive.
func buildIgnorePkgConf(conf string, ignored []string) string {
	var b strings.Builder
	found := false
	scanner := bufio.NewScanner(strings.NewReader(conf))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "IgnorePkg") {
			// Emit the single consolidated directive in place of the first
			// IgnorePkg line, then drop EVERY IgnorePkg line (a conf may carry
			// several) so no stale entry survives a later Unpin.
			if !found {
				found = true
				if len(ignored) > 0 {
					fmt.Fprintf(&b, "IgnorePkg = %s\n", strings.Join(ignored, " "))
				}
			}
			continue
		}
		b.WriteString(line + "\n")
	}

	if !found && len(ignored) > 0 {
		content := b.String()
		if optionsIdx := strings.Index(content, "[options]"); optionsIdx != -1 {
			if nl := strings.Index(content[optionsIdx:], "\n"); nl != -1 {
				insert := optionsIdx + nl + 1
				content = content[:insert] + fmt.Sprintf("IgnorePkg = %s\n", strings.Join(ignored, " ")) + content[insert:]
			}
		}
		b.Reset()
		b.WriteString(content)
	}
	return b.String()
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
	switch {
	case strings.HasSuffix(s, " KiB"):
		multiplier = 1024
		s = strings.TrimSuffix(s, " KiB")
	case strings.HasSuffix(s, " MiB"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, " MiB")
	case strings.HasSuffix(s, " GiB"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, " GiB")
	case strings.HasSuffix(s, " B"):
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
