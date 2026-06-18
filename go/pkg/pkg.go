// Package pkg provides a uniform package-manager abstraction for Linux.
//
// A Manager is built for an explicit Backend over an injected exec.Runner —
// the SDK keeps no global escalation state and every Manager is unit-testable
// with exectest.FakeRunner (no host, no sudo, no container):
//
//	r, _ := exec.NewRunner(exec.Sudo)
//	m, err := pkg.New(pkg.Apt, r)
//	if err != nil { ... }
//	if err := m.Install(ctx, pkg.InstallOptions{}, "vim", "git"); err != nil { ... }
//
// Reads (Search/List/Show/IsInstalled/…) run unprivileged; mutations
// (Install/Remove/Update/Upgrade/Pin/Unpin/Repair/Autoremove) run through the
// Runner's privilege backend. Every package-name and version argument is
// validated before it can reach argv — there is no opt-out.
//
// Use Detect to discover which backends are installed; it lists and never picks,
// so the caller decides (a host can have both a native manager and flatpak).
package pkg

import (
	"context"
	"errors"
	"fmt"
	"os/exec"

	pmexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// ErrUnknownBackend is returned by New for a Backend the SDK does not implement
// (including the zero value). Fail-closed: no silent default.
var ErrUnknownBackend = errors.New("pkg: unknown package-manager backend")

// lookPath is the exec.LookPath seam used by Detect and apt's apt/apt-get
// resolution so binary discovery can be stubbed in tests.
var lookPath = exec.LookPath

// Backend identifies a supported package manager. The zero value is invalid
// (New rejects it); valid values start at 1.
type Backend int

const (
	// Apt is the Debian/Ubuntu package manager (apt / apt-get / dpkg).
	Apt Backend = iota + 1
	// Dnf is the Fedora/RHEL package manager (dnf / rpm).
	Dnf
	// Pacman is the Arch Linux package manager.
	Pacman
	// Zypper is the openSUSE/SLES package manager (zypper / rpm).
	Zypper
	// Flatpak is the cross-distro application bundle manager.
	Flatpak
)

// String returns the canonical lowercase backend name.
func (b Backend) String() string {
	switch b {
	case Apt:
		return "apt"
	case Dnf:
		return "dnf"
	case Pacman:
		return "pacman"
	case Zypper:
		return "zypper"
	case Flatpak:
		return "flatpak"
	default:
		return fmt.Sprintf("Backend(%d)", int(b))
	}
}

// Manager is the uniform package-manager surface. Every method takes a context
// so the caller controls timeout/cancellation. Query methods return typed
// results; mutating methods return error only — a non-zero exit becomes an
// *exec.CommandError carrying the exit code and stderr.
type Manager interface {
	// Backend reports which package-manager backend this Manager drives.
	Backend() Backend

	// --- queries (unprivileged) ---

	// Version returns the package-manager tool version string.
	Version(ctx context.Context) (string, error)
	// Search returns packages whose name/summary matches query.
	Search(ctx context.Context, query string) ([]SearchResult, error)
	// List returns the installed packages.
	List(ctx context.Context) ([]Package, error)
	// ListUpgradable returns packages with an available upgrade.
	ListUpgradable(ctx context.Context) ([]PackageUpdate, error)
	// Show returns detailed information about a single package.
	Show(ctx context.Context, name string) (*Package, error)
	// ListVersions returns the versions available for a package.
	ListVersions(ctx context.Context, name string) (*VersionInfo, error)
	// IsInstalled reports whether name is currently installed.
	IsInstalled(ctx context.Context, name string) (bool, error)
	// InstalledVersion returns the installed version of name, or "" if absent.
	InstalledVersion(ctx context.Context, name string) (string, error)
	// InstalledCount returns the number of installed packages.
	InstalledCount(ctx context.Context) (int, error)
	// HasUpdates reports whether any update is available. When securityOnly is
	// true only security updates are considered (where the backend supports it).
	HasUpdates(ctx context.Context, securityOnly bool) (bool, error)
	// IsPinned reports whether name is held back from upgrades.
	IsPinned(ctx context.Context, name string) (bool, error)
	// ListPinned returns the packages held back from upgrades.
	ListPinned(ctx context.Context) ([]Package, error)

	// --- mutations (privileged) ---

	// Install installs the named packages. opts.Version pins a single package
	// (exactly one name required when set); opts.AllowDowngrade permits a lower
	// version than installed.
	Install(ctx context.Context, opts InstallOptions, packages ...string) error
	// Remove removes the named packages. opts.Purge also deletes configuration
	// where the backend distinguishes it (apt/pacman/flatpak); elsewhere Purge
	// is equivalent to a plain remove.
	Remove(ctx context.Context, opts RemoveOptions, packages ...string) error
	// Update refreshes the package metadata/database.
	Update(ctx context.Context) error
	// Upgrade upgrades the named packages; with no names it performs a full
	// system upgrade (apt dist-upgrade / pacman -Syu / zypper dist-upgrade / …).
	Upgrade(ctx context.Context, packages ...string) error
	// Pin holds the named packages back from upgrades.
	Pin(ctx context.Context, packages ...string) error
	// Unpin releases the named packages so they upgrade again.
	Unpin(ctx context.Context, packages ...string) error
	// Repair attempts to fix a wedged package-manager state (stale locks,
	// interrupted transactions, broken dependencies).
	Repair(ctx context.Context) error
	// Autoremove removes packages installed only as now-unneeded dependencies.
	// It is a no-op (returns nil) on backends with no native equivalent.
	Autoremove(ctx context.Context) error
}

// FlatpakManager is the Manager returned by New(Flatpak, …); it adds remote
// (repository) management, which has no analogue on the native managers.
// Callers reach it with a type assertion:
//
//	if fm, ok := m.(pkg.FlatpakManager); ok { fm.AddRemote(ctx, "flathub", url) }
type FlatpakManager interface {
	Manager
	// AddRemote registers a flatpak remote. name must be a valid remote alias
	// and url an https repository URL.
	AddRemote(ctx context.Context, name, url string) error
	// RemoveRemote deletes a flatpak remote.
	RemoveRemote(ctx context.Context, name string) error
	// ListRemotes returns the configured flatpak remote names.
	ListRemotes(ctx context.Context) ([]string, error)
}

// Option customizes a Manager at construction.
type Option func(*config)

type config struct {
	// system selects flatpak --system (escalated) over --user (unprivileged).
	// Ignored by the native managers, which always operate system-wide.
	system bool
}

// WithUserScope makes a flatpak Manager operate on the per-user installation
// (--user, unprivileged) instead of the system installation. It has no effect
// on the native package managers.
func WithUserScope() Option {
	return func(c *config) { c.system = false }
}

// New builds a Manager for backend b driven by runner. A nil runner or an
// unknown backend is rejected (fail-closed). New is pure — it does not probe
// the host; use Detect to learn which backends are installed.
func New(b Backend, runner pmexec.Runner, opts ...Option) (Manager, error) {
	if runner == nil {
		return nil, fmt.Errorf("pkg: %w", pmexec.ErrRunnerRequired)
	}
	cfg := config{system: true}
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	switch b {
	case Apt:
		return &apt{r: runner}, nil
	case Dnf:
		return &dnf{r: runner}, nil
	case Pacman:
		return &pacman{r: runner}, nil
	case Zypper:
		return &zypper{r: runner}, nil
	case Flatpak:
		return &flatpak{r: runner, system: cfg.system}, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownBackend, int(b))
	}
}

// Detect returns the package-manager backends whose primary binary resolves on
// PATH, in priority order (native managers before flatpak). The result may be
// empty (no supported manager) or hold several entries (e.g. a native manager
// plus flatpak). It lists; it never picks — the caller chooses.
func Detect(ctx context.Context) []Backend {
	var found []Backend
	for _, c := range []struct {
		bin string
		b   Backend
	}{
		{"apt-get", Apt},
		{"dnf", Dnf},
		{"pacman", Pacman},
		{"zypper", Zypper},
		{"flatpak", Flatpak},
	} {
		if _, err := lookPath(c.bin); err == nil {
			found = append(found, c.b)
		}
	}
	return found
}
