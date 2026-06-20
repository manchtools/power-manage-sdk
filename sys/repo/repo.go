// Package repo configures external package-manager repositories through an
// injected exec.Runner, the same dependency-injected idiom as pkg/fs/network.
//
// A Manager is built for an explicit package-manager backend and a Runner; it
// owns the per-backend repository file format (apt deb822 .sources + keyrings,
// dnf .repo, pacman.conf sections, zypper addrepo), GPG public-key import, the
// idempotency comparison, and the post-configuration metadata refresh:
//
//	r, _ := exec.NewRunner(exec.Direct) // the agent runs as root
//	m, err := repo.New(pkg.Dnf, r)
//	if err != nil { ... }
//	out, err := m.Apply(ctx, repo.Repository{Name: "corp", Dnf: &repo.DnfConfig{
//		BaseURL: "https://packages.example.com/el9", GPGCheck: true,
//		GPGKey: "https://packages.example.com/RPM-GPG-KEY", Enabled: true,
//	}})
//
// Privileged file writes are delegated to fs.Manager, so on the Direct (root)
// backend they take the TOCTOU-safe, fd-anchored path — a hardening upgrade over
// a raw `cp`/sudo write into a world-traversable config directory.
//
// GPG keys handled here are PUBLIC repository-signing keys, not secrets: apt
// receives the key material as bytes (the caller downloads it under its own
// network policy) which the Manager dearmors into /etc/apt/keyrings; dnf and
// zypper receive a key reference (an https URL or absolute path) that the package
// manager itself resolves. No exec.Secret is involved.
//
// Repositories belong to a package manager, so callers discover the backend with
// pkg.Detect — repo has no separate Detect. Flatpak has no native-style repo
// (its remotes live on pkg.FlatpakManager), so New rejects it.
package repo

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/manchtools/power-manage-sdk/pkg"
	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/fs"
)

// ErrUnsupportedBackend is returned by New for a backend that has no
// native-style repository configuration: flatpak (whose remotes live on
// pkg.FlatpakManager) and the zero/unknown value. Fail-closed: no silent default.
var ErrUnsupportedBackend = errors.New("repo: unsupported package-manager backend")

// ErrInvalidName is returned when a repository name is empty, too long, or
// contains characters that would be unsafe as a filename or argv operand.
var ErrInvalidName = errors.New("repo: invalid repository name")

// ErrMissingConfig is returned by Apply when the Repository carries no
// configuration for the Manager's backend (e.g. Apply on a Dnf Manager with a
// nil Dnf field). Fail-closed: a repository with nothing to configure is a
// caller bug, not a silent no-op.
var ErrMissingConfig = errors.New("repo: no configuration for this backend")

// ErrInvalidConfig is returned when a repository configuration field is malformed
// — a control character (config-injection) or a shape that would be unsafe to
// splice into a config file or command line. The error names the offending field
// but never echoes its value (URLs/keys can carry per-deployment secrets).
var ErrInvalidConfig = errors.New("repo: invalid repository configuration")

// Repository is a package repository to configure. Set the sub-configuration
// matching the Manager's backend; the others are ignored. (The shape mirrors the
// control-plane RepositoryParams message so a caller maps it field-for-field.)
type Repository struct {
	// Name identifies the repository; it is used to name the on-disk config
	// (and, for apt, the keyring) and as the repo alias for zypper/pacman.
	Name string

	Apt    *AptConfig
	Dnf    *DnfConfig
	Pacman *PacmanConfig
	Zypper *ZypperConfig
}

// AptConfig configures a Debian/Ubuntu APT repository, written in the modern
// deb822 format to /etc/apt/sources.list.d/<name>.sources.
type AptConfig struct {
	// URL is the repository root. apt is intentionally not restricted to https:
	// its trust anchor is the gpg-signed Release file, so an http transport with
	// a trusted key is a legitimate, long-standing configuration.
	URL string
	// Distribution is the suite/codename (e.g. "bookworm"). Empty selects a flat
	// repository ("Suites: /").
	Distribution string
	// Components (e.g. "main", "contrib"). Optional.
	Components []string
	// Arch restricts the architecture (e.g. "amd64"). Optional.
	Arch string
	// GPGKey is the PUBLIC repository-signing key, ASCII-armored or binary. When
	// set it is dearmored and written to /etc/apt/keyrings/<name>.gpg and
	// referenced via Signed-By. The caller downloads it (network policy is the
	// caller's); the Manager never fetches. Empty → no key.
	GPGKey []byte
	// Trusted writes "Trusted: yes" (disables signature verification). Honored
	// only when GPGKey is empty; a configured key always takes precedence.
	Trusted bool
}

// DnfConfig configures a Fedora/RHEL DNF/YUM repository, written to
// /etc/yum.repos.d/<name>.repo.
type DnfConfig struct {
	// BaseURL is the repository base (https required; supports $releasever etc.).
	BaseURL string
	// Description is the human-readable repo name (the .repo "name=" field).
	Description string
	// Enabled writes enabled=1/0.
	Enabled bool
	// GPGCheck writes gpgcheck=1/0.
	GPGCheck bool
	// GPGKey is a key reference (https URL or absolute path) written as gpgkey=
	// and imported with `rpm --import`. Empty → no key import.
	GPGKey string
	// ModuleHotfixes writes module_hotfixes=1 when set.
	ModuleHotfixes bool
}

// PacmanConfig configures an Arch Linux pacman repository as a section appended
// to /etc/pacman.conf.
type PacmanConfig struct {
	// Server is the repository server URL (https required; supports $repo/$arch).
	Server string
	// SigLevel sets the section's SigLevel (e.g. "Optional TrustAll"). Optional.
	SigLevel string
}

// ZypperConfig configures an openSUSE zypper repository via `zypper addrepo`.
type ZypperConfig struct {
	// URL is the repository URL (https required).
	URL string
	// Description is the repo's display name (set with modifyrepo --name).
	Description string
	// Enabled enables/disables the repo (modifyrepo --enable/--disable).
	Enabled bool
	// Autorefresh enables periodic refresh (modifyrepo --refresh).
	Autorefresh bool
	// GPGCheck controls signature checking (addrepo --no-gpgcheck when false).
	GPGCheck bool
	// GPGKey is a key reference imported with `rpm --import`. Optional.
	GPGKey string
	// Type sets the repository type (addrepo --type, e.g. "rpm-md"). Optional.
	Type string
}

// Outcome reports what an Apply/Remove did: the aggregated command output
// (exit code, the human-readable log of steps taken, and any stderr) plus
// whether on-disk state actually changed. Changed is false for an idempotent
// no-op (the configuration already matched), which lets a caller suppress
// spurious state-change events.
type Outcome struct {
	Result  pmexec.Result
	Changed bool
}

// Manager is the repository-configuration surface for a single package-manager
// backend (fixed at construction). Validate is exposed separately so a caller
// can reject a malformed configuration BEFORE taking any privileged side effect
// (e.g. remounting a read-only root); Apply re-validates internally regardless.
type Manager interface {
	// Backend reports which package-manager backend this Manager configures.
	Backend() pkg.Backend
	// Validate checks the repository name and the configuration for this
	// Manager's backend (if present) without touching the system.
	Validate(r Repository) error
	// Apply configures the repository (idempotently) for PRESENT desired state.
	Apply(ctx context.Context, r Repository) (Outcome, error)
	// Remove deletes the named repository (and, for apt, its keyring) for ABSENT
	// desired state. It is idempotent: removing an absent repository reports
	// Changed=false.
	Remove(ctx context.Context, name string) (Outcome, error)
}

// fsManager is the narrow slice of fs.Manager this package uses for privileged
// file operations. Keeping it minimal lets unit tests inject a small fake via
// the newFS seam without driving real privileged file ops.
type fsManager interface {
	ReadFile(ctx context.Context, path string) ([]byte, error)
	ReadDir(ctx context.Context, path string) ([]fs.DirEntry, error)
	WriteFile(ctx context.Context, path string, data []byte, opts fs.WriteOptions) error
	Remove(ctx context.Context, path string) error
	Mkdir(ctx context.Context, path string, opts fs.MkdirOptions) error
	Exists(ctx context.Context, path string) (bool, error)
}

// newFS builds the fs.Manager each Manager delegates privileged file ops to,
// over the same injected Runner. A package var so tests override it with a fake.
var newFS = func(r pmexec.Runner) (fsManager, error) { return fs.New(r) }

// manager is the single Manager implementation; the per-backend behavior is
// selected by b (validated at construction), so there is no per-backend type.
type manager struct {
	b   pkg.Backend
	r   pmexec.Runner
	fsm fsManager
}

// New builds a repository Manager for backend b driven by runner. A nil runner
// or a backend without native repository support (flatpak, the zero value) is
// rejected (fail-closed). New is pure — it does not probe the host; use
// pkg.Detect to learn which backends are installed.
func New(b pkg.Backend, runner pmexec.Runner) (Manager, error) {
	if runner == nil {
		return nil, fmt.Errorf("repo: %w", pmexec.ErrRunnerRequired)
	}
	switch b {
	case pkg.Apt, pkg.Dnf, pkg.Pacman, pkg.Zypper:
		// supported
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedBackend, b)
	}
	fsm, err := newFS(runner)
	if err != nil {
		return nil, err
	}
	return &manager{b: b, r: runner, fsm: fsm}, nil
}

// Backend reports the configured backend.
func (m *manager) Backend() pkg.Backend { return m.b }

// Apply validates then dispatches to the backend-specific configuration path.
func (m *manager) Apply(ctx context.Context, r Repository) (Outcome, error) {
	if err := m.Validate(r); err != nil {
		return Outcome{}, err
	}
	switch m.b {
	case pkg.Apt:
		if r.Apt == nil {
			return Outcome{}, fmt.Errorf("%w: apt", ErrMissingConfig)
		}
		return m.applyApt(ctx, r.Name, r.Apt)
	case pkg.Dnf:
		if r.Dnf == nil {
			return Outcome{}, fmt.Errorf("%w: dnf", ErrMissingConfig)
		}
		return m.applyDnf(ctx, r.Name, r.Dnf)
	case pkg.Pacman:
		if r.Pacman == nil {
			return Outcome{}, fmt.Errorf("%w: pacman", ErrMissingConfig)
		}
		return m.applyPacman(ctx, r.Name, r.Pacman)
	case pkg.Zypper:
		if r.Zypper == nil {
			return Outcome{}, fmt.Errorf("%w: zypper", ErrMissingConfig)
		}
		return m.applyZypper(ctx, r.Name, r.Zypper)
	default:
		// Defense-in-depth: New gates the backend, so this is unreachable for a
		// Manager built through the public constructor.
		return Outcome{}, fmt.Errorf("%w: %s", ErrUnsupportedBackend, m.b)
	}
}

// Remove validates the name then dispatches to the backend-specific removal.
func (m *manager) Remove(ctx context.Context, name string) (Outcome, error) {
	if err := validateName(name); err != nil {
		return Outcome{}, err
	}
	switch m.b {
	case pkg.Apt:
		return m.removeApt(ctx, name)
	case pkg.Dnf:
		return m.removeDnf(ctx, name)
	case pkg.Pacman:
		return m.removePacman(ctx, name)
	case pkg.Zypper:
		return m.removeZypper(ctx, name)
	default:
		return Outcome{}, fmt.Errorf("%w: %s", ErrUnsupportedBackend, m.b)
	}
}

// out builds a successful Outcome from an accumulated log and changed flag.
func out(log string, changed bool) Outcome {
	return Outcome{Result: pmexec.Result{ExitCode: 0, Stdout: log}, Changed: changed}
}

// fsResultErr builds a failure Result carrying the accumulated log as stdout and
// the error text as stderr, for the paths that return both a Result and an error.
func fsResultErr(log string, err error) pmexec.Result {
	return pmexec.Result{ExitCode: 1, Stdout: log, Stderr: err.Error()}
}

// runPriv runs an escalated package-manager command through the Runner and folds
// a non-zero exit into an *exec.CommandError (the error is nil only on a clean
// exit). The Result is returned in all cases so a caller can surface stdout.
func (m *manager) runPriv(ctx context.Context, name string, args ...string) (pmexec.Result, error) {
	res, err := m.r.Run(ctx, pmexec.Command{Name: name, Args: args, Escalate: true})
	if err != nil {
		return res, err
	}
	if res.ExitCode != 0 {
		return res, &pmexec.CommandError{Name: name, ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return res, nil
}

// runStdin runs an UNPRIVILEGED command with stdin (the gpg --dearmor path: it
// processes a public key, needs no privilege, and must not touch any file —
// fs.Manager performs the privileged keyring write). A non-zero exit folds into
// an *exec.CommandError.
func (m *manager) runStdin(ctx context.Context, stdin []byte, name string, args ...string) (pmexec.Result, error) {
	cmd := pmexec.Command{Name: name, Args: args}
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	res, err := m.r.Run(ctx, cmd)
	if err != nil {
		return res, err
	}
	if res.ExitCode != 0 {
		return res, &pmexec.CommandError{Name: name, ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return res, nil
}
