// Package catrust manages the host's system-wide CA trust anchors through an
// injected exec.Runner (plus the fs.Manager for the privileged file writes).
//
//	r, _ := exec.NewRunner(exec.Direct) // writing trust anchors needs root
//	m, err := catrust.New(catrust.CaCertificates, r)
//	if err != nil { ... }
//	err = m.Install(ctx, "acme-corp-root", pemBytes) // every TLS client now trusts it
//
// This installs/removes an operator-supplied CA into the system trust store — the
// mechanism for distributing a private/internal CA across a fleet so devices
// trust internal services or a TLS-inspecting proxy. It is a high-trust,
// privilege-amplifying operation: a CA the host trusts can transparently MITM any
// TLS connection, so Install validates the certificate (well-formed, IsCA,
// currently valid) and the name (safe filename) BEFORE writing. Authorization of
// the request itself is the caller's concern (the agent gates it with a CA-signed
// action, as for other sensitive ops).
//
// Three backends: CaCertificates (Debian/Ubuntu update-ca-certificates), P11Kit
// (Fedora/RHEL/EL/Arch update-ca-trust), and SuseCaCertificates (openSUSE/SLES,
// which ships a same-named update-ca-certificates but with different paths).
// Distrusting a distro-shipped root (a separate blocklist mechanism) is out of
// scope — this manages anchors WE add.
package catrust

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/fs"
)

// Backend selects the trust-store mechanism. Zero is invalid; only implemented
// backends exist.
type Backend int

const (
	// CaCertificates is the Debian/Ubuntu update-ca-certificates flow
	// (anchors in /usr/local/share/ca-certificates).
	CaCertificates Backend = iota + 1
	// P11Kit is the Fedora/RHEL/EL/Arch p11-kit update-ca-trust flow
	// (anchors in /etc/pki/ca-trust/source/anchors).
	P11Kit
	// SuseCaCertificates is the openSUSE/SLES update-ca-certificates flow. SUSE
	// ships a tool of the SAME name as Debian's but reads anchors from
	// /etc/pki/trust/anchors, so it needs its own backend (Detect disambiguates
	// the two by which anchors dir exists).
	SuseCaCertificates
)

// String renders the backend as its canonical name.
func (b Backend) String() string {
	switch b {
	case CaCertificates:
		return "ca-certificates"
	case P11Kit:
		return "p11-kit"
	case SuseCaCertificates:
		return "suse-ca-certificates"
	default:
		return fmt.Sprintf("Backend(%d)", int(b))
	}
}

// ErrUnknownBackend is returned by New for the zero value or any unimplemented
// backend.
var ErrUnknownBackend = errors.New("catrust: unknown backend")

// Anchor is an installed trust anchor this package manages.
type Anchor struct {
	Name    string // the operator-chosen name (the anchor's filename without .crt)
	Subject string // certificate subject DN
	Issuer  string // certificate issuer DN
}

// Manager is the CA-trust surface.
type Manager interface {
	// Install adds (or replaces) a CA anchor under name. certPEM must be a single
	// PEM CA certificate; it is validated before being written.
	Install(ctx context.Context, name string, certPEM []byte) error
	// Remove deletes the anchor previously installed under name and refreshes the
	// trust store. It is idempotent: removing an absent name is a no-op success.
	Remove(ctx context.Context, name string) error
	// List reports the anchors this package manages (not the full system bundle).
	List(ctx context.Context) ([]Anchor, error)
}

// backendConfig captures the per-backend file location + refresh commands. The
// install and remove refreshes differ for ca-certificates (a plain run adds; a
// --fresh run rebuilds without a removed file); p11-kit's extract is a full
// idempotent rebuild for both.
type backendConfig struct {
	// anchorsDirs lists the candidate anchors directories in priority order. Some
	// backends use a single dir, but a mechanism shared by distros that disagree on
	// the path lists several — New resolves to the first that exists (else the
	// first as the canonical default). p11-kit is the case: Fedora/EL and Arch both
	// use update-ca-trust but read different dirs.
	anchorsDirs    []string
	installRefresh []string // [name, args...]
	removeRefresh  []string
}

var backends = map[Backend]backendConfig{
	CaCertificates: {
		anchorsDirs:    []string{"/usr/local/share/ca-certificates"},
		installRefresh: []string{"update-ca-certificates"},
		removeRefresh:  []string{"update-ca-certificates", "--fresh"},
	},
	P11Kit: {
		// Fedora/EL: /etc/pki/ca-trust/source/anchors; Arch: /etc/ca-certificates/
		// trust-source/anchors. Same update-ca-trust command, different dir.
		anchorsDirs:    []string{"/etc/pki/ca-trust/source/anchors", "/etc/ca-certificates/trust-source/anchors"},
		installRefresh: []string{"update-ca-trust", "extract"},
		removeRefresh:  []string{"update-ca-trust", "extract"},
	},
	// SUSE's update-ca-certificates regenerates the consolidated bundle from the
	// anchors dir on every run, so a plain run both adds (install) and drops a
	// removed file (remove) — no Debian-style "--fresh" flag (which SUSE's tool
	// does not accept).
	SuseCaCertificates: {
		anchorsDirs:    []string{"/etc/pki/trust/anchors"},
		installRefresh: []string{"update-ca-certificates"},
		removeRefresh:  []string{"update-ca-certificates"},
	},
}

// resolveAnchorsDir picks the anchors dir to use from a backend's candidates: the
// first that exists on this host, else the first (the canonical default — the
// distro package creates it on install).
func resolveAnchorsDir(candidates []string) string {
	for _, d := range candidates {
		if anchorsDirExists(d) {
			return d
		}
	}
	return candidates[0]
}

// fsManager is the narrow slice of fs.Manager catrust uses for the privileged
// anchor writes/removes; a small interface so tests inject a fake via newFS.
type fsManager interface {
	WriteFile(ctx context.Context, path string, data []byte, opts fs.WriteOptions) error
	Remove(ctx context.Context, path string) error
}

// newFS builds the fs.Manager over the same Runner. A package var for tests.
var newFS = func(r exec.Runner) (fsManager, error) { return fs.New(r) }

// Read seams (the anchors dirs are world-readable, so List needs no escalation).
var (
	readDir  = os.ReadDir
	readFile = os.ReadFile
	stat     = os.Stat
)

type manager struct {
	r          exec.Runner
	fsm        fsManager
	cfg        backendConfig
	anchorsDir string // resolved from cfg.anchorsDirs at construction
}

// New returns a Manager for the named backend. Pure: validates the backend; nil
// runner and unknown backend are rejected.
func New(b Backend, runner exec.Runner) (Manager, error) {
	if runner == nil {
		return nil, fmt.Errorf("catrust: %w", exec.ErrRunnerRequired)
	}
	cfg, ok := backends[b]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrUnknownBackend, int(b))
	}
	fsm, err := newFS(runner)
	if err != nil {
		return nil, err
	}
	return &manager{r: runner, fsm: fsm, cfg: cfg, anchorsDir: resolveAnchorsDir(cfg.anchorsDirs)}, nil
}

// anchorPath is the on-disk path for a named anchor.
func (m *manager) anchorPath(name string) string {
	return m.anchorsDir + "/" + name + anchorExt
}

const anchorExt = ".crt"

// Install validates name + certPEM, writes the anchor, and refreshes the store.
func (m *manager) Install(ctx context.Context, name string, certPEM []byte) error {
	if err := validateName(name); err != nil {
		return err
	}
	if err := validateCACert(certPEM); err != nil {
		return err
	}
	path := m.anchorPath(name)
	if err := m.fsm.WriteFile(ctx, path, certPEM, fs.WriteOptions{Mode: 0o644, Owner: "root", Group: "root"}); err != nil {
		return fmt.Errorf("catrust: write %s: %w", path, err)
	}
	if err := m.refresh(ctx, m.cfg.installRefresh); err != nil {
		return err
	}
	return nil
}

// Remove deletes the named anchor (idempotent) and refreshes the store.
func (m *manager) Remove(ctx context.Context, name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	path := m.anchorPath(name)
	if _, err := stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil // already absent — nothing to do
		}
		return fmt.Errorf("catrust: stat %s: %w", path, err)
	}
	if err := m.fsm.Remove(ctx, path); err != nil {
		return fmt.Errorf("catrust: remove %s: %w", path, err)
	}
	if err := m.refresh(ctx, m.cfg.removeRefresh); err != nil {
		return err
	}
	return nil
}

// List enumerates the managed anchors by parsing the .crt files in the backend's
// anchors dir. A missing dir means none. Unparseable files are skipped.
func (m *manager) List(ctx context.Context) ([]Anchor, error) {
	entries, err := readDir(m.anchorsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []Anchor{}, nil
		}
		return nil, fmt.Errorf("catrust: read %s: %w", m.anchorsDir, err)
	}
	out := make([]Anchor, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !hasAnchorExt(e.Name()) {
			continue
		}
		data, err := readFile(m.anchorsDir + "/" + e.Name())
		if err != nil {
			continue
		}
		cert, err := parseCert(data)
		if err != nil {
			continue
		}
		out = append(out, Anchor{
			Name:    e.Name()[:len(e.Name())-len(anchorExt)],
			Subject: cert.Subject.String(),
			Issuer:  cert.Issuer.String(),
		})
	}
	return out, nil
}

// refresh runs the backend's escalated trust-store rebuild command.
func (m *manager) refresh(ctx context.Context, cmd []string) error {
	res, err := m.r.Run(ctx, exec.Command{Name: cmd[0], Args: cmd[1:], Escalate: true})
	if err != nil {
		return fmt.Errorf("catrust: run %s: %w", cmd[0], err)
	}
	if res.ExitCode != 0 {
		return &exec.CommandError{Name: cmd[0], ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return nil
}
