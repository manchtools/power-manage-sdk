// Package network manages WiFi connection profiles through an injected
// exec.Runner.
//
// Build a Manager for an explicit backend (NetworkManager/nmcli is the only one
// today) and a Runner, then call its methods. Read verbs (ConnectionExists,
// Settings) run unprivileged; mutations (add/modify/delete, reload) escalate
// through the Runner.
//
//	r, _ := exec.NewRunner(exec.Direct)
//	nm, _ := network.New(network.NetworkManager, r)
//	changed, _ := nm.Apply(ctx, profile)
//
// Credentials are exec.Secret values: the WPA PSK and the EAP-TLS client key
// never appear in a command's argv. The PSK is provisioned via a 0600
// NetworkManager keyfile (then `nmcli connection reload`); the client key is
// written to a 0600 file in the profile's cert directory. Both Reveal() sinks
// are enumerated by the archtest fitness function.
//
// Detect reports whether nmcli is usable on the host so a consumer can choose a
// backend explicitly.
package network

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// Backend selects the WiFi-management implementation. Passed explicitly even
// though NetworkManager is the only value today; the zero value is invalid
// (New → ErrUnknownBackend). The never-implemented connman/wpa_supplicant/iwd
// scaffolds are not ported; a real second backend is appended here when actually
// written.
type Backend int

// NetworkManager wraps nmcli.
const NetworkManager Backend = iota + 1

// ErrUnknownBackend is returned by New for the zero value or any Backend the SDK
// does not implement (fail-closed).
var ErrUnknownBackend = fmt.Errorf("network: unknown backend")

// AuthType identifies the WiFi authentication method.
type AuthType int

const (
	// AuthPSK uses WPA2/WPA3 pre-shared key authentication.
	AuthPSK AuthType = iota + 1
	// AuthEAPTLS uses 802.1X EAP-TLS certificate-based authentication.
	AuthEAPTLS
)

// CertBaseDir is the expected parent directory for EAP-TLS cert directories.
// Apply and Delete validate CertDir against this (symlink-aware) so a profile
// can never read or remove files outside the managed tree.
const CertBaseDir = "/var/lib/power-manage/wifi"

// certBaseDir is the value actually enforced by validateProfile /
// safeRemoveCertDir. It defaults to CertBaseDir; it is a var (not the exported
// const) only so tests can point it at a writable temp directory. Production
// always uses CertBaseDir.
var certBaseDir = CertBaseDir

// Profile is a NetworkManager WiFi connection profile.
type Profile struct {
	Name        string      // connection name (e.g. "pm-wifi-<id>")
	SSID        string      // WiFi network SSID
	AuthType    AuthType    // AuthPSK or AuthEAPTLS
	PSK         exec.Secret // WPA2/WPA3 password (PSK only) — never enters argv
	CACert      string      // PEM content (EAP-TLS only)
	ClientCert  string      // PEM content (EAP-TLS only)
	ClientKey   exec.Secret // PEM content (EAP-TLS only) — never enters argv
	Identity    string      // EAP identity (EAP-TLS only)
	AutoConnect bool
	Hidden      bool
	Priority    int
	CertDir     string // directory for EAP-TLS cert files (must be under CertBaseDir)
}

// DeleteOptions configures Delete. CertDir, when set, is the EAP-TLS cert
// directory to clean up after the connection is removed; it must be under
// CertBaseDir (validated, symlink-aware).
type DeleteOptions struct {
	CertDir string
}

// Manager is the WiFi-management contract.
type Manager interface {
	// ConnectionExists reports whether a named connection profile exists.
	ConnectionExists(ctx context.Context, name string) (bool, error)
	// Apply creates or updates a WiFi connection profile, returning whether a
	// change was made.
	Apply(ctx context.Context, p Profile) (changed bool, err error)
	// Delete removes a connection by name and, if opts.CertDir is set, cleans up
	// its cert directory.
	Delete(ctx context.Context, name string, opts DeleteOptions) error
	// Settings returns the current connection settings as a key-value map,
	// unescaped from nmcli terse-mode encoding.
	Settings(ctx context.Context, name string) (map[string]string, error)
}

// Option is the functional-option type for backend-specific knobs (none today).
type Option func(*networkManager)

// New returns a Manager for the named backend, driven by runner. Pure: validates
// the backend is known; it does not probe the host (use Detect). The zero value
// and any unimplemented backend are rejected with ErrUnknownBackend.
func New(b Backend, runner exec.Runner, _ ...Option) (Manager, error) {
	if b != NetworkManager {
		return nil, fmt.Errorf("%w: %d", ErrUnknownBackend, int(b))
	}
	if runner == nil {
		return nil, fmt.Errorf("network: %w", exec.ErrRunnerRequired)
	}
	return &networkManager{r: runner}, nil
}

// validateProfile checks required fields based on auth type. PSK/ClientKey are
// Secrets; an empty Secret counts as absent.
func validateProfile(p Profile) error {
	if p.Name == "" {
		return fmt.Errorf("connection name is required")
	}
	if p.SSID == "" {
		return fmt.Errorf("SSID is required")
	}
	switch p.AuthType {
	case AuthPSK:
		if p.PSK.IsZero() {
			return fmt.Errorf("PSK is required for WPA authentication")
		}
	case AuthEAPTLS:
		if p.Identity == "" {
			return fmt.Errorf("identity is required for EAP-TLS authentication")
		}
		if p.CertDir == "" {
			return fmt.Errorf("cert directory is required for EAP-TLS authentication")
		}
		if !isSubdirOf(certBaseDir, p.CertDir) {
			return fmt.Errorf("cert directory must be under %s, got %s", certBaseDir, p.CertDir)
		}
		if p.ClientCert == "" {
			return fmt.Errorf("client certificate is required for EAP-TLS authentication")
		}
		if p.ClientKey.IsZero() {
			return fmt.Errorf("client key is required for EAP-TLS authentication")
		}
	default:
		return fmt.Errorf("unknown auth type: %d", p.AuthType)
	}
	return nil
}

// isSubdirOf reports whether child is a proper subdirectory of parent (not
// parent itself). Symlinks on existing path components are resolved so a profile
// cannot escape parent via a symlink.
func isSubdirOf(parent, child string) bool {
	resolvedParent := resolvePath(parent)
	resolvedChild := resolvePath(child)
	rel, err := filepath.Rel(resolvedParent, resolvedChild)
	if err != nil {
		return false
	}
	return rel != "." && !strings.HasPrefix(rel, "..")
}

// resolvePath resolves symlinks for existing path components. For paths that
// don't fully exist, it resolves the deepest existing ancestor and appends the
// remaining components.
func resolvePath(p string) string {
	abs, err := absPath(filepath.Clean(p))
	if err != nil {
		return filepath.Clean(p)
	}
	// Fast path: fully existing path resolves directly.
	if resolved, err := evalSymlinks(abs); err == nil {
		return resolved
	}
	// Walk up to the deepest existing ancestor, then re-append the suffix.
	current := abs
	var suffix []string
	for {
		if _, err := statResolve(current); err == nil {
			break
		}
		suffix = append([]string{filepath.Base(current)}, suffix...)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	resolved, err := evalSymlinks(current)
	if err != nil {
		return abs
	}
	return filepath.Join(append([]string{resolved}, suffix...)...)
}

// safeRemoveCertDir validates that certDir is a proper subdirectory of
// certBaseDir before removing. Rejects the base dir itself, parent traversal,
// non-directories, and paths outside the base. A non-existent path is a no-op.
func safeRemoveCertDir(certDir string) error {
	abs, err := absPath(filepath.Clean(certDir))
	if err != nil {
		return fmt.Errorf("resolve cert directory: %w", err)
	}
	if !isSubdirOf(certBaseDir, abs) {
		return fmt.Errorf("cert directory %s is not a subdirectory of %s", abs, certBaseDir)
	}
	info, err := statFile(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat cert directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("cert path %s is not a directory", abs)
	}
	return removeAll(abs)
}
