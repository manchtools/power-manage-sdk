// Package network provides NetworkManager WiFi connection management via nmcli.
package network

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// WiFiAuthType identifies the WiFi authentication method.
type WiFiAuthType int

const (
	// WiFiAuthPSK uses WPA2/WPA3 pre-shared key authentication.
	WiFiAuthPSK WiFiAuthType = 1
	// WiFiAuthEAPTLS uses 802.1X EAP-TLS certificate-based authentication.
	WiFiAuthEAPTLS WiFiAuthType = 2
)

// CertBaseDir is the expected parent directory for cert directories.
// Both CreateOrUpdate and Delete validate paths against this.
const CertBaseDir = "/var/lib/power-manage/wifi"

// WiFiProfile represents a NetworkManager WiFi connection profile.
type WiFiProfile struct {
	Name        string       // Connection name (e.g. "pm-wifi-<id>")
	SSID        string       // WiFi network SSID
	AuthType    WiFiAuthType // PSK or EAP_TLS
	PSK         string       // WPA2/WPA3 password (PSK only)
	CACert      string       // PEM content (EAP-TLS only)
	ClientCert  string       // PEM content (EAP-TLS only)
	ClientKey   string       // PEM content (EAP-TLS only)
	Identity    string       // EAP identity (EAP-TLS only)
	AutoConnect bool
	Hidden      bool
	Priority    int
	CertDir     string // Directory for EAP-TLS cert files (must be under CertBaseDir)
}

// IsAvailable returns true if the CLI for the active WifiBackend is
// installed and reachable. Defaults to nmcli (NetworkManager).
func IsAvailable() bool {
	switch CurrentWifiBackend() {
	case WifiBackendNetworkManager:
		return sysexec.Check("nmcli", "--version")
	default:
		// No concrete implementation for the other backends yet — report
		// unavailable so callers fall through to "wifi not supported"
		// error paths rather than claiming availability.
		return false
	}
}

// ConnectionExists checks if a named NetworkManager connection profile exists.
// Lists all connection names and searches for an exact match so that real
// failures (NetworkManager not running, nmcli not installed, context
// cancellation) propagate as errors instead of collapsing into "not found".
func ConnectionExists(ctx context.Context, name string) (bool, error) {
	result, err := sysexec.Run(ctx, "nmcli", "-t", "-f", "NAME", "con", "show")
	if err != nil {
		return false, fmt.Errorf("list connections: %w", err)
	}
	for _, line := range strings.Split(result.Stdout, "\n") {
		// Only strip CR (for CRLF endings); leading/trailing whitespace can
		// be part of a connection name.
		if unescapeNmcli(strings.TrimRight(line, "\r")) == name {
			return true, nil
		}
	}
	return false, nil
}

// CreateOrUpdate creates or updates a WiFi connection profile.
// It returns whether a change was made and any error.
// Currently only WifiBackendNetworkManager is implemented; calls on
// other backends return ErrWifiBackendNotSupported.
func CreateOrUpdate(ctx context.Context, profile WiFiProfile) (bool, error) {
	if err := requireWifiBackend(WifiBackendNetworkManager, "CreateOrUpdate"); err != nil {
		return false, err
	}
	if err := validateProfile(profile); err != nil {
		return false, err
	}

	exists, err := ConnectionExists(ctx, profile.Name)
	if err != nil {
		return false, err
	}

	if exists {
		return updateConnection(ctx, profile)
	}
	return createConnection(ctx, profile)
}

// createConnection writes certs (if EAP-TLS) and creates a new connection.
// Cleans up certs on failure since no connection exists to use them.
func createConnection(ctx context.Context, p WiFiProfile) (bool, error) {
	if p.AuthType == WiFiAuthEAPTLS {
		if err := writeCerts(p); err != nil {
			return false, fmt.Errorf("write certificates: %w", err)
		}
	}
	args := BuildAddArgs(p)
	if _, err := sysexec.Privileged(ctx, "nmcli", args...); err != nil {
		if p.AuthType == WiFiAuthEAPTLS {
			removeCerts(p.CertDir)
		}
		return false, fmt.Errorf("create connection: %w", err)
	}
	return true, nil
}

// updateConnection modifies an existing connection if settings differ.
// For EAP-TLS, new certs are staged in a temp directory; only on successful
// nmcli modify are they swapped into the final location, leaving live certs
// untouched if modification fails. If GetSettings fails, EAP-TLS still uses
// the staged path so a partial read never causes the live cert dir to be
// overwritten.
func updateConnection(ctx context.Context, p WiFiProfile) (bool, error) {
	current, err := GetSettings(ctx, p.Name)
	if err != nil {
		// Can't read current settings — proceed with modify but skip drift
		// detection. EAP-TLS must still use the staged path so a partial read
		// never destroys the live cert dir.
		if p.AuthType == WiFiAuthEAPTLS {
			return stagedModify(ctx, p, nil)
		}
		return directModify(ctx, p, nil)
	}

	if !needsModify(current, p) {
		return false, nil
	}

	if p.AuthType != WiFiAuthEAPTLS {
		return directModify(ctx, p, current)
	}
	return stagedModify(ctx, p, current)
}

// stagedModify applies an EAP-TLS modify with cert staging. New certs are
// written to a temp directory, nmcli is reconfigured to point at the final
// paths, and only after nmcli succeeds is the cert directory swapped via
// rename-over with rollback. The live cert directory is never destroyed
// before the staged copy is in place.
func stagedModify(ctx context.Context, p WiFiProfile, current map[string]string) (bool, error) {
	tmpDir := p.CertDir + ".tmp"
	staged := p
	staged.CertDir = tmpDir
	defer os.RemoveAll(tmpDir) // best-effort cleanup if anything below fails

	if err := writeCerts(staged); err != nil {
		return false, fmt.Errorf("write staged certificates: %w", err)
	}

	// Modify with the FINAL cert paths (not temp), then move temp into place.
	// This way nmcli's config never references the temp dir.
	if _, err := sysexec.Privileged(ctx, "nmcli", buildModifyArgs(p, current)...); err != nil {
		return false, fmt.Errorf("modify connection: %w", err)
	}

	// nmcli succeeded — swap staged certs into place via rename-over.
	// Move live → .old, staged → live, then delete .old. On failure, attempt
	// to restore .old back so we never leave a missing cert directory.
	oldDir := p.CertDir + ".old"
	liveExists := false
	if _, err := os.Stat(p.CertDir); err == nil {
		if err := os.Rename(p.CertDir, oldDir); err != nil {
			return true, fmt.Errorf("backup old cert directory: %w", err)
		}
		liveExists = true
	}
	if err := os.Rename(tmpDir, p.CertDir); err != nil {
		// Restore the backup
		if liveExists {
			if rerr := os.Rename(oldDir, p.CertDir); rerr != nil {
				return true, fmt.Errorf("install staged certs: %w (rollback also failed: %v)", err, rerr)
			}
		}
		return true, fmt.Errorf("install staged certs: %w", err)
	}
	if liveExists {
		os.RemoveAll(oldDir)
	}
	return true, nil
}

// directModify applies a modify command without staging. Only used for
// non-EAP-TLS profiles, since EAP-TLS always goes through stagedModify to
// protect the live cert directory.
func directModify(ctx context.Context, p WiFiProfile, current map[string]string) (bool, error) {
	if _, err := sysexec.Privileged(ctx, "nmcli", buildModifyArgs(p, current)...); err != nil {
		return false, fmt.Errorf("modify connection: %w", err)
	}
	return true, nil
}

// needsModify performs a two-way comparison between current settings and
// desired. Considers keys from BOTH auth modes so a transition (e.g.
// PSK → EAP-TLS) is detected and stale fields are flagged for clearing.
// For EAP-TLS profiles it also compares the desired PEM contents against
// the certificate files on disk so a cert rotation (same paths, new content)
// triggers a re-write.
func needsModify(current map[string]string, p WiFiProfile) bool {
	desired := buildDesiredSettings(p)

	for key, want := range desired {
		if current[key] != want {
			return true
		}
	}
	for _, key := range allManagedKeys() {
		if _, inCurrent := current[key]; !inCurrent {
			continue
		}
		if _, inDesired := desired[key]; !inDesired {
			return true
		}
	}
	if p.AuthType == WiFiAuthEAPTLS && certsChanged(p) {
		return true
	}
	return false
}

// certsChanged returns true if any of the desired PEM contents differ from
// the file currently installed at the corresponding path under p.CertDir.
// A missing or unreadable file (with non-empty desired content) counts as
// changed so the cert writer runs and installs it.
func certsChanged(p WiFiProfile) bool {
	files := []struct {
		name    string
		content string
	}{
		{"ca.pem", p.CACert},
		{"client.pem", p.ClientCert},
		{"client-key.pem", p.ClientKey},
	}
	for _, f := range files {
		if f.content == "" {
			continue
		}
		existing, err := os.ReadFile(filepath.Join(p.CertDir, f.name))
		if err != nil || string(existing) != f.content {
			return true
		}
	}
	return false
}

// buildModifyArgs builds nmcli modify arguments. If current is non-nil,
// managed keys present in current but absent from the profile are set to ""
// to clear them. The union of both auth-mode key sets is considered so that
// switching auth modes (PSK ↔ EAP-TLS) clears the previous mode's fields
// (e.g. wifi-sec.psk when moving to EAP-TLS).
func buildModifyArgs(p WiFiProfile, current map[string]string) []string {
	args := []string{
		"con", "mod", p.Name,
		"wifi.ssid", p.SSID,
	}
	args = appendAuthArgs(args, p)
	args = appendCommonArgs(args, p)

	if current != nil {
		desired := buildDesiredSettings(p)
		for _, key := range allManagedKeys() {
			if _, inCurrent := current[key]; !inCurrent {
				continue
			}
			if _, inDesired := desired[key]; !inDesired {
				args = append(args, key, "")
			}
		}
	}
	return args
}

// Delete removes a WiFi connection by name and cleans up cert files in certDir.
// Currently only WifiBackendNetworkManager is implemented.
func Delete(ctx context.Context, name, certDir string) error {
	if err := requireWifiBackend(WifiBackendNetworkManager, "Delete"); err != nil {
		return err
	}
	return deleteNM(ctx, name, certDir)
}

// deleteNM is the NetworkManager-specific Delete implementation.
func deleteNM(ctx context.Context, name, certDir string) error {
	exists, err := ConnectionExists(ctx, name)
	if err != nil {
		return err
	}
	if exists {
		if _, err := sysexec.Privileged(ctx, "nmcli", "con", "delete", name); err != nil {
			return fmt.Errorf("delete connection %s: %w", name, err)
		}
	}

	if certDir != "" {
		if err := safeRemoveCertDir(certDir); err != nil {
			return err
		}
	}
	return nil
}

// isSubdirOf checks that child is a proper subdirectory of parent (not parent
// itself). Resolves symlinks on existing path components to prevent escaping
// the parent via symlinks. Handles non-existent paths by resolving the deepest
// existing ancestor.
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
// don't fully exist, it resolves the deepest existing ancestor and appends
// the remaining components.
func resolvePath(p string) string {
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return filepath.Clean(p)
	}
	// Try full resolution first (fast path for existing paths)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	// Walk up to find the deepest existing ancestor
	current := abs
	var suffix []string
	for {
		if _, err := os.Stat(current); err == nil {
			break
		}
		suffix = append([]string{filepath.Base(current)}, suffix...)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	resolved, err := filepath.EvalSymlinks(current)
	if err != nil {
		return abs
	}
	return filepath.Join(append([]string{resolved}, suffix...)...)
}

// safeRemoveCertDir validates that certDir is a proper subdirectory of
// CertBaseDir before removing. Rejects the base dir itself, parent traversal,
// non-directories, and paths outside the base.
func safeRemoveCertDir(certDir string) error {
	abs, err := filepath.Abs(filepath.Clean(certDir))
	if err != nil {
		return fmt.Errorf("resolve cert directory: %w", err)
	}
	if !isSubdirOf(CertBaseDir, abs) {
		return fmt.Errorf("cert directory %s is not a subdirectory of %s", abs, CertBaseDir)
	}
	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat cert directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("cert path %s is not a directory", abs)
	}
	return os.RemoveAll(abs)
}

// GetSettings retrieves current settings of a connection as a key-value map.
// Values are unescaped from nmcli terse-mode encoding (\: -> :, \\ -> \).
func GetSettings(ctx context.Context, name string) (map[string]string, error) {
	result, err := sysexec.Run(ctx, "nmcli", "-t", "-f", "all", "con", "show", name)
	if err != nil {
		return nil, fmt.Errorf("get settings for %s: %w", name, err)
	}

	settings := map[string]string{}
	for _, line := range strings.Split(result.Stdout, "\n") {
		line = strings.TrimRight(line, "\r")
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			// Keys are nmcli field names (no whitespace); values may contain
			// meaningful leading/trailing whitespace (PSKs, SSIDs) and must
			// not be trimmed.
			settings[parts[0]] = unescapeNmcli(parts[1])
		}
	}
	return settings, nil
}

// unescapeNmcli reverses nmcli terse-mode escaping: \\ -> \, \: -> :
func unescapeNmcli(s string) string {
	s = strings.ReplaceAll(s, `\\`, "\x00")
	s = strings.ReplaceAll(s, `\:`, ":")
	s = strings.ReplaceAll(s, "\x00", `\`)
	return s
}

// BuildAddArgs builds nmcli arguments for creating a WiFi connection.
func BuildAddArgs(p WiFiProfile) []string {
	args := []string{
		"con", "add",
		"con-name", p.Name,
		"type", "wifi",
		"ssid", p.SSID,
	}
	args = appendAuthArgs(args, p)
	args = appendCommonArgs(args, p)
	return args
}

// BuildModifyArgs builds nmcli arguments for modifying an existing WiFi connection.
// Does not include unset args for removed keys — use buildModifyArgs internally.
func BuildModifyArgs(p WiFiProfile) []string {
	return buildModifyArgs(p, nil)
}

func appendAuthArgs(args []string, p WiFiProfile) []string {
	switch p.AuthType {
	case WiFiAuthPSK:
		args = append(args,
			"wifi-sec.key-mgmt", "wpa-psk",
			"wifi-sec.psk", p.PSK,
		)
	case WiFiAuthEAPTLS:
		args = append(args,
			"wifi-sec.key-mgmt", "wpa-eap",
			"802-1x.eap", "tls",
			"802-1x.identity", p.Identity,
		)
		if p.CACert != "" {
			args = append(args, "802-1x.ca-cert", filepath.Join(p.CertDir, "ca.pem"))
		}
		if p.ClientCert != "" {
			args = append(args, "802-1x.client-cert", filepath.Join(p.CertDir, "client.pem"))
		}
		if p.ClientKey != "" {
			args = append(args, "802-1x.private-key", filepath.Join(p.CertDir, "client-key.pem"))
		}
	}
	return args
}

func appendCommonArgs(args []string, p WiFiProfile) []string {
	if p.AutoConnect {
		args = append(args, "connection.autoconnect", "yes")
	} else {
		args = append(args, "connection.autoconnect", "no")
	}
	args = append(args, "connection.autoconnect-priority", fmt.Sprintf("%d", p.Priority))
	if p.Hidden {
		args = append(args, "wifi.hidden", "yes")
	} else {
		args = append(args, "wifi.hidden", "no")
	}
	return args
}

// validateProfile checks required fields based on auth type.
func validateProfile(p WiFiProfile) error {
	if p.Name == "" {
		return fmt.Errorf("connection name is required")
	}
	if p.SSID == "" {
		return fmt.Errorf("SSID is required")
	}
	switch p.AuthType {
	case WiFiAuthPSK:
		if p.PSK == "" {
			return fmt.Errorf("PSK is required for WPA authentication")
		}
	case WiFiAuthEAPTLS:
		if p.Identity == "" {
			return fmt.Errorf("identity is required for EAP-TLS authentication")
		}
		if p.CertDir == "" {
			return fmt.Errorf("cert directory is required for EAP-TLS authentication")
		}
		if !isSubdirOf(CertBaseDir, p.CertDir) {
			return fmt.Errorf("cert directory must be under %s, got %s", CertBaseDir, p.CertDir)
		}
		if p.ClientCert == "" {
			return fmt.Errorf("client certificate is required for EAP-TLS authentication")
		}
		if p.ClientKey == "" {
			return fmt.Errorf("client key is required for EAP-TLS authentication")
		}
	default:
		return fmt.Errorf("unknown auth type: %d", p.AuthType)
	}
	return nil
}

// managedKeys returns the set of nmcli keys that this package manages for the
// given auth type. Used to detect when a key was removed from the profile.
func managedKeys(authType WiFiAuthType) []string {
	keys := []string{
		"wifi.ssid",
		"connection.autoconnect",
		"connection.autoconnect-priority",
		"wifi.hidden",
	}
	switch authType {
	case WiFiAuthPSK:
		keys = append(keys, "wifi-sec.key-mgmt", "wifi-sec.psk")
	case WiFiAuthEAPTLS:
		keys = append(keys,
			"wifi-sec.key-mgmt", "802-1x.eap", "802-1x.identity",
			"802-1x.ca-cert", "802-1x.client-cert", "802-1x.private-key",
		)
	}
	return keys
}

// allManagedKeys returns the union of nmcli keys this package manages across
// all auth modes. Used by drift detection and modify-arg construction so that
// fields from a previous auth mode are flagged for clearing during a
// transition (e.g. wifi-sec.psk when switching PSK → EAP-TLS).
func allManagedKeys() []string {
	return []string{
		"wifi.ssid",
		"connection.autoconnect",
		"connection.autoconnect-priority",
		"wifi.hidden",
		"wifi-sec.key-mgmt",
		"wifi-sec.psk",
		"802-1x.eap",
		"802-1x.identity",
		"802-1x.ca-cert",
		"802-1x.client-cert",
		"802-1x.private-key",
	}
}

func buildDesiredSettings(p WiFiProfile) map[string]string {
	desired := map[string]string{
		"wifi.ssid": p.SSID,
	}

	switch p.AuthType {
	case WiFiAuthPSK:
		desired["wifi-sec.key-mgmt"] = "wpa-psk"
		desired["wifi-sec.psk"] = p.PSK
	case WiFiAuthEAPTLS:
		desired["wifi-sec.key-mgmt"] = "wpa-eap"
		desired["802-1x.eap"] = "tls"
		desired["802-1x.identity"] = p.Identity
		if p.CACert != "" {
			desired["802-1x.ca-cert"] = filepath.Join(p.CertDir, "ca.pem")
		}
		if p.ClientCert != "" {
			desired["802-1x.client-cert"] = filepath.Join(p.CertDir, "client.pem")
		}
		if p.ClientKey != "" {
			desired["802-1x.private-key"] = filepath.Join(p.CertDir, "client-key.pem")
		}
	}

	if p.AutoConnect {
		desired["connection.autoconnect"] = "yes"
	} else {
		desired["connection.autoconnect"] = "no"
	}
	desired["connection.autoconnect-priority"] = fmt.Sprintf("%d", p.Priority)
	if p.Hidden {
		desired["wifi.hidden"] = "yes"
	} else {
		desired["wifi.hidden"] = "no"
	}

	return desired
}

// removeCerts removes certificate files written by writeCerts.
// Best-effort — errors are ignored since this is cleanup on failure.
func removeCerts(certDir string) {
	for _, name := range []string{"ca.pem", "client.pem", "client-key.pem"} {
		os.Remove(filepath.Join(certDir, name))
	}
}

// writeCerts writes EAP-TLS certificate files to the profile's CertDir.
func writeCerts(p WiFiProfile) error {
	if err := os.MkdirAll(p.CertDir, 0750); err != nil {
		return fmt.Errorf("create cert directory: %w", err)
	}

	files := []struct {
		name    string
		content string
		mode    os.FileMode
	}{
		{"ca.pem", p.CACert, 0640},
		{"client.pem", p.ClientCert, 0640},
		{"client-key.pem", p.ClientKey, 0600},
	}

	for _, f := range files {
		if f.content == "" {
			continue
		}
		path := filepath.Join(p.CertDir, f.name)
		if err := os.WriteFile(path, []byte(f.content), f.mode); err != nil {
			return fmt.Errorf("write %s: %w", f.name, err)
		}
	}
	return nil
}
