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

// certBaseDir is the expected parent directory for cert directories.
// Delete validates certDir is under this path before removing.
const certBaseDir = "/var/lib/power-manage/wifi"

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
	CertDir     string // Directory for EAP-TLS cert files
}

// IsAvailable returns true if NetworkManager nmcli is installed and reachable.
func IsAvailable() bool {
	return sysexec.Check("nmcli", "--version")
}

// ConnectionExists checks if a named NetworkManager connection profile exists.
func ConnectionExists(name string) bool {
	return sysexec.Check("nmcli", "-t", "-f", "NAME", "con", "show", name)
}

// CreateOrUpdate creates or updates a WiFi connection profile.
// It returns whether a change was made and any error.
func CreateOrUpdate(ctx context.Context, profile WiFiProfile) (bool, error) {
	if err := validateProfile(profile); err != nil {
		return false, err
	}

	// Write certificate files for EAP-TLS before configuring the connection.
	if profile.AuthType == WiFiAuthEAPTLS {
		if err := writeCerts(profile); err != nil {
			return false, fmt.Errorf("write certificates: %w", err)
		}
	}

	if ConnectionExists(profile.Name) {
		return modifyIfNeeded(ctx, profile)
	}

	args := BuildAddArgs(profile)
	result, err := sysexec.Sudo(ctx, "nmcli", args...)
	if err != nil {
		return false, fmt.Errorf("create connection: %w", err)
	}
	if result.ExitCode != 0 {
		return false, fmt.Errorf("nmcli con add failed: %s", result.Stderr)
	}
	return true, nil
}

// Delete removes a WiFi connection by name and cleans up cert files in certDir.
func Delete(ctx context.Context, name, certDir string) error {
	if ConnectionExists(name) {
		result, err := sysexec.Sudo(ctx, "nmcli", "con", "delete", name)
		if err != nil {
			return fmt.Errorf("delete connection %s: %w", name, err)
		}
		if result.ExitCode != 0 {
			return fmt.Errorf("nmcli con delete failed: %s", result.Stderr)
		}
	}

	if certDir != "" {
		if err := safeRemoveCertDir(certDir); err != nil {
			return err
		}
	}
	return nil
}

// safeRemoveCertDir validates that certDir is safe to remove before calling
// os.RemoveAll. Prevents accidental deletion of arbitrary paths.
func safeRemoveCertDir(certDir string) error {
	abs, err := filepath.Abs(filepath.Clean(certDir))
	if err != nil {
		return fmt.Errorf("resolve cert directory: %w", err)
	}
	if abs == "/" || abs == "." {
		return fmt.Errorf("refusing to remove unsafe path: %s", abs)
	}
	rel, err := filepath.Rel(certBaseDir, abs)
	if err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("cert directory %s is not under %s", abs, certBaseDir)
	}
	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // already gone
		}
		return fmt.Errorf("stat cert directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("cert path %s is not a directory", abs)
	}
	return os.RemoveAll(abs)
}

// GetSettings retrieves current settings of a connection as a key-value map.
func GetSettings(ctx context.Context, name string) (map[string]string, error) {
	result, err := sysexec.Run(ctx, "nmcli", "-t", "-f", "all", "con", "show", name)
	if err != nil {
		return nil, fmt.Errorf("get settings for %s: %w", name, err)
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("nmcli show failed: %s", result.Stderr)
	}

	settings := map[string]string{}
	for _, line := range strings.Split(result.Stdout, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			settings[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return settings, nil
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
func BuildModifyArgs(p WiFiProfile) []string {
	args := []string{
		"con", "mod", p.Name,
		"wifi.ssid", p.SSID,
	}
	args = appendAuthArgs(args, p)
	args = appendCommonArgs(args, p)
	return args
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
		// Only add cert path args when cert content is provided
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
	default:
		return fmt.Errorf("unknown auth type: %d", p.AuthType)
	}
	return nil
}

// modifyIfNeeded checks current settings and modifies only if they differ from desired.
func modifyIfNeeded(ctx context.Context, p WiFiProfile) (bool, error) {
	current, err := GetSettings(ctx, p.Name)
	if err != nil {
		// Cannot read settings; modify unconditionally to be safe.
		return modify(ctx, p)
	}

	desired := buildDesiredSettings(p)

	for key, want := range desired {
		if current[key] != want {
			return modify(ctx, p)
		}
	}
	return false, nil
}

func modify(ctx context.Context, p WiFiProfile) (bool, error) {
	args := BuildModifyArgs(p)
	result, err := sysexec.Sudo(ctx, "nmcli", args...)
	if err != nil {
		return false, fmt.Errorf("modify connection: %w", err)
	}
	if result.ExitCode != 0 {
		return false, fmt.Errorf("nmcli con mod failed: %s", result.Stderr)
	}
	return true, nil
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

// writeCerts writes EAP-TLS certificate files to the profile's CertDir.
func writeCerts(p WiFiProfile) error {
	if err := os.MkdirAll(p.CertDir, 0755); err != nil {
		return fmt.Errorf("create cert directory: %w", err)
	}

	files := []struct {
		name    string
		content string
		mode    os.FileMode
	}{
		{"ca.pem", p.CACert, 0644},
		{"client.pem", p.ClientCert, 0644},
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
