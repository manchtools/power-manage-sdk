package network

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// NetworkManager keyfile-based PSK provisioning.
//
// Why this file exists: nmcli accepts `wifi-sec.psk <password>` as a command-line
// argument, which lands the password in /proc/<pid>/cmdline for anything sharing
// the PID namespace to read. The secure path NetworkManager documents is to write
// the connection profile as a keyfile under
// /etc/NetworkManager/system-connections/<name>.nmconnection with mode 0600, then
// `nmcli connection reload` so the daemon picks up the new file.
//
// Format reference:
//
//	https://networkmanager.dev/docs/api/latest/nm-settings-keyfile.html
//
// Only the PSK path uses this file. EAP-TLS provisioning continues through
// `nmcli connection add/modify` because the only secrets there are the cert file
// *paths* (the private-key contents live in the 0600 cert directory written by
// writeCerts) — those paths are not credentials and are safe on argv.

// nmKeyfileDir is NetworkManager's canonical system-connections directory. NM
// watches this dir and reloads on `connection reload`. A var (not const) only so
// tests can redirect it to a writable temp dir.
var nmKeyfileDir = "/etc/NetworkManager/system-connections"

// keyfilePath returns the canonical keyfile path for the given connection name.
// Path separators are replaced defensively so a malformed name can't escape the
// system-connections directory.
func keyfilePath(name string) string {
	safe := strings.ReplaceAll(name, string(filepath.Separator), "_")
	return filepath.Join(nmKeyfileDir, safe+".nmconnection")
}

// validatePSK enforces the WPA-PSK key contract before the secret is rendered
// into the keyfile `psk=` line: a WPA2/WPA3 pre-shared key is either an 8–63
// character passphrase of printable ASCII (0x20–0x7e), or the raw 256-bit PMK
// written as exactly 64 hexadecimal digits. Anything shorter, longer, or a
// 64-character value that is not valid hex is malformed and rejected here, before
// provisionPSK writes the keyfile or runs `nmcli connection reload`.
//
// The PSK is revealed locally to measure its length and character class; this is
// the same sanctioned [wifi-security] PSK sink as buildPSKKeyfile (it never
// reaches argv, a log, or the returned error — the error reports only the
// failure mode, never the value). Callers reach this only through
// validateProfile, so the check precedes any Runner command.
func validatePSK(psk exec.Secret) error {
	v := psk.Reveal()
	n := len(v)
	// A 64-character value is treated as a raw PMK and must be valid hex; a value
	// of any other length must be an 8–63 char printable-ASCII passphrase.
	if n == 64 && isHex(v) {
		return nil
	}
	if n < 8 || n > 63 {
		return fmt.Errorf("invalid PSK: a WPA pre-shared key must be 8–63 characters (or a 64-hex-digit raw PMK)")
	}
	for i := 0; i < n; i++ {
		c := v[i]
		if c < 0x20 || c > 0x7e {
			return fmt.Errorf("invalid PSK: must contain only printable ASCII characters")
		}
	}
	return nil
}

// isHex reports whether s consists solely of hexadecimal digits (used to tell a
// raw 64-octet PMK apart from a malformed 64-character passphrase).
func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isDigit := c >= '0' && c <= '9'
		isLower := c >= 'a' && c <= 'f'
		isUpper := c >= 'A' && c <= 'F'
		if !isDigit && !isLower && !isUpper {
			return false
		}
	}
	return true
}

// buildPSKKeyfile builds a NetworkManager keyfile body for a PSK profile, ready
// to write with mode 0600. The PSK lands in the [wifi-security] section: this is
// the ONLY mechanism that sets the PSK on a connection — argv never carries it.
// p.PSK.Reveal() here is the sole sanctioned PSK sink.
func buildPSKKeyfile(p Profile) []byte {
	var b strings.Builder

	b.WriteString("# Managed by power-manage-agent — do not edit by hand.\n")
	b.WriteString("[connection]\n")
	fmt.Fprintf(&b, "id=%s\n", p.Name)
	b.WriteString("type=wifi\n")
	if p.AutoConnect {
		b.WriteString("autoconnect=true\n")
	} else {
		b.WriteString("autoconnect=false\n")
	}
	fmt.Fprintf(&b, "autoconnect-priority=%d\n", p.Priority)
	b.WriteString("\n")

	b.WriteString("[wifi]\n")
	fmt.Fprintf(&b, "ssid=%s\n", p.SSID)
	b.WriteString("mode=infrastructure\n")
	if p.Hidden {
		b.WriteString("hidden=true\n")
	}
	b.WriteString("\n")

	b.WriteString("[wifi-security]\n")
	b.WriteString("key-mgmt=wpa-psk\n")
	fmt.Fprintf(&b, "psk=%s\n", p.PSK.Reveal())
	b.WriteString("\n")

	b.WriteString("[ipv4]\n")
	b.WriteString("method=auto\n")
	b.WriteString("\n")
	b.WriteString("[ipv6]\n")
	b.WriteString("method=auto\n")

	return []byte(b.String())
}

// writeKeyfile atomically writes the keyfile body to path with mode 0600.
// Atomicity matters because NetworkManager watches the directory: a partial write
// could be picked up mid-flight and yield a half-valid profile. Strategy: write a
// sibling temp file in the same directory, chmod before close (so the final path
// never momentarily exists with default umask perms), then rename over.
func writeKeyfile(path string, content []byte) error {
	dir := filepath.Dir(path)
	if err := mkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create keyfile dir %q: %w", dir, err)
	}
	tmp, err := createTemp(dir, ".pm-keyfile-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp keyfile in %q: %w", dir, err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		_ = removeFile(tmpPath)
		return fmt.Errorf("write keyfile: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = removeFile(tmpPath)
		return fmt.Errorf("chmod keyfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = removeFile(tmpPath)
		return fmt.Errorf("close keyfile: %w", err)
	}
	if err := renameFile(tmpPath, path); err != nil {
		_ = removeFile(tmpPath)
		return fmt.Errorf("rename keyfile to %q: %w", path, err)
	}
	return nil
}
