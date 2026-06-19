package network

import (
	"fmt"
	"path/filepath"
	"strings"
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
		tmp.Close()
		removeFile(tmpPath)
		return fmt.Errorf("write keyfile: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		removeFile(tmpPath)
		return fmt.Errorf("chmod keyfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		removeFile(tmpPath)
		return fmt.Errorf("close keyfile: %w", err)
	}
	if err := renameFile(tmpPath, path); err != nil {
		removeFile(tmpPath)
		return fmt.Errorf("rename keyfile to %q: %w", path, err)
	}
	return nil
}
