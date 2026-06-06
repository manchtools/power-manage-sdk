package network

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// NetworkManager keyfile-based PSK provisioning.
//
// Why this file exists: nmcli accepts `wifi-sec.psk <password>` as a
// command-line argument, which lands the password in
// /proc/<pid>/cmdline. Anything sharing the PID namespace can read it.
// The canonical secure path NetworkManager documents is to write the
// connection profile as a keyfile under
// /etc/NetworkManager/system-connections/<name>.nmconnection with
// mode 0600 and then `nmcli connection reload` so the daemon picks
// up the new file.
//
// Format reference:
//
//	https://networkmanager.dev/docs/api/latest/nm-settings-keyfile.html
//
// Only the PSK path uses this file. EAP-TLS provisioning continues
// through `nmcli connection add` because the only secrets in EAP-TLS
// are the certificate file *paths* (the private-key contents live in
// the 0600 cert directory written by writeCerts) — those paths are
// not credentials and are safe on argv.

// nmKeyfileDir is NetworkManager's canonical system-connections
// directory. NM watches this dir for changes and reloads on
// `connection reload`.
const nmKeyfileDir = "/etc/NetworkManager/system-connections"

// keyfilePath returns the canonical keyfile path for the given
// connection name. Strips path separators defensively so a malformed
// name can't escape the system-connections directory.
func keyfilePath(name string) string {
	safe := strings.ReplaceAll(name, string(filepath.Separator), "_")
	return filepath.Join(nmKeyfileDir, safe+".nmconnection")
}

// BuildPSKKeyfile builds a NetworkManager keyfile body for a PSK
// profile. The returned bytes are ready to be written to disk with
// mode 0600.
//
// The keyfile carries the PSK in the [wifi-security] section. It is
// the only mechanism we use to set the PSK on a connection — argv
// never carries the secret. See appendAuthArgs for the matching
// defensive omission on the argv side.
func BuildPSKKeyfile(p WiFiProfile) []byte {
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
	fmt.Fprintf(&b, "psk=%s\n", p.PSK)
	b.WriteString("\n")

	b.WriteString("[ipv4]\n")
	b.WriteString("method=auto\n")
	b.WriteString("\n")
	b.WriteString("[ipv6]\n")
	b.WriteString("method=auto\n")

	return []byte(b.String())
}

// writeKeyfile atomically writes the given keyfile body to path with
// mode 0600. Atomicity matters because NetworkManager watches the
// directory: a partial write could be picked up mid-flight and yield
// a half-valid profile.
//
// Strategy: write to a sibling temp file in the same directory, chmod
// before close, then rename over. The chmod-before-rename ordering
// avoids a window in which the final path exists with default umask
// permissions while still being scanned by NM.
func writeKeyfile(path string, content []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create keyfile dir %q: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".pm-keyfile-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp keyfile in %q: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	closed := false
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		// If the rename below didn't run (early return on error),
		// remove the temp.
		if _, err := os.Stat(path); err != nil || !sameInode(path, tmpPath) {
			cleanup()
		}
	}()

	if _, err := tmp.Write(content); err != nil {
		return fmt.Errorf("write keyfile: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod keyfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close keyfile: %w", err)
	}
	closed = true
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename keyfile to %q: %w", path, err)
	}
	return nil
}

// sameInode is a defensive cleanup helper: returns true if path1 and
// path2 are the same file (after rename). Used to decide whether the
// temp cleanup should run.
func sameInode(a, b string) bool {
	sa, errA := os.Stat(a)
	sb, errB := os.Stat(b)
	if errA != nil || errB != nil {
		return false
	}
	return os.SameFile(sa, sb)
}

// reloadKeyfiles tells NetworkManager to re-read its on-disk profiles.
// Called after writeKeyfile so the new / updated PSK profile takes
// effect.
func reloadKeyfiles(ctx context.Context) error {
	if _, err := sysexec.Privileged(ctx, "nmcli", "connection", "reload"); err != nil {
		return fmt.Errorf("nmcli connection reload: %w", err)
	}
	return nil
}

// provisionPSKConnection writes the keyfile for a PSK profile and
// reloads NetworkManager. The caller is expected to have already
// validated the profile (validateProfile).
func provisionPSKConnection(ctx context.Context, p WiFiProfile) error {
	body := BuildPSKKeyfile(p)
	if err := writeKeyfile(keyfilePath(p.Name), body); err != nil {
		return err
	}
	return reloadKeyfiles(ctx)
}
