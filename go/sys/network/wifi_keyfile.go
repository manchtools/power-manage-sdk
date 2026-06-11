package network

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/keyfile"
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
//
// Every operator-supplied field (Name, SSID, PSK) is routed through the
// keyfile.Builder, which refuses a value carrying a newline / CR / NUL.
// That is what stops an SSID or PSK like "x\n[connection]\npermissions=…"
// from injecting extra keys or sections into this root-owned, root-parsed
// file. An injected field makes BuildPSKKeyfile return an error and a nil
// body — never a partially-rendered keyfile. CreateOrUpdate rejects the
// same input earlier via validateProfile; this is the defense-in-depth
// layer for any caller that reaches BuildPSKKeyfile directly.
func BuildPSKKeyfile(p WiFiProfile) ([]byte, error) {
	kf := &keyfile.Builder{}
	kf.Comment("Managed by power-manage-agent — do not edit by hand.")

	kf.Section("connection")
	kf.Set("id", p.Name)
	kf.Set("type", "wifi")
	if p.AutoConnect {
		kf.Set("autoconnect", "true")
	} else {
		kf.Set("autoconnect", "false")
	}
	kf.Set("autoconnect-priority", strconv.Itoa(p.Priority))

	kf.Section("wifi")
	kf.Set("ssid", p.SSID)
	kf.Set("mode", "infrastructure")
	if p.Hidden {
		kf.Set("hidden", "true")
	}

	kf.Section("wifi-security")
	kf.Set("key-mgmt", "wpa-psk")
	kf.Set("psk", p.PSK)

	kf.Section("ipv4")
	kf.Set("method", "auto")

	kf.Section("ipv6")
	kf.Set("method", "auto")

	body, err := kf.Bytes()
	if err != nil {
		return nil, fmt.Errorf("build PSK keyfile: %w", err)
	}
	return body, nil
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
	body, err := BuildPSKKeyfile(p)
	if err != nil {
		return err
	}
	if err := writeKeyfile(keyfilePath(p.Name), body); err != nil {
		return err
	}
	return reloadKeyfiles(ctx)
}
