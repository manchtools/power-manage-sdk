package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildPSKKeyfile_ContainsPSKInWifiSecuritySection(t *testing.T) {
	p := WiFiProfile{
		Name:        "pm-wifi-abc123",
		SSID:        "CorpNet",
		AuthType:    WiFiAuthPSK,
		PSK:         "hunter2",
		AutoConnect: true,
		Hidden:      true,
		Priority:    10,
	}
	got := string(BuildPSKKeyfile(p))

	// Spot-check the structurally important lines. We don't pin the
	// whole file body because tweaking trailing whitespace or section
	// ordering shouldn't break the test — only the contract that the
	// PSK lands in [wifi-security] under `psk=`.
	for _, want := range []string{
		"[connection]",
		"id=pm-wifi-abc123",
		"type=wifi",
		"autoconnect=true",
		"autoconnect-priority=10",
		"[wifi]",
		"ssid=CorpNet",
		"hidden=true",
		"[wifi-security]",
		"key-mgmt=wpa-psk",
		"psk=hunter2",
		"[ipv4]",
		"method=auto",
		"[ipv6]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("keyfile body missing %q:\n%s", want, got)
		}
	}

	// Defensive: the keyfile must not silently fall through to an
	// EAP-TLS-shaped block when the auth type is PSK — that would be a
	// regression of the auth-type switch.
	if strings.Contains(got, "[802-1x]") {
		t.Errorf("PSK keyfile must not contain [802-1x] section:\n%s", got)
	}
}

func TestBuildPSKKeyfile_AutoConnectFalseAndNoHidden(t *testing.T) {
	got := string(BuildPSKKeyfile(WiFiProfile{
		Name:     "pm-wifi-2",
		SSID:     "OpenNet",
		AuthType: WiFiAuthPSK,
		PSK:      "p",
	}))
	if !strings.Contains(got, "autoconnect=false") {
		t.Errorf("expected autoconnect=false in keyfile:\n%s", got)
	}
	if strings.Contains(got, "hidden=") {
		t.Errorf("hidden=true is the only emitted form; hidden=false should be absent (NM default):\n%s", got)
	}
}

func TestKeyfilePath_StripsPathSeparators(t *testing.T) {
	got := keyfilePath("../escape/attempt")
	// The path-separator strip is what stops directory traversal: a
	// name like `../escape/attempt` lands in a single filename
	// (`.._escape_attempt.nmconnection`) inside nmKeyfileDir rather
	// than escaping into a sibling directory.
	if filepath.Dir(got) != nmKeyfileDir {
		t.Errorf("keyfile escaped nmKeyfileDir: dir=%q, full=%q", filepath.Dir(got), got)
	}
	if strings.ContainsRune(filepath.Base(got), filepath.Separator) {
		t.Errorf("keyfile basename must not contain path separators: %q", filepath.Base(got))
	}
	if !strings.HasSuffix(got, ".nmconnection") {
		t.Errorf("keyfile path must end with .nmconnection, got %q", got)
	}
}

func TestWriteKeyfile_AtomicAndMode0600(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "pm-wifi-test.nmconnection")
	content := []byte("[connection]\nid=pm-wifi-test\n")

	if err := writeKeyfile(target, content); err != nil {
		t.Fatalf("writeKeyfile: %v", err)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("keyfile mode = %o, want 0600", mode)
	}

	read, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(read) != string(content) {
		t.Errorf("keyfile body mismatch:\n got: %q\nwant: %q", read, content)
	}

	// No tmp leftovers in the directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".pm-keyfile-") {
			t.Errorf("temp keyfile not cleaned up: %s", e.Name())
		}
	}
}
