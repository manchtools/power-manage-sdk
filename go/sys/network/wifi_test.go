package network

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsAvailable(t *testing.T) {
	available := IsAvailable()
	t.Logf("nmcli available: %v", available)
}

func TestBuildAddArgs_PSK(t *testing.T) {
	p := WiFiProfile{
		Name:        "pm-wifi-abc123",
		SSID:        "CorpNet",
		AuthType:    WiFiAuthPSK,
		PSK:         "hunter2",
		AutoConnect: true,
		Hidden:      true,
		Priority:    10,
	}

	args := BuildAddArgs(p)

	expected := []string{
		"con", "add",
		"con-name", "pm-wifi-abc123",
		"type", "wifi",
		"ssid", "CorpNet",
		"wifi-sec.key-mgmt", "wpa-psk",
		"wifi-sec.psk", "hunter2",
		"connection.autoconnect", "yes",
		"connection.autoconnect-priority", "10",
		"wifi.hidden", "yes",
	}

	assertArgs(t, expected, args)
}

func TestBuildAddArgs_EAPTLS(t *testing.T) {
	p := WiFiProfile{
		Name:        "pm-wifi-xyz789",
		SSID:        "SecureNet",
		AuthType:    WiFiAuthEAPTLS,
		Identity:    "user@corp.com",
		CACert:      "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
		ClientCert:  "-----BEGIN CERTIFICATE-----\nCLIENT\n-----END CERTIFICATE-----",
		ClientKey:   "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----",
		AutoConnect: false,
		CertDir:     "/var/lib/power-manage/wifi/xyz789",
	}

	args := BuildAddArgs(p)

	expected := []string{
		"con", "add",
		"con-name", "pm-wifi-xyz789",
		"type", "wifi",
		"ssid", "SecureNet",
		"wifi-sec.key-mgmt", "wpa-eap",
		"802-1x.eap", "tls",
		"802-1x.identity", "user@corp.com",
		"802-1x.ca-cert", "/var/lib/power-manage/wifi/xyz789/ca.pem",
		"802-1x.client-cert", "/var/lib/power-manage/wifi/xyz789/client.pem",
		"802-1x.private-key", "/var/lib/power-manage/wifi/xyz789/client-key.pem",
		"connection.autoconnect", "no",
		"connection.autoconnect-priority", "0",
		"wifi.hidden", "no",
	}

	assertArgs(t, expected, args)
}

func TestBuildModifyArgs_PSK(t *testing.T) {
	p := WiFiProfile{
		Name:        "pm-wifi-abc123",
		SSID:        "CorpNet",
		AuthType:    WiFiAuthPSK,
		PSK:         "newpass",
		AutoConnect: true,
		Priority:    5,
	}

	args := BuildModifyArgs(p)

	expected := []string{
		"con", "mod", "pm-wifi-abc123",
		"wifi.ssid", "CorpNet",
		"wifi-sec.key-mgmt", "wpa-psk",
		"wifi-sec.psk", "newpass",
		"connection.autoconnect", "yes",
		"connection.autoconnect-priority", "5",
		"wifi.hidden", "no",
	}

	assertArgs(t, expected, args)
}

func TestBuildModifyArgs_EAPTLS(t *testing.T) {
	p := WiFiProfile{
		Name:        "pm-wifi-xyz789",
		SSID:        "SecureNet",
		AuthType:    WiFiAuthEAPTLS,
		Identity:    "user@corp.com",
		CertDir:     "/var/lib/power-manage/wifi/xyz789",
		AutoConnect: false,
		Hidden:      true,
		Priority:    3,
	}

	args := BuildModifyArgs(p)

	expected := []string{
		"con", "mod", "pm-wifi-xyz789",
		"wifi.ssid", "SecureNet",
		"wifi-sec.key-mgmt", "wpa-eap",
		"802-1x.eap", "tls",
		"802-1x.identity", "user@corp.com",
		"802-1x.ca-cert", "/var/lib/power-manage/wifi/xyz789/ca.pem",
		"802-1x.client-cert", "/var/lib/power-manage/wifi/xyz789/client.pem",
		"802-1x.private-key", "/var/lib/power-manage/wifi/xyz789/client-key.pem",
		"connection.autoconnect", "no",
		"connection.autoconnect-priority", "3",
		"wifi.hidden", "yes",
	}

	assertArgs(t, expected, args)
}

func TestConnectionExists_NonExistent(t *testing.T) {
	if !IsAvailable() {
		t.Skip("nmcli not available")
	}

	exists := ConnectionExists("pm-wifi-nonexistent-test-98765")
	if exists {
		t.Error("expected non-existent connection to return false")
	}
}

func TestBuildDesiredSettings(t *testing.T) {
	p := WiFiProfile{
		Name:        "test",
		SSID:        "MyNet",
		AuthType:    WiFiAuthPSK,
		PSK:         "secret",
		AutoConnect: true,
		Hidden:      false,
		Priority:    3,
	}

	settings := buildDesiredSettings(p)

	checks := map[string]string{
		"wifi.ssid":                       "MyNet",
		"wifi-sec.key-mgmt":              "wpa-psk",
		"wifi-sec.psk":                   "secret",
		"connection.autoconnect":          "yes",
		"connection.autoconnect-priority": "3",
		"wifi.hidden":                     "no",
	}

	for key, want := range checks {
		got, ok := settings[key]
		if !ok {
			t.Errorf("missing key %s", key)
			continue
		}
		if got != want {
			t.Errorf("settings[%s] = %q, want %q", key, got, want)
		}
	}
}

func TestValidateProfile(t *testing.T) {
	tests := []struct {
		name    string
		profile WiFiProfile
		wantErr bool
	}{
		{"valid PSK", WiFiProfile{Name: "test", SSID: "net", AuthType: WiFiAuthPSK, PSK: "pass"}, false},
		{"valid EAP-TLS", WiFiProfile{Name: "test", SSID: "net", AuthType: WiFiAuthEAPTLS, Identity: "user", CertDir: "/tmp"}, false},
		{"missing name", WiFiProfile{SSID: "net", AuthType: WiFiAuthPSK, PSK: "pass"}, true},
		{"missing SSID", WiFiProfile{Name: "test", AuthType: WiFiAuthPSK, PSK: "pass"}, true},
		{"missing PSK", WiFiProfile{Name: "test", SSID: "net", AuthType: WiFiAuthPSK}, true},
		{"missing identity", WiFiProfile{Name: "test", SSID: "net", AuthType: WiFiAuthEAPTLS, CertDir: "/tmp"}, true},
		{"missing certdir", WiFiProfile{Name: "test", SSID: "net", AuthType: WiFiAuthEAPTLS, Identity: "user"}, true},
		{"unknown auth", WiFiProfile{Name: "test", SSID: "net", AuthType: 99}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProfile(tt.profile)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateProfile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWriteCerts(t *testing.T) {
	dir := t.TempDir()

	p := WiFiProfile{
		CertDir:    dir,
		CACert:     "ca-content",
		ClientCert: "client-content",
		ClientKey:  "key-content",
	}

	if err := writeCerts(p); err != nil {
		t.Fatalf("writeCerts: %v", err)
	}

	// Verify files exist and have correct content.
	files := map[string]string{
		"ca.pem":         "ca-content",
		"client.pem":     "client-content",
		"client-key.pem": "key-content",
	}
	for name, want := range files {
		data, err := readFile(t, dir, name)
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		if string(data) != want {
			t.Errorf("%s content = %q, want %q", name, data, want)
		}
	}

	// Verify file permissions
	perms := map[string]os.FileMode{
		"ca.pem":         0644,
		"client.pem":     0644,
		"client-key.pem": 0600,
	}
	for name, wantPerm := range perms {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("stat %s: %v", name, err)
			continue
		}
		if got := info.Mode().Perm(); got != wantPerm {
			t.Errorf("%s permissions = %o, want %o", name, got, wantPerm)
		}
	}
}

func TestWriteCerts_SkipsEmpty(t *testing.T) {
	dir := t.TempDir()

	p := WiFiProfile{
		CertDir:    dir,
		CACert:     "ca-content",
		ClientCert: "",
		ClientKey:  "",
	}

	if err := writeCerts(p); err != nil {
		t.Fatalf("writeCerts: %v", err)
	}

	// ca.pem should exist
	if _, err := readFile(t, dir, "ca.pem"); err != nil {
		t.Errorf("ca.pem should exist: %v", err)
	}

	// client.pem and client-key.pem should NOT exist
	for _, name := range []string{"client.pem", "client-key.pem"} {
		_, err := readFile(t, dir, name)
		if err == nil {
			t.Errorf("%s should not exist when content is empty", name)
		}
	}
}

func readFile(t *testing.T, dir, name string) ([]byte, error) {
	t.Helper()
	return os.ReadFile(filepath.Join(dir, name))
}

// assertArgs checks that actual contains all expected args in order.
func assertArgs(t *testing.T, expected, actual []string) {
	t.Helper()

	if len(actual) < len(expected) {
		t.Errorf("got %d args, want at least %d\ngot:  %v\nwant: %v", len(actual), len(expected), actual, expected)
		return
	}

	for i, want := range expected {
		if i >= len(actual) {
			t.Errorf("missing arg at index %d: want %q", i, want)
			continue
		}
		if actual[i] != want {
			t.Errorf("arg[%d] = %q, want %q\nfull args: %v", i, actual[i], want, actual)
		}
	}
}
