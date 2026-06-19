package network

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// assertArgs checks that actual exactly matches expected.
func assertArgs(t *testing.T, expected, actual []string) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("got %d args, want %d\ngot:  %v\nwant: %v", len(actual), len(expected), actual, expected)
	}
	for i, want := range expected {
		if actual[i] != want {
			t.Errorf("arg[%d] = %q, want %q\nfull: %v", i, actual[i], want, actual)
		}
	}
}

func TestBuildAddArgs_EAPTLS(t *testing.T) {
	dir := "/var/lib/power-manage/wifi/xyz"
	args := buildAddArgs(Profile{
		Name: "pm-wifi-xyz", SSID: "SecureNet", AuthType: AuthEAPTLS,
		Identity: "user@corp.com", CACert: realCACert, ClientCert: realClientCert,
		ClientKey: exec.NewMultilineSecret(realPEMKey), CertDir: dir, AutoConnect: true, Priority: 5,
	})
	assertArgs(t, []string{
		"con", "add", "con-name", "pm-wifi-xyz", "type", "wifi", "ssid", "SecureNet",
		"wifi-sec.key-mgmt", "wpa-eap", "802-1x.eap", "tls", "802-1x.identity", "user@corp.com",
		"802-1x.ca-cert", filepath.Join(dir, "ca.pem"),
		"802-1x.client-cert", filepath.Join(dir, "client.pem"),
		"802-1x.private-key", filepath.Join(dir, "client-key.pem"),
		"connection.autoconnect", "yes",
		"connection.autoconnect-priority", "5",
		"wifi.hidden", "no",
	}, args)
}

func TestBuildAddArgs_EAPTLS_NoCertContent(t *testing.T) {
	args := buildAddArgs(Profile{
		Name: "pm-wifi-xyz", SSID: "SecureNet", AuthType: AuthEAPTLS,
		Identity: "user@corp.com", CertDir: "/var/lib/power-manage/wifi/xyz",
	})
	// No cert-path args when the content is empty / key is zero.
	assertArgs(t, []string{
		"con", "add", "con-name", "pm-wifi-xyz", "type", "wifi", "ssid", "SecureNet",
		"wifi-sec.key-mgmt", "wpa-eap", "802-1x.eap", "tls", "802-1x.identity", "user@corp.com",
		"connection.autoconnect", "no",
		"connection.autoconnect-priority", "0",
		"wifi.hidden", "no",
	}, args)
}

func TestBuildModifyArgs_EAPTLS_NoCurrent(t *testing.T) {
	dir := "/var/lib/power-manage/wifi/xyz"
	args := buildModifyArgs(Profile{
		Name: "pm-wifi-xyz", SSID: "SecureNet", AuthType: AuthEAPTLS,
		Identity: "user@corp.com", CACert: realCACert, ClientCert: realClientCert,
		ClientKey: exec.NewMultilineSecret(realPEMKey), CertDir: dir, Hidden: true, Priority: 3,
	}, nil)
	assertArgs(t, []string{
		"con", "mod", "pm-wifi-xyz", "wifi.ssid", "SecureNet",
		"wifi-sec.key-mgmt", "wpa-eap", "802-1x.eap", "tls", "802-1x.identity", "user@corp.com",
		"802-1x.ca-cert", filepath.Join(dir, "ca.pem"),
		"802-1x.client-cert", filepath.Join(dir, "client.pem"),
		"802-1x.private-key", filepath.Join(dir, "client-key.pem"),
		"connection.autoconnect", "no",
		"connection.autoconnect-priority", "3",
		"wifi.hidden", "yes",
	}, args)
}

// A PSK → EAP-TLS conversion must clear the stale wifi-sec.psk that the keyfile
// path had set, otherwise NetworkManager would keep two key-mgmt secrets.
func TestBuildModifyArgs_ClearsStalePSKOnTransition(t *testing.T) {
	dir := "/var/lib/power-manage/wifi/xyz"
	current := map[string]string{
		"wifi.ssid":         "SecureNet",
		"wifi-sec.key-mgmt": "wpa-psk",
		"wifi-sec.psk":      "old-secret",
	}
	args := buildModifyArgs(Profile{
		Name: "pm-wifi-xyz", SSID: "SecureNet", AuthType: AuthEAPTLS,
		Identity: "u", CACert: realCACert, ClientCert: realClientCert,
		ClientKey: exec.NewMultilineSecret(realPEMKey), CertDir: dir,
	}, current)

	// wifi-sec.psk is present in current but absent from the EAP desired set, so
	// it must be cleared (set to "").
	foundClear := false
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "wifi-sec.psk" && args[i+1] == "" {
			foundClear = true
		}
	}
	if !foundClear {
		t.Errorf("transition did not clear wifi-sec.psk; args = %v", args)
	}
	// key-mgmt is in desired (wpa-eap), so it is set, not cleared.
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "wifi-sec.key-mgmt" && args[i+1] == "" {
			t.Error("wifi-sec.key-mgmt should be set to wpa-eap, not cleared")
		}
	}
}

func TestAppendCommonArgs(t *testing.T) {
	got := appendCommonArgs(nil, Profile{AutoConnect: true, Hidden: true, Priority: 7})
	assertArgs(t, []string{
		"connection.autoconnect", "yes",
		"connection.autoconnect-priority", "7",
		"wifi.hidden", "yes",
	}, got)
	got = appendCommonArgs(nil, Profile{AutoConnect: false, Hidden: false})
	assertArgs(t, []string{
		"connection.autoconnect", "no",
		"connection.autoconnect-priority", "0",
		"wifi.hidden", "no",
	}, got)
}

func TestBuildDesiredSettings_EAPTLS(t *testing.T) {
	dir := "/var/lib/power-manage/wifi/xyz"
	d := buildDesiredSettings(Profile{
		SSID: "SecureNet", AuthType: AuthEAPTLS, Identity: "u",
		CACert: realCACert, ClientCert: realClientCert,
		ClientKey: exec.NewMultilineSecret(realPEMKey), CertDir: dir,
		AutoConnect: true, Hidden: false, Priority: 2,
	})
	want := map[string]string{
		"wifi.ssid":                       "SecureNet",
		"wifi-sec.key-mgmt":               "wpa-eap",
		"802-1x.eap":                      "tls",
		"802-1x.identity":                 "u",
		"802-1x.ca-cert":                  filepath.Join(dir, "ca.pem"),
		"802-1x.client-cert":              filepath.Join(dir, "client.pem"),
		"802-1x.private-key":              filepath.Join(dir, "client-key.pem"),
		"connection.autoconnect":          "yes",
		"connection.autoconnect-priority": "2",
		"wifi.hidden":                     "no",
	}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("desired[%q] = %q, want %q", k, d[k], v)
		}
	}
	// The PSK secret must never appear in the comparison map.
	if _, ok := d["wifi-sec.psk"]; ok {
		t.Error("buildDesiredSettings leaked a wifi-sec.psk key (Secret must stay out of the diff map)")
	}
}

func TestNeedsModify(t *testing.T) {
	dir := t.TempDir()
	p := eapProfile(t, dir)
	if err := writeCerts(p); err != nil { // on-disk certs match desired
		t.Fatal(err)
	}
	matching := map[string]string{
		"wifi.ssid":                       "SecureNet",
		"wifi-sec.key-mgmt":               "wpa-eap",
		"802-1x.eap":                      "tls",
		"802-1x.identity":                 "device@corp.example.com",
		"802-1x.ca-cert":                  filepath.Join(dir, "ca.pem"),
		"802-1x.client-cert":              filepath.Join(dir, "client.pem"),
		"802-1x.private-key":              filepath.Join(dir, "client-key.pem"),
		"connection.autoconnect":          "yes",
		"connection.autoconnect-priority": "0",
		"wifi.hidden":                     "no",
	}
	if needsModify(matching, p) {
		t.Error("needsModify = true when settings and certs all match")
	}

	t.Run("value drift", func(t *testing.T) {
		drifted := copyMap(matching)
		drifted["wifi.ssid"] = "OldName"
		if !needsModify(drifted, p) {
			t.Error("needsModify = false despite an SSID change")
		}
	})
	t.Run("stale managed key present", func(t *testing.T) {
		withStale := copyMap(matching)
		withStale["wifi-sec.psk"] = "leftover" // present in current, absent from desired
		if !needsModify(withStale, p) {
			t.Error("needsModify = false despite a stale wifi-sec.psk to clear")
		}
	})
	t.Run("cert content rotated on disk", func(t *testing.T) {
		rotated := eapProfile(t, dir)
		rotated.ClientKey = exec.NewMultilineSecret("-----BEGIN PRIVATE KEY-----\nNEW\n-----END PRIVATE KEY-----\n")
		if !needsModify(matching, rotated) {
			t.Error("needsModify = false despite a rotated client key on disk")
		}
	})
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func TestAllManagedKeys(t *testing.T) {
	keys := allManagedKeys()
	must := []string{"wifi-sec.psk", "wifi-sec.key-mgmt", "802-1x.private-key", "wifi.ssid"}
	for _, m := range must {
		found := false
		for _, k := range keys {
			if k == m {
				found = true
			}
		}
		if !found {
			t.Errorf("allManagedKeys missing %q (needed to clear it on a mode transition)", m)
		}
	}
}

func TestUnescapeNmcli(t *testing.T) {
	cases := map[string]string{
		`plain`:   `plain`,
		`a\:b`:    `a:b`,
		`a\\b`:    `a\b`,
		`a\\:b`:   `a\:b`, // \\ → \, then the literal : stays
		`x\:y\\z`: `x:y\z`,
	}
	for in, want := range cases {
		if got := unescapeNmcli(in); got != want {
			t.Errorf("unescapeNmcli(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDetect(t *testing.T) {
	orig := lookPath
	defer func() { lookPath = orig }()

	lookPath = func(string) (string, error) { return "/usr/bin/nmcli", nil }
	if got := Detect(context.Background()); len(got) != 1 || got[0] != NetworkManager {
		t.Errorf("Detect(nmcli present) = %v, want [NetworkManager]", got)
	}
	lookPath = func(string) (string, error) { return "", os.ErrNotExist }
	if got := Detect(context.Background()); len(got) != 0 {
		t.Errorf("Detect(nmcli absent) = %v, want empty", got)
	}
}
