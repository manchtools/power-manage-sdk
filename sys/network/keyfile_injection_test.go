package network

import (
	"context"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// TestValidateProfile_RejectsControlChars: Name/SSID/PSK are rendered into the
// .nmconnection keyfile (id=/ssid=/psk=); a control character (notably a
// newline) would inject extra INI lines or sections. validateProfile must reject
// them; legitimate values must pass.
func TestValidateProfile_RejectsControlChars(t *testing.T) {
	ok := mustSecret(t, "Hunter2-Corp-PSK-distinctive")
	valid := Profile{Name: "pm-wifi-1", SSID: "CorpNet", AuthType: AuthPSK, PSK: ok}
	if err := validateProfile(valid); err != nil {
		t.Fatalf("a clean PSK profile was rejected: %v", err)
	}

	bad := map[string]Profile{
		"newline in name":      {Name: "pm\n[connection]\nid=evil", SSID: "Corp", AuthType: AuthPSK, PSK: ok},
		"leading dash in name": {Name: "-x", SSID: "Corp", AuthType: AuthPSK, PSK: ok},
		"empty name":           {Name: "", SSID: "Corp", AuthType: AuthPSK, PSK: ok},
		"newline in ssid":      {Name: "pm-wifi-1", SSID: "Corp\nhidden=true", AuthType: AuthPSK, PSK: ok},
		"NUL in ssid":          {Name: "pm-wifi-1", SSID: "Corp\x00", AuthType: AuthPSK, PSK: ok},
		// A normal NewSecret PSK can't hold a newline, but a NewMultilineSecret one
		// can — and its own doc forbids using it for a keyfile psk= line. The
		// profile validator is what enforces that, so test it via that constructor.
		"newline in psk":      {Name: "pm-wifi-1", SSID: "Corp", AuthType: AuthPSK, PSK: exec.NewMultilineSecret("pass\n[wifi-security]\nkey-mgmt=none")},
		"newline in identity": {Name: "pm-wifi-1", SSID: "Corp", AuthType: AuthEAPTLS, Identity: "user\nx"},
	}
	for name, p := range bad {
		t.Run(name, func(t *testing.T) {
			if err := validateProfile(p); err == nil {
				t.Errorf("validateProfile accepted an injectable profile (%s)", name)
			}
		})
	}
}

func TestValidateProfile_RejectsWeakOrMalformedPSK(t *testing.T) {
	cases := map[string]string{
		"too short":    "short7!",
		"too long":     strings.Repeat("a", 65),
		"bad 64-octet": strings.Repeat("z", 64),
	}
	for name, psk := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validateProfile(Profile{Name: "pm-wifi-1", SSID: "CorpNet", AuthType: AuthPSK, PSK: mustSecret(t, psk)}); err == nil {
				t.Fatalf("validateProfile accepted malformed WPA-PSK case %q", name)
			}
		})
	}
}

// TestApply_RejectsInjectionBeforeAnyCommand: Apply validates the profile first,
// so an injectable field is refused before any nmcli runs or keyfile is written.
func TestApply_RejectsInjectionBeforeAnyCommand(t *testing.T) {
	r := &recordingRunner{}
	_, err := mgr(t, r).Apply(context.Background(), Profile{
		Name: "pm\nid=evil", SSID: "Corp", AuthType: AuthPSK, PSK: mustSecret(t, "Hunter2xxxxxxx"),
	})
	if err == nil {
		t.Fatal("Apply accepted a newline-injected name")
	}
	if n := len(r.calls); n != 0 {
		t.Errorf("Apply ran %d commands; an injectable profile must be refused first", n)
	}
}

func TestConnectionNameMethods_RejectInvalidName(t *testing.T) {
	for _, name := range []string{"-x", "a\nb", "", "x\x00y", "tenant/prod"} {
		t.Run(name, func(t *testing.T) {
			r := &recordingRunner{}
			m := mgr(t, r)
			if _, err := m.ConnectionExists(context.Background(), name); err == nil {
				t.Errorf("ConnectionExists(%q) = nil err, want a validation error", name)
			}
			if _, err := m.Settings(context.Background(), name); err == nil {
				t.Errorf("Settings(%q) = nil err, want a validation error", name)
			}
			if err := m.Delete(context.Background(), name, DeleteOptions{}); err == nil {
				t.Errorf("Delete(%q) = nil err, want a validation error", name)
			}
			if n := len(r.calls); n != 0 {
				t.Errorf("an invalid name reached nmcli (%d calls)", n)
			}
		})
	}
}

// A legitimate connection name (including one with embedded spaces, which nmcli
// permits) must be accepted by the name validator.
func TestValidateConnName_AllowsLegitNames(t *testing.T) {
	for _, name := range []string{"pm-wifi-01", "Corp Net", "home_5GHz"} {
		if err := validateConnName(name); err != nil {
			t.Errorf("validateConnName(%q) = %v, want nil", name, err)
		}
	}
	if !strings.Contains(validateConnName("").Error(), "required") {
		t.Error("empty name should report 'required'")
	}
}
