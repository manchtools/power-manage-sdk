package network

import (
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/keyfile"
)

// Threat model: a WiFi profile (SSID / PSK / connection name / EAP
// identity) is operator-supplied and lands in a ROOT-owned
// /etc/NetworkManager/system-connections/<name>.nmconnection that NM
// loads as root. A field carrying a newline can inject arbitrary keyfile
// keys or whole sections (e.g. flip permissions, redirect DNS, disable
// security). The contract: such a profile must be REJECTED before any
// keyfile is built or written — fail closed, not silently stripped.

// injectionPayloads are sourced from the keyfile grammar (newline / CR /
// NUL break a line), not from the validator, so an under-specified
// validator can't hide behind matching test data.
var injectionPayloads = []string{
	"x\n[connection]\npermissions=user:root:",
	"x\r\nid=hijacked",
	"x\npsk=attacker-known",
	"x\x00",
	"\n",
	"\r",
}

func TestValidateProfile_RejectsInjectionInPSKFields(t *testing.T) {
	base := func() WiFiProfile {
		return WiFiProfile{
			Name:     "pm-wifi-ok",
			SSID:     "CorpNet",
			AuthType: WiFiAuthPSK,
			PSK:      "hunter2",
		}
	}

	// Cover every field that reaches the keyfile: connection name, SSID,
	// and PSK. For each, the absent/empty case is already covered by the
	// required-field checks; here we assert the present-but-malformed case
	// is rejected.
	fields := map[string]func(*WiFiProfile, string){
		"Name": func(p *WiFiProfile, v string) { p.Name = v },
		"SSID": func(p *WiFiProfile, v string) { p.SSID = v },
		"PSK":  func(p *WiFiProfile, v string) { p.PSK = v },
	}

	for field, set := range fields {
		for _, payload := range injectionPayloads {
			p := base()
			set(&p, payload)
			err := validateProfile(p)
			if err == nil {
				t.Errorf("validateProfile accepted injection in %s=%q, want rejection", field, payload)
			}
		}
	}
}

func TestValidateProfile_AcceptsLegitimatePSKProfile(t *testing.T) {
	// Guard against over-rejection: a real SSID with spaces and a WPA
	// passphrase full of symbols must still pass.
	p := WiFiProfile{
		Name:     "pm-wifi-ok",
		SSID:     "Corp Net 5GHz #2",
		AuthType: WiFiAuthPSK,
		PSK:      "p@ss w0rd=#1;ok[]",
	}
	if err := validateProfile(p); err != nil {
		t.Errorf("validateProfile rejected a legitimate profile: %v", err)
	}
}

func TestValidateProfile_RejectsInjectionInEAPIdentity(t *testing.T) {
	// The EAP-TLS identity reaches nmcli argv (and would reach a keyfile
	// if that path grew one); reject line-breaking bytes there too.
	p := WiFiProfile{
		Name:       "pm-wifi-eap",
		SSID:       "CorpNet",
		AuthType:   WiFiAuthEAPTLS,
		Identity:   "user\ninjected=1",
		CertDir:    CertBaseDir + "/pm-wifi-eap",
		ClientCert: "cert.pem",
		ClientKey:  "key.pem",
	}
	if err := validateProfile(p); err == nil {
		t.Error("validateProfile accepted injection in EAP Identity, want rejection")
	}
}

func TestBuildPSKKeyfile_FailsClosedOnInjection(t *testing.T) {
	// Defense in depth: even if a caller bypasses validateProfile and
	// calls BuildPSKKeyfile directly, it must return an error (not a
	// keyfile body containing the injected section).
	p := WiFiProfile{
		Name:     "pm-wifi",
		SSID:     "Evil\n[connection]\npermissions=user:root:",
		AuthType: WiFiAuthPSK,
		PSK:      "hunter2",
	}
	body, err := BuildPSKKeyfile(p)
	if err == nil {
		t.Fatalf("BuildPSKKeyfile accepted injection, returned body:\n%s", body)
	}
	if body != nil {
		t.Errorf("BuildPSKKeyfile returned a body on error, want nil:\n%s", body)
	}
	// And the error must be the typed keyfile error so callers can branch.
	if !strings.Contains(err.Error(), keyfile.ErrUnsafeValue.Error()) {
		t.Errorf("BuildPSKKeyfile error = %v, want it to wrap ErrUnsafeValue", err)
	}
}
