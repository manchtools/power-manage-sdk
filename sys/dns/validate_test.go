package dns

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateConfig(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"valid v4 + domain + iface", Config{Nameservers: []string{"1.1.1.1"}, SearchDomains: []string{"corp.example"}, Interface: "eth0"}, false},
		{"valid v6", Config{Nameservers: []string{"2001:4860:4860::8888"}}, false},
		{"valid empty", Config{}, false},
		{"valid trailing-dot FQDN", Config{SearchDomains: []string{"corp.example."}}, false},
		{"nameserver not an IP", Config{Nameservers: []string{"not.an.ip"}}, true},
		{"nameserver flag-shaped", Config{Nameservers: []string{"-rf"}}, true},
		{"empty domain", Config{SearchDomains: []string{""}}, true},
		{"domain with space", Config{SearchDomains: []string{"a b"}}, true},
		{"domain with newline (injection)", Config{SearchDomains: []string{"a\nDNS=evil"}}, true},
		{"domain flag-shaped label", Config{SearchDomains: []string{"-evil.com"}}, true},
		{"interface flag-shaped", Config{Interface: "-eth0"}, true},
		{"interface too long", Config{Interface: strings.Repeat("a", 16)}, true},
		{"interface bad char", Config{Interface: "eth0;rm"}, true},
		{"domain over 253", Config{SearchDomains: []string{strings.Repeat("a.", 130) + "com"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateConfig(tc.cfg)
			if tc.wantErr && err == nil {
				t.Errorf("validateConfig(%+v) = nil, want error", tc.cfg)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateConfig(%+v) = %v, want nil", tc.cfg, err)
			}
			if tc.wantErr && err != nil && !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("error must wrap ErrInvalidConfig, got %v", err)
			}
		})
	}
}

func TestPartitionByFamily(t *testing.T) {
	v4, v6 := partitionByFamily([]string{"1.1.1.1", "2001:db8::1", "8.8.8.8", "fe80::1"})
	if strings.Join(v4, ",") != "1.1.1.1,8.8.8.8" {
		t.Errorf("v4 = %v, want [1.1.1.1 8.8.8.8]", v4)
	}
	if strings.Join(v6, ",") != "2001:db8::1,fe80::1" {
		t.Errorf("v6 = %v, want [2001:db8::1 fe80::1]", v6)
	}
	// Defensive skip of an unparseable entry (unreachable post-validation).
	v4, v6 = partitionByFamily([]string{"garbage", "1.2.3.4"})
	if strings.Join(v4, ",") != "1.2.3.4" || len(v6) != 0 {
		t.Errorf("partition(garbage,1.2.3.4) = (%v,%v), want ([1.2.3.4],[])", v4, v6)
	}
}
