package firewall

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// skipIfNotFirewalldUsable mirrors skipIfNotNftablesUsable: skip the
// test when firewall-cmd isn't present or we can't elevate. CI runs
// these inside containers where root is available; dev machines and
// macOS CI skip cleanly.
func skipIfNotFirewalldUsable(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/usr/bin/firewall-cmd"); err != nil {
		t.Skip("firewall-cmd not available on this system")
	}
	if os.Geteuid() != 0 {
		t.Skip("firewalld integration tests require root")
	}
}

// TestFirewalldServiceXML_TCPPort — the simplest case. Lock in the
// exact XML body the backend writes for a "open this TCP port" rule
// so refactors don't silently change what firewalld parses.
func TestFirewalldServiceXML_TCPPort(t *testing.T) {
	got := firewalldServiceXML(Rule{
		Name:     "ssh-in",
		Allow:    true,
		Protocol: ProtocolTCP,
		Port:     22,
	})
	want := strings.Join([]string{
		`<?xml version="1.0" encoding="utf-8"?>`,
		`<service>`,
		`  <short>pm:ssh-in</short>`,
		`  <description>power-manage managed rule</description>`,
		`  <port port="22" protocol="tcp"/>`,
		`</service>`,
		``,
	}, "\n")
	if got != want {
		t.Fatalf("firewalldServiceXML:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestFirewalldServiceXML_UDPPort — UDP toggle.
func TestFirewalldServiceXML_UDPPort(t *testing.T) {
	got := firewalldServiceXML(Rule{
		Name:     "dns",
		Allow:    true,
		Protocol: ProtocolUDP,
		Port:     53,
	})
	if !strings.Contains(got, `<port port="53" protocol="udp"/>`) {
		t.Fatalf("missing UDP port line:\n%s", got)
	}
}

// TestFirewalldRejectsUnsupportedRules — the v1 firewalld backend only
// translates simple "allow this port/proto" rules. Anything that needs
// a rich rule (deny, source scope, dest scope) must surface as
// ErrInvalidRule with a clear message so the operator can pick a
// different backend or wait for v2.
func TestFirewalldRejectsUnsupportedRules(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
		hint string // expected substring in the error
	}{
		{
			name: "deny",
			rule: Rule{Name: "block", Allow: false, Protocol: ProtocolTCP, Port: 22},
			hint: "deny",
		},
		{
			name: "source-scope",
			rule: Rule{Name: "from-net", Allow: true, Protocol: ProtocolTCP, Port: 22, Source: "10.0.0.0/8"},
			hint: "source",
		},
		{
			name: "dest-scope",
			rule: Rule{Name: "to-host", Allow: true, Protocol: ProtocolTCP, Port: 22, Dest: "192.168.1.1"},
			hint: "destination",
		},
		{
			name: "no-protocol",
			rule: Rule{Name: "any", Allow: true, Port: 22},
			hint: "protocol",
		},
		{
			name: "any-protocol-explicit",
			rule: Rule{Name: "any-explicit", Allow: true, Protocol: ProtocolAny, Port: 22},
			hint: "protocol",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := firewalldValidateRule(tc.rule)
			if !errors.Is(err, ErrInvalidRule) {
				t.Fatalf("firewalldValidateRule(%s) = %v; want ErrInvalidRule", tc.name, err)
			}
			if !strings.Contains(err.Error(), tc.hint) {
				t.Fatalf("err = %v; want message mentioning %q", err, tc.hint)
			}
		})
	}
}

// TestFirewalldParseListServices_FiltersPMPrefix — `firewall-cmd
// --list-services` returns a space-separated list mixing system
// services (ssh, dhcpv6-client, etc.) with our `pm-<name>` ones. List
// must hand back only the pm-managed entries with the prefix stripped.
func TestFirewalldParseListServices_FiltersPMPrefix(t *testing.T) {
	input := "ssh dhcpv6-client cockpit pm-web-https pm-ssh-in mosh"
	got := firewalldFilterPMServices(input)
	want := []string{"web-https", "ssh-in"}
	if len(got) != len(want) {
		t.Fatalf("got %v; want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q; want %q", i, got[i], want[i])
		}
	}
}

// =============================================================================
// Integration tests — gated by firewall-cmd binary + root. Each test
// cleans up the services it created so subsequent runs start fresh.
// =============================================================================

func TestFirewalldIntegration_ApplyListRemoveCycle(t *testing.T) {
	skipIfNotFirewalldUsable(t)
	ctx := context.Background()
	rule := Rule{Name: "pm-test-svc", Allow: true, Protocol: ProtocolTCP, Port: 12345}
	t.Cleanup(func() { _ = removeFirewalld(ctx, rule.Name) })

	if err := applyFirewalld(ctx, rule); err != nil {
		t.Fatalf("applyFirewalld: %v", err)
	}
	rules, err := listFirewalld(ctx)
	if err != nil {
		t.Fatalf("listFirewalld: %v", err)
	}
	found := false
	for _, r := range rules {
		if r.Name == rule.Name {
			found = true
		}
	}
	if !found {
		t.Fatalf("applied rule not visible in List: %+v", rules)
	}

	if err := removeFirewalld(ctx, rule.Name); err != nil {
		t.Fatalf("removeFirewalld: %v", err)
	}
}

func TestFirewalldIntegration_ApplyIsIdempotent(t *testing.T) {
	skipIfNotFirewalldUsable(t)
	ctx := context.Background()
	rule := Rule{Name: "pm-idemp", Allow: true, Protocol: ProtocolTCP, Port: 12346}
	t.Cleanup(func() { _ = removeFirewalld(ctx, rule.Name) })

	for i := 0; i < 3; i++ {
		if err := applyFirewalld(ctx, rule); err != nil {
			t.Fatalf("applyFirewalld #%d: %v", i, err)
		}
	}
	rules, _ := listFirewalld(ctx)
	count := 0
	for _, r := range rules {
		if r.Name == rule.Name {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("after 3 applies: rule appears %d times; want exactly 1", count)
	}
}
