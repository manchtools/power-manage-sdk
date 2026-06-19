package firewall

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

const firewalldTestNamespace = "fwtest"

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
	got := firewalldServiceXML(firewalldTestNamespace, Rule{
		ID:       "ssh-in",
		Allow:    true,
		Protocol: ProtocolTCP,
		Port:     22,
	})
	want := strings.Join([]string{
		`<?xml version="1.0" encoding="utf-8"?>`,
		`<service>`,
		`  <short>fwtest-ssh-in</short>`,
		`  <description>fwtest managed rule</description>`,
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
	got := firewalldServiceXML(firewalldTestNamespace, Rule{
		ID:       "dns",
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
			rule: Rule{ID: "block", Allow: false, Protocol: ProtocolTCP, Port: 22},
			hint: "deny",
		},
		{
			name: "source-scope",
			rule: Rule{ID: "from-net", Allow: true, Protocol: ProtocolTCP, Port: 22, Source: "10.0.0.0/8"},
			hint: "source",
		},
		{
			name: "dest-scope",
			rule: Rule{ID: "to-host", Allow: true, Protocol: ProtocolTCP, Port: 22, Dest: "192.168.1.1"},
			hint: "destination",
		},
		{
			name: "no-protocol",
			rule: Rule{ID: "any", Allow: true, Port: 22},
			hint: "protocol",
		},
		{
			name: "any-protocol-explicit",
			rule: Rule{ID: "any-explicit", Allow: true, Protocol: ProtocolAny, Port: 22},
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

// TestFirewalldFilterNamespaceServices — `firewall-cmd --list-services`
// returns a space-separated list mixing system services (ssh,
// dhcpv6-client, etc.) with our `<namespace>-<id>` ones. List must
// hand back only the namespace-managed entries with the prefix
// stripped, and must NOT match services owned by a different namespace.
func TestFirewalldFilterNamespaceServices(t *testing.T) {
	input := "ssh dhcpv6-client cockpit fwtest-web-https other-myapp fwtest-ssh-in mosh"
	got := firewalldFilterNamespaceServices(input, firewalldTestNamespace)
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

func firewalldIntegrationManager(t *testing.T) Manager {
	t.Helper()
	r, err := exec.NewRunner(exec.Direct) // skip guard guarantees we are root
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	return newMgr(t, Firewalld, firewalldTestNamespace, r)
}

func TestFirewalldIntegration_ApplyListRemoveCycle(t *testing.T) {
	skipIfNotFirewalldUsable(t)
	ctx := context.Background()
	m := firewalldIntegrationManager(t)
	rule := Rule{ID: "test-svc", Allow: true, Protocol: ProtocolTCP, Port: 12345}
	t.Cleanup(func() { _ = m.RemoveRule(ctx, rule.ID) })

	if err := m.ApplyRule(ctx, rule); err != nil {
		t.Fatalf("ApplyRule: %v", err)
	}
	rules, err := m.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, r := range rules {
		if r.ID == rule.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("applied rule not visible in List: %+v", rules)
	}

	if err := m.RemoveRule(ctx, rule.ID); err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}
}

func TestFirewalldIntegration_ApplyIsIdempotent(t *testing.T) {
	skipIfNotFirewalldUsable(t)
	ctx := context.Background()
	m := firewalldIntegrationManager(t)
	rule := Rule{ID: "idemp", Allow: true, Protocol: ProtocolTCP, Port: 12346}
	t.Cleanup(func() { _ = m.RemoveRule(ctx, rule.ID) })

	for i := 0; i < 3; i++ {
		if err := m.ApplyRule(ctx, rule); err != nil {
			t.Fatalf("ApplyRule #%d: %v", i, err)
		}
	}
	rules, _ := m.List(ctx)
	count := 0
	for _, r := range rules {
		if r.ID == rule.ID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("after 3 applies: rule appears %d times; want exactly 1", count)
	}
}
