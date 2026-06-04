package firewall

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// skipIfNotNftablesUsable t.Skip()s the test when nft isn't on PATH OR
// we lack the privilege to mutate the kernel's filter table. Mirrors
// the skipIfNotApt pattern from sys/pkg — keeps the CI run cheap on
// machines where the tool isn't installed (e.g. macOS dev boxes).
func skipIfNotNftablesUsable(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/usr/sbin/nft"); err != nil {
		if _, err2 := os.Stat("/usr/bin/nft"); err2 != nil {
			t.Skip("nft binary not available on this system")
		}
	}
	if os.Geteuid() != 0 {
		t.Skip("nftables integration tests require root")
	}
}

// TestNftBuildScript_AcceptTCP — the simplest valid case. Lock in the
// exact nft batch grammar so future refactors of the builder don't
// silently change what we send to the kernel.
func TestNftBuildScript_AcceptTCP(t *testing.T) {
	got := nftBuildApplyScript(Rule{
		Name:     "ssh-in",
		Allow:    true,
		Protocol: ProtocolTCP,
		Port:     22,
	}, 0)
	want := strings.Join([]string{
		`add table inet pm_filter`,
		`add chain inet pm_filter input { type filter hook input priority 0; policy accept; }`,
		`add rule inet pm_filter input tcp dport 22 accept comment "pm:ssh-in"`,
	}, "\n") + "\n"
	if got != want {
		t.Fatalf("nftBuildApplyScript:\n--- got  ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestNftBuildScript_DropUDP — Deny side + UDP, verifies the
// allow→accept/drop and protocol→tcp/udp toggles independently.
func TestNftBuildScript_DropUDP(t *testing.T) {
	got := nftBuildApplyScript(Rule{
		Name:     "block-dns",
		Allow:    false,
		Protocol: ProtocolUDP,
		Port:     53,
	}, 0)
	if !strings.Contains(got, `add rule inet pm_filter input udp dport 53 drop comment "pm:block-dns"`) {
		t.Fatalf("missing expected rule line:\n%s", got)
	}
}

// TestNftBuildScript_WithSourceAndDest — exercises the optional
// source / dest fields. Source comes BEFORE protocol match, dest comes
// AFTER (mirrors nft's own statement order from manpage examples and
// keeps the rule readable).
func TestNftBuildScript_WithSourceAndDest(t *testing.T) {
	got := nftBuildApplyScript(Rule{
		Name:     "from-vpn",
		Allow:    true,
		Protocol: ProtocolTCP,
		Port:     443,
		Source:   "10.0.0.0/8",
		Dest:     "192.168.1.10",
	}, 0)
	want := `add rule inet pm_filter input ip saddr 10.0.0.0/8 ip daddr 192.168.1.10 tcp dport 443 accept comment "pm:from-vpn"`
	if !strings.Contains(got, want) {
		t.Fatalf("missing expected rule line:\n%s", got)
	}
}

// TestNftBuildScript_AnyProtocolNoPort — when Protocol is empty and
// Port is 0 we still produce a valid rule (just accept from a source).
// This is the "allow this network full access" case.
func TestNftBuildScript_AnyProtocolNoPort(t *testing.T) {
	got := nftBuildApplyScript(Rule{
		Name:   "trusted-net",
		Allow:  true,
		Source: "172.16.0.0/12",
	}, 0)
	want := `add rule inet pm_filter input ip saddr 172.16.0.0/12 accept comment "pm:trusted-net"`
	if !strings.Contains(got, want) {
		t.Fatalf("missing expected rule line:\n%s", got)
	}
}

// TestNftBuildScript_ReplacesExistingHandle — when a rule already
// exists and we're updating, the batch must DELETE the old handle in
// the same transaction as the new ADD. Atomic; if either fails the
// kernel rolls back both.
func TestNftBuildScript_ReplacesExistingHandle(t *testing.T) {
	got := nftBuildApplyScript(Rule{
		Name:     "ssh-in",
		Allow:    true,
		Protocol: ProtocolTCP,
		Port:     22,
	}, 17)
	if !strings.Contains(got, `delete rule inet pm_filter input handle 17`) {
		t.Fatalf("missing delete-of-old-handle line:\n%s", got)
	}
	if !strings.Contains(got, `add rule inet pm_filter input tcp dport 22 accept comment "pm:ssh-in"`) {
		t.Fatalf("missing add-new-rule line:\n%s", got)
	}
}

// TestNftBuildScript_RejectsAnyProtocolWithPort — Port without a
// concrete Protocol can't be expressed as a single nft rule (we'd need
// two rules, tcp + udp); reject up front so the operator gets a clear
// "specify protocol" error instead of a confusing nft parse failure.
func TestNftBuildScript_RejectsAnyProtocolWithPort(t *testing.T) {
	// This call would have to surface the error somewhere — by
	// convention with the rest of sys/* we route it through
	// ApplyRule's normal path. The builder itself returns the script
	// it would have produced + an error; callers branch on the error.
	script, err := nftBuildApplyScriptStrict(Rule{
		Name:  "any-22",
		Allow: true,
		Port:  22, // no Protocol
	}, 0)
	if err == nil {
		t.Fatalf("nftBuildApplyScriptStrict(port without protocol) returned nil err; got script:\n%s", script)
	}
	if !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("err = %v; want a message mentioning protocol", err)
	}
}

// TestNftParseRules_PicksOutPMComments — the List path. Take a chunk
// of nft -j list-table output (one pm-managed rule, one system rule
// without our comment prefix) and assert only the pm rule comes back,
// with fields reconstructed correctly.
func TestNftParseRules_PicksOutPMComments(t *testing.T) {
	// Subset of nft's JSON output — a table, a chain, two rules.
	// Only the second rule carries our "pm:" comment prefix.
	input := `{
		"nftables": [
			{"metainfo": {"version": "1.0.0"}},
			{"table": {"family": "inet", "name": "pm_filter", "handle": 1}},
			{"chain": {"family": "inet", "table": "pm_filter", "name": "input", "handle": 2,
				"type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
			{"rule": {"family": "inet", "table": "pm_filter", "chain": "input", "handle": 8,
				"expr": [
					{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
					{"accept": null}
				]}},
			{"rule": {"family": "inet", "table": "pm_filter", "chain": "input", "handle": 9,
				"expr": [
					{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}},
					{"accept": null}
				],
				"comment": "pm:web-https"}}
		]
	}`

	rules, err := nftParseRules(json.RawMessage(input))
	if err != nil {
		t.Fatalf("nftParseRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules; want 1 (only the pm-tagged one)", len(rules))
	}
	want := Rule{
		Name:     "web-https",
		Allow:    true,
		Protocol: ProtocolTCP,
		Port:     443,
	}
	if !reflect.DeepEqual(rules[0], want) {
		t.Fatalf("rules[0] = %+v; want %+v", rules[0], want)
	}
}

// TestNftParseRules_NoTableYet — a freshly-installed system with no
// pm_filter table yet produces an nft error rather than valid JSON.
// The parser must treat that as "zero rules", not a hard error, so
// the first call after fresh install reports an empty managed set.
func TestNftParseRules_NoTableYet(t *testing.T) {
	rules, err := nftParseRules(json.RawMessage(`{"nftables":[]}`))
	if err != nil {
		t.Fatalf("nftParseRules(empty): %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("rules = %v; want empty", rules)
	}
}

// TestNftFindRuleHandle — given the same listing fixture, the helper
// that looks up a rule's handle by Name must return the handle of the
// pm-tagged rule (and report "not found" for anything else).
func TestNftFindRuleHandle(t *testing.T) {
	input := `{"nftables":[
		{"rule": {"family": "inet", "table": "pm_filter", "chain": "input", "handle": 9,
			"expr": [{"accept": null}], "comment": "pm:web-https"}}
	]}`
	handle, found := nftFindRuleHandle(json.RawMessage(input), "web-https")
	if !found || handle != 9 {
		t.Fatalf("nftFindRuleHandle(web-https) = (%d, %v); want (9, true)", handle, found)
	}
	if _, found := nftFindRuleHandle(json.RawMessage(input), "no-such"); found {
		t.Fatal("nftFindRuleHandle(missing) reported found=true")
	}
}

// =============================================================================
// Integration tests — gated by nft binary + root. Idempotent: each test
// cleans up the pm_filter table on exit so the next run starts fresh.
// =============================================================================

func TestNftablesIntegration_ApplyListRemoveCycle(t *testing.T) {
	skipIfNotNftablesUsable(t)
	t.Cleanup(func() { _ = nftDeleteManagedTable(context.Background()) })

	ctx := context.Background()
	rule := Rule{Name: "test-ssh", Allow: true, Protocol: ProtocolTCP, Port: 22}

	if err := applyNftables(ctx, rule); err != nil {
		t.Fatalf("applyNftables: %v", err)
	}
	rules, err := listNftables(ctx)
	if err != nil {
		t.Fatalf("listNftables: %v", err)
	}
	if len(rules) != 1 || rules[0].Name != "test-ssh" {
		t.Fatalf("listNftables = %+v; want [{Name:test-ssh ...}]", rules)
	}
	if err := removeNftables(ctx, "test-ssh"); err != nil {
		t.Fatalf("removeNftables: %v", err)
	}
	rules, _ = listNftables(ctx)
	if len(rules) != 0 {
		t.Fatalf("after remove: listNftables = %+v; want empty", rules)
	}
}

func TestNftablesIntegration_ApplyIsIdempotent(t *testing.T) {
	skipIfNotNftablesUsable(t)
	t.Cleanup(func() { _ = nftDeleteManagedTable(context.Background()) })

	ctx := context.Background()
	rule := Rule{Name: "idemp", Allow: true, Protocol: ProtocolTCP, Port: 8080}
	for i := 0; i < 3; i++ {
		if err := applyNftables(ctx, rule); err != nil {
			t.Fatalf("applyNftables #%d: %v", i, err)
		}
	}
	rules, _ := listNftables(ctx)
	if len(rules) != 1 {
		t.Fatalf("after 3 applies: rules = %+v; want exactly 1", rules)
	}
}

func TestNftablesIntegration_RemoveOnMissingIsNoOp(t *testing.T) {
	skipIfNotNftablesUsable(t)
	t.Cleanup(func() { _ = nftDeleteManagedTable(context.Background()) })

	if err := removeNftables(context.Background(), "never-applied"); err != nil {
		t.Fatalf("removeNftables(missing) = %v; want nil", err)
	}
}
