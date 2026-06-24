package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// nftTestNamespace is the namespace every nftables test uses. Tests
// scope their own table via this constant so each test owns
// `inet <ns>_filter` and the kernel state is isolated from other
// packages' rules.
const nftTestNamespace = "fwtest"

// skipIfNotNftablesUsable t.Skip()s the test when nft isn't on PATH OR
// we lack the privilege to mutate the kernel's filter table. Keeps the
// CI run cheap on machines where the tool isn't installed (e.g. macOS
// dev boxes).
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
	got, err := nftBuildApplyScriptStrict(nftTestNamespace, Rule{
		ID:       "ssh-in",
		Allow:    true,
		Protocol: ProtocolTCP,
		Port:     22,
	}, 0)
	if err != nil {
		t.Fatalf("nftBuildApplyScriptStrict(accept tcp): %v", err)
	}
	want := strings.Join([]string{
		`add table inet fwtest_filter`,
		`add chain inet fwtest_filter input { type filter hook input priority 0; policy accept; }`,
		`add rule inet fwtest_filter input tcp dport 22 accept comment "ssh-in"`,
	}, "\n") + "\n"
	if got != want {
		t.Fatalf("nftBuildApplyScriptStrict:\n--- got  ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestNftBuildScript_DropUDP — Deny side + UDP, verifies the
// allow→accept/drop and protocol→tcp/udp toggles independently.
func TestNftBuildScript_DropUDP(t *testing.T) {
	got, err := nftBuildApplyScriptStrict(nftTestNamespace, Rule{
		ID:       "block-dns",
		Allow:    false,
		Protocol: ProtocolUDP,
		Port:     53,
	}, 0)
	if err != nil {
		t.Fatalf("nftBuildApplyScriptStrict(drop udp): %v", err)
	}
	if !strings.Contains(got, `add rule inet fwtest_filter input udp dport 53 drop comment "block-dns"`) {
		t.Fatalf("missing expected rule line:\n%s", got)
	}
}

// TestNftBuildScript_WithSourceAndDest — exercises the optional
// source / dest fields. Source comes BEFORE protocol match, dest comes
// AFTER (mirrors nft's own statement order from manpage examples).
func TestNftBuildScript_WithSourceAndDest(t *testing.T) {
	got, err := nftBuildApplyScriptStrict(nftTestNamespace, Rule{
		ID:       "from-vpn",
		Allow:    true,
		Protocol: ProtocolTCP,
		Port:     443,
		Source:   "10.0.0.0/8",
		Dest:     "192.168.1.10",
	}, 0)
	if err != nil {
		t.Fatalf("nftBuildApplyScriptStrict(source and dest): %v", err)
	}
	want := `add rule inet fwtest_filter input ip saddr 10.0.0.0/8 ip daddr 192.168.1.10 tcp dport 443 accept comment "from-vpn"`
	if !strings.Contains(got, want) {
		t.Fatalf("missing expected rule line:\n%s", got)
	}
}

// TestNftBuildScript_AnyProtocolNoPort — when Protocol is empty and
// Port is 0 we still produce a valid rule (just accept from a source).
// This is the "allow this network full access" case.
func TestNftBuildScript_AnyProtocolNoPort(t *testing.T) {
	got, err := nftBuildApplyScriptStrict(nftTestNamespace, Rule{
		ID:     "trusted-net",
		Allow:  true,
		Source: "172.16.0.0/12",
	}, 0)
	if err != nil {
		t.Fatalf("nftBuildApplyScriptStrict(any protocol no port): %v", err)
	}
	want := `add rule inet fwtest_filter input ip saddr 172.16.0.0/12 accept comment "trusted-net"`
	if !strings.Contains(got, want) {
		t.Fatalf("missing expected rule line:\n%s", got)
	}
}

// TestNftBuildScript_ReplacesExistingHandle — when a rule already
// exists and we're updating, the batch must DELETE the old handle in
// the same transaction as the new ADD. Atomic; if either fails the
// kernel rolls back both.
func TestNftBuildScript_ReplacesExistingHandle(t *testing.T) {
	got, err := nftBuildApplyScriptStrict(nftTestNamespace, Rule{
		ID:       "ssh-in",
		Allow:    true,
		Protocol: ProtocolTCP,
		Port:     22,
	}, 17)
	if err != nil {
		t.Fatalf("nftBuildApplyScriptStrict(replace handle): %v", err)
	}
	if !strings.Contains(got, `delete rule inet fwtest_filter input handle 17`) {
		t.Fatalf("missing delete-of-old-handle line:\n%s", got)
	}
	if !strings.Contains(got, `add rule inet fwtest_filter input tcp dport 22 accept comment "ssh-in"`) {
		t.Fatalf("missing add-new-rule line:\n%s", got)
	}
}

// TestNftBuildScript_WithIPv6Source — IPv6 source addresses must emit
// `ip6 saddr` (not the IPv4-only `ip saddr`), because nft's inet family
// is family-agnostic at the table level but every match expression is
// family-specific. Without this, IPv6 rules silently never match.
func TestNftBuildScript_WithIPv6Source(t *testing.T) {
	got, err := nftBuildApplyScriptStrict(nftTestNamespace, Rule{
		ID:       "from-vpn6",
		Allow:    true,
		Protocol: ProtocolTCP,
		Port:     443,
		Source:   "2001:db8::/32",
	}, 0)
	if err != nil {
		t.Fatalf("nftBuildApplyScriptStrict(IPv6 source): %v", err)
	}
	want := `add rule inet fwtest_filter input ip6 saddr 2001:db8::/32 tcp dport 443 accept comment "from-vpn6"`
	if !strings.Contains(got, want) {
		t.Fatalf("missing IPv6 rule line:\n%s", got)
	}
}

// TestNftBuildScript_WithIPv6BareAddress — bare IPv6 addresses (no
// CIDR) also classify as IPv6. ParseIP needs to be tried as a fallback
// to ParseCIDR.
func TestNftBuildScript_WithIPv6BareAddress(t *testing.T) {
	got, err := nftBuildApplyScriptStrict(nftTestNamespace, Rule{
		ID:     "from-localhost6",
		Allow:  true,
		Source: "::1",
	}, 0)
	if err != nil {
		t.Fatalf("nftBuildApplyScriptStrict(bare IPv6): %v", err)
	}
	if !strings.Contains(got, `ip6 saddr ::1`) {
		t.Fatalf("missing ip6 saddr line:\n%s", got)
	}
}

// TestNftBuildScript_RejectsMixedIPFamilies — a rule with an IPv4 source
// and an IPv6 dest (or vice versa) could never match a real packet
// because a packet is either v4 or v6. nft would accept the rule but
// it would silently never fire; we'd rather surface the
// nonsense up front.
func TestNftBuildScript_RejectsMixedIPFamilies(t *testing.T) {
	_, err := nftBuildApplyScriptStrict(nftTestNamespace, Rule{
		ID:     "mixed-fam",
		Allow:  true,
		Source: "10.0.0.0/8",
		Dest:   "2001:db8::1",
	}, 0)
	if err == nil {
		t.Fatalf("nftBuildApplyScriptStrict(mixed v4 source + v6 dest) = nil; want ErrInvalidRule")
	}
	if !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("err = %v; want ErrInvalidRule", err)
	}
}

// TestNftBuildScript_RejectsInvalidSource — anything that isn't a
// parseable IP or CIDR is an operator error; surface it as
// ErrInvalidRule before nft sees nonsense.
func TestNftBuildScript_RejectsInvalidSource(t *testing.T) {
	_, err := nftBuildApplyScriptStrict(nftTestNamespace, Rule{
		ID:     "bad-src",
		Allow:  true,
		Source: "not-an-ip",
	}, 0)
	if !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("nftBuildApplyScriptStrict(garbage source) = %v; want ErrInvalidRule", err)
	}
}

// TestNftBuildScript_RejectsAnyProtocolWithPort — Port without a
// concrete Protocol can't be expressed as a single nft rule (we'd need
// two rules, tcp + udp); reject up front so the operator gets a clear
// "specify protocol" error instead of a confusing nft parse failure.
func TestNftBuildScript_RejectsAnyProtocolWithPort(t *testing.T) {
	script, err := nftBuildApplyScriptStrict(nftTestNamespace, Rule{
		ID:    "any-22",
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

// TestNftParseRules_ReturnsAllInTable — the table is the namespace, so
// every rule in the table is owned by the Manager. Take a chunk of nft
// -j list-table output and assert each rule round-trips correctly.
// Rules without comments are skipped (they're either system-installed
// or operator-added by hand).
func TestNftParseRules_ReturnsAllInTable(t *testing.T) {
	// Subset of nft's JSON output — a table, a chain, two rules. The
	// first rule has no comment (operator added it manually); the
	// second has one and should round-trip.
	input := `{
		"nftables": [
			{"metainfo": {"version": "1.0.0"}},
			{"table": {"family": "inet", "name": "fwtest_filter", "handle": 1}},
			{"chain": {"family": "inet", "table": "fwtest_filter", "name": "input", "handle": 2,
				"type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
			{"rule": {"family": "inet", "table": "fwtest_filter", "chain": "input", "handle": 8,
				"expr": [
					{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
					{"accept": null}
				]}},
			{"rule": {"family": "inet", "table": "fwtest_filter", "chain": "input", "handle": 9,
				"expr": [
					{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}},
					{"accept": null}
				],
				"comment": "web-https"}}
		]
	}`

	rules, err := nftParseRules(json.RawMessage(input))
	if err != nil {
		t.Fatalf("nftParseRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules; want 1 (only the commented one)", len(rules))
	}
	want := Rule{
		ID:       "web-https",
		Allow:    true,
		Protocol: ProtocolTCP,
		Port:     443,
	}
	if !reflect.DeepEqual(rules[0], want) {
		t.Fatalf("rules[0] = %+v; want %+v", rules[0], want)
	}
}

// TestNftParseRules_NoTableYet — a freshly-installed system with no
// table yet produces an nft error rather than valid JSON. The parser
// must treat that as "zero rules", not a hard error, so the first call
// after fresh install reports an empty managed set.
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
// that looks up a rule's handle by ID must return the handle of the
// matching rule (and report "not found" for anything else).
func TestNftFindRuleHandle(t *testing.T) {
	input := `{"nftables":[
		{"rule": {"family": "inet", "table": "fwtest_filter", "chain": "input", "handle": 9,
			"expr": [{"accept": null}], "comment": "web-https"}}
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
// cleans up its namespace's table on exit so the next run starts fresh.
// =============================================================================

// nftIntegrationBackend builds a concrete *nftables driven by a real root Runner
// for the integration cycle tests (also exposes nftDeleteManagedTable for
// cleanup).
func nftIntegrationBackend(t *testing.T) *nftables {
	t.Helper()
	r, err := exec.NewRunner(exec.Direct) // skip guard guarantees we are root
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	return &nftables{base: base{ns: nftTestNamespace, cmd: cmd{r: r}}}
}

func TestNftablesIntegration_ApplyListRemoveCycle(t *testing.T) {
	skipIfNotNftablesUsable(t)
	n := nftIntegrationBackend(t)
	t.Cleanup(func() { _ = n.nftDeleteManagedTable(context.Background()) })

	ctx := context.Background()
	rule := Rule{ID: "test-ssh", Allow: true, Protocol: ProtocolTCP, Port: 22}

	if err := n.ApplyRule(ctx, rule); err != nil {
		t.Fatalf("ApplyRule: %v", err)
	}
	rules, err := n.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "test-ssh" {
		t.Fatalf("List = %+v; want [{ID:test-ssh ...}]", rules)
	}
	if err := n.RemoveRule(ctx, "test-ssh"); err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}
	rules, _ = n.List(ctx)
	if len(rules) != 0 {
		t.Fatalf("after remove: List = %+v; want empty", rules)
	}
}

func TestNftablesIntegration_ApplyIsIdempotent(t *testing.T) {
	skipIfNotNftablesUsable(t)
	n := nftIntegrationBackend(t)
	t.Cleanup(func() { _ = n.nftDeleteManagedTable(context.Background()) })

	ctx := context.Background()
	rule := Rule{ID: "idemp", Allow: true, Protocol: ProtocolTCP, Port: 8080}
	for i := 0; i < 3; i++ {
		if err := n.ApplyRule(ctx, rule); err != nil {
			t.Fatalf("ApplyRule #%d: %v", i, err)
		}
	}
	rules, _ := n.List(ctx)
	if len(rules) != 1 {
		t.Fatalf("after 3 applies: rules = %+v; want exactly 1", rules)
	}
}

func TestNftablesIntegration_RemoveOnMissingIsNoOp(t *testing.T) {
	skipIfNotNftablesUsable(t)
	n := nftIntegrationBackend(t)
	t.Cleanup(func() { _ = n.nftDeleteManagedTable(context.Background()) })

	if err := n.RemoveRule(context.Background(), "never-applied"); err != nil {
		t.Fatalf("RemoveRule(missing) = %v; want nil", err)
	}
}
