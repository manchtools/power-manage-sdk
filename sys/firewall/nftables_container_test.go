//go:build container

// Container-based real-execution tests for the nftables backend. The fake-runner
// unit tests assert the emitted nft argv/ruleset; these load rules into the REAL
// nft binary and the kernel netfilter state (in the container's own network
// namespace), then read them back with `nft -j list` and the SDK's own JSON
// parser. This is an anti-rot guard: a future nft version that changes its JSON
// shape, its address normalisation, or its acceptance of a rule fails loudly
// here instead of silently in production.
//
// Needs CAP_NET_ADMIN (nft writes kernel state). Self-skips when nft is absent.
package firewall

import (
	"context"
	osexec "os/exec"
	"testing"
	"time"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

const fwCtxTimeout = 30 * time.Second

func requireNft(t *testing.T) {
	t.Helper()
	if _, err := osexec.LookPath("nft"); err != nil {
		t.Skip("nft not on PATH")
	}
}

func nftMgr(t *testing.T, ns string) Manager {
	t.Helper()
	r, err := exec.NewRunner(exec.Direct) // container runs as root
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	m, err := New(Nftables, ns, r)
	if err != nil {
		t.Fatalf("New(Nftables, %q): %v", ns, err)
	}
	return m
}

func findRule(rules []Rule, id string) (Rule, bool) {
	for _, r := range rules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

// TestNftablesApplyListRemove_Container pins the full ApplyRule → List →
// RemoveRule round-trip against real nft, including idempotency.
func TestNftablesApplyListRemove_Container(t *testing.T) {
	requireNft(t)
	m := nftMgr(t, "pmrt")
	ctx, cancel := context.WithTimeout(context.Background(), fwCtxTimeout)
	defer cancel()

	rule := Rule{ID: "allow_ssh", Allow: true, Protocol: ProtocolTCP, Port: 22, Source: "10.0.0.0/24"}
	if err := m.ApplyRule(ctx, rule); err != nil {
		t.Fatalf("ApplyRule: %v", err)
	}

	rules, err := m.List(ctx)
	if err != nil {
		t.Fatalf("List after Apply: %v", err)
	}
	got, ok := findRule(rules, "allow_ssh")
	if !ok {
		t.Fatalf("applied rule not found in List; got %+v", rules)
	}
	if got.Allow != rule.Allow || got.Protocol != rule.Protocol || got.Port != rule.Port || got.Source != rule.Source {
		t.Errorf("round-trip mismatch:\n applied = %+v\n listed  = %+v", rule, got)
	}

	// Idempotent: applying the same rule again must not duplicate it.
	if err := m.ApplyRule(ctx, rule); err != nil {
		t.Fatalf("ApplyRule (2nd): %v", err)
	}
	rules, err = m.List(ctx)
	if err != nil {
		t.Fatalf("List after 2nd Apply: %v", err)
	}
	if n := len(rules); n != 1 {
		t.Errorf("after re-applying the same rule, List = %d rules, want 1: %+v", n, rules)
	}

	// Remove → gone.
	if err := m.RemoveRule(ctx, "allow_ssh"); err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}
	rules, err = m.List(ctx)
	if err != nil {
		t.Fatalf("List after Remove: %v", err)
	}
	if _, ok := findRule(rules, "allow_ssh"); ok {
		t.Errorf("rule still present after RemoveRule: %+v", rules)
	}
}

// TestNftablesV4MappedIPv6_Container documents the real-nft behaviour for a
// v4-mapped IPv6 source (::ffff:10.0.0.1) — the audit suspected real nft rejects
// it (atomic batch rollback → rule silently never applies). Against real nft we
// assert the honest contract: ApplyRule must either reject it up front OR apply
// it AND have it survive a List round-trip — it must NOT silently disappear
// (accepted by ApplyRule but absent from List), which would be the dangerous
// "rule thought-applied but not enforced" state.
func TestNftablesV4MappedIPv6_Container(t *testing.T) {
	requireNft(t)
	m := nftMgr(t, "pmv4m")
	ctx, cancel := context.WithTimeout(context.Background(), fwCtxTimeout)
	defer cancel()

	rule := Rule{ID: "v4mapped", Allow: false, Source: "::ffff:10.0.0.1"}
	err := m.ApplyRule(ctx, rule)
	if err != nil {
		// Rejecting a v4-mapped source up front is an acceptable, safe outcome.
		t.Logf("ApplyRule(::ffff:10.0.0.1) rejected up front: %v (acceptable)", err)
		return
	}
	rules, lerr := m.List(ctx)
	if lerr != nil {
		t.Fatalf("List: %v", lerr)
	}
	if _, ok := findRule(rules, "v4mapped"); !ok {
		t.Fatalf("ApplyRule accepted ::ffff:10.0.0.1 but the rule is ABSENT from List — silently-unapplied rule (false sense of protection); ApplyRule should have failed instead")
	}
}
