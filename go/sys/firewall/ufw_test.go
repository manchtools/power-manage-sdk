package firewall

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

const ufwTestNamespace = "fwtest"

// skipIfNotUFWUsable — same shape as the firewalld / nftables variants.
// CI runs root inside a container; dev hosts and macOS skip cleanly.
func skipIfNotUFWUsable(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/usr/sbin/ufw"); err != nil {
		if _, err := os.Stat("/usr/bin/ufw"); err != nil {
			t.Skip("ufw not available on this system")
		}
	}
	if os.Geteuid() != 0 {
		t.Skip("ufw integration tests require root")
	}
}

// TestUFWBuildAddArgs_SimplePortAllow — the bread-and-butter "open this
// TCP port" rule. Lock in the exact argv ufw receives so a refactor of
// the builder can't silently drift the wire format.
func TestUFWBuildAddArgs_SimplePortAllow(t *testing.T) {
	got, err := ufwBuildAddArgs(ufwTestNamespace, Rule{
		ID:       "ssh-in",
		Allow:    true,
		Protocol: ProtocolTCP,
		Port:     22,
	})
	if err != nil {
		t.Fatalf("ufwBuildAddArgs: %v", err)
	}
	want := []string{"allow", "22/tcp", "comment", "fwtest:ssh-in"}
	assertArgsEqual(t, got, want)
}

// TestUFWBuildAddArgs_Deny — the deny verb. ufw exposes "deny" natively
// (unlike firewalld v1), so the Rule.Allow=false path must round-trip.
func TestUFWBuildAddArgs_Deny(t *testing.T) {
	got, err := ufwBuildAddArgs(ufwTestNamespace, Rule{
		ID:       "block-ssh",
		Allow:    false,
		Protocol: ProtocolTCP,
		Port:     22,
	})
	if err != nil {
		t.Fatalf("ufwBuildAddArgs: %v", err)
	}
	if got[0] != "deny" {
		t.Fatalf("expected first arg 'deny', got %q in %v", got[0], got)
	}
}

// TestUFWBuildAddArgs_SourceScope — once a rule has a source CIDR ufw
// requires the long "from SRC to DST port PORT proto PROTO" form.
// Sanity-check the shape so we don't accidentally emit the short form
// (which ufw would silently broaden into an any-source rule).
func TestUFWBuildAddArgs_SourceScope(t *testing.T) {
	got, err := ufwBuildAddArgs(ufwTestNamespace, Rule{
		ID:       "from-lan",
		Allow:    true,
		Protocol: ProtocolTCP,
		Port:     22,
		Source:   "10.0.0.0/8",
	})
	if err != nil {
		t.Fatalf("ufwBuildAddArgs: %v", err)
	}
	joined := strings.Join(got, " ")
	for _, want := range []string{"from 10.0.0.0/8", "to any", "port 22", "proto tcp", "comment fwtest:from-lan"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in args: %v", want, got)
		}
	}
}

// TestUFWBuildAddArgs_DestScope — symmetric guard on the destination
// path. ufw uses the same long form, just populates the "to" side.
func TestUFWBuildAddArgs_DestScope(t *testing.T) {
	got, err := ufwBuildAddArgs(ufwTestNamespace, Rule{
		ID:       "to-host",
		Allow:    true,
		Protocol: ProtocolTCP,
		Port:     22,
		Dest:     "192.168.1.1",
	})
	if err != nil {
		t.Fatalf("ufwBuildAddArgs: %v", err)
	}
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "from any") || !strings.Contains(joined, "to 192.168.1.1") {
		t.Errorf("missing scoped from/to in args: %v", got)
	}
}

// TestUFWBuildAddArgs_RejectsPortWithoutProto — same rejection nftables
// makes. A port without a concrete protocol is ambiguous; ufw would
// expand it into both tcp+udp implicitly, which silently widens the
// rule. Better to surface ErrInvalidRule and let the caller decide.
func TestUFWBuildAddArgs_RejectsPortWithoutProto(t *testing.T) {
	_, err := ufwBuildAddArgs(ufwTestNamespace, Rule{
		ID:       "ambiguous",
		Allow:    true,
		Port:     22,
		Protocol: ProtocolAny,
	})
	if !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("want ErrInvalidRule for port-without-proto, got %v", err)
	}
}

// TestUFWBuildAddArgs_RejectsEmpty — a Rule with no Port and no Protocol
// is a no-op at the firewall level; rather than silently emit nothing
// or apply an "allow everything from anywhere" rule, refuse early.
func TestUFWBuildAddArgs_RejectsEmpty(t *testing.T) {
	_, err := ufwBuildAddArgs(ufwTestNamespace, Rule{
		ID:    "empty",
		Allow: true,
	})
	if !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("want ErrInvalidRule for empty-rule, got %v", err)
	}
}

// TestUFWFindRuleNumber_ByID — `ufw status numbered` is the only way
// to learn a rule's index for `ufw delete N`, and it's the only path
// we have to "is this rule already there?". Lock in the parse against a
// captured sample so a ufw version that adds columns can't silently
// break idempotency. Also confirms that another namespace's rules
// (`other:foo`) and unrelated comments (`cockpit-managed`) don't match.
func TestUFWFindRuleNumber_ByID(t *testing.T) {
	status := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # fwtest:ssh-in
[ 2] 53/udp                     ALLOW IN    Anywhere                   # fwtest:dns
[ 3] 22/tcp                     DENY IN     10.0.0.0/8                 # fwtest:block-net
[ 4] 80/tcp                     ALLOW IN    Anywhere                   # cockpit-managed
[ 5] 443/tcp                    ALLOW IN    Anywhere                   # other:web-https
`
	cases := map[string]int{
		"ssh-in":    1,
		"dns":       2,
		"block-net": 3,
	}
	for id, wantNum := range cases {
		gotNum, ok := ufwFindRuleNumber(status, ufwTestNamespace, id)
		if !ok {
			t.Errorf("ufwFindRuleNumber(%q) not found", id)
			continue
		}
		if gotNum != wantNum {
			t.Errorf("ufwFindRuleNumber(%q) = %d, want %d", id, gotNum, wantNum)
		}
	}
	// IDs not in the namespace → not found.
	if _, ok := ufwFindRuleNumber(status, ufwTestNamespace, "nonexistent"); ok {
		t.Errorf("ufwFindRuleNumber(nonexistent) reported found")
	}
	// Another namespace's id → not found by THIS namespace.
	if _, ok := ufwFindRuleNumber(status, ufwTestNamespace, "web-https"); ok {
		t.Errorf("ufwFindRuleNumber should not match other-namespace rules")
	}
	// System-managed rule (no namespace prefix) → not found.
	if _, ok := ufwFindRuleNumber(status, ufwTestNamespace, "cockpit-managed"); ok {
		t.Errorf("ufwFindRuleNumber should not match non-namespace rules")
	}
}

// TestUFWParseStatus_PicksOutNamespacedRules — List must return only
// rules in this Manager's namespace. Cockpit, system services,
// and rules owned by a different Manager stay outside the inspection
// surface.
func TestUFWParseStatus_PicksOutNamespacedRules(t *testing.T) {
	status := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # fwtest:ssh-in
[ 2] 53/udp                     ALLOW IN    Anywhere                   # fwtest:dns
[ 3] 80/tcp                     ALLOW IN    Anywhere                   # cockpit-managed
[ 4] 22/tcp                     DENY IN     10.0.0.0/8                 # fwtest:block-net
[ 5] 443/tcp                    ALLOW IN    Anywhere                   # other:web-https
`
	rules, err := ufwParseStatus(status, ufwTestNamespace)
	if err != nil {
		t.Fatalf("ufwParseStatus: %v", err)
	}
	ids := make(map[string]Rule)
	for _, r := range rules {
		ids[r.ID] = r
	}
	for _, want := range []string{"ssh-in", "dns", "block-net"} {
		if _, ok := ids[want]; !ok {
			t.Errorf("missing in-namespace rule %q in parsed output: %+v", want, rules)
		}
	}
	if _, ok := ids["cockpit-managed"]; ok {
		t.Errorf("non-namespace rule leaked into List output")
	}
	if _, ok := ids["web-https"]; ok {
		t.Errorf("other-namespace rule leaked into List output")
	}
	// Spot-check the deny rule round-tripped Allow=false.
	if r, ok := ids["block-net"]; ok && r.Allow {
		t.Errorf("block-net round-tripped with Allow=true; want false")
	}
}

// TestUFWParseStatus_InactiveReturnsEmpty — when ufw is installed but
// not enabled, `ufw status numbered` prints "Status: inactive" and no
// rules. List on an inactive firewall should be an empty slice + nil
// error, not a parse error.
func TestUFWParseStatus_InactiveReturnsEmpty(t *testing.T) {
	rules, err := ufwParseStatus("Status: inactive\n", ufwTestNamespace)
	if err != nil {
		t.Fatalf("ufwParseStatus(inactive): %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("inactive ufw should yield zero rules, got %+v", rules)
	}
}

// assertArgsEqual is a small helper so the argv-shape tests read cleanly.
func assertArgsEqual(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("args length mismatch: got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q (full got=%v)", i, got[i], want[i], got)
		}
	}
}

// =============================================================================
// Integration tests — gated by ufw binary + root. Each test cleans up
// its own rules so subsequent runs start fresh.
// =============================================================================

func ufwIntegrationManager(t *testing.T) Manager {
	t.Helper()
	r, err := exec.NewRunner(exec.Direct) // skip guard guarantees we are root
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	return newMgr(t, UFW, ufwTestNamespace, r)
}

func TestUFWIntegration_ApplyListRemoveCycle(t *testing.T) {
	skipIfNotUFWUsable(t)
	ctx := context.Background()
	m := ufwIntegrationManager(t)
	rule := Rule{ID: "test-rule", Allow: true, Protocol: ProtocolTCP, Port: 12345}
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

func TestUFWIntegration_ApplyIsIdempotent(t *testing.T) {
	skipIfNotUFWUsable(t)
	ctx := context.Background()
	m := ufwIntegrationManager(t)
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
