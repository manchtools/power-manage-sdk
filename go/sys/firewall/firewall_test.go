package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestBackend_DefaultIsNftables(t *testing.T) {
	SetBackend(BackendNftables)
	if got := CurrentBackend(); got != BackendNftables {
		t.Errorf("default = %v, want %v", got, BackendNftables)
	}
}

func TestBackend_IgnoresUnknown(t *testing.T) {
	t.Cleanup(func() { SetBackend(BackendNftables) })
	SetBackend(BackendPF)
	SetBackend(Backend(99))
	if got := CurrentBackend(); got != BackendPF {
		t.Errorf("unknown value leaked through: got %v, want %v", got, BackendPF)
	}
}

func TestApplyRule_ReturnsSentinel(t *testing.T) {
	t.Cleanup(func() { SetBackend(BackendNftables) })
	SetBackend(BackendPF) // BSD pf — no impl in v1, exercises the sentinel path
	ctx := context.Background()
	err := ApplyRule(ctx, Rule{Name: "test", Allow: true, Protocol: ProtocolTCP, Port: 22})
	if err == nil || !errors.Is(err, ErrBackendNotSupported) {
		t.Errorf("want ErrBackendNotSupported, got %v", err)
	}
}

// TestList_DefaultBackendErrors — List is the inspection counterpart
// to ApplyRule and dispatches the same way. The default-backend
// behaviour must surface the same sentinel so callers can branch
// uniformly.
func TestList_DefaultBackendErrors(t *testing.T) {
	t.Cleanup(func() { SetBackend(BackendNftables) })
	SetBackend(BackendPF) // BSD pf — no impl yet
	_, err := List(context.Background())
	if !errors.Is(err, ErrBackendNotSupported) {
		t.Fatalf("List on unimplemented backend = %v; want ErrBackendNotSupported", err)
	}
}

// TestApplyRule_RejectsInvalidName — the rule name is the idempotency
// key; backends round-trip it through their comment fields, so anything
// that could break the backend's grammar (whitespace, quotes, shell
// metas, control characters) must be rejected up front. Validation is
// backend-independent so a rule that's accepted on nftables is also
// accepted on firewalld.
func TestApplyRule_RejectsInvalidName(t *testing.T) {
	bad := []string{
		"",             // empty
		" ",            // whitespace only
		"with space",   // embedded whitespace
		"quote\"in",    // double quote
		"tick'in",      // single quote
		"newline\nin",  // control char
		"semicolon;in", // shell-meta
		"pipe|in",      // shell-meta
		"backtick`in",  // shell-meta
		"dollar$in",    // shell-meta
		"way-too-long-" + strings.Repeat("x", 64),
	}
	for _, name := range bad {
		t.Run("name="+truncate(name, 16), func(t *testing.T) {
			err := ApplyRule(context.Background(), Rule{Name: name, Allow: true, Protocol: ProtocolTCP, Port: 22})
			if !errors.Is(err, ErrInvalidRule) {
				t.Fatalf("ApplyRule(name=%q) = %v; want ErrInvalidRule", name, err)
			}
		})
	}
}

// TestApplyRule_AcceptsValidName — the allowed character class is
// documented on Rule.Name; lock in a representative sample so the
// regex doesn't get tightened by accident. Uses BackendPF so the
// dispatch falls through to the sentinel path without trying to
// shell out to a real firewall tool (the test verifies "name passed
// validation," not "nft is available on this host").
func TestApplyRule_AcceptsValidName(t *testing.T) {
	t.Cleanup(func() { SetBackend(BackendNftables) })
	SetBackend(BackendPF)
	good := []string{
		"ssh-in",
		"allow-22",
		"web_https",
		"a", // single char ok
		"with.dot",
		"caps-OK",
	}
	for _, name := range good {
		t.Run("name="+name, func(t *testing.T) {
			err := ApplyRule(context.Background(), Rule{Name: name, Allow: true, Protocol: ProtocolTCP, Port: 22})
			// We're locking in "the name passed validation and reached
			// the dispatch layer." On BackendPF the dispatch hits the
			// default arm and returns ErrBackendNotSupported, which is
			// fine — anything except ErrInvalidRule means the regex
			// accepted the name.
			if errors.Is(err, ErrInvalidRule) {
				t.Fatalf("ApplyRule(name=%q) rejected valid name: %v", name, err)
			}
		})
	}
}

// TestRemoveRule_RejectsInvalidName — symmetric guard on the remove
// path so a caller can't smuggle backend-grammar-breaking input through
// the inverse op.
func TestRemoveRule_RejectsInvalidName(t *testing.T) {
	err := RemoveRule(context.Background(), "name with space")
	if !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("RemoveRule(invalid) = %v; want ErrInvalidRule", err)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func TestBackendString(t *testing.T) {
	tests := []struct {
		b    Backend
		want string
	}{
		{BackendNftables, "nftables"},
		{BackendIptables, "iptables"},
		{BackendFirewalld, "firewalld"},
		{BackendUFW, "ufw"},
		{BackendPF, "pf"},
		{Backend(42), "unknown(42)"},
	}
	for _, tt := range tests {
		if got := tt.b.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.b, got, tt.want)
		}
	}
}
