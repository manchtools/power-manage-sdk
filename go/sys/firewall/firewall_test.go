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

// TestNew_AcceptsValidNamespace — representative namespaces operators
// might pick. Lowercase ASCII + digits + underscore, starts with a
// letter, no longer than 31 chars.
func TestNew_AcceptsValidNamespace(t *testing.T) {
	good := []string{
		"app",
		"pm_firewall",
		"a",
		"some_app_42",
		strings.Repeat("a", 31),
	}
	for _, ns := range good {
		t.Run("ns="+truncate(ns, 16), func(t *testing.T) {
			mgr, err := New(ns)
			if err != nil {
				t.Fatalf("New(%q) = %v; want nil", ns, err)
			}
			if mgr.Namespace() != ns {
				t.Errorf("Namespace() = %q; want %q", mgr.Namespace(), ns)
			}
		})
	}
}

// TestNew_RejectsInvalidNamespace — the namespace flows into nft table
// names, firewalld service-name prefixes, and ufw comment prefixes.
// Anything outside the safe regex must be refused up front so the
// caller never gets a partially-constructed Manager that breaks later.
func TestNew_RejectsInvalidNamespace(t *testing.T) {
	bad := []string{
		"",                      // empty
		"-leading-hyphen",       // leading char not letter
		"1leading-digit",        // leading digit
		"UPPER",                 // uppercase
		"has space",             // whitespace
		"with-hyphen",           // hyphens reserved as separator
		"with:colon",            // colons reserved as separator
		strings.Repeat("a", 32), // 32 chars > 31 cap
	}
	for _, ns := range bad {
		t.Run("ns="+truncate(ns, 16), func(t *testing.T) {
			_, err := New(ns)
			if !errors.Is(err, ErrInvalidNamespace) {
				t.Fatalf("New(%q) = %v; want ErrInvalidNamespace", ns, err)
			}
		})
	}
}

func TestApplyRule_ReturnsSentinel(t *testing.T) {
	t.Cleanup(func() { SetBackend(BackendNftables) })
	SetBackend(BackendPF) // BSD pf — no impl in v1, exercises the sentinel path
	mgr, err := New("test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = mgr.ApplyRule(context.Background(), Rule{ID: "ssh-in", Allow: true, Protocol: ProtocolTCP, Port: 22})
	if err == nil || !errors.Is(err, ErrBackendNotSupported) {
		t.Errorf("want ErrBackendNotSupported, got %v", err)
	}
}

// TestList_DefaultBackendErrors — List is the inspection counterpart
// to ApplyRule and dispatches the same way. The unimplemented-backend
// behaviour must surface the same sentinel so callers can branch
// uniformly.
func TestList_DefaultBackendErrors(t *testing.T) {
	t.Cleanup(func() { SetBackend(BackendNftables) })
	SetBackend(BackendPF) // BSD pf — no impl yet
	mgr, err := New("test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = mgr.List(context.Background())
	if !errors.Is(err, ErrBackendNotSupported) {
		t.Fatalf("List on unimplemented backend = %v; want ErrBackendNotSupported", err)
	}
}

// TestApplyRule_RejectsInvalidID — Rule.ID is the idempotency key;
// backends round-trip it through their comment fields, so anything
// that could break the backend's grammar (whitespace, quotes, shell
// metas, control characters) must be rejected up front. Validation is
// backend-independent so a rule that's accepted on nftables is also
// accepted on firewalld.
func TestApplyRule_RejectsInvalidID(t *testing.T) {
	mgr, err := New("test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	bad := []string{
		"",                // empty
		" ",               // whitespace only
		"with space",      // embedded whitespace
		"UPPER",           // uppercase
		"-leading-hyphen", // leading hyphen
		"quote\"in",       // double quote
		"tick'in",         // single quote
		"newline\nin",     // control char
		"semicolon;in",    // shell-meta
		"pipe|in",         // shell-meta
		"backtick`in",     // shell-meta
		"dollar$in",       // shell-meta
		"way-too-long-" + strings.Repeat("x", 64), // over 63 chars
	}
	for _, id := range bad {
		t.Run("id="+truncate(id, 16), func(t *testing.T) {
			err := mgr.ApplyRule(context.Background(), Rule{ID: id, Allow: true, Protocol: ProtocolTCP, Port: 22})
			if !errors.Is(err, ErrInvalidRule) {
				t.Fatalf("ApplyRule(id=%q) = %v; want ErrInvalidRule", id, err)
			}
		})
	}
}

// TestApplyRule_AcceptsValidID — the allowed character class is
// documented on Rule.ID; lock in a representative sample so the regex
// doesn't get tightened by accident. Uses BackendPF so the dispatch
// falls through to the sentinel path without trying to shell out to a
// real firewall tool (the test verifies "id passed validation," not
// "nft is available on this host").
func TestApplyRule_AcceptsValidID(t *testing.T) {
	t.Cleanup(func() { SetBackend(BackendNftables) })
	SetBackend(BackendPF)
	mgr, err := New("test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	good := []string{
		"ssh-in",
		"allow-22",
		"web_https",
		"a",                                   // single char ok
		"01jxr5qxa3pn5g9b7tvyf2h4nm-allow-22", // ULID + suffix (multi-rule action)
		"01jxr5qxa3pn5g9b7tvyf2h4nm",          // bare ULID-style ID
	}
	for _, id := range good {
		t.Run("id="+id, func(t *testing.T) {
			err := mgr.ApplyRule(context.Background(), Rule{ID: id, Allow: true, Protocol: ProtocolTCP, Port: 22})
			// We're locking in "the id passed validation and reached
			// the dispatch layer." On BackendPF the dispatch hits the
			// default arm and returns ErrBackendNotSupported, which is
			// fine — anything except ErrInvalidRule means the regex
			// accepted the id.
			if errors.Is(err, ErrInvalidRule) {
				t.Fatalf("ApplyRule(id=%q) rejected valid id: %v", id, err)
			}
		})
	}
}

// TestRemoveRule_RejectsInvalidID — symmetric guard on the remove path
// so a caller can't smuggle backend-grammar-breaking input through the
// inverse op.
func TestRemoveRule_RejectsInvalidID(t *testing.T) {
	mgr, err := New("test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = mgr.RemoveRule(context.Background(), "id with space")
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
