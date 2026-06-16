package encryption

import (
	"strings"
	"testing"
)

func TestValidatePassphrase(t *testing.T) {
	cases := []struct {
		name       string
		pass       string
		minLen     int
		complexity Complexity
		wantOK     bool
	}{
		{"too short", "abc", 8, ComplexityNone, false},
		{"long enough, no complexity", "abcdefghij", 8, ComplexityNone, true},
		{"alphanumeric: letters only", "abcdefgh", 8, ComplexityAlphanumeric, false},
		{"alphanumeric: digits only", "12345678", 8, ComplexityAlphanumeric, false},
		{"alphanumeric: valid", "abc12345", 8, ComplexityAlphanumeric, true},
		{"complex: missing special", "abc12345", 8, ComplexityComplex, false},
		{"complex: missing digit", "abcdefg!", 8, ComplexityComplex, false},
		{"complex: missing letter", "1234567!", 8, ComplexityComplex, false},
		{"complex: valid", "abc123!@", 8, ComplexityComplex, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := ValidatePassphrase(c.pass, c.minLen, c.complexity)
			if (msg == "") != c.wantOK {
				t.Errorf("ValidatePassphrase(%q) = %q, wantOK=%v", c.pass, msg, c.wantOK)
			}
		})
	}
}

func TestHashPassphrase(t *testing.T) {
	h1 := HashPassphrase("same")
	if h1 != HashPassphrase("same") {
		t.Error("HashPassphrase not deterministic")
	}
	if h1 == HashPassphrase("different") {
		t.Error("distinct inputs hashed to the same value")
	}
	if len(h1) != 128 { // SHA-512 = 64 bytes = 128 hex chars
		t.Errorf("hash length = %d, want 128 (SHA-512 hex)", len(h1))
	}
	if strings.ToLower(h1) != h1 {
		t.Error("hash should be lowercase hex")
	}
}

func TestIsRecentlyUsed(t *testing.T) {
	pass := "my-passphrase"
	hash := HashPassphrase(pass)
	if !IsRecentlyUsed(pass, []string{"x", hash, "y"}) {
		t.Error("IsRecentlyUsed = false for a matching hash")
	}
	if IsRecentlyUsed(pass, []string{"x", "y"}) {
		t.Error("IsRecentlyUsed = true with no matching hash")
	}
	if IsRecentlyUsed(pass, nil) {
		t.Error("IsRecentlyUsed = true on an empty list")
	}
}
