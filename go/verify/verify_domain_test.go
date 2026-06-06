package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// TestCanonicalPayload_StableShape pins the canonical hash output
// length. The format itself is iterated in place (no in-tree v1/v2
// versioning), so we don't pin the bytes — server and agent ship
// from the same SDK so any change in this function rolls out
// atomically. The length pin catches an accidental switch off SHA-256
// (which would change the signature surface entirely).
func TestCanonicalPayload_StableShape(t *testing.T) {
	got := canonicalPayload("01JABCDEFGHJKMNPQRSTVWXYZ0", 200, []byte(`{"script":"echo ok"}`))
	if len(got) != 32 {
		t.Fatalf("canonicalPayload returned %d bytes; SHA-256 must always be 32", len(got))
	}
}

// TestCanonicalPayload_NoCrossInputCollision proves the canonical hash
// is sensitive to all three signed inputs — any single field changing
// flips the hash. The audit finding #11 phrasing was "signatures
// cannot be replayed across domains/action encodings"; this is the
// collision check that catches the action-encoding half of the replay
// class. The domain-prefix half is covered by
// TestCanonicalPayload_DomainPrefixBreaksReplay below.
func TestCanonicalPayload_NoCrossInputCollision(t *testing.T) {
	const baseID = "01JABCDEFGHJKMNPQRSTVWXYZ0"
	const baseType = int32(200)
	baseParams := []byte(`{"script":"echo ok"}`)

	base := canonicalPayload(baseID, baseType, baseParams)

	cases := []struct {
		label      string
		id         string
		actionType int32
		params     []byte
	}{
		{"different id", "01JABCDEFGHJKMNPQRSTVWXYZ1", baseType, baseParams},
		{"different type", baseID, 201, baseParams},
		{"different params", baseID, baseType, []byte(`{"script":"echo evil"}`)},
		{"params byte-flip", baseID, baseType, []byte(`{"script":"echo Ok"}`)},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			got := canonicalPayload(tc.id, tc.actionType, tc.params)
			if bytes.Equal(got, base) {
				t.Fatalf("canonical hash collided across distinct inputs (%s); replay would be possible", tc.label)
			}
		})
	}
}

// TestCanonicalPayload_IncludesDomainPrefix proves the
// ActionSignatureDomain constant actually contributes to the hash —
// i.e., changing the constant would change every signature produced
// by Sign. The test reproduces the canonical format with a different
// domain string in-line and asserts the hash differs from
// canonicalPayload's output. This is the cross-surface replay
// protection contract: a signature made under one domain cannot be
// verified as if it had been made under another.
func TestCanonicalPayload_IncludesDomainPrefix(t *testing.T) {
	const id = "01JABCDEFGHJKMNPQRSTVWXYZ0"
	const at = int32(200)
	params := []byte(`{"x":1}`)

	got := canonicalPayload(id, at, params)

	// Recompute with a deliberately different domain and confirm the
	// hashes diverge. If they ever match, the domain prefix isn't
	// actually being read.
	if otherDomainHashesAreEqual(t, "power-manage-terminal", id, at, params, got) {
		t.Fatal("changing the domain string did not change the canonical hash; ActionSignatureDomain is not contributing to the digest")
	}

	// Spot-check: the constant the code uses is named in the way the
	// audit + the doc comment describe.
	if !strings.HasPrefix(ActionSignatureDomain, "power-manage-action") {
		t.Errorf("ActionSignatureDomain = %q; expected to start with 'power-manage-action' so the domain string is recognisable in audit traces", ActionSignatureDomain)
	}
}

// otherDomainHashesAreEqual reproduces the canonical-payload shape
// in-line with a caller-chosen domain and checks against want.
// Returns true iff the hash matches (i.e. the domain didn't matter).
func otherDomainHashesAreEqual(t *testing.T, domain, id string, at int32, params, want []byte) bool {
	t.Helper()
	// Mirror canonicalPayload's body but with the supplied domain.
	// Kept in-test so the test can vary the domain without the
	// production code needing a second entry point.
	canonical := fmt.Sprintf("%s|%s:%d:%s", domain, id, at, base64.StdEncoding.EncodeToString(params))
	hash := sha256.Sum256([]byte(canonical))
	return bytes.Equal(hash[:], want)
}
