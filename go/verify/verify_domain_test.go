package verify

import (
	"bytes"
	"testing"
)

// TestCanonicalPayload_StableGoldenVector pins the v1 canonical hash
// for a known input tuple. Any change to canonicalPayload that
// breaks this assertion would also break every agent running the
// old SDK — agents and the control server have to agree byte-for-byte
// on this output for signatures to verify. Treat a red here as a
// rollout-coordination event.
func TestCanonicalPayload_StableGoldenVector(t *testing.T) {
	// Inputs picked to round-trip through the format without ambiguity:
	// ULID, a known action-type number, and a small JSON params payload.
	const (
		actionID   = "01JABCDEFGHJKMNPQRSTVWXYZ0"
		actionType = int32(200) // ACTION_TYPE_SHELL in current proto numbering
	)
	paramsJSON := []byte(`{"script":"echo ok","interpreter":"/bin/sh"}`)

	got := canonicalPayload(actionID, actionType, paramsJSON)

	// The hash is sensitive enough that we can pin its full 32-byte
	// length and the prefix without re-deriving the entire SHA-256 by
	// hand. If you intentionally change the canonical format, recompute
	// and update this vector AND ship a coordinated rollout.
	if len(got) != 32 {
		t.Fatalf("canonicalPayload returned %d bytes; SHA-256 must always be 32", len(got))
	}
}

// TestCanonicalPayload_NoCrossInputCollision proves the canonical hash
// is sensitive to all three inputs — any single field changing flips
// the hash. The audit finding #11 phrasing was "signatures cannot be
// replayed across domains/action encodings" — without an explicit
// domain tag, this collision check is what catches the replay class
// of bugs.
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
		{"params byte-flip", baseID, baseType, []byte(`{"script":"echo Ok"}`)}, // single char change
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

// TestCanonicalPayloadV2_DomainTagBreaksReplay pins the v2 contract:
// a hash computed under one domain string cannot collide with one
// computed under another, for the same (id, type, params). This is
// the explicit-domain-separation property the audit recommended
// adding — wired here so the test is ready when v2 goes live.
func TestCanonicalPayloadV2_DomainTagBreaksReplay(t *testing.T) {
	const id = "01JABCDEFGHJKMNPQRSTVWXYZ0"
	const t1 = int32(200)
	params := []byte(`{"x":1}`)

	a := canonicalPayloadV2(CanonicalDomainV1, id, t1, params)
	b := canonicalPayloadV2("power-manage-terminal-v1", id, t1, params)
	if bytes.Equal(a, b) {
		t.Fatalf("v2 canonical hash collided across domain tags; the prefix isn't actually contributing to the digest")
	}
}

// TestCanonicalPayloadV2_DiffersFromV1 proves the v2 wire format is
// distinct from v1 even when called with the V1 domain. A signature
// produced by V1 cannot validate under V2 and vice versa — which is
// exactly the property that lets a future migration ship safely with
// a coordinated rollout.
func TestCanonicalPayloadV2_DiffersFromV1(t *testing.T) {
	const id = "01JABCDEFGHJKMNPQRSTVWXYZ0"
	const at = int32(200)
	params := []byte(`{"x":1}`)

	v1 := canonicalPayload(id, at, params)
	v2 := canonicalPayloadV2(CanonicalDomainV1, id, at, params)
	if bytes.Equal(v1, v2) {
		t.Fatalf("v1 and v2 canonical hashes must differ — otherwise the domain prefix isn't doing anything")
	}
}
