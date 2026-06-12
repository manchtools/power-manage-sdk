package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"
)

// TestCanonicalDigest_StableShape pins the digest length. The format is
// iterated in place (no in-tree versioning — server and agent ship from
// the same SDK), so we don't pin the bytes; the length pin catches an
// accidental switch off SHA-256.
func TestCanonicalDigest_StableShape(t *testing.T) {
	if got := canonicalDigest([]byte("envelope-bytes")); len(got) != 32 {
		t.Fatalf("canonicalDigest returned %d bytes; SHA-256 must be 32", len(got))
	}
}

// TestCanonicalDigest_MixesDomain proves the domain tag actually
// contributes: the digest of a payload is NOT the bare SHA-256 of that
// payload, and it equals the explicit length-prefixed-domain formula. If
// the domain ever stopped being mixed in, a signature for this surface
// could be replayed against another surface sharing the CA key.
func TestCanonicalDigest_MixesDomain(t *testing.T) {
	payload := []byte("envelope-bytes")

	bare := sha256.Sum256(payload)
	if bytes.Equal(canonicalDigest(payload), bare[:]) {
		t.Fatal("canonicalDigest equals the bare SHA-256 of the payload — the domain tag is not contributing")
	}

	// Reproduce the documented pre-image: len32(domain) || domain || payload.
	h := sha256.New()
	var lenPrefix [4]byte
	binary.BigEndian.PutUint32(lenPrefix[:], uint32(len(ActionSignatureDomain)))
	h.Write(lenPrefix[:])
	h.Write([]byte(ActionSignatureDomain))
	h.Write(payload)
	if !bytes.Equal(canonicalDigest(payload), h.Sum(nil)) {
		t.Fatal("canonicalDigest does not match the documented len32(domain)||domain||payload pre-image")
	}
}

// TestCanonicalDigest_LengthPrefixDefeatsDomainConfusion pins that the
// 4-byte length prefix makes "domain || payload" unambiguous: a digest
// computed WITHOUT the length prefix (a different framing) differs, so no
// other domain string can be confused with ActionSignatureDomain followed
// by an attacker-chosen payload prefix.
func TestCanonicalDigest_LengthPrefixDefeatsDomainConfusion(t *testing.T) {
	payload := []byte("p")

	// Framing without the length prefix (the naive domain||payload concat).
	unframed := sha256.Sum256(append([]byte(ActionSignatureDomain), payload...))
	if bytes.Equal(canonicalDigest(payload), unframed[:]) {
		t.Fatal("canonicalDigest matches the unframed domain||payload concat — the length prefix is not applied")
	}
}

// TestCanonicalDigest_SensitiveToPayload pins that distinct payloads yield
// distinct digests (the binding the signature relies on).
func TestCanonicalDigest_SensitiveToPayload(t *testing.T) {
	if bytes.Equal(canonicalDigest([]byte("a")), canonicalDigest([]byte("b"))) {
		t.Fatal("canonicalDigest collided across distinct payloads")
	}
}

// TestActionSignatureDomain_Recognizable keeps the domain string auditable.
func TestActionSignatureDomain_Recognizable(t *testing.T) {
	if !strings.HasPrefix(ActionSignatureDomain, "power-manage-action") {
		t.Errorf("ActionSignatureDomain = %q; expected to start with 'power-manage-action'", ActionSignatureDomain)
	}
}
