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
	if got := canonicalDigest(ActionSignatureDomain, []byte("envelope-bytes")); len(got) != 32 {
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
	if bytes.Equal(canonicalDigest(ActionSignatureDomain, payload), bare[:]) {
		t.Fatal("canonicalDigest equals the bare SHA-256 of the payload — the domain tag is not contributing")
	}

	// Reproduce the documented pre-image: len32(domain) || domain || payload.
	h := sha256.New()
	var lenPrefix [4]byte
	binary.BigEndian.PutUint32(lenPrefix[:], uint32(len(ActionSignatureDomain)))
	h.Write(lenPrefix[:])
	h.Write([]byte(ActionSignatureDomain))
	h.Write(payload)
	if !bytes.Equal(canonicalDigest(ActionSignatureDomain, payload), h.Sum(nil)) {
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
	if bytes.Equal(canonicalDigest(ActionSignatureDomain, payload), unframed[:]) {
		t.Fatal("canonicalDigest matches the unframed domain||payload concat — the length prefix is not applied")
	}
}

// TestCanonicalDigest_SensitiveToPayload pins that distinct payloads yield
// distinct digests (the binding the signature relies on).
func TestCanonicalDigest_SensitiveToPayload(t *testing.T) {
	if bytes.Equal(canonicalDigest(ActionSignatureDomain, []byte("a")), canonicalDigest(ActionSignatureDomain, []byte("b"))) {
		t.Fatal("canonicalDigest collided across distinct payloads")
	}
}

// TestCanonicalDigest_DistinctDomainsDisjoint is the load-bearing
// cross-surface guard: the SAME payload under two different domains must
// produce different digests. This is what makes a signature minted for one
// surface (e.g. an action) impossible to replay against another (e.g. an
// osquery/log/LUKS-revoke/inventory dispatch) even though they all share the
// CA key. Every distinct pair of the declared domains is checked, so adding a
// new domain that collides with an existing one fails here.
func TestCanonicalDigest_DistinctDomainsDisjoint(t *testing.T) {
	payload := []byte("identical-payload-bytes")
	domains := []string{
		ActionSignatureDomain,
		OSQuerySignatureDomain,
		LogQuerySignatureDomain,
		LuksRevokeSignatureDomain,
		InventorySignatureDomain,
	}
	// Domains must be unique strings.
	seen := map[string]bool{}
	for _, d := range domains {
		if seen[d] {
			t.Fatalf("duplicate signing domain %q — domains must be disjoint", d)
		}
		seen[d] = true
	}
	// Same payload under any two distinct domains must hash differently.
	for i := 0; i < len(domains); i++ {
		for j := i + 1; j < len(domains); j++ {
			if bytes.Equal(canonicalDigest(domains[i], payload), canonicalDigest(domains[j], payload)) {
				t.Fatalf("canonicalDigest collided across domains %q and %q — cross-surface replay is possible",
					domains[i], domains[j])
			}
		}
	}
}

// TestSigningDomains_Recognizable keeps the domain strings auditable and
// pins the action domain byte-stable (the action path must not drift).
func TestSigningDomains_Recognizable(t *testing.T) {
	if ActionSignatureDomain != "power-manage-action" {
		t.Errorf("ActionSignatureDomain = %q; the action signing path must stay byte-stable", ActionSignatureDomain)
	}
	for _, d := range []string{
		OSQuerySignatureDomain, LogQuerySignatureDomain,
		LuksRevokeSignatureDomain, InventorySignatureDomain,
	} {
		if !strings.HasPrefix(d, "power-manage-") {
			t.Errorf("signing domain %q should start with 'power-manage-'", d)
		}
	}
}
