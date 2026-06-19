package verify

import (
	"bytes"
	"testing"

	"github.com/manchtools/power-manage-sdk/cryptotest"
	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// ---------------------------------------------------------------------------
// SignDomain / VerifyDomain — the per-surface signing primitive WS4 adds.
//
// Contract restated: the control server signs a payload under a named domain
// (SignDomain); the agent verifies it under the SAME domain (VerifyDomain). A
// signature minted under one domain MUST NOT verify under another (no
// cross-surface replay), a byte-tampered signature MUST be rejected, and an
// absent signature MUST be rejected (fail closed).
// ---------------------------------------------------------------------------

func TestSignVerifyDomain_RoundTrip_AllDomains(t *testing.T) {
	certPEM, key, _ := cryptotest.GenCA(t, "Test CA")
	signer := NewActionSigner(key)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	domains := []string{
		OSQuerySignatureDomain, LogQuerySignatureDomain,
		LuksRevokeSignatureDomain, InventorySignatureDomain,
	}
	payload := []byte("canonical-payload-bytes")

	for _, d := range domains {
		t.Run(d, func(t *testing.T) {
			sig, err := signer.SignDomain(d, payload)
			if err != nil {
				t.Fatalf("SignDomain(%s): %v", d, err)
			}
			// correct
			if err := verifier.VerifyDomain(d, payload, sig); err != nil {
				t.Fatalf("VerifyDomain(%s) on a valid signature: %v", d, err)
			}
			// present-but-WRONG: byte-tampered signature
			tampered := append([]byte(nil), sig...)
			tampered[len(tampered)/2] ^= 0xFF
			if err := verifier.VerifyDomain(d, payload, tampered); err == nil {
				t.Fatalf("VerifyDomain(%s) accepted a byte-tampered signature", d)
			}
			// present-but-WRONG: payload mutated after signing (field swap analogue)
			mutated := append([]byte(nil), payload...)
			mutated[0] ^= 0xFF
			if err := verifier.VerifyDomain(d, mutated, sig); err == nil {
				t.Fatalf("VerifyDomain(%s) accepted a signature over different payload bytes", d)
			}
			// ABSENT: no signature → fail closed
			if err := verifier.VerifyDomain(d, payload, nil); err == nil {
				t.Fatalf("VerifyDomain(%s) accepted an empty signature", d)
			}
		})
	}
}

// TestVerifyDomain_RejectsCrossDomainSignature is the load-bearing
// cross-surface guard at the sign/verify level: a signature minted under one
// domain must NOT verify under any other domain, even for the identical
// payload. This is what stops a compromised relay from lifting, say, an
// inventory signature onto a LUKS-revoke instruction.
func TestVerifyDomain_RejectsCrossDomainSignature(t *testing.T) {
	certPEM, key, _ := cryptotest.GenCA(t, "Test CA")
	signer := NewActionSigner(key)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	payload := []byte("identical-payload")

	domains := []string{
		ActionSignatureDomain, OSQuerySignatureDomain, LogQuerySignatureDomain,
		LuksRevokeSignatureDomain, InventorySignatureDomain,
	}
	for i := range domains {
		sig, err := signer.SignDomain(domains[i], payload)
		if err != nil {
			t.Fatalf("SignDomain(%s): %v", domains[i], err)
		}
		for j := range domains {
			if i == j {
				continue
			}
			if err := verifier.VerifyDomain(domains[j], payload, sig); err == nil {
				t.Fatalf("signature for %q verified under %q — cross-surface replay possible",
					domains[i], domains[j])
			}
		}
	}
}

// TestSignDomain_RefusesEmptyPayload pins the signer fail-closed: an empty
// payload is never signed (a blank pre-image would be trivially forgeable).
func TestSignDomain_RefusesEmptyPayload(t *testing.T) {
	_, key, _ := cryptotest.GenCA(t, "Test CA")
	signer := NewActionSigner(key)
	if _, err := signer.SignDomain(OSQuerySignatureDomain, nil); err == nil {
		t.Fatal("SignDomain accepted an empty payload")
	}
}

// TestActionPath_ByteStable pins that the refactor to a domain-parameterised
// canonicalDigest did NOT change the action signing path: a signature minted
// with Sign still verifies with Verify, and equals signing the same envelope
// bytes under ActionSignatureDomain via SignDomain.
func TestActionPath_ByteStable(t *testing.T) {
	certPEM, key, _ := cryptotest.GenCA(t, "Test CA")
	signer := NewActionSigner(key)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	env := []byte("an-action-envelope")

	sig, err := signer.Sign(env)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := verifier.Verify(env, sig); err != nil {
		t.Fatalf("Verify on Sign output: %v", err)
	}
	// Action path == SignDomain under the action domain (same pre-image).
	if err := verifier.VerifyDomain(ActionSignatureDomain, env, sig); err != nil {
		t.Fatalf("action signature did not verify under ActionSignatureDomain via VerifyDomain: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Canonical encoders — clone-clear-signature deterministic marshal.
// ---------------------------------------------------------------------------

// TestOSQueryCanonical_ClearsSignatureAndBindsFields pins that the canonical:
//   - is independent of the signature field (so signing can't cover itself),
//   - changes when any security-relevant field changes (binding), and
//   - rejects nil.
func TestOSQueryCanonical_ClearsSignatureAndBindsFields(t *testing.T) {
	base := &pm.OSQuery{QueryId: "01HQUERY", Table: "processes", Limit: 50}

	c1, err := OSQueryCanonical(base)
	if err != nil {
		t.Fatalf("OSQueryCanonical: %v", err)
	}

	// Setting the signature must NOT change the canonical (it is cleared).
	withSig := &pm.OSQuery{QueryId: "01HQUERY", Table: "processes", Limit: 50, Signature: []byte("xxxx")}
	c2, err := OSQueryCanonical(withSig)
	if err != nil {
		t.Fatalf("OSQueryCanonical(withSig): %v", err)
	}
	if !bytes.Equal(c1, c2) {
		t.Fatal("OSQueryCanonical changed when only the signature field changed — it must be cleared")
	}
	// The input message must not be mutated (clone, not in-place clear).
	if len(withSig.Signature) == 0 {
		t.Fatal("OSQueryCanonical cleared the caller's Signature field — must operate on a clone")
	}

	// Each security-relevant field must bind: change it → canonical changes.
	bind := []struct {
		name string
		mut  func(q *pm.OSQuery)
	}{
		{"table", func(q *pm.OSQuery) { q.Table = "shadow" }},
		{"raw_sql", func(q *pm.OSQuery) { q.RawSql = "SELECT * FROM shadow" }},
		{"limit", func(q *pm.OSQuery) { q.Limit = 999 }},
		{"query_id", func(q *pm.OSQuery) { q.QueryId = "01HOTHER" }},
		{"columns", func(q *pm.OSQuery) { q.Columns = []string{"hash"} }},
	}
	for _, b := range bind {
		mutated := &pm.OSQuery{QueryId: "01HQUERY", Table: "processes", Limit: 50}
		b.mut(mutated)
		cm, err := OSQueryCanonical(mutated)
		if err != nil {
			t.Fatalf("OSQueryCanonical(%s): %v", b.name, err)
		}
		if bytes.Equal(c1, cm) {
			t.Fatalf("OSQueryCanonical did not bind field %q — mutating it left the canonical unchanged", b.name)
		}
	}

	if _, err := OSQueryCanonical(nil); err == nil {
		t.Fatal("OSQueryCanonical(nil) should error")
	}
}

// TestLogQueryCanonical_BindsUnit pins the unit binding the WS4 charter relies
// on (a compromised gateway must not be able to swap the unit) and that the
// signature field is cleared.
func TestLogQueryCanonical_BindsUnit(t *testing.T) {
	a := &pm.LogQuery{QueryId: "01HLOG", Unit: "nginx.service", Lines: 100}
	b := &pm.LogQuery{QueryId: "01HLOG", Unit: "ssh.service", Lines: 100}
	ca, err := LogQueryCanonical(a)
	if err != nil {
		t.Fatalf("LogQueryCanonical(a): %v", err)
	}
	cb, err := LogQueryCanonical(b)
	if err != nil {
		t.Fatalf("LogQueryCanonical(b): %v", err)
	}
	if bytes.Equal(ca, cb) {
		t.Fatal("LogQueryCanonical did not bind unit")
	}
	withSig := &pm.LogQuery{QueryId: "01HLOG", Unit: "nginx.service", Lines: 100, Signature: []byte("zz")}
	cs, err := LogQueryCanonical(withSig)
	if err != nil {
		t.Fatalf("LogQueryCanonical(withSig): %v", err)
	}
	if !bytes.Equal(ca, cs) {
		t.Fatal("LogQueryCanonical did not clear the signature field")
	}
}

// TestLuksAndInventoryCanonical_BindIdentifiers pins that the LUKS-revoke
// canonical binds action_id and the inventory canonical binds query_id (the
// only adversary-relevant fields), and both clear the signature + reject nil.
func TestLuksAndInventoryCanonical_BindIdentifiers(t *testing.T) {
	lA, err := RevokeLuksDeviceKeyCanonical(&pm.RevokeLuksDeviceKey{ActionId: "01HAAA"})
	if err != nil {
		t.Fatalf("RevokeLuksDeviceKeyCanonical: %v", err)
	}
	lB, err := RevokeLuksDeviceKeyCanonical(&pm.RevokeLuksDeviceKey{ActionId: "01HBBB"})
	if err != nil {
		t.Fatalf("RevokeLuksDeviceKeyCanonical: %v", err)
	}
	if bytes.Equal(lA, lB) {
		t.Fatal("RevokeLuksDeviceKeyCanonical did not bind action_id")
	}
	lSig, err := RevokeLuksDeviceKeyCanonical(&pm.RevokeLuksDeviceKey{ActionId: "01HAAA", Signature: []byte("q")})
	if err != nil {
		t.Fatalf("RevokeLuksDeviceKeyCanonical(withSig): %v", err)
	}
	if !bytes.Equal(lA, lSig) {
		t.Fatal("RevokeLuksDeviceKeyCanonical did not clear the signature field")
	}
	if _, err := RevokeLuksDeviceKeyCanonical(nil); err == nil {
		t.Fatal("RevokeLuksDeviceKeyCanonical(nil) should error")
	}

	iA, err := RequestInventoryCanonical(&pm.RequestInventory{QueryId: "01HINV1"})
	if err != nil {
		t.Fatalf("RequestInventoryCanonical: %v", err)
	}
	iB, err := RequestInventoryCanonical(&pm.RequestInventory{QueryId: "01HINV2"})
	if err != nil {
		t.Fatalf("RequestInventoryCanonical: %v", err)
	}
	if bytes.Equal(iA, iB) {
		t.Fatal("RequestInventoryCanonical did not bind query_id")
	}
	iSig, err := RequestInventoryCanonical(&pm.RequestInventory{QueryId: "01HINV1", Signature: []byte("q")})
	if err != nil {
		t.Fatalf("RequestInventoryCanonical(withSig): %v", err)
	}
	if !bytes.Equal(iA, iSig) {
		t.Fatal("RequestInventoryCanonical did not clear the signature field")
	}
	if _, err := RequestInventoryCanonical(nil); err == nil {
		t.Fatal("RequestInventoryCanonical(nil) should error")
	}
}

// TestEndToEnd_OSQuerySignThenVerify exercises the full WS4 path at the SDK
// level: build a message, sign its canonical under the osquery domain, attach
// the signature, then verify the received message. Proves both the happy path
// and that mutating the message after signing (field swap) is rejected.
func TestEndToEnd_OSQuerySignThenVerify(t *testing.T) {
	certPEM, key, _ := cryptotest.GenCA(t, "Test CA")
	signer := NewActionSigner(key)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	// Control server side: sign the canonical, attach signature.
	msg := &pm.OSQuery{QueryId: "01HQUERY", RawSql: "SELECT 1"}
	canon, err := OSQueryCanonical(msg)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	sig, err := signer.SignDomain(OSQuerySignatureDomain, canon)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	msg.Signature = sig

	// Agent side: re-derive canonical from the received message, verify.
	got, err := OSQueryCanonical(msg)
	if err != nil {
		t.Fatalf("agent canonical: %v", err)
	}
	if err := verifier.VerifyDomain(OSQuerySignatureDomain, got, msg.Signature); err != nil {
		t.Fatalf("agent verify on a correctly signed message: %v", err)
	}

	// Field swap: a compromised gateway mutates raw_sql after signing.
	msg.RawSql = "SELECT * FROM shadow"
	swapped, err := OSQueryCanonical(msg)
	if err != nil {
		t.Fatalf("swapped canonical: %v", err)
	}
	if err := verifier.VerifyDomain(OSQuerySignatureDomain, swapped, msg.Signature); err == nil {
		t.Fatal("verify accepted a message whose raw_sql was swapped after signing")
	}
}
