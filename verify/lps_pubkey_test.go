package verify

import (
	"bytes"
	"testing"

	"github.com/manchtools/power-manage-sdk/cryptotest"
	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// LpsPublicKeyCanonical must clear the signature field (the signature cannot
// cover itself), bind the key bytes, and be deterministic — the exact bytes
// control signs are the bytes the agent re-derives and verifies.
func TestLpsPublicKeyCanonical_ClearsSignatureAndBindsKey(t *testing.T) {
	if _, err := LpsPublicKeyCanonical(nil); err == nil {
		t.Fatal("nil LpsPublicKey accepted")
	}

	key := bytes.Repeat([]byte{0x42}, 32)
	unsigned := &pm.LpsPublicKey{PublicKey: key}
	signed := &pm.LpsPublicKey{PublicKey: key, Signature: []byte("sig")}

	a, err := LpsPublicKeyCanonical(unsigned)
	if err != nil {
		t.Fatalf("canonical(unsigned): %v", err)
	}
	b, err := LpsPublicKeyCanonical(signed)
	if err != nil {
		t.Fatalf("canonical(signed): %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Error("canonical bytes differ with/without signature — signature field not cleared")
	}
	if signed.Signature == nil {
		t.Error("canonical mutated its input (signature cleared on the caller's message)")
	}

	other := &pm.LpsPublicKey{PublicKey: bytes.Repeat([]byte{0x43}, 32)}
	c, err := LpsPublicKeyCanonical(other)
	if err != nil {
		t.Fatalf("canonical(other): %v", err)
	}
	if bytes.Equal(a, c) {
		t.Error("canonical bytes identical for different keys — key bytes not bound")
	}
}

// End-to-end over the real domain: control signs the canonical form under
// LpsPublicKeySignatureDomain, the agent verifies fail-closed — and a
// key-swap after signing is rejected (the hostile-gateway case the domain
// signature exists to prevent).
func TestLpsPublicKey_SignThenVerify_RejectsKeySwap(t *testing.T) {
	certPEM, key, _ := cryptotest.GenCA(t, "Test CA")
	signer := NewActionSigner(key)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	msg := &pm.LpsPublicKey{PublicKey: bytes.Repeat([]byte{0x42}, 32)}
	canonical, err := LpsPublicKeyCanonical(msg)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	sig, err := signer.SignDomain(LpsPublicKeySignatureDomain, canonical)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	msg.Signature = sig

	// Agent side: re-derive canonical from the received message, verify.
	rx, err := LpsPublicKeyCanonical(msg)
	if err != nil {
		t.Fatalf("canonical(rx): %v", err)
	}
	if err := verifier.VerifyDomain(LpsPublicKeySignatureDomain, rx, msg.Signature); err != nil {
		t.Fatalf("valid signed key rejected: %v", err)
	}

	// Hostile gateway swaps the key bytes but keeps the signature.
	swapped := &pm.LpsPublicKey{PublicKey: bytes.Repeat([]byte{0x66}, 32), Signature: sig}
	sc, err := LpsPublicKeyCanonical(swapped)
	if err != nil {
		t.Fatalf("canonical(swapped): %v", err)
	}
	if err := verifier.VerifyDomain(LpsPublicKeySignatureDomain, sc, swapped.Signature); err == nil {
		t.Fatal("key swapped after signing was accepted — gateway substitution possible")
	}
}
