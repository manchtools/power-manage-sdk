// Package verify provides action signature verification and signing.
//
// The control server signs actions with its CA private key
// (ActionSigner). Agents verify those signatures against the
// matching CA certificate's public key (ActionVerifier). The two
// sides exchange the signature over an SHA-256 hash of the
// canonical payload:
//
//	canonical = sprintf("%s:%d:%s", actionID, actionType,
//	                    base64.StdEncoding.EncodeToString(paramsJSON))
//
// `actionType` is the protobuf enum's integer value (rendered with
// %d), so signing and verifying must agree on the enum encoding —
// renaming an enum entry in the proto without coordinating server
// and agent rollouts will not break verification, but renumbering
// it will.
//
// Supported key algorithms: ECDSA (verified via ecdsa.VerifyASN1,
// signed via ecdsa.SignASN1) and RSA (PKCS#1 v1.5 with SHA-256).
// Other key types — including Ed25519 — are explicitly rejected so
// a key-type drift between server and agent surfaces as a clear
// error instead of a silent signature mismatch.
package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// CanonicalDomainV1 is the implicit domain tag of the current action
// canonical format. The signed message today is:
//
//	canonical = sprintf("%s:%d:%s", actionID, actionType, base64(paramsJSON))
//
// There is no explicit domain prefix on the wire — the implicit
// "this is an action signed by the power-manage control server CA"
// scope is what the CA key carries. That works because the CA key is
// only used for one thing today.
//
// CanonicalDomainV1 captures the intent so future signing surfaces
// can declare their own domains (e.g. CanonicalDomainTerminalV1) and
// canonicalPayloadV2 can prepend the tag explicitly to prevent
// cross-surface signature replay. See finding #11 of the 2026-06-06
// audit and verify_test.go's TestCanonicalPayload_NoCrossInputCollision
// for the current compatibility envelope and the test contract that
// catches accidental collisions.
const CanonicalDomainV1 = "power-manage-action-v1"

// canonicalPayload builds the canonical string used for signing and verification.
//
// Format (v1, on-wire today):
//
//	SHA-256( sprintf("%s:%d:%s", actionID, actionType, base64(paramsJSON)) )
//
// The format is sensitive to all three inputs — any single field
// changing flips the hash. See TestCanonicalPayload_NoCrossInputCollision
// for the explicit non-collision contract.
//
// Domain separation: the implicit domain ("power-manage action signed
// by the CA") is carried by the CA key, not by an in-payload tag.
// If a second signing surface is ever introduced (e.g. terminal
// session tokens signed with the same CA key), introduce a v2
// canonical format that prepends an explicit domain string and route
// both sides through the new function — keeping v1 in place for
// during-rollout compatibility. canonicalPayloadV2 below is the
// scaffolding for that change; today's signer / verifier still use
// v1.
func canonicalPayload(actionID string, actionType int32, paramsJSON []byte) []byte {
	canonical := fmt.Sprintf("%s:%d:%s", actionID, actionType,
		base64.StdEncoding.EncodeToString(paramsJSON))
	hash := sha256.Sum256([]byte(canonical))
	return hash[:]
}

// canonicalPayloadV2 is the domain-tagged successor canonical payload.
// Not yet wired into Sign / Verify — present so the domain-separation
// contract has a concrete reference and so we can add cross-domain
// non-collision tests today. Switching the public surface to v2 needs
// a coordinated agent + control rollout because verifiers on the old
// SDK would reject a v2 signature.
func canonicalPayloadV2(domain, actionID string, actionType int32, paramsJSON []byte) []byte {
	canonical := fmt.Sprintf("%s|%s:%d:%s", domain, actionID, actionType,
		base64.StdEncoding.EncodeToString(paramsJSON))
	hash := sha256.Sum256([]byte(canonical))
	return hash[:]
}

// ActionVerifier verifies action signatures using the CA's public key.
type ActionVerifier struct {
	pubKey crypto.PublicKey
}

// NewActionVerifier creates a new action verifier from a PEM-encoded CA certificate.
func NewActionVerifier(caCertPEM []byte) (*ActionVerifier, error) {
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	return &ActionVerifier{pubKey: cert.PublicKey}, nil
}

// Verify checks the signature of an action payload.
func (v *ActionVerifier) Verify(actionID string, actionType int32, paramsJSON, signature []byte) error {
	if len(signature) == 0 {
		return fmt.Errorf("no signature provided for action %s", actionID)
	}

	hash := canonicalPayload(actionID, actionType, paramsJSON)

	switch key := v.pubKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, hash, signature) {
			return fmt.Errorf("invalid ECDSA signature for action %s", actionID)
		}
		return nil
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash, signature); err != nil {
			return fmt.Errorf("invalid RSA signature for action %s: %w", actionID, err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type: %T", v.pubKey)
	}
}

// ActionSigner signs action payloads using a private key.
// This ensures agents can verify actions originated from the control server.
type ActionSigner struct {
	key crypto.Signer
}

// NewActionSigner creates a new action signer from a crypto.Signer (e.g. *ecdsa.PrivateKey).
func NewActionSigner(key crypto.Signer) *ActionSigner {
	return &ActionSigner{key: key}
}

// Sign produces a signature over the canonical action payload.
func (s *ActionSigner) Sign(actionID string, actionType int32, paramsJSON []byte) ([]byte, error) {
	hash := canonicalPayload(actionID, actionType, paramsJSON)

	switch key := s.key.(type) {
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, key, hash)
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", s.key)
	}
}
