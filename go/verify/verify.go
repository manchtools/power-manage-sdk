// Package verify provides action signature signing and verification.
//
// The control server signs actions with its CA private key (ActionSigner);
// agents verify those signatures against the matching CA certificate's
// public key (ActionVerifier).
//
// # What is signed
//
// The signature is computed over the DETERMINISTIC protobuf wire bytes of
// a pm.SignedActionEnvelope (see MarshalEnvelope) — the full executed
// action: action id, action type, params, desired_state, timeout_seconds,
// schedule, and target_device_id. The agent verifies the signature over
// the bytes it received and unmarshals THOSE SAME bytes to execute, so the
// executed message is byte-for-byte the verified message. There is no
// separate JSON "canonical" form and no typed-params/canonical-params
// split (the sdk#82 gap): one representation, signed and transported.
//
// Binding the whole envelope means a compromised gateway or Valkey relay
// cannot flip desired_state, swap params, change the timeout/schedule, lift
// the type onto SYNC, or retarget the device under a still-valid signature.
//
// # Pre-image
//
//	digest = SHA-256( len32(domain) || domain || envelopeBytes )
//
// The length-prefixed domain tag (ActionSignatureDomain) keeps this
// signing surface disjoint from any other surface that might one day share
// the CA key — the length prefix makes "domain || bytes" unambiguous so no
// other domain string can be confused with this one followed by a payload.
//
// Determinism is belt-and-braces: correctness comes from signing and
// TRANSPORTING the exact bytes, then verifying-and-unmarshalling those same
// bytes. The server (Go) always signs and the agent (Go) always verifies;
// the web client never verifies an action signature, so cross-language or
// cross-version marshalling drift cannot bite.
//
// Supported key algorithms: ECDSA (ecdsa.VerifyASN1 / ecdsa.SignASN1) and
// RSA (PKCS#1 v1.5 with SHA-256). Other key types — including Ed25519 —
// are explicitly rejected so a key-type drift between server and agent
// surfaces as a clear error instead of a silent signature mismatch.
//
// No backward-compatibility shim: the project has no stable release, so the
// signing format is iterated in place. Server and agent must always be on
// matching SDK versions for verification to succeed.
package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
)

// ActionSignatureDomain is the domain tag mixed into every action-signature
// pre-image. Every distinct signing surface that might share the CA key
// declares its own domain string; the length-prefixed mix keeps the
// pre-image hashes disjoint so a signature for one surface can never be
// replayed against another.
const ActionSignatureDomain = "power-manage-action"

// canonicalDigest hashes the length-prefixed domain tag followed by the
// envelope bytes. The 4-byte big-endian domain length makes the
// concatenation unambiguous: no other domain string can collide with
// ActionSignatureDomain followed by an attacker-chosen payload prefix.
func canonicalDigest(envelopeBytes []byte) []byte {
	h := sha256.New()
	var lenPrefix [4]byte
	binary.BigEndian.PutUint32(lenPrefix[:], uint32(len(ActionSignatureDomain)))
	h.Write(lenPrefix[:])
	h.Write([]byte(ActionSignatureDomain))
	h.Write(envelopeBytes)
	return h.Sum(nil)
}

// ActionVerifier verifies action signatures using the CA's public key.
type ActionVerifier struct {
	pubKey crypto.PublicKey
}

// NewActionVerifier creates a verifier from a PEM-encoded CA certificate.
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

// Verify checks signature against the deterministic envelope bytes. The
// caller MUST pass the exact bytes it received (and, on success, unmarshal
// those same bytes to execute) — never a re-marshalled copy.
func (v *ActionVerifier) Verify(envelopeBytes, signature []byte) error {
	if len(signature) == 0 {
		return fmt.Errorf("no signature provided for action envelope")
	}
	if len(envelopeBytes) == 0 {
		return fmt.Errorf("empty action envelope")
	}

	digest := canonicalDigest(envelopeBytes)

	switch key := v.pubKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest, signature) {
			return fmt.Errorf("invalid ECDSA signature for action envelope")
		}
		return nil
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, signature); err != nil {
			return fmt.Errorf("invalid RSA signature for action envelope: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type: %T", v.pubKey)
	}
}

// ActionSigner signs action envelopes using the CA private key, so agents
// can verify actions originated from the control server.
type ActionSigner struct {
	key crypto.Signer
}

// NewActionSigner creates a signer from a crypto.Signer (e.g. *ecdsa.PrivateKey).
func NewActionSigner(key crypto.Signer) *ActionSigner {
	return &ActionSigner{key: key}
}

// Sign produces a signature over the deterministic envelope bytes. The
// caller MUST transport these exact bytes alongside the signature (see
// MarshalEnvelope) — the agent verifies and executes the same bytes.
func (s *ActionSigner) Sign(envelopeBytes []byte) ([]byte, error) {
	if len(envelopeBytes) == 0 {
		return nil, fmt.Errorf("refusing to sign an empty action envelope")
	}
	digest := canonicalDigest(envelopeBytes)

	switch key := s.key.(type) {
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, key, digest)
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", s.key)
	}
}
