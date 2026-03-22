// Package verify provides action signature verification and signing.
//
// Actions are signed by the control server and verified by agents using the
// CA certificate's public key. The canonical payload format is:
//
//	"actionID:actionType:base64(paramsJSON)"
//
// Both ECDSA and RSA keys are supported.
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

// canonicalPayload builds the canonical string used for signing and verification.
func canonicalPayload(actionID string, actionType int32, paramsJSON []byte) []byte {
	canonical := fmt.Sprintf("%s:%d:%s", actionID, actionType,
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
