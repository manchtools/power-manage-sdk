package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// generateTestCA creates a self-signed ECDSA CA certificate and key.
func generateTestCA(t *testing.T) (certPEM []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), key
}

// generateTestRSACA creates a self-signed RSA CA for testing.
func generateTestRSACA(t *testing.T) (certPEM []byte, key *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test RSA CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create RSA CA certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), key
}

// TestSignVerify_BytesRoundTrip_ECDSA pins that a signature minted over a
// byte string verifies with the matching CA public key.
func TestSignVerify_BytesRoundTrip_ECDSA(t *testing.T) {
	certPEM, caKey := generateTestCA(t)
	signer := NewActionSigner(caKey)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("NewActionVerifier: %v", err)
	}
	payload := []byte("deterministic-envelope-bytes")
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := verifier.Verify(payload, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestSignVerify_BytesRoundTrip_RSA exercises the RSA branch.
func TestSignVerify_BytesRoundTrip_RSA(t *testing.T) {
	certPEM, rsaKey := generateTestRSACA(t)
	signer := NewActionSigner(rsaKey)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("NewActionVerifier: %v", err)
	}
	payload := []byte("rsa-deterministic-envelope-bytes")
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := verifier.Verify(payload, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestVerify_EmptySignatureRejected covers the ABSENT signature path.
func TestVerify_EmptySignatureRejected(t *testing.T) {
	certPEM, _ := generateTestCA(t)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("NewActionVerifier: %v", err)
	}
	if err := verifier.Verify([]byte("envelope"), nil); err == nil {
		t.Fatal("expected error for nil signature")
	}
	if err := verifier.Verify([]byte("envelope"), []byte{}); err == nil {
		t.Fatal("expected error for empty signature")
	}
}

// TestVerify_EmptyEnvelopeRejected covers the ABSENT envelope path.
func TestVerify_EmptyEnvelopeRejected(t *testing.T) {
	certPEM, caKey := generateTestCA(t)
	signer := NewActionSigner(caKey)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("NewActionVerifier: %v", err)
	}
	sig, err := signer.Sign([]byte("x"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := verifier.Verify(nil, sig); err == nil {
		t.Fatal("expected error for nil envelope")
	}
	if err := verifier.Verify([]byte{}, sig); err == nil {
		t.Fatal("expected error for empty envelope")
	}
}

// TestSign_RefusesEmptyEnvelope is the signer-side fail-closed.
func TestSign_RefusesEmptyEnvelope(t *testing.T) {
	_, caKey := generateTestCA(t)
	signer := NewActionSigner(caKey)
	if _, err := signer.Sign(nil); err == nil {
		t.Fatal("expected Sign to refuse a nil envelope")
	}
	if _, err := signer.Sign([]byte{}); err == nil {
		t.Fatal("expected Sign to refuse an empty envelope")
	}
}

// TestVerify_ByteTamperedSignature flips one byte of the ASN.1 signature
// (not a wrong key) so a no-op verify cannot pass.
func TestVerify_ByteTamperedSignature(t *testing.T) {
	certPEM, caKey := generateTestCA(t)
	signer := NewActionSigner(caKey)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("NewActionVerifier: %v", err)
	}
	payload := []byte("envelope-bytes")
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tampered := append([]byte(nil), sig...)
	tampered[len(tampered)-1] ^= 0x01
	if err := verifier.Verify(payload, tampered); err == nil {
		t.Fatal("expected error for byte-tampered signature")
	}
}

// TestVerify_ByteTamperedEnvelope flips one byte of the signed bytes.
func TestVerify_ByteTamperedEnvelope(t *testing.T) {
	certPEM, caKey := generateTestCA(t)
	signer := NewActionSigner(caKey)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("NewActionVerifier: %v", err)
	}
	payload := []byte("envelope-bytes-to-tamper")
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tampered := append([]byte(nil), payload...)
	tampered[0] ^= 0x01
	if err := verifier.Verify(tampered, sig); err == nil {
		t.Fatal("expected error for byte-tampered envelope")
	}
}

// TestVerify_WrongKey signs with one CA and verifies with another.
func TestVerify_WrongKey(t *testing.T) {
	certPEM, _ := generateTestCA(t)
	_, differentKey := generateTestCA(t)
	signer := NewActionSigner(differentKey)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("NewActionVerifier: %v", err)
	}
	sig, err := signer.Sign([]byte("envelope"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := verifier.Verify([]byte("envelope"), sig); err == nil {
		t.Fatal("expected error when verifying with the wrong CA")
	}
}

// TestSignVerify_LargeEnvelope round-trips a 1 MiB payload.
func TestSignVerify_LargeEnvelope(t *testing.T) {
	certPEM, caKey := generateTestCA(t)
	signer := NewActionSigner(caKey)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("NewActionVerifier: %v", err)
	}
	payload := make([]byte, 1<<20)
	for i := range payload {
		payload[i] = byte('a' + (i % 26))
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := verifier.Verify(payload, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestNewActionVerifier_InvalidPEM(t *testing.T) {
	if _, err := NewActionVerifier([]byte("not-a-pem")); err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestNewActionVerifier_InvalidCertificate(t *testing.T) {
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-a-certificate")})
	if _, err := NewActionVerifier(badPEM); err == nil {
		t.Fatal("expected error for invalid certificate DER")
	}
}
