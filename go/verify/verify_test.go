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

// generateTestCA creates a self-signed CA certificate and private key for testing.
func generateTestCA(t *testing.T) (certPEM []byte, key *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
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

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM, key
}

// generateTestRSACA creates a self-signed RSA CA for testing.
func generateTestRSACA(t *testing.T) (certPEM []byte, key *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test RSA CA",
		},
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

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM, key
}

func TestSignVerifyRoundTrip_ECDSA(t *testing.T) {
	certPEM, caKey := generateTestCA(t)

	signer := NewActionSigner(caKey)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("NewActionVerifier: %v", err)
	}

	actionID := "01HWXYZ123456789ABCDEFGH"
	actionType := int32(1) // PACKAGE
	paramsJSON := []byte(`{"name":"nginx","desired_state":"PRESENT"}`)

	sig, err := signer.Sign(actionID, actionType, paramsJSON)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := verifier.Verify(actionID, actionType, paramsJSON, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestSignVerifyRoundTrip_RSA(t *testing.T) {
	certPEM, rsaKey := generateTestRSACA(t)

	signer := NewActionSigner(rsaKey)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("NewActionVerifier: %v", err)
	}

	actionID := "01HWXYZ123456789ABCDEFGH"
	actionType := int32(7) // SHELL
	paramsJSON := []byte(`{"script":"echo hello"}`)

	sig, err := signer.Sign(actionID, actionType, paramsJSON)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := verifier.Verify(actionID, actionType, paramsJSON, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerify_EmptySignature(t *testing.T) {
	certPEM, _ := generateTestCA(t)

	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("NewActionVerifier: %v", err)
	}

	err = verifier.Verify("action123", 1, []byte(`{}`), nil)
	if err == nil {
		t.Fatal("expected error for empty signature")
	}
}

func TestVerify_InvalidSignature(t *testing.T) {
	certPEM, _ := generateTestCA(t)

	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("NewActionVerifier: %v", err)
	}

	err = verifier.Verify("action123", 1, []byte(`{}`), []byte("not-a-signature"))
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestVerify_TamperedPayload(t *testing.T) {
	certPEM, caKey := generateTestCA(t)

	signer := NewActionSigner(caKey)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("NewActionVerifier: %v", err)
	}

	actionID := "01HWXYZ123456789ABCDEFGH"
	actionType := int32(1)
	paramsJSON := []byte(`{"name":"nginx"}`)

	sig, err := signer.Sign(actionID, actionType, paramsJSON)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Tamper with the action ID
	if err := verifier.Verify("01HWXYZ_TAMPERED_ID", actionType, paramsJSON, sig); err == nil {
		t.Fatal("expected error for tampered action ID")
	}

	// Tamper with the action type
	if err := verifier.Verify(actionID, int32(99), paramsJSON, sig); err == nil {
		t.Fatal("expected error for tampered action type")
	}

	// Tamper with the params
	if err := verifier.Verify(actionID, actionType, []byte(`{"name":"malware"}`), sig); err == nil {
		t.Fatal("expected error for tampered params")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	certPEM, _ := generateTestCA(t)
	_, differentKey := generateTestCA(t) // Generate a different CA

	signer := NewActionSigner(differentKey) // Sign with a different key
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("NewActionVerifier: %v", err)
	}

	sig, err := signer.Sign("action123", 1, []byte(`{}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify with the original CA — should fail
	if err := verifier.Verify("action123", 1, []byte(`{}`), sig); err == nil {
		t.Fatal("expected error when verifying with wrong CA")
	}
}

func TestNewActionVerifier_InvalidPEM(t *testing.T) {
	_, err := NewActionVerifier([]byte("not-a-pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestNewActionVerifier_InvalidCertificate(t *testing.T) {
	badPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not-a-certificate"),
	})

	_, err := NewActionVerifier(badPEM)
	if err == nil {
		t.Fatal("expected error for invalid certificate DER")
	}
}

func TestSignVerify_EmptyParams(t *testing.T) {
	certPEM, caKey := generateTestCA(t)

	signer := NewActionSigner(caKey)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("NewActionVerifier: %v", err)
	}

	sig, err := signer.Sign("action123", 0, []byte{})
	if err != nil {
		t.Fatalf("Sign with empty params: %v", err)
	}

	if err := verifier.Verify("action123", 0, []byte{}, sig); err != nil {
		t.Fatalf("Verify with empty params: %v", err)
	}
}

func TestSignVerify_LargePayload(t *testing.T) {
	certPEM, caKey := generateTestCA(t)

	signer := NewActionSigner(caKey)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("NewActionVerifier: %v", err)
	}

	// 1MB payload
	largeParams := make([]byte, 1<<20)
	for i := range largeParams {
		largeParams[i] = byte('a' + (i % 26))
	}

	sig, err := signer.Sign("action123", 1, largeParams)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := verifier.Verify("action123", 1, largeParams, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}
