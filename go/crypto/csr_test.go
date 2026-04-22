package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestGenerateCSR(t *testing.T) {
	csrPEM, keyPEM, err := GenerateCSR("test-host.example.com")
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}

	// Verify CSR PEM is valid
	csrBlock, _ := pem.Decode(csrPEM)
	if csrBlock == nil {
		t.Fatal("CSR PEM decode returned nil")
	}
	if csrBlock.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("CSR PEM type = %q, want CERTIFICATE REQUEST", csrBlock.Type)
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}

	if csr.Subject.CommonName != "test-host.example.com" {
		t.Fatalf("CSR CN = %q, want test-host.example.com", csr.Subject.CommonName)
	}

	// The CSR MUST NOT carry any SANs — the Control Server's CA
	// refuses to sign CSRs that include DNSNames, IPAddresses,
	// EmailAddresses, or URIs. Agent certs are client certs
	// identified by the device ID the CA writes into the issued
	// cert, not by anything the agent self-asserts in the CSR.
	// See internal/ca/ca.go on the server side.
	if len(csr.DNSNames) != 0 {
		t.Fatalf("CSR DNSNames = %v, want empty (server rejects CSRs with SANs)", csr.DNSNames)
	}
	if len(csr.IPAddresses) != 0 {
		t.Fatalf("CSR IPAddresses = %v, want empty", csr.IPAddresses)
	}
	if len(csr.EmailAddresses) != 0 {
		t.Fatalf("CSR EmailAddresses = %v, want empty", csr.EmailAddresses)
	}
	if len(csr.URIs) != 0 {
		t.Fatalf("CSR URIs = %v, want empty", csr.URIs)
	}

	// Verify signature on CSR
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature check failed: %v", err)
	}

	// Verify key PEM is valid ECDSA P-256
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("key PEM decode returned nil")
	}
	if keyBlock.Type != "EC PRIVATE KEY" {
		t.Fatalf("key PEM type = %q, want EC PRIVATE KEY", keyBlock.Type)
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("ParseECPrivateKey: %v", err)
	}

	if key.Curve != elliptic.P256() {
		t.Fatalf("key curve = %v, want P-256", key.Curve.Params().Name)
	}
}

func TestGenerateCSR_DifferentHostnames(t *testing.T) {
	hostnames := []string{
		"simple",
		"host.example.com",
		"host-with-dashes.test.internal",
		"192.168.1.1",
	}

	for _, hostname := range hostnames {
		t.Run(hostname, func(t *testing.T) {
			csrPEM, _, err := GenerateCSR(hostname)
			if err != nil {
				t.Fatalf("GenerateCSR(%q): %v", hostname, err)
			}

			block, _ := pem.Decode(csrPEM)
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Fatalf("ParseCertificateRequest: %v", err)
			}

			if csr.Subject.CommonName != hostname {
				t.Fatalf("CN = %q, want %q", csr.Subject.CommonName, hostname)
			}
		})
	}
}

func TestGenerateCSR_UniqueKeys(t *testing.T) {
	_, keyPEM1, err := GenerateCSR("host1")
	if err != nil {
		t.Fatalf("first GenerateCSR: %v", err)
	}

	_, keyPEM2, err := GenerateCSR("host2")
	if err != nil {
		t.Fatalf("second GenerateCSR: %v", err)
	}

	if string(keyPEM1) == string(keyPEM2) {
		t.Fatal("two GenerateCSR calls produced identical keys")
	}
}

func TestGenerateCSRFromKey(t *testing.T) {
	// Generate a key first
	_, keyPEM, err := GenerateCSR("original-host")
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}

	// Generate CSR from existing key with different hostname (renewal scenario)
	csrPEM, err := GenerateCSRFromKey("renewed-host", keyPEM)
	if err != nil {
		t.Fatalf("GenerateCSRFromKey: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}

	if csr.Subject.CommonName != "renewed-host" {
		t.Fatalf("CN = %q, want renewed-host", csr.Subject.CommonName)
	}

	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature check failed: %v", err)
	}
}

func TestGenerateCSRFromKey_InvalidPEM(t *testing.T) {
	_, err := GenerateCSRFromKey("host", []byte("not-a-pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestGenerateCSRFromKey_InvalidKey(t *testing.T) {
	badPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: []byte("not-a-key"),
	})

	_, err := GenerateCSRFromKey("host", badPEM)
	if err == nil {
		t.Fatal("expected error for invalid key DER")
	}
}

func TestGenerateCSRFromKey_SameKeyProducesDifferentCSR(t *testing.T) {
	// The CSR itself might differ due to nonces in the signature,
	// but the public key embedded in both CSRs should be identical.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	csrPEM1, err := GenerateCSRFromKey("host-a", keyPEM)
	if err != nil {
		t.Fatalf("first CSR: %v", err)
	}

	csrPEM2, err := GenerateCSRFromKey("host-b", keyPEM)
	if err != nil {
		t.Fatalf("second CSR: %v", err)
	}

	// Parse both and verify they use the same public key
	block1, _ := pem.Decode(csrPEM1)
	csr1, _ := x509.ParseCertificateRequest(block1.Bytes)

	block2, _ := pem.Decode(csrPEM2)
	csr2, _ := x509.ParseCertificateRequest(block2.Bytes)

	pub1 := csr1.PublicKey.(*ecdsa.PublicKey)
	pub2 := csr2.PublicKey.(*ecdsa.PublicKey)

	if pub1.X.Cmp(pub2.X) != 0 || pub1.Y.Cmp(pub2.Y) != 0 {
		t.Fatal("CSRs from same key have different public keys")
	}

	// But hostnames should differ
	if csr1.Subject.CommonName == csr2.Subject.CommonName {
		t.Fatal("CSRs should have different CNs")
	}
}
