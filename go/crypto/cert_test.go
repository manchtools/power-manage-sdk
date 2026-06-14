package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// genCA creates a self-signed CA cert (PEM) + its key.
func genCA(t *testing.T, cn string) ([]byte, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key, cert
}

// genSubCA creates a CA cert (PEM) signed BY parent — a cross-signed /
// successor CA, the legitimate-rotation continuity case.
func genSubCA(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("subca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create subca: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestCAFingerprintFromPEM pins that the fingerprint is the lowercase hex
// SHA-256 of the certificate DER — byte-identical to the server's
// ca.FingerprintFromPEM, so an operator-supplied pin (derived from the
// control CA, e.g. `openssl x509 -outform DER | sha256sum`) matches.
func TestCAFingerprintFromPEM(t *testing.T) {
	caPEM, _, caCert := genCA(t, "fp-ca")
	want := hex.EncodeToString(func() []byte { s := sha256.Sum256(caCert.Raw); return s[:] }())

	got, err := CAFingerprintFromPEM(caPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("fingerprint = %q, want %q", got, want)
	}
	if len(got) != 64 {
		t.Errorf("fingerprint length = %d, want 64", len(got))
	}
	for _, c := range got {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("fingerprint %q is not lowercase hex", got)
		}
	}

	// ABSENT / malformed inputs fail.
	if _, err := CAFingerprintFromPEM(nil); err == nil {
		t.Error("empty PEM accepted; want error")
	}
	if _, err := CAFingerprintFromPEM([]byte("not a pem")); err == nil {
		t.Error("non-PEM accepted; want error")
	}
}

// TestVerifyCAContinuity pins the rotation guard: a returned CA is only
// adopted if it is byte-identical to, or cross-signed by, the enrolled
// CA. An unrelated CA (the trust-anchor-swap attack) is refused.
func TestVerifyCAContinuity(t *testing.T) {
	oldPEM, oldKey, oldCert := genCA(t, "old-ca")
	successorPEM := genSubCA(t, "successor-ca", oldCert, oldKey)
	unrelatedPEM, _, _ := genCA(t, "attacker-ca")

	t.Run("byte-identical accepted", func(t *testing.T) {
		if err := VerifyCAContinuity(oldPEM, oldPEM); err != nil {
			t.Errorf("identical CA rejected: %v", err)
		}
	})
	t.Run("cross-signed successor accepted", func(t *testing.T) {
		if err := VerifyCAContinuity(oldPEM, successorPEM); err != nil {
			t.Errorf("cross-signed successor CA rejected: %v", err)
		}
	})
	t.Run("unrelated CA refused", func(t *testing.T) {
		if err := VerifyCAContinuity(oldPEM, unrelatedPEM); err == nil {
			t.Error("unrelated CA accepted; want refusal (trust-anchor swap)")
		}
	})
	t.Run("empty new CA refused", func(t *testing.T) {
		if err := VerifyCAContinuity(oldPEM, nil); err == nil {
			t.Error("empty new CA accepted; want error")
		}
	})
	t.Run("malformed PEM refused", func(t *testing.T) {
		if err := VerifyCAContinuity(oldPEM, []byte("garbage")); err == nil {
			t.Error("malformed new CA accepted; want error")
		}
		if err := VerifyCAContinuity([]byte("garbage"), oldPEM); err == nil {
			t.Error("malformed old CA accepted; want error")
		}
	})
}
