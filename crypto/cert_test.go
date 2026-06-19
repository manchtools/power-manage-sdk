package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/manchtools/power-manage-sdk/cryptotest"
)

// TestCAFingerprintFromPEM pins that the fingerprint is the lowercase hex
// SHA-256 of the certificate DER — byte-identical to the server's
// ca.FingerprintFromPEM, so an operator-supplied pin (derived from the
// control CA, e.g. `openssl x509 -outform DER | sha256sum`) matches.
func TestCAFingerprintFromPEM(t *testing.T) {
	caPEM, _, caCert := cryptotest.GenCA(t, "fp-ca")
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
	oldPEM, oldKey, oldCert := cryptotest.GenCA(t, "old-ca")
	successorPEM := cryptotest.GenSubCA(t, "successor-ca", oldCert, oldKey)
	unrelatedPEM, _, _ := cryptotest.GenCA(t, "attacker-ca")

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
