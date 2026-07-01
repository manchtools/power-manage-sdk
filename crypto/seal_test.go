package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"
)

func genRecipient(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	priv, err := GenerateX25519()
	if err != nil {
		t.Fatalf("GenerateX25519: %v", err)
	}
	return priv
}

const testInfo = "power-manage-test-seal:v1"

// Criterion 1: seal → open round-trips the exact plaintext, and the sealed
// layout starts with the 32-byte ephemeral public key.
func TestSealToPublicKey_RoundTrip(t *testing.T) {
	priv := genRecipient(t)
	plaintext := []byte("s3cret-rotated-password")
	aad := []byte("device|action|user")

	sealed, err := SealToPublicKey(priv.PublicKey(), plaintext, aad, testInfo)
	if err != nil {
		t.Fatalf("SealToPublicKey: %v", err)
	}
	if len(sealed) < sealedOverhead+1 {
		t.Fatalf("sealed blob too short: %d bytes, want >= %d", len(sealed), sealedOverhead+1)
	}

	got, err := OpenWithPrivateKey(priv, sealed, aad, testInfo)
	if err != nil {
		t.Fatalf("OpenWithPrivateKey: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

// Criterion 2: any tampered byte, wrong AAD, wrong info, or wrong private key
// must fail authentication and return no plaintext.
func TestOpenWithPrivateKey_RejectsTamperAndContextMismatch(t *testing.T) {
	priv := genRecipient(t)
	plaintext := []byte("s3cret")
	aad := []byte("device|action|user")
	sealed, err := SealToPublicKey(priv.PublicKey(), plaintext, aad, testInfo)
	if err != nil {
		t.Fatalf("SealToPublicKey: %v", err)
	}

	// Flip one byte in every region of the blob: ephemeral key, nonce,
	// ciphertext, tag (the last byte).
	for _, idx := range []int{0, 33, sealedOverhead, len(sealed) - 1} {
		mut := bytes.Clone(sealed)
		mut[idx] ^= 0x01
		if pt, err := OpenWithPrivateKey(priv, mut, aad, testInfo); err == nil {
			t.Errorf("tamper at byte %d: open succeeded, returned %q", idx, pt)
		}
	}

	if _, err := OpenWithPrivateKey(priv, sealed, []byte("device|action|OTHER"), testInfo); err == nil {
		t.Error("wrong AAD accepted")
	}
	if _, err := OpenWithPrivateKey(priv, sealed, aad, "power-manage-other:v1"); err == nil {
		t.Error("wrong info accepted")
	}
	other := genRecipient(t)
	if _, err := OpenWithPrivateKey(other, sealed, aad, testInfo); err == nil {
		t.Error("wrong private key accepted")
	}
}

// Criterion 3: empty AAD and empty info are refused by construction on both
// seal and open — no naked calls.
func TestSealOpen_RequireAADAndInfo(t *testing.T) {
	priv := genRecipient(t)
	pt := []byte("x")
	aad := []byte("a")

	if _, err := SealToPublicKey(priv.PublicKey(), pt, nil, testInfo); !errors.Is(err, ErrAADRequired) {
		t.Errorf("seal with empty aad: err = %v, want ErrAADRequired", err)
	}
	if _, err := SealToPublicKey(priv.PublicKey(), pt, aad, ""); !errors.Is(err, ErrInfoRequired) {
		t.Errorf("seal with empty info: err = %v, want ErrInfoRequired", err)
	}

	sealed, err := SealToPublicKey(priv.PublicKey(), pt, aad, testInfo)
	if err != nil {
		t.Fatalf("SealToPublicKey: %v", err)
	}
	if _, err := OpenWithPrivateKey(priv, sealed, nil, testInfo); !errors.Is(err, ErrAADRequired) {
		t.Errorf("open with empty aad: err = %v, want ErrAADRequired", err)
	}
	if _, err := OpenWithPrivateKey(priv, sealed, aad, ""); !errors.Is(err, ErrInfoRequired) {
		t.Errorf("open with empty info: err = %v, want ErrInfoRequired", err)
	}
}

// Criterion 4: sealing the same plaintext twice to the same recipient must
// produce different blobs (fresh ephemeral key + fresh nonce per call).
func TestSealToPublicKey_OutputsDiffer(t *testing.T) {
	priv := genRecipient(t)
	pt := []byte("same-plaintext")
	aad := []byte("same-aad")

	a, err := SealToPublicKey(priv.PublicKey(), pt, aad, testInfo)
	if err != nil {
		t.Fatalf("seal a: %v", err)
	}
	b, err := SealToPublicKey(priv.PublicKey(), pt, aad, testInfo)
	if err != nil {
		t.Fatalf("seal b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("two seals of the same plaintext are byte-identical — ephemeral key or nonce is being reused")
	}
	if bytes.Equal(a[:x25519KeyLen], b[:x25519KeyLen]) {
		t.Error("ephemeral public keys are identical across seals")
	}
}

// Criterion 5: a blob shorter than the minimum sealed length is rejected with
// a malformed-input error, not a generic auth failure or a panic.
func TestOpenWithPrivateKey_RejectsMalformedShortBlob(t *testing.T) {
	priv := genRecipient(t)
	for _, n := range []int{0, 1, x25519KeyLen, sealedOverhead} {
		blob := make([]byte, n)
		if _, err := rand.Read(blob); err != nil {
			t.Fatalf("rand: %v", err)
		}
		if _, err := OpenWithPrivateKey(priv, blob, []byte("a"), testInfo); !errors.Is(err, ErrMalformedCiphertext) {
			t.Errorf("blob len %d: err = %v, want ErrMalformedCiphertext", n, err)
		}
	}
}

// ParseX25519PublicKey accepts exactly 32 bytes and round-trips the encoding.
func TestParseX25519PublicKey(t *testing.T) {
	priv := genRecipient(t)
	raw := priv.PublicKey().Bytes()

	pub, err := ParseX25519PublicKey(raw)
	if err != nil {
		t.Fatalf("ParseX25519PublicKey: %v", err)
	}
	if !bytes.Equal(pub.Bytes(), raw) {
		t.Error("parsed key does not round-trip its encoding")
	}

	for _, n := range []int{0, 31, 33} {
		if _, err := ParseX25519PublicKey(make([]byte, n)); err == nil {
			t.Errorf("ParseX25519PublicKey accepted %d bytes", n)
		}
	}
}
