package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func key32(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpen_RoundTrip(t *testing.T) {
	key := key32(t)
	pt := []byte("super secret credential")
	aad := []byte("pm-agent:credentials:v1")
	ct, err := SealWithAAD(key, pt, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(ct, pt) {
		t.Fatal("ciphertext contains the plaintext verbatim")
	}
	got, err := OpenWithAAD(key, ct, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Errorf("round-trip = %q, want %q", got, pt)
	}
}

func TestSealOpen_EmptyPlaintextRoundTrips(t *testing.T) {
	key := key32(t)
	aad := []byte("domain")
	ct, err := SealWithAAD(key, nil, aad)
	if err != nil {
		t.Fatalf("Seal(nil): %v", err)
	}
	got, err := OpenWithAAD(key, ct, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty plaintext must round-trip to empty, got %q", got)
	}
}

func TestOpen_WrongAADFails(t *testing.T) {
	key := key32(t)
	ct, _ := SealWithAAD(key, []byte("x"), []byte("domain-A"))
	if _, err := OpenWithAAD(key, ct, []byte("domain-B")); err == nil {
		t.Fatal("Open with a DIFFERENT AAD must fail authentication (domain separation)")
	}
}

func TestOpen_WrongKeyFails(t *testing.T) {
	ct, _ := SealWithAAD(key32(t), []byte("x"), []byte("d"))
	if _, err := OpenWithAAD(key32(t), ct, []byte("d")); err == nil {
		t.Fatal("Open with a different key must fail")
	}
}

func TestOpen_TamperedCiphertextFails(t *testing.T) {
	key := key32(t)
	aad := []byte("d")
	ct, _ := SealWithAAD(key, []byte("hello world"), aad)
	ct[len(ct)-1] ^= 0xff // flip a tag byte
	if _, err := OpenWithAAD(key, ct, aad); err == nil {
		t.Fatal("a tampered ciphertext must fail authentication")
	}
}

func TestSealOpen_RejectsBadKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		k := make([]byte, n)
		if _, err := SealWithAAD(k, []byte("x"), []byte("d")); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Seal with a %d-byte key: err = %v, want ErrInvalidKey", n, err)
		}
		if _, err := OpenWithAAD(k, make([]byte, 64), []byte("d")); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Open with a %d-byte key: err = %v, want ErrInvalidKey", n, err)
		}
	}
}

// Domain-separation AAD is MANDATORY: a naked AEAD call (nil/empty AAD) must be
// refused by both Seal and Open, so the nil-AAD class is impossible to use.
func TestSealOpen_RejectsEmptyAAD(t *testing.T) {
	key := key32(t)
	for _, aad := range [][]byte{nil, {}} {
		if _, err := SealWithAAD(key, []byte("x"), aad); !errors.Is(err, ErrAADRequired) {
			t.Errorf("Seal with empty AAD: err = %v, want ErrAADRequired", err)
		}
		if _, err := OpenWithAAD(key, make([]byte, 64), aad); !errors.Is(err, ErrAADRequired) {
			t.Errorf("Open with empty AAD: err = %v, want ErrAADRequired", err)
		}
	}
}

func TestOpen_RejectsMalformedCiphertext(t *testing.T) {
	key := key32(t)
	aad := []byte("d")
	// A valid AES-256-GCM ciphertext is at least nonce(12) + tag(16) = 28 bytes.
	// Anything shorter cannot carry BOTH a nonce and a tag, so it is malformed and
	// must be rejected up front with the precise ErrMalformedCiphertext — not pass
	// the length check and fail later inside gcm.Open with a generic auth error.
	for _, n := range []int{0, 4, 12, 27} { // 12 = nonce-only, 27 = one short of nonce+tag
		if _, err := OpenWithAAD(key, make([]byte, n), aad); !errors.Is(err, ErrMalformedCiphertext) {
			t.Errorf("Open(%d-byte ciphertext): err = %v, want ErrMalformedCiphertext", n, err)
		}
	}
}

func TestSeal_NonceIsRandomPerCall(t *testing.T) {
	key := key32(t)
	pt := []byte("identical plaintext")
	aad := []byte("identical aad")
	a, _ := SealWithAAD(key, pt, aad)
	b, _ := SealWithAAD(key, pt, aad)
	if bytes.Equal(a, b) {
		t.Fatal("two seals of identical input produced identical output — the nonce is not random (catastrophic nonce reuse for GCM)")
	}
}
