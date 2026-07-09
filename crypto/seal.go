package crypto

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Asymmetric sealing: an ECIES-style construction for one-way secrets that a
// low-trust relay must not be able to read (LPS passwords crossing the
// gateway). The sender seals to the recipient's long-lived X25519 public key;
// only the holder of the matching private key can open.
//
// Construction, per seal:
//
//	eph            = fresh X25519 keypair (crypto/rand, fail-closed)
//	shared         = X25519(eph.priv, recipient.pub)
//	key            = HKDF-SHA256(secret=shared, salt=eph.pub||recipient.pub, info)  [32 bytes]
//	blob           = eph.pub(32) || SealWithAAD(key, plaintext, aad)
//
// Binding both public keys into the HKDF salt ties the derived key to this
// exact (ephemeral, recipient) pair, and the mandatory info string domain-
// separates every sealing surface — a blob sealed for one purpose can never
// open under another even if the same recipient key were reused. The AAD
// rides through the underlying AEAD unchanged, so tampering with either the
// context or any blob byte fails authentication.

const (
	// x25519KeyLen is the encoded length of an X25519 public key.
	x25519KeyLen = 32
	// aeadOverhead is the AEAD framing the sealed blob carries after the
	// ephemeral key: the prepended 96-bit GCM nonce plus the 16-byte tag.
	aeadOverhead = 12 + 16
	// sealedOverhead is the total non-plaintext size of a sealed blob.
	sealedOverhead = x25519KeyLen + aeadOverhead
	// MinSealedLen is the smallest possible valid sealed blob: the
	// construction overhead plus one plaintext byte. Boundary validators
	// (proto `min=` tags, the gateway's legacy-cleartext guard) use it to
	// reject anything that cannot possibly be a sealed blob — in particular
	// a legacy cleartext secret from a pre-sealed-transport agent.
	MinSealedLen = sealedOverhead + 1
)

// ErrInfoRequired is returned when the HKDF info string is empty. Like the
// AEAD's mandatory AAD, the domain-separation info is required by
// construction so two sealing surfaces can never derive the same key from the
// same recipient.
var ErrInfoRequired = errors.New("crypto: HKDF info is required (domain separation; no naked seal calls)")

// GenerateX25519 generates a recipient keypair for SealToPublicKey /
// OpenWithPrivateKey. The private key's Bytes() form is what a recipient
// persists (encrypted at rest); reconstruct with ecdh.X25519().NewPrivateKey.
func GenerateX25519() (*ecdh.PrivateKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate x25519 key: %w", err)
	}
	return priv, nil
}

// ParseX25519PublicKey parses the 32-byte encoding of an X25519 public key
// (the PublicKey().Bytes() form that crosses the wire).
func ParseX25519PublicKey(raw []byte) (*ecdh.PublicKey, error) {
	if len(raw) != x25519KeyLen {
		return nil, fmt.Errorf("crypto: x25519 public key must be %d bytes, got %d", x25519KeyLen, len(raw))
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse x25519 public key: %w", err)
	}
	return pub, nil
}

// SealToPublicKey encrypts plaintext so that only the holder of recipient's
// private key can read it, binding aad as authenticated context and info as
// the mandatory domain-separation string. Returns
// ephemeralPub(32) || nonce || ciphertext || tag.
//
// A fresh ephemeral keypair and a fresh AEAD nonce are generated per call
// from crypto/rand; an RNG failure fails closed. Both a non-empty aad and a
// non-empty info are required by construction.
func SealToPublicKey(recipient *ecdh.PublicKey, plaintext, aad []byte, info string) ([]byte, error) {
	if recipient == nil {
		return nil, errors.New("crypto: nil recipient public key")
	}
	if len(aad) == 0 {
		return nil, ErrAADRequired
	}
	if info == "" {
		return nil, ErrInfoRequired
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate ephemeral key: %w", err)
	}
	key, err := deriveSealKey(eph, recipient, info)
	if err != nil {
		return nil, err
	}
	sealed, err := SealWithAAD(key, plaintext, aad)
	if err != nil {
		return nil, err
	}
	return append(eph.PublicKey().Bytes(), sealed...), nil
}

// OpenWithPrivateKey reverses SealToPublicKey: it splits the ephemeral public
// key, re-derives the sealing key with the SAME info, and authenticates +
// decrypts under the SAME aad. Any mismatch — a tampered byte anywhere in the
// blob, a different aad, a different info, or the wrong private key — returns
// an error and no plaintext.
func OpenWithPrivateKey(priv *ecdh.PrivateKey, sealed, aad []byte, info string) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("crypto: nil private key")
	}
	if len(aad) == 0 {
		return nil, ErrAADRequired
	}
	if info == "" {
		return nil, ErrInfoRequired
	}
	// A valid blob carries the ephemeral key, the nonce, the tag, and at
	// least one plaintext byte; reject anything shorter up front with a
	// precise error rather than a generic authentication failure.
	if len(sealed) <= sealedOverhead {
		return nil, ErrMalformedCiphertext
	}
	ephPub, err := ecdh.X25519().NewPublicKey(sealed[:x25519KeyLen])
	if err != nil {
		return nil, fmt.Errorf("crypto: parse ephemeral public key: %w", err)
	}
	key, err := deriveOpenKey(priv, ephPub, info)
	if err != nil {
		return nil, err
	}
	return OpenWithAAD(key, sealed[x25519KeyLen:], aad)
}

// deriveSealKey derives the sender-side AEAD key: ECDH(eph.priv,
// recipient.pub) expanded through HKDF-SHA256 with both public keys as salt.
func deriveSealKey(eph *ecdh.PrivateKey, recipient *ecdh.PublicKey, info string) ([]byte, error) {
	shared, err := eph.ECDH(recipient)
	if err != nil {
		return nil, fmt.Errorf("crypto: ecdh: %w", err)
	}
	return expandKey(shared, eph.PublicKey().Bytes(), recipient.Bytes(), info)
}

// deriveOpenKey derives the recipient-side AEAD key: ECDH(recipient.priv,
// eph.pub) with the same salt ordering (ephemeral first) as deriveSealKey.
func deriveOpenKey(priv *ecdh.PrivateKey, ephPub *ecdh.PublicKey, info string) ([]byte, error) {
	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("crypto: ecdh: %w", err)
	}
	return expandKey(shared, ephPub.Bytes(), priv.PublicKey().Bytes(), info)
}

func expandKey(shared, ephPub, recipientPub []byte, info string) ([]byte, error) {
	salt := append(append(make([]byte, 0, 2*x25519KeyLen), ephPub...), recipientPub...)
	key, err := hkdf.Key(sha256.New, shared, salt, info, keyLen)
	if err != nil {
		return nil, fmt.Errorf("crypto: hkdf: %w", err)
	}
	return key, nil
}
