package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// keyLen is the required symmetric key length: AES-256.
const keyLen = 32

var (
	// ErrInvalidKey is returned when the key is not exactly 32 bytes (AES-256).
	ErrInvalidKey = errors.New("crypto: key must be 32 bytes (AES-256)")

	// ErrAADRequired is returned when the AAD is empty. Domain-separation AAD is
	// MANDATORY: a naked AEAD call (nil/empty AAD) is refused by construction, so
	// two different ciphertext domains can never be confused or cross-decrypted,
	// and "forgot the AAD" is impossible to do silently.
	ErrAADRequired = errors.New("crypto: AAD is required (domain separation; no naked AEAD calls)")

	// ErrMalformedCiphertext is returned when a ciphertext is too short to carry
	// its prepended nonce.
	ErrMalformedCiphertext = errors.New("crypto: ciphertext too short")
)

// SealWithAAD encrypts plaintext with AES-256-GCM under key, binding aad as
// additional authenticated data, and returns nonce||ciphertext||tag.
//
// A fresh random 96-bit nonce is generated PER CALL and prepended to the output.
// The nonce is generated here, never taken from the caller, so nonce reuse under
// the same key (catastrophic for GCM) cannot be introduced by a caller mistake;
// a crypto/rand failure fails closed rather than emitting a predictable nonce.
//
// Both a 32-byte key and a NON-EMPTY aad are required: an empty aad is rejected
// (ErrAADRequired) so every ciphertext is domain-separated. The AEAD tag covers
// the plaintext AND the aad, so a wrong key, a wrong-domain aad, or any tamper
// fails authentication in OpenWithAAD.
func SealWithAAD(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(aad) == 0 {
		return nil, ErrAADRequired
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: generate nonce: %w", err)
	}
	// Seal appends the ciphertext+tag to its first argument, so passing nonce as
	// the destination yields nonce||ciphertext||tag.
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// OpenWithAAD reverses SealWithAAD: it splits the prepended nonce, then
// authenticates and decrypts under key with the SAME aad. Any authentication
// failure — a wrong key, a wrong-domain aad, or a tampered ciphertext — returns
// an error and NO plaintext. A 32-byte key and a non-empty aad are required.
func OpenWithAAD(key, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(aad) == 0 {
		return nil, ErrAADRequired
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, ErrMalformedCiphertext
	}
	nonce, ct := ciphertext[:ns], ciphertext[ns:]
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: open: %w", err)
	}
	return pt, nil
}

// newGCM builds an AES-256-GCM AEAD, rejecting a key that is not 32 bytes.
func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != keyLen {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}
	return gcm, nil
}
