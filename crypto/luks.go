package crypto

import (
	"crypto/ecdh"
	"errors"
)

// ErrLuksContextIncomplete is returned when the device or action context
// field is empty. Both are required so the AAD unambiguously binds the sealed
// passphrase to exactly one (device, action) record; a partial join would
// bind loosely and is refused.
var ErrLuksContextIncomplete = errors.New("crypto: LUKS seal context requires non-empty device and action")

// ErrEmptySecret is returned when the plaintext to seal is empty. An empty
// secret would seal to a blob one byte below MinSealedLen and be rejected by
// the downstream boundary validators with a confusing wire error — failing
// fast here names the real cause. Shared by the LPS and LUKS seal helpers.
var ErrEmptySecret = errors.New("crypto: secret to seal must be non-empty")

// LUKS passphrase sealing (spec 25): the agent seals each managed LUKS
// passphrase to the control server's X25519 public key — the SAME control
// keypair LPS sealing uses — so the relaying gateway can never read a
// device's disk-encryption secret. As with LPS, this is the ONE place the
// domain-separation info and the context AAD are constructed: the agent
// (SealLuksPassphrase) and the control server (OpenLuksPassphrase) both call
// through here, so the two sides cannot drift. The info string differs from
// LPS's, so a blob sealed under one domain never opens under the other even
// with an identical AAD (see TestLuksLpsDomainSeparation).

// luksSealInfo is the HKDF domain-separation string for LUKS passphrase
// sealing. Versioned so a future construction change can coexist during
// rollout.
const luksSealInfo = "power-manage-luks-passphrase:v1"

// luksSealAAD binds a sealed LUKS passphrase to its (device, action) context
// so a valid blob cannot be relocated to another device/action record.
// deviceID and actionID are ULIDs (Crockford base32 — never contain '|'), so
// the join is unambiguous. The literal "luks" third component mirrors the
// server's at-rest SecretAAD(device, action, "luks") construction. The
// device_path is deliberately NOT part of the AAD (spec 25 pins the AAD to
// the at-rest shape); two volumes under one (device, action) share a seal
// context.
func luksSealAAD(deviceID, actionID string) []byte {
	return []byte(deviceID + "|" + actionID + "|luks")
}

// SealLuksPassphrase seals passphrase to the control server's public key,
// binding the (deviceID, actionID) context. The output is the opaque blob
// the agent puts on the wire; only the holder of the matching private key
// (control) can open it.
func SealLuksPassphrase(recipient *ecdh.PublicKey, passphrase, deviceID, actionID string) ([]byte, error) {
	if passphrase == "" {
		return nil, ErrEmptySecret
	}
	if deviceID == "" || actionID == "" {
		return nil, ErrLuksContextIncomplete
	}
	return SealToPublicKey(recipient, []byte(passphrase), luksSealAAD(deviceID, actionID), luksSealInfo)
}

// OpenLuksPassphrase reverses SealLuksPassphrase on the control server: it
// unseals with the control private key under the SAME (deviceID, actionID)
// context. A blob sealed for a different context, tampered, sealed to a
// different key, or sealed under the LPS domain fails authentication and
// returns an error and no plaintext.
func OpenLuksPassphrase(priv *ecdh.PrivateKey, sealed []byte, deviceID, actionID string) (string, error) {
	if deviceID == "" || actionID == "" {
		return "", ErrLuksContextIncomplete
	}
	pt, err := OpenWithPrivateKey(priv, sealed, luksSealAAD(deviceID, actionID), luksSealInfo)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
