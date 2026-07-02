package crypto

import (
	"crypto/ecdh"
	"errors"
)

// ErrLpsContextIncomplete is returned when any of the (device, action,
// username) context fields is empty. All three are required so the AAD
// unambiguously binds the sealed password to exactly one record; a
// non-empty-but-partial join (e.g. "device|action|") would bind loosely and
// is refused.
var ErrLpsContextIncomplete = errors.New("crypto: LPS seal context requires non-empty device, action, and username")

// LPS password sealing: the agent seals each rotated local password to the
// control server's X25519 public key so the relaying gateway (the least-
// trusted server-side actor) can never read it. This is the ONE place the
// domain-separation info and the context AAD are constructed — the agent
// (SealLpsPassword) and the control server (OpenLpsPassword) both call
// through here, so the two sides cannot drift on either value. Drift would
// not be caught by any single-repo test (the seal happens on the agent, the
// open on the server) and would silently break every unseal, so it is
// deliberately impossible to construct them separately.

// lpsSealInfo is the HKDF domain-separation string for LPS password sealing.
// Versioned so a future construction change can coexist during rollout.
const lpsSealInfo = "power-manage-lps-password:v1"

// lpsSealAAD binds a sealed LPS password to its (device, action, username)
// context so a valid blob cannot be relocated to another device/action/user
// record. deviceID and actionID are ULIDs (Crockford base32 — never contain
// '|') and username is a validated local username, so the join is
// unambiguous. This mirrors SecretAAD's construction on the server's at-rest
// path.
func lpsSealAAD(deviceID, actionID, username string) []byte {
	return []byte(deviceID + "|" + actionID + "|" + username)
}

// SealLpsPassword seals password to the control server's LPS public key,
// binding the (deviceID, actionID, username) context. The output is the
// opaque blob the agent puts on the wire; only the holder of the matching
// private key (control) can open it. All three context fields are required —
// an empty one makes the AAD ambiguous and is refused by the underlying AEAD.
func SealLpsPassword(recipient *ecdh.PublicKey, password, deviceID, actionID, username string) ([]byte, error) {
	if deviceID == "" || actionID == "" || username == "" {
		return nil, ErrLpsContextIncomplete
	}
	return SealToPublicKey(recipient, []byte(password), lpsSealAAD(deviceID, actionID, username), lpsSealInfo)
}

// OpenLpsPassword reverses SealLpsPassword on the control server: it unseals
// with the LPS private key under the SAME (deviceID, actionID, username)
// context. A blob sealed for a different context, tampered, or sealed to a
// different key fails authentication and returns an error and no plaintext.
func OpenLpsPassword(priv *ecdh.PrivateKey, sealed []byte, deviceID, actionID, username string) (string, error) {
	if deviceID == "" || actionID == "" || username == "" {
		return "", ErrLpsContextIncomplete
	}
	pt, err := OpenWithPrivateKey(priv, sealed, lpsSealAAD(deviceID, actionID, username), lpsSealInfo)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
