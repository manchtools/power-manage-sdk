package luks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"unicode"
)

// Complexity represents password complexity requirements.
type Complexity int

const (
	ComplexityNone         Complexity = 0
	ComplexityAlphanumeric Complexity = 1 // letters + digits
	ComplexityComplex      Complexity = 2 // letters + digits + special chars
)

// ValidatePassphrase checks a passphrase against length and complexity requirements.
// Returns a human-readable error message if validation fails, or "" if valid.
func ValidatePassphrase(passphrase string, minLength int, complexity Complexity) string {
	if len(passphrase) < minLength {
		return fmt.Sprintf("Passphrase must be at least %d characters long.", minLength)
	}

	switch complexity {
	case ComplexityAlphanumeric:
		hasLetter := false
		hasDigit := false
		for _, r := range passphrase {
			if unicode.IsLetter(r) {
				hasLetter = true
			}
			if unicode.IsDigit(r) {
				hasDigit = true
			}
		}
		if !hasLetter || !hasDigit {
			return "Passphrase must contain both letters and digits."
		}

	case ComplexityComplex:
		hasLetter := false
		hasDigit := false
		hasSpecial := false
		for _, r := range passphrase {
			if unicode.IsLetter(r) {
				hasLetter = true
			} else if unicode.IsDigit(r) {
				hasDigit = true
			} else {
				hasSpecial = true
			}
		}
		if !hasLetter || !hasDigit || !hasSpecial {
			return "Passphrase must contain letters, digits, and special characters."
		}
	}

	return ""
}

// IsRecentlyUsed checks if the SHA-256 hash of a passphrase matches any in the
// provided list of recent hashes.
func IsRecentlyUsed(passphrase string, recentHashes []string) bool {
	hash := HashPassphrase(passphrase)
	for _, h := range recentHashes {
		if h == hash {
			return true
		}
	}
	return false
}

// HashPassphrase returns the SHA-256 hex hash of a passphrase.
func HashPassphrase(passphrase string) string {
	h := sha256.Sum256([]byte(passphrase))
	return hex.EncodeToString(h[:])
}
