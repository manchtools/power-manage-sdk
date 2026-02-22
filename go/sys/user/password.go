package user

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const (
	// MinPasswordLength is the minimum allowed password length.
	MinPasswordLength = 8
	// MaxPasswordLength is the maximum allowed password length.
	MaxPasswordLength = 128

	charsetAlphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	charsetSpecial      = "!@#$%^&*()_+-=[]{}|;:,.<>?"
)

// GeneratePassword creates a cryptographically secure random password.
// If complex is true, the password includes special characters.
// Length must be between MinPasswordLength and MaxPasswordLength.
// Uses crypto/rand.Int for uniform distribution (no modulo bias).
func GeneratePassword(length int, complex bool) (string, error) {
	if length < MinPasswordLength {
		return "", fmt.Errorf("password length must be at least %d", MinPasswordLength)
	}
	if length > MaxPasswordLength {
		return "", fmt.Errorf("password length must be at most %d", MaxPasswordLength)
	}

	charset := charsetAlphanumeric
	if complex {
		charset += charsetSpecial
	}

	charsetLen := big.NewInt(int64(len(charset)))
	password := make([]byte, length)

	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("failed to generate random index: %w", err)
		}
		password[i] = charset[idx.Int64()]
	}

	return string(password), nil
}
