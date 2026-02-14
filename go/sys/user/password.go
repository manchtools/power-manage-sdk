package user

import (
	"crypto/rand"
	"fmt"
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

	password := make([]byte, length)
	randomBytes := make([]byte, length)

	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	for i := 0; i < length; i++ {
		password[i] = charset[randomBytes[i]%byte(len(charset))]
	}

	return string(password), nil
}
