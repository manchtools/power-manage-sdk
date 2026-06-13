package encryption

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
)

// ErrInvalidDevicePath is returned when a device path passed to a LUKS /
// TPM operation is not an absolute, canonical path under /dev/.
var ErrInvalidDevicePath = errors.New("invalid device path")

// validateDevicePath guards the devicePath argument before it reaches
// cryptsetup / systemd-cryptenroll argv. Those run as root, so a
// flag-shaped value (e.g. "--header=/tmp/evil", "--master-key-file") would
// be parsed as an option and redirect the privileged operation, and a
// path-escape ("/dev/../etc/x") would point it elsewhere. Requiring an
// absolute, canonical path under /dev/ closes both: a "/dev/"-prefixed
// value can never begin with '-', and a canonical path has no `.`/`..`
// segments. The check is lexical only — symlink resolution (e.g. of
// /dev/disk/by-uuid/...) is left to cryptsetup, which the operation needs
// anyway.
func validateDevicePath(devicePath string) error {
	if devicePath == "" {
		return fmt.Errorf("%w: device path is empty", ErrInvalidDevicePath)
	}
	if strings.ContainsAny(devicePath, "\x00\n\r") {
		return fmt.Errorf("%w: device path contains control characters", ErrInvalidDevicePath)
	}
	if filepath.Clean(devicePath) != devicePath {
		return fmt.Errorf("%w: device path %q is not canonical", ErrInvalidDevicePath, devicePath)
	}
	if !strings.HasPrefix(devicePath, "/dev/") || devicePath == "/dev/" {
		return fmt.Errorf("%w: device path %q must name a device under /dev/", ErrInvalidDevicePath, devicePath)
	}
	return nil
}

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

// HashPassphrase returns the SHA-512 hex hash of a passphrase.
// Used only for local passphrase reuse detection, not for authentication.
func HashPassphrase(passphrase string) string {
	h := sha512.Sum512([]byte(passphrase))
	return hex.EncodeToString(h[:])
}
