package user

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

const (
	// MinPasswordLength is the minimum allowed generated-password length.
	MinPasswordLength = 8
	// MaxPasswordLength is the maximum allowed generated-password length.
	MaxPasswordLength = 128

	charsetAlphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	charsetSpecial      = "!@#$%^&*()_+-=[]{}|;:,.<>?"
)

// randInt is a seam over crypto/rand.Int so the (practically unreachable)
// RNG-failure error path is exercisable in tests.
var randInt = rand.Int

// Complexity selects the character set GeneratePassword draws from.
type Complexity int

const (
	// ComplexityAlphanumeric uses letters and digits only (the zero value).
	ComplexityAlphanumeric Complexity = iota
	// ComplexityComplex adds special characters.
	ComplexityComplex
)

// GeneratePassword returns a cryptographically secure random password as a
// Secret. length must be in [MinPasswordLength, MaxPasswordLength]. crypto/rand
// gives a uniform distribution (no modulo bias).
func GeneratePassword(length int, c Complexity) (exec.Secret, error) {
	if length < MinPasswordLength {
		return exec.Secret{}, fmt.Errorf("password length must be at least %d", MinPasswordLength)
	}
	if length > MaxPasswordLength {
		return exec.Secret{}, fmt.Errorf("password length must be at most %d", MaxPasswordLength)
	}

	charset := charsetAlphanumeric
	if c == ComplexityComplex {
		charset += charsetSpecial
	}
	charsetLen := big.NewInt(int64(len(charset)))
	buf := make([]byte, length)
	for i := range buf {
		idx, err := randInt(rand.Reader, charsetLen)
		if err != nil {
			return exec.Secret{}, fmt.Errorf("generate random index: %w", err)
		}
		buf[i] = charset[idx.Int64()]
	}
	// The charset contains no newline/CR, so NewSecret cannot reject this.
	return exec.NewSecret(string(buf))
}

// SetPassword sets a user's password via chpasswd. The Secret guarantees the
// password carries no newline/CR (NewSecret rejects them), so it cannot inject a
// second chpasswd "user:password" record, and the username is IsValidName-checked.
func (u *shadowUtils) SetPassword(ctx context.Context, name string, password exec.Secret) error {
	if err := validateUsername(name); err != nil {
		return err
	}
	// Reveal() here is the single sanctioned chpasswd sink (see the Secret
	// redaction contract / the Reveal fitness function).
	stdin := strings.NewReader(name + ":" + password.Reveal())
	res, err := u.exec(ctx, exec.Command{Name: "chpasswd", Stdin: stdin, Escalate: true})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return &exec.CommandError{Name: "chpasswd", ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return nil
}

// ExpirePassword forces a password change on next login (chage -d 0).
func (u *shadowUtils) ExpirePassword(ctx context.Context, name string) error {
	if err := validateUsername(name); err != nil {
		return err
	}
	return u.run(ctx, "chage", "-d", "0", name)
}
