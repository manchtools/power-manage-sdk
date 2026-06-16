package exec

import (
	"errors"
	"strings"
)

// ErrSecretContainsNewline is returned by NewSecret when the value contains a
// newline or carriage return. A credential is frequently piped to a tool's
// stdin (chpasswd, cryptsetup); an embedded newline would split it into a
// second record, so it is rejected at construction.
var ErrSecretContainsNewline = errors.New("secret contains a newline or carriage return")

// Secret wraps a sensitive string (password, LUKS key, wifi PSK / client key)
// so it cannot reach a log or formatted string by accident: String, GoString,
// and the %v/%s/%#v verbs all render "[REDACTED]". The plaintext is retrievable
// ONLY via Reveal — the single sanctioned sink. A fitness function (see
// sdk/docs/sdk-rework-design.md §6) fails the build if Reveal is called outside
// the known credential sinks, so the redaction can't be quietly defeated.
type Secret struct {
	v string
}

// NewSecret constructs a Secret, rejecting embedded newlines/CR (see
// ErrSecretContainsNewline). An empty secret is valid — some callers legitimately
// clear or omit a key.
func NewSecret(v string) (Secret, error) {
	if strings.ContainsAny(v, "\n\r") {
		return Secret{}, ErrSecretContainsNewline
	}
	return Secret{v: v}, nil
}

// String renders the redaction sentinel so a Secret in a log/format never leaks.
func (s Secret) String() string { return "[REDACTED]" }

// GoString renders the redaction sentinel for the %#v verb as well.
func (s Secret) GoString() string { return "[REDACTED]" }

// Reveal returns the underlying plaintext. This is the ONLY sanctioned sink;
// every other access path redacts.
func (s Secret) Reveal() string { return s.v }

// IsZero reports whether the secret is empty.
func (s Secret) IsZero() bool { return s.v == "" }
