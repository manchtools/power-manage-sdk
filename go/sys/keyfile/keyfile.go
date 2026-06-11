// Package keyfile builds glib-style INI / keyfile content — the format
// used by NetworkManager system-connections, systemd units, and
// freedesktop .desktop entries — with fail-closed validation of every
// section name, key, and value.
//
// Why this exists: the format is line-oriented. A value is everything
// after `key=` up to the newline, and a `[name]` on its own line opens a
// section. A value (or key, or section name) that contains a newline,
// carriage return, or NUL can therefore inject additional keys or whole
// sections into a file that a privileged daemon later parses as root —
// exactly the class of bug where a wifi SSID or PSK carrying
// "\n[connection]\npermissions=user:root:" reshapes a profile the
// operator never authored.
//
// Builder refuses such input rather than silently stripping it, so a
// malformed field surfaces as an error at the boundary instead of a
// structurally-corrupted file on disk. Callers that interpolate external
// input into a keyfile should build it through Builder (or at minimum run
// each value through ValidateValue) rather than hand-rolling fmt.Fprintf.
package keyfile

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnsafeValue is returned when a section name, key, or value contains a
// character that would break the line-oriented keyfile grammar.
var ErrUnsafeValue = errors.New("unsafe keyfile content")

// lineBreakingBytes are the bytes that let a single field break out of its
// `key=value` line: newline and carriage return open a new line (and thus
// a new key or `[section]`), and NUL truncates the field in glib's C-string
// parser. This is the same set sys/remote uses to guard URLs.
const lineBreakingBytes = "\n\r\x00"

// ValidateValue returns ErrUnsafeValue when v cannot appear as a scalar
// keyfile value without altering the file's structure. It is the
// fail-closed boundary every caller interpolating external input into a
// keyfile value must pass through. Ordinary content — spaces, `=`, `#`,
// `;`, brackets, unicode — is accepted, because none of those break a
// value line (they matter only in the key/section position or for
// list-typed keys), and rejecting them would refuse legitimate WPA
// passphrases and SSIDs.
func ValidateValue(v string) error {
	if i := strings.IndexAny(v, lineBreakingBytes); i >= 0 {
		return fmt.Errorf("%w: value contains %q at offset %d", ErrUnsafeValue, v[i], i)
	}
	return nil
}

// ValidateKey applies the value ban plus the key-specific ones: a key must
// be non-empty, must not contain `=` (which would split it into a
// different key/value), and must not begin with `[` (which would read as a
// section header).
func ValidateKey(k string) error {
	if k == "" {
		return fmt.Errorf("%w: empty key", ErrUnsafeValue)
	}
	if err := ValidateValue(k); err != nil {
		return err
	}
	if strings.ContainsRune(k, '=') {
		return fmt.Errorf("%w: key %q contains '='", ErrUnsafeValue, k)
	}
	if strings.HasPrefix(k, "[") {
		return fmt.Errorf("%w: key %q begins with '['", ErrUnsafeValue, k)
	}
	return nil
}

// ValidateSection applies the value ban plus a bracket ban: a section name
// must be non-empty and must not contain `[` or `]`, either of which would
// reshape the `[name]` header line.
func ValidateSection(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty section name", ErrUnsafeValue)
	}
	if err := ValidateValue(name); err != nil {
		return err
	}
	if strings.ContainsAny(name, "[]") {
		return fmt.Errorf("%w: section name %q contains '[' or ']'", ErrUnsafeValue, name)
	}
	return nil
}

// Builder accumulates sections and key/value pairs and renders a keyfile
// body, validating every section, key, and value as it is added. The
// zero value is ready to use.
//
// Errors are sticky: the first failed Comment/Section/Set records the
// error and every later add is a no-op, so a caller can append fluently
// and check exactly once via Bytes. This guarantees Bytes never returns a
// partially-rendered file that contains an injected line.
type Builder struct {
	b            strings.Builder
	err          error
	sectionCount int
}

// Comment writes a `# text` comment line. The comment text is validated
// like a value (no line-breaking bytes) so it cannot itself inject keys.
func (k *Builder) Comment(text string) *Builder {
	if k.err != nil {
		return k
	}
	if err := ValidateValue(text); err != nil {
		k.err = err
		return k
	}
	fmt.Fprintf(&k.b, "# %s\n", text)
	return k
}

// Section opens a new `[name]` section. A blank line is emitted before
// every section after the first so a value can never visually run into the
// following header.
func (k *Builder) Section(name string) *Builder {
	if k.err != nil {
		return k
	}
	if err := ValidateSection(name); err != nil {
		k.err = err
		return k
	}
	if k.sectionCount > 0 {
		k.b.WriteByte('\n')
	}
	fmt.Fprintf(&k.b, "[%s]\n", name)
	k.sectionCount++
	return k
}

// Set writes a `key=value` line, validating both halves.
func (k *Builder) Set(key, value string) *Builder {
	if k.err != nil {
		return k
	}
	if err := ValidateKey(key); err != nil {
		k.err = err
		return k
	}
	if err := ValidateValue(value); err != nil {
		k.err = err
		return k
	}
	fmt.Fprintf(&k.b, "%s=%s\n", key, value)
	return k
}

// Bytes returns the rendered keyfile body, or the first validation error
// encountered. On error it returns a nil body so a caller can never write
// a partially-rendered (and possibly injected) file.
func (k *Builder) Bytes() ([]byte, error) {
	if k.err != nil {
		return nil, k.err
	}
	return []byte(k.b.String()), nil
}

// Err returns the first validation error recorded so far, or nil.
func (k *Builder) Err() error {
	return k.err
}
