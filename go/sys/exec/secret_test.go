package exec

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Secret must never let plaintext reach a log/format by accident: String(),
// %v, %s, and %#v all render the redaction sentinel; only Reveal() returns the
// bytes. The constructor rejects embedded newlines/CR (a credential piped to
// chpasswd/cryptsetup stdin must be a single line — a newline would split it
// into a second record).

func TestNewSecret_RejectsNewlineAndCR(t *testing.T) {
	for _, bad := range []string{"a\nb", "a\rb", "trailing\n", "\r", "x\r\ny"} {
		if _, err := NewSecret(bad); !errors.Is(err, ErrSecretContainsNewline) {
			t.Errorf("NewSecret(%q) err = %v, want ErrSecretContainsNewline", bad, err)
		}
	}
}

func TestNewSecret_EmptyIsValidAndZero(t *testing.T) {
	s, err := NewSecret("")
	if err != nil {
		t.Fatalf("NewSecret(\"\") err = %v, want nil", err)
	}
	if !s.IsZero() {
		t.Errorf("empty secret IsZero() = false, want true")
	}
}

func TestSecret_RedactsEverywhereButReveal(t *testing.T) {
	const plaintext = "hunter2-s3cr3t"
	s, err := NewSecret(plaintext)
	if err != nil {
		t.Fatalf("NewSecret err = %v", err)
	}
	if s.IsZero() {
		t.Errorf("non-empty secret IsZero() = true, want false")
	}
	if got := s.Reveal(); got != plaintext {
		t.Errorf("Reveal() = %q, want %q", got, plaintext)
	}
	// Format through an interface value — the realistic accidental-leak path
	// (loggers take ...any). This also keeps the %s case honest: a direct
	// fmt.Sprintf("%s", stringer) is a staticcheck S1025 smell, and routing via
	// `any` is exactly how a credential would actually reach a log.
	var logged any = s
	renders := map[string]string{
		"String()": s.String(),
		"%v":       fmt.Sprintf("%v", logged),
		"%s":       fmt.Sprintf("%s", logged),
		"%#v":      fmt.Sprintf("%#v", logged),
		"%+v":      fmt.Sprintf("%+v", logged),
	}
	for verb, out := range renders {
		if strings.Contains(out, plaintext) {
			t.Errorf("%s leaked the plaintext: %q", verb, out)
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Errorf("%s = %q, want it to contain [REDACTED]", verb, out)
		}
	}
}

// A Secret embedded in a larger struct must still redact when the OUTER value
// is formatted — the most common accidental-leak path (logging a config/options
// struct that happens to carry a credential).
func TestSecret_RedactsWhenNestedInStruct(t *testing.T) {
	const plaintext = "nested-passphrase"
	s, _ := NewSecret(plaintext)
	type creds struct {
		User string
		Pass Secret
	}
	out := fmt.Sprintf("%v", creds{User: "deploy", Pass: s})
	if strings.Contains(out, plaintext) {
		t.Fatalf("nested Secret leaked plaintext: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("nested Secret not redacted: %q", out)
	}
}
