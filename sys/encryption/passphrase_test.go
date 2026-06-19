package encryption

import (
	"io"
	"math/big"
	"strings"
	"testing"
)

func TestGeneratePassphrase(t *testing.T) {
	s, err := GeneratePassphrase(3)
	if err != nil {
		t.Fatal(err)
	}
	phrase := s.Reveal()
	if len(phrase) < 32 {
		t.Errorf("passphrase %q is %d chars, want >= 32", phrase, len(phrase))
	}
	if got := strings.Count(phrase, "-") + 1; got < 3 {
		t.Errorf("passphrase %q has %d words, want >= 3", phrase, got)
	}
	if strings.ContainsAny(phrase, "\n\r") {
		t.Error("passphrase contains a newline/CR")
	}
	// It is a Secret: redacts in logs.
	if s.String() != "[REDACTED]" || strings.Contains(s.String(), phrase) {
		t.Errorf("passphrase Secret not redacted: %q", s.String())
	}
}

func TestGeneratePassphrase_ClampsMinWordsToThree(t *testing.T) {
	// Asking for 1 word still yields at least 3 (and >= 32 chars).
	s, err := GeneratePassphrase(1)
	if err != nil {
		t.Fatal(err)
	}
	if words := strings.Count(s.Reveal(), "-") + 1; words < 3 {
		t.Errorf("words = %d, want the floor of 3", words)
	}
}

func TestGeneratePassphrase_RNGFailure(t *testing.T) {
	restore := randInt
	randInt = func(io.Reader, *big.Int) (*big.Int, error) { return nil, io.ErrUnexpectedEOF }
	defer func() { randInt = restore }()

	if _, err := GeneratePassphrase(3); err == nil {
		t.Error("GeneratePassphrase returned nil error when the RNG failed")
	}
}
