package user

import (
	"errors"
	"testing"
)

// The GECOS / comment field lands in `useradd/usermod -c <comment>` and,
// ultimately, as a colon-delimited field in /etc/passwd. A ':' would split
// the passwd record into extra fields and a newline would forge a whole
// record, so ValidateComment must reject both (plus other control bytes).
// Ordinary descriptive text — spaces, commas (GECOS sub-field separator),
// unicode — must be accepted.
func TestValidateComment(t *testing.T) {
	for _, ok := range []string{
		"",
		"Alice Example",
		"Alice,Room 1,555-1234,555-5678", // GECOS sub-fields
		"Ünïcode Náme",
	} {
		if err := ValidateComment(ok); err != nil {
			t.Errorf("ValidateComment(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"root:x:0:0",   // colon — passwd field injection
		"name\nroot:x", // newline — passwd record injection
		"name\rx",      // CR
		"name\x00x",    // NUL
	} {
		if err := ValidateComment(bad); err == nil {
			t.Errorf("ValidateComment(%q) = nil, want ErrInvalidComment", bad)
		} else if !errors.Is(err, ErrInvalidComment) {
			t.Errorf("ValidateComment(%q) error = %v, want ErrInvalidComment", bad, err)
		}
	}
}
