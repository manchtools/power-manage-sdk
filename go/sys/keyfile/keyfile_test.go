package keyfile

import (
	"errors"
	"strings"
	"testing"
)

// The contract under test: a glib-style keyfile is line-oriented. A value
// is everything after `key=` up to the newline; `[name]` on its own line
// opens a section. So a newline, carriage return, or NUL in any section
// name, key, or value lets a single field inject additional keys or whole
// sections into a file a privileged daemon (NetworkManager, systemd) later
// parses as root. The builder must REFUSE such input (fail closed), never
// silently strip it.

func TestValidateValue_RejectsLineBreakingBytes(t *testing.T) {
	// Derived from the format's grammar, not from the implementation:
	// these are exactly the bytes that terminate or restructure a
	// `key=value` line. Each must be rejected wherever it appears in the
	// value (start, middle, end) so a check can't pass by only guarding
	// one position.
	for _, bad := range []string{
		"\n",
		"\r",
		"\x00",
		"value\ninjected=1",
		"value\r\n[evil]",
		"trailing\n",
		"\nleading",
		"mid\x00dle",
	} {
		if err := ValidateValue(bad); err == nil {
			t.Errorf("ValidateValue(%q) = nil, want ErrUnsafeValue", bad)
		} else if !errors.Is(err, ErrUnsafeValue) {
			t.Errorf("ValidateValue(%q) error = %v, want ErrUnsafeValue", bad, err)
		}
	}
}

func TestValidateValue_AcceptsOrdinaryValues(t *testing.T) {
	// A scalar value legitimately carries spaces, `=`, `#`, `;`, `[`, `]`,
	// and unicode — none of those break a keyfile line (they are only
	// meaningful in the key/section position, or as list separators for
	// list-typed keys). Rejecting them would break real WPA passphrases
	// and SSIDs, so the validator must accept them.
	for _, ok := range []string{
		"hunter2",
		"Corp Net 5GHz",
		"p@ss=w0rd#1;2[3]",
		"日本語ネット",
		"",
	} {
		if err := ValidateValue(ok); err != nil {
			t.Errorf("ValidateValue(%q) = %v, want nil", ok, err)
		}
	}
}

func TestValidateKey_RejectsSeparatorAndHeader(t *testing.T) {
	// A key carries the same line-break ban as a value, PLUS it must not
	// contain `=` (that would split into a different key/value) and must
	// not begin with `[` (that would read as a section header). An empty
	// key is meaningless and rejected.
	for _, bad := range []string{"", "a=b", "[section", "k\ney", "k\x00"} {
		if err := ValidateKey(bad); err == nil {
			t.Errorf("ValidateKey(%q) = nil, want error", bad)
		} else if !errors.Is(err, ErrUnsafeValue) {
			t.Errorf("ValidateKey(%q) error = %v, want ErrUnsafeValue", bad, err)
		}
	}
	for _, ok := range []string{"id", "autoconnect-priority", "key-mgmt"} {
		if err := ValidateKey(ok); err != nil {
			t.Errorf("ValidateKey(%q) = %v, want nil", ok, err)
		}
	}
}

func TestValidateSection_RejectsBrackets(t *testing.T) {
	for _, bad := range []string{"", "a]b", "a[b", "sec\ntion", "sec\x00"} {
		if err := ValidateSection(bad); err == nil {
			t.Errorf("ValidateSection(%q) = nil, want error", bad)
		} else if !errors.Is(err, ErrUnsafeValue) {
			t.Errorf("ValidateSection(%q) error = %v, want ErrUnsafeValue", bad, err)
		}
	}
	for _, ok := range []string{"connection", "wifi-security", "802-1x"} {
		if err := ValidateSection(ok); err != nil {
			t.Errorf("ValidateSection(%q) = %v, want nil", ok, err)
		}
	}
}

func TestBuilder_RendersValidKeyfile(t *testing.T) {
	b := &Builder{}
	b.Comment("Managed — do not edit")
	b.Section("connection")
	b.Set("id", "pm-wifi-1")
	b.Set("type", "wifi")
	b.Section("wifi")
	b.Set("ssid", "Corp Net")

	out, err := b.Bytes()
	if err != nil {
		t.Fatalf("Bytes() error = %v, want nil", err)
	}
	got := string(out)
	for _, want := range []string{
		"# Managed — do not edit\n",
		"[connection]\n",
		"id=pm-wifi-1\n",
		"type=wifi\n",
		"[wifi]\n",
		"ssid=Corp Net\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered keyfile missing %q:\n%s", want, got)
		}
	}
	// A blank line must separate sections so a value's trailing content
	// can never visually run into the next header.
	if !strings.Contains(got, "type=wifi\n\n[wifi]") {
		t.Errorf("expected blank line between sections:\n%s", got)
	}
}

func TestBuilder_FailsClosedOnInjectedValue(t *testing.T) {
	// The load-bearing test: a value carrying a newline + forged section
	// must make the WHOLE build fail, and Bytes must return no content —
	// never a partially-rendered file with the injection in it.
	b := &Builder{}
	b.Section("wifi")
	b.Set("ssid", "Evil\n[connection]\npermissions=user:root:")

	out, err := b.Bytes()
	if err == nil {
		t.Fatalf("Bytes() = nil error, want ErrUnsafeValue; out=%q", out)
	}
	if !errors.Is(err, ErrUnsafeValue) {
		t.Errorf("Bytes() error = %v, want ErrUnsafeValue", err)
	}
	if out != nil {
		t.Errorf("Bytes() returned %q on error, want nil (no partial keyfile)", out)
	}
}

func TestBuilder_FirstFailureIsSticky(t *testing.T) {
	// Once an add fails validation, later well-formed adds must not mask
	// the error: the builder records the first failure and Bytes surfaces
	// it. Otherwise a caller appending fluently could append a valid pair
	// after a poisoned one and get a "successful" build.
	b := &Builder{}
	b.Section("wifi")
	b.Set("ssid", "ok\ninjected=1")
	b.Set("mode", "infrastructure") // valid, must NOT clear the prior error
	if _, err := b.Bytes(); !errors.Is(err, ErrUnsafeValue) {
		t.Errorf("Bytes() error = %v, want ErrUnsafeValue (first failure sticky)", err)
	}
}
