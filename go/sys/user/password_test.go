package user

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

func TestGeneratePassword_Bounds(t *testing.T) {
	if _, err := GeneratePassword(MinPasswordLength-1, ComplexityAlphanumeric); err == nil {
		t.Error("too-short length accepted")
	}
	if _, err := GeneratePassword(MaxPasswordLength+1, ComplexityAlphanumeric); err == nil {
		t.Error("too-long length accepted")
	}
}

func TestGeneratePassword_LengthCharsetAndSecret(t *testing.T) {
	s, err := GeneratePassword(24, ComplexityAlphanumeric)
	if err != nil {
		t.Fatal(err)
	}
	pw := s.Reveal()
	if len(pw) != 24 {
		t.Errorf("length = %d, want 24", len(pw))
	}
	for _, c := range pw {
		if !strings.ContainsRune(charsetAlphanumeric, c) {
			t.Errorf("alphanumeric password contains out-of-charset rune %q", c)
		}
	}
	// It is a Secret: never reveals plaintext through formatting.
	if got := s.String(); got != "[REDACTED]" || strings.Contains(got, pw) {
		t.Errorf("generated password not redacted: %q", got)
	}
	// The generator never produces a newline/CR (would break chpasswd).
	if strings.ContainsAny(pw, "\n\r") {
		t.Error("generated password contains a newline/CR")
	}
}

func TestGeneratePassword_ComplexUsesSpecialAndStaysInCharset(t *testing.T) {
	// Every char stays within alphanumeric+special, AND across many draws at
	// least one special char actually appears — so this fails if ComplexityComplex
	// ever regresses to alphanumeric-only. With 50×32 chars drawn from an ~87-char
	// set containing ~25 specials, P(never a special) is astronomically small.
	sawSpecial := false
	for i := 0; i < 50; i++ {
		s, err := GeneratePassword(32, ComplexityComplex)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range s.Reveal() {
			if !strings.ContainsRune(charsetAlphanumeric+charsetSpecial, c) {
				t.Fatalf("complex password contains out-of-charset rune %q", c)
			}
			if strings.ContainsRune(charsetSpecial, c) {
				sawSpecial = true
			}
		}
	}
	if !sawSpecial {
		t.Error("ComplexityComplex produced no special character across 50×32 chars — it may have regressed to alphanumeric-only")
	}
}

func TestSetPassword_ChpasswdStdinAndSecretNeverInArgv(t *testing.T) {
	f := exectest.New(exec.Direct)
	secret, err := exec.NewSecret("sup3r-s3cret-value")
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr(t, f).SetPassword(context.Background(), "deploy", secret); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	if len(calls) != 1 {
		t.Fatalf("got %d calls, want 1", len(calls))
	}
	c := calls[0]
	if c.Name != "chpasswd" || !c.Escalate {
		t.Errorf("command = %q escalate=%v, want escalated chpasswd", c.Name, c.Escalate)
	}
	// The plaintext must go through STDIN, never argv.
	for _, a := range c.Args {
		if strings.Contains(a, "sup3r-s3cret-value") {
			t.Errorf("secret leaked into argv: %q", a)
		}
	}
	if c.Stdin == nil {
		t.Fatal("chpasswd received no stdin")
	}
	got, _ := io.ReadAll(c.Stdin)
	if string(got) != "deploy:sup3r-s3cret-value" {
		t.Errorf("chpasswd stdin = %q, want %q", got, "deploy:sup3r-s3cret-value")
	}
}

func TestSetPassword_MapsNonZeroExit(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{ExitCode: 1, Stderr: "chpasswd: (user deploy) pam_chauthtok() failed, error:\nAuthentication token manipulation error"}, nil)
	err := mgr(t, f).SetPassword(context.Background(), "deploy", exec.Secret{})
	var ce *exec.CommandError
	if !errors.As(err, &ce) || ce.ExitCode != 1 {
		t.Errorf("err = %v, want *exec.CommandError exit 1", err)
	}
}

func TestExpirePassword_Golden(t *testing.T) {
	f := exectest.New(exec.Direct)
	if err := mgr(t, f).ExpirePassword(context.Background(), "deploy"); err != nil {
		t.Fatal(err)
	}
	wantOneCmd(t, f, "chage", []string{"-d", "0", "deploy"}, true)
}
