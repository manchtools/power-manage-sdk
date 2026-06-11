package user

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Threat model: a login shell flows into `useradd/usermod -s <shell>`.
// usermod does NOT restrict -s to /etc/shells, so without an SDK-side
// check an operator could point any account at an arbitrary binary
// (/tmp/evil) — a persistence/escalation primitive. ValidateLoginShell
// fails closed: the value must be a clean absolute path AND be listed in
// /etc/shells (or be a recognized non-login shell).

func TestValidateLoginShellSyntax_RejectsUnsafeShapes(t *testing.T) {
	// Wrong cases come from the argv + path threat model, not the
	// validator: a relative path can't be resolved deterministically, a
	// leading dash is flag injection, control chars smuggle args / forge
	// logs, and a non-canonical path hides the real target.
	for _, bad := range []string{
		"",
		"bash",           // relative
		"bin/bash",       // relative
		"-c",             // flag shape
		"--login",        // flag shape
		"/bin/../bin/sh", // non-canonical
		"/bin/bash\n",    // control char
		"/bin/bash\x00",  // NUL
		"/bin/ba sh\rx",  // CR
	} {
		if err := ValidateLoginShellSyntax(bad); err == nil {
			t.Errorf("ValidateLoginShellSyntax(%q) = nil, want ErrInvalidShell", bad)
		} else if !errors.Is(err, ErrInvalidShell) {
			t.Errorf("ValidateLoginShellSyntax(%q) error = %v, want ErrInvalidShell", bad, err)
		}
	}
	if err := ValidateLoginShellSyntax("/bin/bash"); err != nil {
		t.Errorf("ValidateLoginShellSyntax(/bin/bash) = %v, want nil", err)
	}
}

func TestValidateLoginShell_EnforcesAllowlist(t *testing.T) {
	// Point the allowlist at a fixture so the test is host-independent.
	// Include comments and blank lines (real /etc/shells has them) to
	// prove they are ignored, not matched.
	dir := t.TempDir()
	shellsFile := filepath.Join(dir, "shells")
	content := "# /etc/shells: valid login shells\n/bin/bash\n\n/usr/bin/zsh\n# trailing comment\n"
	if err := os.WriteFile(shellsFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := loginShellsFile
	loginShellsFile = shellsFile
	t.Cleanup(func() { loginShellsFile = orig })

	// Listed shells are accepted.
	for _, ok := range []string{"/bin/bash", "/usr/bin/zsh"} {
		if err := ValidateLoginShell(ok); err != nil {
			t.Errorf("ValidateLoginShell(%q) = %v, want nil", ok, err)
		}
	}
	// A binary NOT in /etc/shells is rejected even though it is a clean
	// absolute path — this is the core control.
	if err := ValidateLoginShell("/tmp/evil"); !errors.Is(err, ErrInvalidShell) {
		t.Errorf("ValidateLoginShell(/tmp/evil) = %v, want ErrInvalidShell", err)
	}
	// A comment line must not be treated as an allowed shell.
	if err := ValidateLoginShell("# /etc/shells: valid login shells"); !errors.Is(err, ErrInvalidShell) {
		t.Errorf("ValidateLoginShell(comment) = %v, want ErrInvalidShell", err)
	}
	// Syntactically bad shells are rejected before allowlist lookup.
	if err := ValidateLoginShell("-c"); !errors.Is(err, ErrInvalidShell) {
		t.Errorf("ValidateLoginShell(-c) = %v, want ErrInvalidShell", err)
	}
}

func TestValidateLoginShell_AcceptsNonLoginShells(t *testing.T) {
	// nologin/false disable interactive login — a security-positive target.
	// They must be accepted even when /etc/shells omits them (many distros
	// do). Use a fixture WITHOUT them to prove the non-login set is what
	// admits them.
	dir := t.TempDir()
	shellsFile := filepath.Join(dir, "shells")
	if err := os.WriteFile(shellsFile, []byte("/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := loginShellsFile
	loginShellsFile = shellsFile
	t.Cleanup(func() { loginShellsFile = orig })

	for _, ok := range []string{"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"} {
		if err := ValidateLoginShell(ok); err != nil {
			t.Errorf("ValidateLoginShell(%q) = %v, want nil (non-login shell)", ok, err)
		}
	}
}

func TestValidateLoginShell_MissingShellsFileFailsClosed(t *testing.T) {
	// If /etc/shells can't be read, a normal shell must NOT be admitted
	// (fail closed); only the hardcoded non-login set remains valid.
	orig := loginShellsFile
	loginShellsFile = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { loginShellsFile = orig })

	if err := ValidateLoginShell("/bin/bash"); !errors.Is(err, ErrInvalidShell) {
		t.Errorf("ValidateLoginShell with missing shells file = %v, want ErrInvalidShell", err)
	}
	if err := ValidateLoginShell("/usr/sbin/nologin"); err != nil {
		t.Errorf("ValidateLoginShell(nologin) with missing shells file = %v, want nil", err)
	}
}
