package fs

import (
	"errors"
	"strings"
	"testing"
)

// These tests pin audit finding #10 — the centralized path
// validation that every privileged file op should call before the
// path reaches exec. We exercise ValidatePath directly; the wiring
// into RemoveStrict/Remove/WriteFile/SetMode/SetOwnership/ReadFile/
// Mkdir/RemoveDir/CopyFile is structural (they all call ValidatePath
// at the top).

func TestValidatePath_AcceptsCanonicalShapes(t *testing.T) {
	for _, p := range []string{
		"/etc/sudoers.d/pm-power",
		"/var/lib/power-manage/wifi/abc/ca.pem",
		"/tmp/pm-test-keyfile",
		"/home/alice/file with spaces.txt",
		"relative/looking/path",
	} {
		t.Run(p, func(t *testing.T) {
			if err := ValidatePath(p); err != nil {
				t.Fatalf("ValidatePath(%q) = %v; want nil", p, err)
			}
		})
	}
}

func TestValidatePath_RejectsEmpty(t *testing.T) {
	err := ValidatePath("")
	if !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("err = %v; want ErrInvalidPath", err)
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error %q should mention empty", err)
	}
}

func TestValidatePath_RejectsNULByte(t *testing.T) {
	err := ValidatePath("/etc/sudoers.d/pm-power\x00.evil")
	if !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("err = %v; want ErrInvalidPath", err)
	}
	if !strings.Contains(err.Error(), "NUL") {
		t.Errorf("error %q should mention NUL", err)
	}
}

func TestValidatePath_RejectsLeadingDash(t *testing.T) {
	// `--no-preserve-root` is the headline horror story; anything
	// starting with `-` would be parsed as a flag by rm/chmod/chown
	// even before the path argv slot is consumed.
	for _, p := range []string{
		"-no-preserve-root",
		"--force",
		"-rf",
		"-",
	} {
		t.Run(p, func(t *testing.T) {
			err := ValidatePath(p)
			if !errors.Is(err, ErrInvalidPath) {
				t.Fatalf("ValidatePath(%q) = %v; want ErrInvalidPath", p, err)
			}
		})
	}
}
