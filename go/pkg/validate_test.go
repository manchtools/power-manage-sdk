package pkg

import (
	"strings"
	"testing"
)

// TestValidatePackageName_Accepts pins the set of shapes we know
// real-world package managers use. Regressions that reject any of
// these break legitimate actions.
func TestValidatePackageName_Accepts(t *testing.T) {
	cases := []string{
		"nginx",
		"curl",
		"gcc-12",
		"libasound2t64",
		"libstdc++6",
		"firefox-esr",
		"linux-image-amd64",
		"libc6:i386",          // apt multiarch
		"libc6:amd64",         // apt multiarch
		"python3.11",          // dnf
		"base-devel",          // pacman
		"org.videolan.VLC",    // flatpak reverse-DNS
		"org.videolan.VLC/x86_64/stable",
		"runtime/org.freedesktop.Platform/x86_64/23.08",
		"foo-1.2.3",
		"_notquite",           // starts alphanum... actually "_" is not alphanum. Skip.
	}
	for _, name := range cases {
		if name == "_notquite" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			if err := ValidatePackageName(name); err != nil {
				t.Errorf("legitimate name rejected: %v", err)
			}
		})
	}
}

// TestValidatePackageName_RejectsOptionInjection is the core of the
// fix: every leading-dash / leading-equals input is a potential
// option-injection attack on the underlying package manager, and
// must be refused at the SDK boundary.
func TestValidatePackageName_RejectsOptionInjection(t *testing.T) {
	cases := []string{
		"",
		"-y",
		"--force",
		"=evil",
		" nginx",              // leading whitespace
		"nginx ",              // trailing whitespace — we refuse via character class
		"foo bar",             // embedded space — argv confusion
		"pkg;rm -rf /",        // shell metachar
		"pkg|cat",
		"pkg&whoami",
		"`reboot`",
		"$(reboot)",
		"pkg\nmalicious",
		"pkg\x00",
		"pkg=1.2.3",           // apt name=version goes via InstallOptions.Version
		"pkg*",                // glob
		"pkg?",
		"pkg>out",
		"pkg<in",
		"pkg'quote",
		"pkg\"quote",
		"pkg\\back",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			err := ValidatePackageName(name)
			if err == nil {
				t.Errorf("expected rejection of %q", name)
				return
			}
			if !strings.Contains(err.Error(), "package name") {
				t.Errorf("error should name the field; got: %v", err)
			}
		})
	}
}

// TestValidatePackageName_LengthCap asserts the 256-character cap.
func TestValidatePackageName_LengthCap(t *testing.T) {
	ok := "a" + strings.Repeat("b", 255)
	if err := ValidatePackageName(ok); err != nil {
		t.Errorf("256-char name rejected: %v", err)
	}
	tooLong := "a" + strings.Repeat("b", 256)
	if err := ValidatePackageName(tooLong); err == nil {
		t.Errorf("257-char name accepted; expected rejection")
	}
}
