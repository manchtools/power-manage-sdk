package pkg

import (
	"fmt"
	"regexp"
)

// validPackageName is the allowlist every package-name argument must
// match before it reaches apt / dnf / pacman / zypper / flatpak.
//
// The first character MUST be alphanumeric. That single rule kills
// the entire class of "option injection" attacks where a caller
// smuggles a flag past the verb by naming a package `--force` or
// `-y=evil` — every package manager would have treated those as
// additional options rather than a package name. The subsequent
// character set covers the grammars every manager we support
// actually uses:
//
//   - apt / dpkg: alphanum + `._-` plus multiarch `:arch` suffix.
//   - dnf / zypper: alphanum + `._-`, occasionally `+` (libstdc++).
//   - pacman: alphanum + `._-+@`.
//   - flatpak refs: reverse-DNS app IDs with `.`, plus optional
//     `/arch/branch` suffix, e.g. `org.videolan.VLC/x86_64/stable`.
//
// Characters we intentionally forbid: whitespace, NUL, shell
// metacharacters (`|&;<>`, backticks, `$`, `\`), quote chars, `=`
// (apt's name=version separator — version must come through the
// dedicated InstallOptions.Version field, not the name), `*`, `?`
// and other glob characters.
//
// Length is capped at 256 to bound pathological inputs before they
// reach argv.
var validPackageName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+:/@~-]{0,255}$`)

// ValidatePackageName returns a non-nil error when name would be
// unsafe to pass as a positional argument to any of the supported
// package managers. Callers MUST invoke this (or
// ValidatePackageNames) at the top of every public method that
// accepts a package name, before any exec.CommandContext call.
func ValidatePackageName(name string) error {
	if name == "" {
		return fmt.Errorf("package name is empty")
	}
	if !validPackageName.MatchString(name) {
		return fmt.Errorf("invalid package name %q: must start with [a-zA-Z0-9] and contain only [a-zA-Z0-9._+:/@~-]", name)
	}
	return nil
}

// ValidatePackageNames runs ValidatePackageName against every entry.
// Returns the first rejection; does not try to be exhaustive —
// actions are signed and a rejection here is a caller bug, not an
// adversarial probe to enumerate.
func ValidatePackageNames(names []string) error {
	for _, n := range names {
		if err := ValidatePackageName(n); err != nil {
			return err
		}
	}
	return nil
}
