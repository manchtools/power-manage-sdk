package pkg

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
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

// validPackageVersion guards InstallOptions.Version (and any other
// "version" field that ends up on a package-manager argv). The
// audit's finding #7 explicitly called out version fields alongside
// names — without this, a caller could smuggle option-shaped or
// shell-shaped input through Version even when Name was strict.
//
// The grammar covers the cross-distro version dialects we have to
// support:
//
//   - Debian / Ubuntu: epoch:upstream-debian_revision, e.g.
//     `1:2.4.6-1ubuntu0.10`.
//   - RPM (dnf / zypper): EVR with `~` / `^` separators in modern
//     Fedora pre-release semantics.
//   - Arch: `1.2.3-1`, possibly with `:epoch` prefix.
//
// Empty is allowed: ValidatePackageVersion("") returns nil so the
// "no specific version" path stays implicit. Length cap mirrors
// validPackageName.
var validPackageVersion = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+:~^-]{0,127}$`)

// ValidatePackageVersion checks a version string before it lands in
// `<name>=<version>` (apt) or similar argv constructs. Empty version
// is treated as "no version pinned" and accepted; any non-empty
// version must match the cross-distro grammar in validPackageVersion.
func ValidatePackageVersion(version string) error {
	if version == "" {
		return nil
	}
	if !validPackageVersion.MatchString(version) {
		return fmt.Errorf("invalid package version %q: must start with [a-zA-Z0-9] and contain only [a-zA-Z0-9._+:~^-]", version)
	}
	return nil
}

// validRemoteName guards a Flatpak remote name. First char alphanumeric
// (so a name can never be flag-shaped), then the reverse-DNS / id charset
// flatpak accepts, capped at 64. Same option-injection rationale as
// validPackageName.
var validRemoteName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// remoteURLSchemes are the only schemes a Flatpak remote URL may carry.
// flatpak remotes are served over https / oci (optionally plain http for
// an internal mirror). Restricting the scheme refuses both transport
// injection (ext::, file://) and flag-shaped values (which have no
// scheme), so a URL can never be reinterpreted as a remote-add option
// like --from or --gpg-import.
var remoteURLSchemes = map[string]bool{
	"https":     true,
	"http":      true,
	"oci+https": true,
	"oci+http":  true,
}

// ValidateRemoteName returns a non-nil error when name is unsafe to pass
// as a Flatpak remote name argument.
func ValidateRemoteName(name string) error {
	if name == "" {
		return fmt.Errorf("remote name is empty")
	}
	if !validRemoteName.MatchString(name) {
		return fmt.Errorf("invalid remote name %q: must start with [a-zA-Z0-9] and contain only [a-zA-Z0-9._-], max 64 chars", name)
	}
	return nil
}

// ValidateRemoteURL returns a non-nil error when rawURL is unsafe to pass
// as a Flatpak remote URL. It must be a control-character-free absolute URL
// whose scheme is one of remoteURLSchemes.
func ValidateRemoteURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("remote url is empty")
	}
	if strings.ContainsAny(rawURL, "\x00\n\r\t ") {
		return fmt.Errorf("invalid remote url: contains whitespace or control characters")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid remote url %q: %w", rawURL, err)
	}
	if !remoteURLSchemes[strings.ToLower(u.Scheme)] {
		return fmt.Errorf("invalid remote url %q: scheme must be one of https, http, oci+https, oci+http", rawURL)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid remote url %q: missing host", rawURL)
	}
	return nil
}
