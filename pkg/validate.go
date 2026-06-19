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

// --- WS8 argv-hardening validators (sdk#88) --------------------------------
//
// These guard the package-manager invocation surface that the generic
// ValidatePackageName does not cover: an RPM %{NAME} read off a crafted
// .rpm, a dnf/zypper/pacman repository base URL, a dnf/zypper GPG key
// reference, and a flatpak remote alias. Each is MANDATORY at the argv
// boundary it protects (see agent/internal/executor) and, in concert
// with exec.SeparatePositionals, ensures a flag-shaped or
// metacharacter-bearing value can never be reparsed as an option.

// validRpmPackageName matches a legitimate RPM %{NAME}. The first
// character MUST be alphanumeric — that single rule kills the option-
// injection class where a crafted .rpm sets %{NAME} to `-e` or
// `--eval=%{lua:...}` and `rpm -q`/`rpm -e` reparses it as a flag/macro.
// RPM names use `[a-zA-Z0-9._+-]` (note '+' for libstdc++); the broader
// set ValidatePackageName allows (`:/@~`) is not part of an RPM NAME.
var validRpmPackageName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,255}$`)

// ValidateRpmPackageName returns a non-nil error when name is not a
// safe RPM %{NAME} to pass to `rpm -q`/`rpm -e`. The name a crafted
// .rpm reports is untrusted; callers MUST validate it before it reaches
// argv. Mirrors ValidatePackageName / the deb-side validDebPkgName.
func ValidateRpmPackageName(name string) error {
	if name == "" {
		return fmt.Errorf("rpm package name is empty")
	}
	if !validRpmPackageName.MatchString(name) {
		return fmt.Errorf("invalid rpm package name %q: must start with [a-zA-Z0-9] and contain only [a-zA-Z0-9._+-]", name)
	}
	return nil
}

// validRemoteName matches a flatpak remote alias (e.g. "flathub",
// "gnome-nightly"). Same leading-alphanumeric anti-option-injection
// rule; remote aliases never contain a path separator or whitespace.
var validRemoteName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

// ValidateRemoteName returns a non-nil error when name is not a safe
// flatpak remote alias to pass as an operand to `flatpak install`. A
// flag-shaped remote (`--from=…`) would otherwise be parsed as an
// option.
func ValidateRemoteName(name string) error {
	if name == "" {
		return fmt.Errorf("flatpak remote name is empty")
	}
	if !validRemoteName.MatchString(name) {
		return fmt.Errorf("invalid flatpak remote name %q: must start with [a-zA-Z0-9] and contain only [a-zA-Z0-9._-]", name)
	}
	return nil
}

// hasCtrlOrSpace reports whether s contains any ASCII control character,
// whitespace, or DEL. Used to reject config-injection (newlines smuggle
// extra directives into a repo file) and argv confusion (spaces split a
// single field into multiple arguments) in URL/ref fields where the
// generic ValidatePackageName grammar does not apply. r <= ' ' covers
// NUL through space (incl. \t \n \r); 0x7f is DEL.
func hasCtrlOrSpace(s string) bool {
	for _, r := range s {
		if r <= ' ' || r == 0x7f {
			return true
		}
	}
	return false
}

// ValidateRepoBaseURL validates a dnf baseurl / zypper url / pacman
// server. A repository base URL is where the package manager fetches
// ROOT-installed packages, so it must be https (no http/ftp/file — the
// transport is the only thing standing between a MITM and arbitrary
// root code), a real URL with a host, and free of control characters.
// Package-manager template variables ($releasever, $arch, $basearch)
// survive url.Parse and are intentionally allowed.
//
// NOTE: apt is deliberately NOT validated through here — apt's security
// model is the gpg-signed Release file, so an http transport with a
// trusted key is a legitimate, long-standing configuration.
func ValidateRepoBaseURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("repository base URL is empty")
	}
	if hasCtrlOrSpace(rawURL) {
		return fmt.Errorf("repository base URL contains whitespace or control characters")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("repository base URL is not a valid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("repository base URL must use https, got scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("repository base URL has no host")
	}
	return nil
}

// ValidateGpgKeyRef validates a dnf/zypper Gpgkey reference before it
// reaches `rpm --import`. Accepted iff it is (a) an https URL with a
// host, (b) a file:// absolute path (file:///… — empty host, no `..`),
// or (c) a bare absolute filesystem path (no `..`). Everything else is
// refused: a leading '-' (option injection into `rpm --import`),
// plaintext http (MITM of the trust anchor itself), rpm's `ext::`
// external transport (which executes a command), and relative or
// traversing paths.
func ValidateGpgKeyRef(ref string) error {
	if ref == "" {
		return fmt.Errorf("gpg key ref is empty")
	}
	if hasCtrlOrSpace(ref) {
		return fmt.Errorf("gpg key ref contains whitespace or control characters")
	}
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("gpg key ref %q is flag-shaped (leading '-')", ref)
	}
	switch {
	case strings.HasPrefix(ref, "https://"):
		u, err := url.Parse(ref)
		if err != nil {
			return fmt.Errorf("gpg key ref is not a valid URL: %w", err)
		}
		if u.Host == "" {
			return fmt.Errorf("gpg key https ref has no host")
		}
		return nil
	case strings.HasPrefix(ref, "file://"):
		u, err := url.Parse(ref)
		if err != nil {
			return fmt.Errorf("gpg key ref is not a valid URL: %w", err)
		}
		if u.Host != "" {
			return fmt.Errorf("gpg key file ref must be file:///absolute/path (no host)")
		}
		if !strings.HasPrefix(u.Path, "/") || strings.Contains(u.Path, "..") {
			return fmt.Errorf("gpg key file ref must be an absolute path with no '..'")
		}
		return nil
	case strings.HasPrefix(ref, "/"):
		if strings.Contains(ref, "..") {
			return fmt.Errorf("gpg key path ref must not contain '..'")
		}
		return nil
	default:
		return fmt.Errorf("gpg key ref %q must be an https URL, a file:// absolute path, or an absolute filesystem path", ref)
	}
}
