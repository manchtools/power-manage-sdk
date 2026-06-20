package repo

import (
	"fmt"
	"net/url"
	"regexp"

	"github.com/manchtools/power-manage-sdk/pkg"
)

// Field grammars. A repository name becomes a filename (and, for apt, a keyring
// path) and an argv operand, so it must start alphanumeric and use only a narrow
// safe set — this also blocks path traversal and option injection. The enum-like
// fields (distribution, component, arch, siglevel, zypper type) carry naturally
// narrow grammars; an allowlist costs nothing and removes config/argument
// injection on the values spliced into config files and command lines.
var (
	validName            = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
	validAptDistribution = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
	validAptComponent    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
	validAptArch         = regexp.MustCompile(`^[a-z0-9][a-z0-9,_-]*$`)
	validPacmanSigLevel  = regexp.MustCompile(`^[a-zA-Z ]+$`)
	validZypperType      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]*$`)
)

// maxNameLen bounds the repository name. It mirrors the agent's historical
// runtime guard; the control plane enforces a tighter proto limit upstream, so
// in practice names are far shorter.
const maxNameLen = 128

// hasControl reports whether s contains any ASCII control character (NUL,
// newline, CR, tab, …) or DEL. A newline is the classic config-injection vector
// — it would smuggle extra directives into a repo file — and control characters
// have no place in a URL, description, or key reference.
func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// validateName checks a repository name.
func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name is empty", ErrInvalidName)
	}
	if len(name) > maxNameLen {
		return fmt.Errorf("%w: name exceeds %d characters", ErrInvalidName, maxNameLen)
	}
	if !validName.MatchString(name) {
		return fmt.Errorf("%w: name must match [a-zA-Z0-9][a-zA-Z0-9._-]*", ErrInvalidName)
	}
	return nil
}

// rejectControl returns an ErrInvalidConfig naming field if s holds a control
// character. The value itself is never echoed (it may carry per-deployment
// secrets); the field name is enough for an operator to find the action.
func rejectControl(field, s string) error {
	if hasControl(s) {
		return fmt.Errorf("%w: field %q contains a control character", ErrInvalidConfig, field)
	}
	return nil
}

// badShape returns an ErrInvalidConfig naming field for a shape violation.
func badShape(field string) error {
	return fmt.Errorf("%w: field %q has an invalid shape", ErrInvalidConfig, field)
}

// Validate checks the name and the configuration for this Manager's backend.
// A sub-config for a different backend is ignored. A name-only Repository
// (no sub-config) validates the name alone — the shape Remove uses.
func (m *manager) Validate(r Repository) error {
	if err := validateName(r.Name); err != nil {
		return err
	}
	switch m.b {
	case pkg.Apt:
		if r.Apt != nil {
			return validateApt(r.Apt)
		}
	case pkg.Dnf:
		if r.Dnf != nil {
			return validateDnf(r.Dnf)
		}
	case pkg.Pacman:
		if r.Pacman != nil {
			return validatePacman(r.Pacman)
		}
	case pkg.Zypper:
		if r.Zypper != nil {
			return validateZypper(r.Zypper)
		}
	}
	return nil
}

// validateAptURL checks an apt repository URL. apt is exempt from the https
// requirement (its trust anchor is the gpg-signed Release file), so http is
// accepted alongside https — but the value must still be a real URL. It is
// written into a deb822 "URIs:" field, so a raw space (which hasControl allows)
// or a control character would smuggle a SECOND URI/field into the line
// ("https://h/a https://evil/" → two URIs); a non-URL, a non-http(s) scheme
// (file://, ftp://), a host-less URL, or embedded credentials (which would leak
// into the on-disk config) have no place there either.
func validateAptURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("%w: field %q is required", ErrInvalidConfig, "apt.url")
	}
	for _, r := range rawURL {
		if r <= ' ' || r == 0x7f { // any whitespace (incl. space) or control char
			return badShape("apt.url")
		}
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return badShape("apt.url")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return badShape("apt.url")
	}
	if u.Host == "" {
		return badShape("apt.url")
	}
	if u.User != nil {
		return badShape("apt.url")
	}
	return nil
}

func validateApt(c *AptConfig) error {
	if err := validateAptURL(c.URL); err != nil {
		return err
	}
	if err := rejectControl("apt.distribution", c.Distribution); err != nil {
		return err
	}
	if c.Distribution != "" && !validAptDistribution.MatchString(c.Distribution) {
		return badShape("apt.distribution")
	}
	for _, comp := range c.Components {
		if err := rejectControl("apt.components", comp); err != nil {
			return err
		}
		if !validAptComponent.MatchString(comp) {
			return badShape("apt.components")
		}
	}
	if err := rejectControl("apt.arch", c.Arch); err != nil {
		return err
	}
	if c.Arch != "" && !validAptArch.MatchString(c.Arch) {
		return badShape("apt.arch")
	}
	// c.GPGKey is multi-line PUBLIC key content written verbatim to a keyring
	// file, never spliced into a config line or argv — so it is intentionally not
	// control-char validated.
	return nil
}

func validateDnf(c *DnfConfig) error {
	if c.BaseURL == "" {
		return fmt.Errorf("%w: field %q is required", ErrInvalidConfig, "dnf.baseurl")
	}
	if err := rejectControl("dnf.description", c.Description); err != nil {
		return err
	}
	// ValidateRepoBaseURL/ValidateGpgKeyRef also reject control chars, so they
	// subsume an explicit rejectControl for these fields.
	if pkg.ValidateRepoBaseURL(c.BaseURL) != nil {
		return badShape("dnf.baseurl")
	}
	if c.GPGKey != "" && pkg.ValidateGpgKeyRef(c.GPGKey) != nil {
		return badShape("dnf.gpgkey")
	}
	return nil
}

func validatePacman(c *PacmanConfig) error {
	if c.Server == "" {
		return fmt.Errorf("%w: field %q is required", ErrInvalidConfig, "pacman.server")
	}
	if err := rejectControl("pacman.sig_level", c.SigLevel); err != nil {
		return err
	}
	if c.SigLevel != "" && !validPacmanSigLevel.MatchString(c.SigLevel) {
		return badShape("pacman.sig_level")
	}
	if pkg.ValidateRepoBaseURL(c.Server) != nil {
		return badShape("pacman.server")
	}
	return nil
}

func validateZypper(c *ZypperConfig) error {
	if c.URL == "" {
		return fmt.Errorf("%w: field %q is required", ErrInvalidConfig, "zypper.url")
	}
	if err := rejectControl("zypper.description", c.Description); err != nil {
		return err
	}
	if err := rejectControl("zypper.type", c.Type); err != nil {
		return err
	}
	if c.Type != "" && !validZypperType.MatchString(c.Type) {
		return badShape("zypper.type")
	}
	if pkg.ValidateRepoBaseURL(c.URL) != nil {
		return badShape("zypper.url")
	}
	if c.GPGKey != "" && pkg.ValidateGpgKeyRef(c.GPGKey) != nil {
		return badShape("zypper.gpgkey")
	}
	return nil
}
