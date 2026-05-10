package pkg

import (
	"context"
	"errors"
	"os/exec"
)

// ErrNoPackageManager is returned when no supported package manager is found.
var ErrNoPackageManager = errors.New("no supported package manager found")

// hasBinary reports whether name resolves through PATH. Switched from
// the previous os.Stat("/usr/bin/<tool>") shape so detection works on
// distributions that install package-manager tools elsewhere — NixOS
// (/run/current-system/sw/bin), Alpine BusyBox layouts, /usr/local/bin
// installs, and Home Manager profiles.
func hasBinary(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Detect returns the appropriate package manager for the current
// system. The returned Manager has package-name validation applied
// via WithValidation — every public method that takes a package
// name refuses inputs that fail ValidatePackageName. Callers that
// want the raw underlying Manager (e.g. for tests that deliberately
// exercise invalid names) can instantiate NewApt / NewDnf /
// NewPacman / NewZypper directly.
func Detect() (Manager, error) {
	return DetectWithContext(context.Background())
}

// DetectWithContext returns the appropriate package manager with
// context. See Detect for the validation-wrapping contract.
func DetectWithContext(ctx context.Context) (Manager, error) {
	// Check for apt (Debian/Ubuntu)
	if hasBinary("apt-get") {
		return WithValidation(NewAptWithContext(ctx)), nil
	}

	// Check for dnf (Fedora/RHEL 8+)
	if hasBinary("dnf") {
		return WithValidation(NewDnfWithContext(ctx)), nil
	}

	// Check for pacman (Arch Linux)
	if hasBinary("pacman") {
		return WithValidation(NewPacmanWithContext(ctx)), nil
	}

	// Check for zypper (openSUSE/SLES)
	if hasBinary("zypper") {
		return WithValidation(NewZypperWithContext(ctx)), nil
	}

	return nil, ErrNoPackageManager
}

// IsApt returns true if apt is available.
func IsApt() bool { return hasBinary("apt-get") }

// IsDnf returns true if dnf is available.
func IsDnf() bool { return hasBinary("dnf") }

// IsPacman returns true if pacman is available.
func IsPacman() bool { return hasBinary("pacman") }

// IsZypper returns true if zypper is available.
func IsZypper() bool { return hasBinary("zypper") }

// IsFlatpak returns true if flatpak is available.
func IsFlatpak() bool { return hasBinary("flatpak") }
