package pkg

import (
	"context"
	"errors"
	"os"
)

// ErrNoPackageManager is returned when no supported package manager is found.
var ErrNoPackageManager = errors.New("no supported package manager found")

// Detect returns the appropriate package manager for the current system.
func Detect() (Manager, error) {
	return DetectWithContext(context.Background())
}

// DetectWithContext returns the appropriate package manager with context.
func DetectWithContext(ctx context.Context) (Manager, error) {
	// Check for apt (Debian/Ubuntu)
	if _, err := os.Stat("/usr/bin/apt-get"); err == nil {
		return NewAptWithContext(ctx), nil
	}

	// Check for dnf (Fedora/RHEL 8+)
	if _, err := os.Stat("/usr/bin/dnf"); err == nil {
		return NewDnfWithContext(ctx), nil
	}

	return nil, ErrNoPackageManager
}

// IsApt returns true if apt is available.
func IsApt() bool {
	_, err := os.Stat("/usr/bin/apt-get")
	return err == nil
}

// IsDnf returns true if dnf is available.
func IsDnf() bool {
	_, err := os.Stat("/usr/bin/dnf")
	return err == nil
}
