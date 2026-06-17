package pkg

// Package represents an installed or available package.
type Package struct {
	Name         string
	Version      string
	Architecture string
	Description  string
	Status       string // installed, available, upgradable, pinned
	Size         int64  // installed size in bytes
	Repository   string
	Pinned       bool // whether the package is pinned (hold)
}

// PackageUpdate represents an available update for a package.
type PackageUpdate struct {
	Name           string
	CurrentVersion string
	NewVersion     string
	Architecture   string
	Repository     string
}

// SearchResult represents a package search result.
type SearchResult struct {
	Name        string
	Version     string
	Description string
	Repository  string
}

// VersionInfo represents available versions of a package.
type VersionInfo struct {
	Name      string
	Versions  []AvailableVersion
	Installed string // currently installed version, empty if not installed
}

// AvailableVersion represents a specific version available for installation.
type AvailableVersion struct {
	Version    string
	Repository string
	Size       int64
}

// InstallOptions configures an Install call.
type InstallOptions struct {
	// Version pins the install to a specific version. When set, exactly one
	// package name must be given (a version applies to a single package).
	Version string
	// AllowDowngrade permits installing a lower version than the one installed.
	AllowDowngrade bool
}

// RemoveOptions configures a Remove call.
type RemoveOptions struct {
	// Purge also removes configuration/data where the backend distinguishes it
	// (apt purge / pacman -Rns / flatpak --delete-data). On backends with no
	// such distinction it is equivalent to a plain remove.
	Purge bool
}
