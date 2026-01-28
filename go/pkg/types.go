// Package pkg provides package manager abstractions for Linux systems.
package pkg

import "time"

// Package represents an installed or available package.
type Package struct {
	Name         string
	Version      string
	Architecture string
	Description  string
	Status       string // installed, available, upgradable, pinned
	Size         int64  // installed size in bytes
	Repository   string
	Pinned       bool   // whether the package is pinned (hold)
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

// CommandResult represents the result of a package manager command.
type CommandResult struct {
	Success  bool
	ExitCode int
	Stdout   string
	Stderr   string
	Duration time.Duration
}

// InstallOptions configures package installation behavior.
type InstallOptions struct {
	Version        string // specific version to install (empty for latest)
	AllowDowngrade bool   // allow downgrading if installed version is higher
}

// Manager defines the interface for package managers.
type Manager interface {
	// Info returns the package manager name and version.
	Info() (name, version string, err error)

	// Install installs one or more packages (latest version).
	Install(packages ...string) (*CommandResult, error)

	// InstallVersion installs a package with specific version options.
	InstallVersion(name string, opts InstallOptions) (*CommandResult, error)

	// Remove removes one or more packages.
	Remove(packages ...string) (*CommandResult, error)

	// Update updates the package database.
	Update() (*CommandResult, error)

	// Upgrade upgrades all packages or specific packages.
	Upgrade(packages ...string) (*CommandResult, error)

	// Search searches for packages matching a query.
	Search(query string) ([]SearchResult, error)

	// List lists installed packages.
	List() ([]Package, error)

	// ListUpgradable lists packages with available upgrades.
	ListUpgradable() ([]PackageUpdate, error)

	// Show returns detailed information about a package.
	Show(name string) (*Package, error)

	// ListVersions lists all available versions of a package.
	ListVersions(name string) (*VersionInfo, error)

	// IsInstalled checks if a package is installed.
	IsInstalled(name string) (bool, error)

	// GetInstalledVersion returns the installed version of a package.
	GetInstalledVersion(name string) (string, error)

	// Pin prevents a package from being upgraded.
	Pin(packages ...string) (*CommandResult, error)

	// Unpin allows a package to be upgraded again.
	Unpin(packages ...string) (*CommandResult, error)

	// ListPinned lists all pinned packages.
	ListPinned() ([]Package, error)

	// IsPinned checks if a package is pinned.
	IsPinned(name string) (bool, error)
}
