// Package pkg provides package manager abstractions for Linux systems.
package pkg

import "time"

// Package represents an installed or available package.
type Package struct {
	Name         string
	Version      string
	Architecture string
	Description  string
	Status       string // installed, available, upgradable
	Size         int64  // installed size in bytes
	Repository   string
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

// CommandResult represents the result of a package manager command.
type CommandResult struct {
	Success  bool
	ExitCode int
	Stdout   string
	Stderr   string
	Duration time.Duration
}

// Manager defines the interface for package managers.
type Manager interface {
	// Info returns the package manager name and version.
	Info() (name, version string, err error)

	// Install installs one or more packages.
	Install(packages ...string) (*CommandResult, error)

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

	// IsInstalled checks if a package is installed.
	IsInstalled(name string) (bool, error)
}
