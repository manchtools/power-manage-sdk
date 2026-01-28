# Package Manager SDK

A Go library for interacting with Linux package managers (apt, dnf) with structured data output.

## Installation

```go
import "github.com/yourorg/power-manage/sdk/go/pkg"
```

## Quick Start

```go
// Auto-detect the system's package manager
pm, err := pkg.Detect()
if err != nil {
    log.Fatal(err)
}

// Get package manager info
name, version, _ := pm.Info()
fmt.Printf("Using %s %s\n", name, version)
```

## Usage

### Install Packages

```go
// Install latest version
result, err := pm.Install("nginx", "curl")

// Install specific version
result, err := pm.InstallVersion("nginx", pkg.InstallOptions{
    Version: "1.24.0-1",
})

// Install specific version with downgrade support
result, err := pm.InstallVersion("nginx", pkg.InstallOptions{
    Version:        "1.22.0-1",
    AllowDowngrade: true,
})
```

### List Available Versions

```go
info, err := pm.ListVersions("nginx")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Package: %s\n", info.Name)
fmt.Printf("Installed: %s\n", info.Installed)
fmt.Println("Available versions:")
for _, v := range info.Versions {
    fmt.Printf("  %s (%s)\n", v.Version, v.Repository)
}
```

### Get Installed Version

```go
version, err := pm.GetInstalledVersion("nginx")
if err != nil {
    fmt.Println("Package not installed")
} else {
    fmt.Printf("Installed version: %s\n", version)
}
```

### Pin Packages (Prevent Upgrades)

```go
// Pin a package to prevent automatic upgrades
result, err := pm.Pin("nginx", "curl")

// Check if a package is pinned
pinned, _ := pm.IsPinned("nginx")
fmt.Printf("nginx pinned: %v\n", pinned)

// List all pinned packages
pinnedPkgs, _ := pm.ListPinned()
for _, p := range pinnedPkgs {
    fmt.Printf("%s %s (pinned)\n", p.Name, p.Version)
}

// Unpin to allow upgrades again
result, err := pm.Unpin("nginx")
```

### List Installed Packages

```go
packages, err := pm.List()
if err != nil {
    log.Fatal(err)
}

for _, p := range packages {
    pinStatus := ""
    if p.Pinned {
        pinStatus = " [pinned]"
    }
    fmt.Printf("%-30s %-20s%s\n", p.Name, p.Version, pinStatus)
}
```

### Search for Packages

```go
results, err := pm.Search("nginx")
if err != nil {
    log.Fatal(err)
}

for _, r := range results {
    fmt.Printf("%s: %s\n", r.Name, r.Description)
}
```

### Remove Packages

```go
result, err := pm.Remove("nginx")
if err != nil {
    log.Printf("Remove failed: %s", result.Stderr)
}
```

### Check for Updates

```go
// Update package database
pm.Update()

// List available upgrades
updates, err := pm.ListUpgradable()
if err != nil {
    log.Fatal(err)
}

for _, u := range updates {
    fmt.Printf("%s: %s -> %s\n", u.Name, u.CurrentVersion, u.NewVersion)
}

// Upgrade all packages
result, err := pm.Upgrade()

// Or upgrade specific packages
result, err := pm.Upgrade("nginx", "curl")
```

### Get Package Details

```go
p, err := pm.Show("nginx")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Name: %s\n", p.Name)
fmt.Printf("Version: %s\n", p.Version)
fmt.Printf("Status: %s\n", p.Status)
fmt.Printf("Pinned: %v\n", p.Pinned)
fmt.Printf("Size: %d bytes\n", p.Size)
fmt.Printf("Description: %s\n", p.Description)
```

### Check if Package is Installed

```go
installed, err := pm.IsInstalled("nginx")
if installed {
    fmt.Println("nginx is installed")
}
```

## Using Specific Package Managers

```go
// Use apt directly
apt := pkg.NewApt()
packages, _ := apt.List()

// Use dnf directly
dnf := pkg.NewDnf()
packages, _ := dnf.List()

// With context for timeouts
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

apt := pkg.NewAptWithContext(ctx)
dnf := pkg.NewDnfWithContext(ctx)
```

## Detection Helpers

```go
// Check which package manager is available
if pkg.IsApt() {
    fmt.Println("Debian/Ubuntu system")
}

if pkg.IsDnf() {
    fmt.Println("Fedora/RHEL system")
}
```

## Types

### Package

```go
type Package struct {
    Name         string
    Version      string
    Architecture string
    Description  string
    Status       string // "installed", "available", "pinned"
    Size         int64  // bytes
    Repository   string
    Pinned       bool   // whether the package is held/versionlocked
}
```

### PackageUpdate

```go
type PackageUpdate struct {
    Name           string
    CurrentVersion string
    NewVersion     string
    Architecture   string
    Repository     string
}
```

### VersionInfo

```go
type VersionInfo struct {
    Name      string
    Versions  []AvailableVersion
    Installed string // currently installed version
}

type AvailableVersion struct {
    Version    string
    Repository string
    Size       int64
}
```

### InstallOptions

```go
type InstallOptions struct {
    Version        string // specific version to install (empty for latest)
    AllowDowngrade bool   // allow downgrading if installed version is higher
}
```

### SearchResult

```go
type SearchResult struct {
    Name        string
    Version     string
    Description string
    Repository  string
}
```

### CommandResult

```go
type CommandResult struct {
    Success  bool
    ExitCode int
    Stdout   string
    Stderr   string
    Duration time.Duration
}
```

## Supported Package Managers

| Manager | Systems | Detection | Pinning |
|---------|---------|-----------|---------|
| apt | Debian, Ubuntu, Linux Mint | `/usr/bin/apt-get` | `apt-mark hold/unhold` |
| dnf | Fedora, RHEL 8+, CentOS Stream | `/usr/bin/dnf` | `dnf versionlock` (requires plugin) |

## Notes

### Version Formats

- **apt**: Use exact version string from `apt-cache madison`, e.g., `1.24.0-1ubuntu1`
- **dnf**: Use version-release format, e.g., `1.24.0-1.fc39`

### Pinning Requirements

- **apt**: No additional setup required
- **dnf**: Requires `python3-dnf-plugin-versionlock` package:
  ```bash
  dnf install python3-dnf-plugin-versionlock
  ```

### Downgrading

When using `AllowDowngrade: true`:
- **apt**: Uses `--allow-downgrades` flag
- **dnf**: Uses `--allowerasing` flag, falls back to `dnf downgrade` if needed
