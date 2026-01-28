# Package Manager SDK

A Go library for interacting with Linux package managers (apt, dnf) with structured data output and a fluent builder API.

## Installation

```go
import "github.com/manchtools/power-manage/sdk/go/pkg"
```

## Quick Start

```go
// Auto-detect and create a package manager with builder API
pm, err := pkg.New()
if err != nil {
    log.Fatal(err)
}

// Install latest version
result, err := pm.Install("nginx").Run()

// Install specific version
result, err := pm.Install("nginx").Version("1.24.0-1").Run()

// Install with downgrade support
result, err := pm.Install("nginx").Version("1.22.0-1").AllowDowngrade().Run()
```

## Builder API

The builder pattern provides a fluent interface for package operations:

### Install

```go
// Install latest
pm.Install("nginx").Run()

// Install specific version
pm.Install("nginx").Version("1.24.0-1").Run()

// Install older version (downgrade)
pm.Install("nginx").Version("1.22.0-1").AllowDowngrade().Run()
```

### Remove

```go
// Remove package
pm.Remove("nginx").Run()

// Remove multiple packages
pm.Remove("nginx", "curl", "wget").Run()

// Purge (remove with config files, apt only)
pm.Remove("nginx").Purge().Run()
```

### Upgrade

```go
// Upgrade all packages
pm.Upgrade().Run()

// Upgrade specific packages
pm.Upgrade("nginx", "curl").Run()
```

### Pin/Unpin

```go
// Pin packages to prevent upgrades
pm.Pin("nginx", "curl").Run()

// Unpin to allow upgrades
pm.Unpin("nginx").Run()
```

## Direct Manager Access

The `PackageManager` embeds the `Manager` interface, so you can still access all methods directly:

```go
pm, _ := pkg.New()

// Builder API
pm.Install("nginx").Version("1.24.0").Run()

// Direct access
packages, _ := pm.List()
versions, _ := pm.ListVersions("nginx")
pinned, _ := pm.IsPinned("nginx")
```

## Low-Level Manager Interface

For more control, use the Manager interface directly:

```go
// Auto-detect
manager, err := pkg.Detect()

// Or use specific implementations
apt := pkg.NewApt()
dnf := pkg.NewDnf()

// All Manager methods available
manager.Install("nginx")
manager.InstallVersion("nginx", pkg.InstallOptions{
    Version:        "1.24.0-1",
    AllowDowngrade: true,
})
manager.Remove("nginx")
manager.List()
manager.ListVersions("nginx")
manager.Pin("nginx")
```

## Query Methods

```go
pm, _ := pkg.New()

// List installed packages
packages, _ := pm.List()
for _, p := range packages {
    fmt.Printf("%s %s (pinned: %v)\n", p.Name, p.Version, p.Pinned)
}

// List available versions
info, _ := pm.ListVersions("nginx")
fmt.Printf("Installed: %s\n", info.Installed)
for _, v := range info.Versions {
    fmt.Printf("  %s (%s)\n", v.Version, v.Repository)
}

// Get installed version
version, _ := pm.GetInstalledVersion("nginx")

// Check if installed
installed, _ := pm.IsInstalled("nginx")

// Check if pinned
pinned, _ := pm.IsPinned("nginx")

// List pinned packages
pinnedPkgs, _ := pm.ListPinned()

// List upgradable packages
updates, _ := pm.ListUpgradable()
for _, u := range updates {
    fmt.Printf("%s: %s -> %s\n", u.Name, u.CurrentVersion, u.NewVersion)
}

// Search packages
results, _ := pm.Search("nginx")

// Get package details
p, _ := pm.Show("nginx")
```

## Context Support

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

// With context
apt := pkg.NewAptWithContext(ctx)
dnf := pkg.NewDnfWithContext(ctx)

// Or via Detect
manager, _ := pkg.DetectWithContext(ctx)
pm := pkg.NewPackageManager(manager)
```

## Types

### Package

```go
type Package struct {
    Name         string
    Version      string
    Architecture string
    Description  string
    Status       string // "installed", "available"
    Size         int64  // bytes
    Repository   string
    Pinned       bool   // held/versionlocked
}
```

### VersionInfo

```go
type VersionInfo struct {
    Name      string
    Versions  []AvailableVersion
    Installed string
}

type AvailableVersion struct {
    Version    string
    Repository string
    Size       int64
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

- **apt**: Use exact version from `apt-cache madison`, e.g., `1.24.0-1ubuntu1`
- **dnf**: Use version-release format, e.g., `1.24.0-1.fc39`

### Pinning Requirements

- **apt**: No additional setup required
- **dnf**: Uses `python3-dnf-plugin-versionlock` (automatically installed when pinning is first used)
