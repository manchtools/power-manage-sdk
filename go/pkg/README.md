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

### List Installed Packages

```go
packages, err := pm.List()
if err != nil {
    log.Fatal(err)
}

for _, p := range packages {
    fmt.Printf("%-30s %-20s %s\n", p.Name, p.Version, p.Architecture)
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

### Install Packages

```go
result, err := pm.Install("nginx", "curl")
if err != nil {
    log.Printf("Install failed: %s", result.Stderr)
}
fmt.Printf("Success: %v, Duration: %v\n", result.Success, result.Duration)
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
pkg, err := pm.Show("nginx")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Name: %s\n", pkg.Name)
fmt.Printf("Version: %s\n", pkg.Version)
fmt.Printf("Status: %s\n", pkg.Status)
fmt.Printf("Size: %d bytes\n", pkg.Size)
fmt.Printf("Description: %s\n", pkg.Description)
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
    Status       string // "installed" or "available"
    Size         int64  // bytes
    Repository   string
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

| Manager | Systems | Detection |
|---------|---------|-----------|
| apt | Debian, Ubuntu, Linux Mint | `/usr/bin/apt-get` |
| dnf | Fedora, RHEL 8+, CentOS Stream | `/usr/bin/dnf` |
