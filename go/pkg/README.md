# Package Manager SDK

A Go library for driving Linux package managers (apt, dnf, pacman, zypper,
flatpak) through a single `Manager` interface built over an injected
`exec.Runner` — no global escalation state, fully unit-testable with
`exectest.FakeRunner` (no host, no sudo, no container).

## Installation

```go
import (
    "github.com/manchtools/power-manage/sdk/go/pkg"
    "github.com/manchtools/power-manage/sdk/go/sys/exec"
)
```

## Quick Start

```go
// Build a Runner for the host's escalation backend, then a Manager for a backend.
r, err := exec.NewRunner(exec.Sudo) // or exec.Doas / exec.Direct (already root)
if err != nil {
    log.Fatal(err)
}
m, err := pkg.New(pkg.Apt, r)
if err != nil {
    log.Fatal(err)
}

ctx := context.Background()

// Install latest
err = m.Install(ctx, pkg.InstallOptions{}, "nginx", "curl")

// Install a pinned version (exactly one package when Version is set)
err = m.Install(ctx, pkg.InstallOptions{Version: "1.24.0-1"}, "nginx")

// Allow a downgrade
err = m.Install(ctx, pkg.InstallOptions{Version: "1.22.0-1", AllowDowngrade: true}, "nginx")
```

Mutating methods (`Install`/`Remove`/`Update`/`Upgrade`/`Pin`/`Unpin`/`Repair`/
`Autoremove`) return `error` only — a non-zero exit becomes an
`*exec.CommandError` carrying the exit code and stderr (`errors.As` to inspect).
Query methods return typed results.

## Choosing a backend

`New` is pure — it does not probe the host. Use `Detect` to learn which
backends are installed (it lists, in priority order; it never picks):

```go
for _, b := range pkg.Detect(ctx) {
    fmt.Println(b) // "apt", "dnf", "flatpak", ...
}
m, err := pkg.New(pkg.Dnf, r)
```

An unknown backend or a nil runner is rejected (`pkg.ErrUnknownBackend` /
"runner is required") — fail-closed, no silent default.

## Mutations

```go
m.Install(ctx, pkg.InstallOptions{}, "nginx")
m.Remove(ctx, pkg.RemoveOptions{}, "nginx")
m.Remove(ctx, pkg.RemoveOptions{Purge: true}, "nginx") // also delete config/data where supported
m.Update(ctx)                                          // refresh metadata
m.Upgrade(ctx)                                         // full system upgrade (no names)
m.Upgrade(ctx, "nginx", "curl")                        // upgrade specific packages
m.Pin(ctx, "nginx")                                    // hold back from upgrades
m.Unpin(ctx, "nginx")
m.Autoremove(ctx)                                      // remove now-unneeded deps (no-op on zypper)
m.Repair(ctx)                                          // clear stale locks / fix broken state
```

Reads run unprivileged; mutations escalate through the Runner's backend
(`sudo -n` / `doas -n` / bare for `Direct`).

## Queries

```go
ver, _ := m.Version(ctx)                 // package-manager tool version
packages, _ := m.List(ctx)               // installed packages
updates, _ := m.ListUpgradable(ctx)      // []PackageUpdate
p, _ := m.Show(ctx, "nginx")             // *Package
info, _ := m.ListVersions(ctx, "nginx")  // *VersionInfo
ok, _ := m.IsInstalled(ctx, "nginx")
v, _ := m.InstalledVersion(ctx, "nginx") // "" if absent
n, _ := m.InstalledCount(ctx)
has, _ := m.HasUpdates(ctx, false)       // true if any update; pass true for security-only (where supported)
pinned, _ := m.IsPinned(ctx, "nginx")
held, _ := m.ListPinned(ctx)
results, _ := m.Search(ctx, "nginx")
```

## Flatpak

`New(pkg.Flatpak, r)` returns a value that also satisfies `FlatpakManager`,
adding remote (repository) management. Use `WithUserScope()` to operate on the
per-user installation (`--user`, unprivileged) instead of the system one:

```go
m, _ := pkg.New(pkg.Flatpak, r)                 // system scope (--system, escalated)
mu, _ := pkg.New(pkg.Flatpak, r, pkg.WithUserScope()) // per-user (--user, unprivileged)

if fm, ok := m.(pkg.FlatpakManager); ok {
    fm.AddRemote(ctx, "flathub", "https://dl.flathub.org/repo/flathub.flatpakrepo")
    remotes, _ := fm.ListRemotes(ctx)
    fm.RemoveRemote(ctx, "flathub")
}
```

`AddRemote` validates the alias (`ValidateRemoteName`) and the URL
(`ValidateRepoBaseURL`, https only). Flatpak does not support traditional
version pinning, so `InstallOptions.Version` is validated but ignored for it.

## Types

```go
type InstallOptions struct {
    Version        string // pins a single package; requires exactly one name
    AllowDowngrade bool
}

type RemoveOptions struct {
    Purge bool // also remove config/data (apt purge / pacman -Rns / flatpak --delete-data)
}

type Package struct {
    Name, Version, Architecture, Description, Status, Repository string
    Size                                                         int64 // bytes
    Pinned                                                       bool
}

type PackageUpdate struct {
    Name, CurrentVersion, NewVersion, Architecture, Repository string
}

type VersionInfo struct {
    Name      string
    Versions  []AvailableVersion
    Installed string
}
```

## Supported Package Managers

| Backend | Systems | `Detect` binary | Pinning |
|---------|---------|-----------------|---------|
| `pkg.Apt` | Debian, Ubuntu, Mint | `apt-get` | `apt-mark hold/unhold` |
| `pkg.Dnf` | Fedora, RHEL 8+, CentOS Stream | `dnf` | `dnf versionlock` (plugin auto-installed) |
| `pkg.Pacman` | Arch, Manjaro | `pacman` | `IgnorePkg` in `/etc/pacman.conf` |
| `pkg.Zypper` | openSUSE, SLES | `zypper` | `zypper addlock/removelock` |
| `pkg.Flatpak` | Cross-distro | `flatpak` | `flatpak mask` |

## Argument-Hardening Validators

Every value that reaches a package-manager `argv` is validated against its
*intent* before the command runs. Package names and versions are checked inside
each method (there is no opt-out). The remaining exported validators are
**mandatory** at the argv boundaries they protect (the agent's executors call
them, and positionals are passed after an explicit `--` end-of-options separator
built with `exec.SeparatePositionals`, so a flag-shaped value can never be
reparsed as an option):

| Validator | Guards | Rule |
|-----------|--------|------|
| `ValidatePackageName` / `ValidatePackageNames` | apt/dnf/pacman/zypper/flatpak names | first char alphanumeric, then `[a-zA-Z0-9._+:/@~-]`, ≤256 |
| `ValidatePackageVersion` | `<name>=<version>` argv | cross-distro EVR grammar, empty = "no pin" |
| `ValidateRpmPackageName` | `rpm -q` / `rpm -e <NAME>` (NAME read off a crafted `.rpm`) | first char alphanumeric, then `[a-zA-Z0-9._+-]`, ≤256 |
| `ValidateRepoBaseURL` | dnf `baseurl` / zypper `url` / pacman `server` / flatpak remote URL | **https only**, host required, control-char free (template vars `$releasever`/`$arch` allowed). apt is excluded — its security is the gpg-signed Release file. |
| `ValidateGpgKeyRef` | dnf/zypper `gpgkey` passed to `rpm --import` | https URL, `file:///abs` path, or absolute path; no `..`, no leading `-`, no `http://`, no `ext::` |
| `ValidateRemoteName` | flatpak remote alias | first char alphanumeric, then `[a-zA-Z0-9._-]`, ≤128 |

In addition, pacman's `Pin` runs a stricter `[a-zA-Z0-9][a-zA-Z0-9._+-]*` gate
before a name is written to `IgnorePkg`, blocking config-injection even for
names that `ValidatePackageName` would accept.

## Testing

Because the Manager is built with an injected Runner, tests pass an
`exectest.FakeRunner`, script command results, and assert on the exact
`exec.Command`s the Manager built (argv, escalation, stdin) — no real package
manager is invoked:

```go
f := exectest.New(exec.Direct)
f.Push(exec.Result{Stdout: "..."}, nil)
m, _ := pkg.New(pkg.Apt, f)
m.Install(ctx, pkg.InstallOptions{}, "nginx")
// f.Calls()[0] is the recorded `apt install -y --fix-broken nginx`
```

## Notes

- **Non-interactive mode**: apt commands run with
  `DEBIAN_FRONTEND=noninteractive`; the C locale (`LANG=C`/`LC_ALL=C`) is forced
  on every command for stable English-only output parsing.
- **Version formats**: apt `1.24.0-1ubuntu1`, dnf `1.24.0-1.fc39`, pacman
  `1.24.0-1`, zypper `1.24.0-1.1`. Flatpak addresses bundles by application ID
  (e.g. `org.mozilla.firefox`) and has no version pin.
- **Pinning setup**: dnf auto-installs `python3-dnf-plugin-versionlock` on first
  use; pacman edits `/etc/pacman.conf` (root). apt/zypper need no setup.
```
