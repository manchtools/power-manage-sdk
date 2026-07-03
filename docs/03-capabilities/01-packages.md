---
title: Packages
label: Packages
description: Install, remove, upgrade, and query software across apt, dnf, pacman, zypper, and flatpak behind one Manager.
icon: "📦"
---

# Packages

`pkg` manages software through the host's native package manager behind a single
`Manager` interface. One set of calls drives apt, dnf, pacman, zypper, or
flatpak — you pick the backend, the SDK speaks its dialect.

It follows the [architecture](/concepts/architecture): build a Runner, choose a
[Backend](/concepts/backends), get a Manager.

## Construct a manager

`pkg.Detect` reports which package managers are actually installed, so a caller
can pick one instead of guessing:

```go
r, err := exec.NewRunner(exec.Sudo) // package mutations need root
if err != nil {
    return err
}

backends := pkg.Detect(ctx) // e.g. [apt] on Debian, [dnf] on Fedora
if len(backends) == 0 {
    return errors.New("no supported package manager on this host")
}

m, err := pkg.New(backends[0], r)
if err != nil {
    return err
}
```

<!-- docref: begin src=pkg/pkg.go#Detect:374bb12a -->
`Detect` lists the backends whose tool is present on `PATH`; it never picks one
and never constructs a Manager — the caller reads the list, chooses explicitly,
and passes that choice to `New`. There is no hidden auto-detection.
<!-- docref: end -->

<!-- docref: begin src=pkg/pkg.go#New:e40499cf -->
`New` is pure and fail-closed: it validates the backend and rejects a nil
Runner before returning a Manager, and it does **not** probe the host. A
zero-value or unimplemented backend is an error, not a silent default — so a
misconfigured caller fails loudly at construction rather than mid-operation.
<!-- docref: end -->

## Install, remove, upgrade

Every mutation returns the command's `exec.Result` (exit code, stdout, stderr)
so a caller can surface exactly what the package manager did:

```go
res, err := m.Install(ctx, pkg.InstallOptions{}, "vim", "git")
if err != nil {
    return fmt.Errorf("install failed: %w", err)
}
fmt.Println(res.Stdout)

if _, err := m.Remove(ctx, pkg.RemoveOptions{}, "telnet"); err != nil {
    return err
}

// Refresh the index first on backends that need it (pacman's UpgradeAll
// already syncs in-transaction), then upgrade everything. A failed
// refresh must not fall through to the upgrade:
if _, err := m.Update(ctx); err != nil {
    return err
}
if _, err := m.UpgradeAll(ctx, pkg.UpgradeOptions{}); err != nil {
    return err
}

// Or upgrade specific packages:
if _, err := m.Upgrade(ctx, "openssl"); err != nil {
    return err
}

// Drop orphaned dependencies:
if _, err := m.Autoremove(ctx); err != nil {
    return err
}
```

<!-- docref: begin src=pkg/dnf.go#dnf.Install:24ff67e3 -->
Package names are passed as operands after a `--` separator, so a name that
begins with `-` can never be reinterpreted as a flag, and every mutation returns
the package manager's `exec.Result`.
<!-- docref: end -->

## Query installed state

<!-- docref: begin src=sys/exec/runner.go#Direct:ed029c0e,pkg/exec.go#runRead:cc3d492f -->
Reads never escalate — the query path runs each command without the privilege
wrapper, so a `Direct` Runner is enough:
<!-- docref: end -->

```go
ok, err := m.IsInstalled(ctx, "curl")
ver, err := m.InstalledVersion(ctx, "curl") // "" when absent
n, err := m.InstalledCount(ctx)             // total installed packages
```

<!-- docref: begin src=pkg/dnf.go#dnf.IsInstalled:28231b96,pkg/dnf.go#dnf.InstalledVersion:f0b1ff2e -->
The queries are unprivileged: `IsInstalled` reports whether a package is present,
and `InstalledVersion` returns its version or an empty string when it isn't
installed.
<!-- docref: end -->

## Backends

<!-- docref: begin src=pkg/pkg.go#Backend:11393461 -->
The backend is fixed at construction and selected from an explicit set —
apt, dnf, pacman, zypper, and flatpak. The zero value is invalid; only
implemented backends exist, so there is no "unknown backend" that silently does
nothing.
<!-- docref: end -->

Behavioural differences the Manager smooths over but you should know about:

<!-- docref: begin src=pkg/pkg.go#Manager:48758d2d,pkg/pacman.go#pacman.UpgradeAll:ac396816 -->
- `Update` is the explicit index refresh; `UpgradeAll` maps to the backend's
  full upgrade (`apt dist-upgrade` / `dnf upgrade` / `zypper dist-upgrade` /
  `flatpak update`) and does **not** re-sync the index first — except
  **pacman**, whose `-Syu` syncs the database and upgrades in one transaction
  (Arch does not support partial upgrades).
- `UpgradeOptions.SecurityOnly` narrows the upgrade to security updates where
  the backend supports it (apt / dnf / zypper); **pacman** and **flatpak** have
  no security-only concept and fail closed with `ErrSecurityOnlyUnsupported`
  rather than silently running a full upgrade.
- **flatpak** installs are per-remote application IDs, not distro package names;
  use it for desktop apps, the distro backends for system packages.
- `Upgrade` with an empty package list is a **no-op**, never a full upgrade —
  an accidentally-empty list must not upgrade the whole system; `UpgradeAll` is
  the explicit way to do that. `Autoremove` prunes no-longer-needed
  dependencies, and is a no-op on backends with no native equivalent.
<!-- docref: end -->

{% callout type="info" title="Reference" %}
The full method set and option fields are generated API docs on
[pkg.go.dev](https://pkg.go.dev/github.com/manchtools/power-manage-sdk/pkg).
This page is the task-oriented recipe; the reference lists the surface.
{% /callout %}

## Related

- Repositories (`sys/repo`) — configure the repositories these package managers
  install from.
- [Architecture](/concepts/architecture) — the Runner / Backend / Manager model.
- [Errors](/concepts/errors) — how failures are reported.
