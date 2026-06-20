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

_, err = m.Remove(ctx, pkg.RemoveOptions{}, "telnet")
// Refresh the index and upgrade everything:
_, err = m.UpgradeAll(ctx, pkg.UpgradeOptions{})
// Or upgrade specific packages:
_, err = m.Upgrade(ctx, "openssl")
// Drop orphaned dependencies:
_, err = m.Autoremove(ctx)
```

Package names are passed as operands after a `--` separator, so a name that
begins with `-` can never be reinterpreted as a flag.

## Query installed state

Reads do not need escalation — a `Direct` Runner is enough:

```go
ok, err := m.IsInstalled(ctx, "curl")
ver, err := m.InstalledVersion(ctx, "curl") // "" when absent
n, err := m.InstalledCount(ctx)             // total installed packages
```

## Backends

<!-- docref: begin src=pkg/pkg.go#Backend:11393461 -->
The backend is fixed at construction and selected from an explicit set —
apt, dnf, pacman, zypper, and flatpak. The zero value is invalid; only
implemented backends exist, so there is no "unknown backend" that silently does
nothing.
<!-- docref: end -->

Behavioural differences the Manager smooths over but you should know about:

- **apt / dnf / zypper** refresh their index as part of an upgrade; **pacman**
  uses `-Sy` to sync the database first.
- **flatpak** installs are per-remote application IDs, not distro package names;
  use it for desktop apps, the distro backends for system packages.
- **dnf / zypper / apt** resolve dependencies automatically; `Autoremove`
  prunes what's no longer needed.

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
