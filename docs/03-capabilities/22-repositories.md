---
title: Repositories
label: Repositories
description: Configure the package repositories a host installs from — apt, dnf, pacman, zypper — idempotently, with the right file format per backend.
icon: "🗄️"
---

# Repositories

`sys/repo` configures the external package repositories a host installs from. It
owns the per-backend file format (apt deb822 `.sources` + keyrings, dnf `.repo`,
pacman.conf sections, `zypper addrepo`), GPG public-key handling, and the
idempotency comparison — so you never hand-write a `.repo` file.

## Construct a manager

```go
r, err := exec.NewRunner(exec.Sudo) // writing repo config needs root
if err != nil {
    return err
}
m, err := repo.New(pkg.Dnf, r) // pkg.Apt / pkg.Dnf / pkg.Pacman / pkg.Zypper
if err != nil {
    return err
}
```

<!-- docref: begin src=sys/repo/repo.go#New:73121dda -->
`New` reuses the `pkg.Backend` enum and is fail-closed: a nil Runner or a
backend without native repository support (flatpak, the zero value) is
rejected. It is pure — it does not probe the host; use `pkg.Detect` to learn
which backends are installed.
<!-- docref: end -->

## Apply and remove

```go
out, err := m.Apply(ctx, repo.Repository{Name: "corp", Dnf: &repo.DnfConfig{
    BaseURL:  "https://packages.example.com/el9",
    GPGCheck: true,
    GPGKey:   "https://packages.example.com/RPM-GPG-KEY",
    Enabled:  true,
}})
// out.Changed is false on an idempotent no-op (the config already matched).

_, err = m.Remove(ctx, "corp") // idempotent: removing an absent repo is a no-op
```

<!-- docref: begin src=sys/repo/zypper.go#manager.removeZypper:1fdcf57a -->
`Remove` is idempotent even where the tool makes it tricky: `zypper removerepo`
exits 0 whether or not the alias existed, so the absent-repo no-op is detected
from its "not found" message rather than the exit code (`Changed: false`).
<!-- docref: end -->

<!-- docref: begin src=sys/repo/repo.go#manager.Apply:b7a6f4f5 -->
`Apply` validates the repository (name and the backend's config) before touching
the system, then writes the backend's native format and refreshes the index. It
is idempotent — an unchanged config reports `Changed: false` — so re-applying the
same desired state is safe and produces no spurious change events.
<!-- docref: end -->

{% callout type="info" title="GPG keys are public material" %}
<!-- docref: begin src=sys/repo/apt.go#updateAptKey:f3733dcc,sys/repo/dnf.go#manager.applyDnf:0bc9b98b -->
The signing keys here are *public* repository keys, not secrets. apt receives the
key bytes (dearmored into `/etc/apt/keyrings`); dnf and zypper take a key
reference (URL or path) the package manager imports — and dnf imports it only
when `GPGCheck` is on, so a key is never trusted system-wide while the
repository itself verifies nothing.
<!-- docref: end -->
{% /callout %}

## Related

- [Packages](/capabilities/packages) — install software from the repositories
  configured here.
- [Backends](/concepts/backends) — the `pkg.Backend` enum shared with `pkg`.
