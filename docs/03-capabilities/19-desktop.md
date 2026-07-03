---
title: Desktop & sessions
label: Desktop & sessions
description: Enumerate desktop sessions and home users, and run a command as a specific user with their environment — a real privilege drop.
icon: "🖥️"
---

# Desktop & sessions

`sys/desktop` bridges system actions to individual users: list active graphical
sessions and home users, and run a command **as** one of them with that user's
environment.

## Construct a manager

```go
r, err := exec.NewRunner(exec.Sudo) // dropping to another user needs root
if err != nil {
    return err
}
m, err := desktop.New(r)
if err != nil {
    return err
}
```

## Enumerate users and sessions

```go
sessions, err := m.ActiveSessions(ctx)              // active local graphical sessions (loginctl)
users, err := m.HomeUsers(ctx)                      // accounts with a home under /home
flat, err := m.UsersWithFlatpakInstall(ctx, "org.example.App") // who has it installed
```

<!-- docref: begin src=sys/desktop/users.go#manager.HomeUsers:41afbbaf -->
`HomeUsers` enumerates accounts whose home lives directly under the configured
home root (default `/home`), confirming each against passwd — so a stale
`userdel`-without-`-r` directory is skipped rather than treated as a user.
<!-- docref: end -->

## Run commands as a user

```go
ru, err := desktop.RunAsRunner(r, session) // r is the root Runner
if err != nil {
    return err
}
// ru is an exec.Runner that executes AS the session's user — compose it like any
// other Runner, e.g. a per-user Flatpak manager:
fp, _ := pkg.New(pkg.Flatpak, ru, pkg.WithUserScope())
_, err = fp.Install(ctx, pkg.InstallOptions{Remote: "flathub"}, "org.x.App")
```

<!-- docref: begin src=sys/desktop/runas_runner.go#RunAsRunner:f70588a4 -->
`RunAsRunner` wraps a base Runner so every command it runs executes as the
session's user via `runuser`, with a per-user environment: `HOME`, `USER`,
`XDG_RUNTIME_DIR`, and the session bus address. `PATH` is always re-applied last
with a curated per-user value (the user's `~/.local/bin` first, never root's
`PATH`), so an action cannot override it. The base Runner must run as root —
`runuser` performs the privilege drop — and the caller's command env is screened
through the same hijack blocklist, so `LD_PRELOAD` and friends never leak into a
user-scoped command.
<!-- docref: end -->

{% callout type="info" title="It's a Runner, not a one-shot" %}
<!-- docref: begin src=sys/desktop/runas_runner.go#RunAsRunner:f70588a4 -->
`RunAsRunner` returns an `exec.Runner` you compose with any capability (a per-user
Flatpak manager, a script exec), so the privilege drop and environment are wired
in once and reused — no separate streaming pipeline to build.
<!-- docref: end -->
{% /callout %}

## Related

- [Identity](/capabilities/identity) — the user accounts these sessions belong to.
- [Notifications](/capabilities/notify) — a lighter-weight TTY broadcast.
