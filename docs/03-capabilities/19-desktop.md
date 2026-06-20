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

## Run a command as a user

```go
cmd, err := m.RunAsCommand(ctx, session, desktop.RunAsOptions{}, "flatpak", "update", "-y")
if err != nil {
    return err
}
out, err := cmd.Output() // runs as the session's user
```

<!-- docref: begin src=sys/desktop/runas.go#manager.RunAsCommand:c91323e7 -->
`RunAsCommand` builds (but does not run) a command that executes as the session's
user via `runuser`, with a per-user environment: `HOME`, `USER`, `XDG_RUNTIME_DIR`,
and the session bus address. `PATH` is always re-applied last with a curated
per-user value (the user's `~/.local/bin` first, never root's `PATH`), so an
action cannot override it. The agent's own environment is replaced wholesale —
`LD_PRELOAD` and friends never leak into a user-scoped command.
<!-- docref: end -->

{% callout type="info" title="It returns a command, doesn't run it" %}
`RunAsCommand` returns an `*exec.Cmd` you run yourself, so you control streaming,
stdin, and output capture. The privilege drop and environment are already wired
in.
{% /callout %}

## Related

- [Identity](/capabilities/identity) — the user accounts these sessions belong to.
- [Notifications](/capabilities/notify) — a lighter-weight TTY broadcast.
