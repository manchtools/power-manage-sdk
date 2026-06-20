---
title: Identity
label: Identity
description: Manage Linux users and groups — create, modify, lock, set passwords (without leaking them), and manage group membership.
icon: "👤"
---

# Identity

`sys/user` manages local Linux accounts and groups through the shadow-utils
tools (`useradd`, `usermod`, `gpasswd`, …) behind one `Manager`. Password
material is handled as an [`exec.Secret`](/concepts/architecture) so it never
lands on a command line.

## Construct a manager

User mutations need root, so build an escalating Runner:

```go
r, err := exec.NewRunner(exec.Sudo)
if err != nil {
    return err
}
m, err := user.New(user.ShadowUtils, r)
if err != nil {
    return err
}
```

<!-- docref: begin src=sys/user/user.go#New:97cb2f96 -->
`New` is fail-closed: it rejects an unknown backend and a nil Runner before
returning a Manager, so a misconfigured caller fails at construction rather than
on the first account operation.
<!-- docref: end -->

## Create, modify, delete

```go
err := m.Create(ctx, "deploy", user.CreateOptions{
    System:  true,
    Shell:   "/usr/sbin/nologin",
    Comment: "deployment service account",
})

err = m.Modify(ctx, "deploy", user.ModifyOptions{Shell: "/bin/bash"})

ok, err := m.Exists(ctx, "deploy")
info, err := m.Get(ctx, "deploy") // uid, gid, home, shell, …

err = m.Delete(ctx, "deploy", user.DeleteOptions{RemoveHome: true})
```

<!-- docref: begin src=sys/user/user.go#shadowUtils.Create:e0468cf4 -->
`Create` drives `useradd` through the escalated Runner. A system account
(`System: true`) defaults to a `nologin` shell, so a service account can't be
logged into by accident.
<!-- docref: end -->

## Passwords are secrets, not arguments

`SetPassword` takes an `exec.Secret`, not a string:

```go
pw, err := exec.NewSecret("correct horse battery staple")
if err != nil {
    return err // rejects a newline-bearing password (would break chpasswd)
}
err = m.SetPassword(ctx, "deploy", pw)
```

<!-- docref: begin src=sys/exec/secret.go#NewSecret:23b7677a -->
`NewSecret` rejects a value containing a newline or carriage return: such a value
fed to `chpasswd` on stdin would split into a second record and set a password
for an unintended account, so it is refused at construction. (For credentials
written verbatim to a file, where newlines are legitimate payload, use
`NewMultilineSecret`.)
<!-- docref: end -->

<!-- docref: begin src=sys/user/password.go#shadowUtils.SetPassword:acf8cd55 -->
`SetPassword` feeds `name:secret` to `chpasswd` on **stdin** — the password
never appears in the process's argv, where any other process could read it from
`/proc/<pid>/cmdline`. The `Reveal` call here is the single sanctioned sink for
the secret, enforced by a fitness function.
<!-- docref: end -->

<!-- docref: begin src=sys/exec/secret.go#Secret:0e14e52a -->
An `exec.Secret` wraps sensitive material so it cannot leak by accident. Its
`String`/`GoString` render as `[REDACTED]`, so it never appears in logs, panics,
or `%v` formatting; the real value is reachable only through an explicit
`Reveal`. For a password that means one call site (here, fed to `chpasswd` on
stdin, never on argv where another process could read it from `/proc`).
<!-- docref: end -->

Other account-state operations:

```go
err := m.Lock(ctx, "deploy")          // disable login
err = m.Unlock(ctx, "deploy")
err = m.ExpirePassword(ctx, "deploy") // force a change at next login
err = m.KillSessions(ctx, "deploy")   // terminate the user's processes
```

## Groups and membership

```go
err := m.GroupEnsure(ctx, "docker")      // create if absent (idempotent)
err = m.AddToGroup(ctx, "deploy", "docker")
err = m.RemoveFromGroup(ctx, "deploy", "docker")

members, err := m.GroupMembers(ctx, "docker")
primary, err := m.PrimaryGroup(ctx, "deploy")
groups, err := m.SupplementaryGroups(ctx, "deploy")
```

<!-- docref: begin src=sys/user/group.go#shadowUtils.GroupEnsure:b1136668 -->
`GroupEnsure` is idempotent: it creates the group only if it isn't already
present, so it is safe to call on every reconcile.
<!-- docref: end -->

{% callout type="info" title="Reference" %}
The full method set and option fields are generated API docs on
[pkg.go.dev](https://pkg.go.dev/github.com/manchtools/power-manage-sdk/sys/user).
{% /callout %}

## Related

- [Architecture](/concepts/architecture) — Runner / Backend / Manager, and why
  passwords are injected as `exec.Secret`.
- Desktop & sessions (`sys/desktop`) — run a command as one of these users in
  their desktop session.
