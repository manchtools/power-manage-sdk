---
title: Notifications
label: Notifications
description: Broadcast a message to logged-in users — all of them, or a named subset — via wall.
icon: "📢"
---

# Notifications

`sys/notify` sends a message to logged-in users — a maintenance heads-up, a
reboot warning — via `wall`.

## Construct a manager

```go
r, err := exec.NewRunner(exec.Sudo) // wall to all users needs root
if err != nil {
    return err
}
m, err := notify.New(r)
if err != nil {
    return err
}
```

## Broadcast

```go
err := m.NotifyAll(ctx, "Maintenance", "Rebooting in 5 minutes — save your work.")

// Or just specific users:
err = m.NotifyUsers(ctx, []string{"alice", "bob"}, "Heads up", "Your session ends soon.")
```

<!-- docref: begin src=sys/notify/notify.go#notifier.NotifyAll:13680e9e -->
`NotifyAll` broadcasts the message via `wall` to every logged-in user on a TTY
and, where a desktop session is reachable, as a desktop notification; the title
and body are handed to the tools as data rather than spliced into a shell
command.
<!-- docref: end -->

<!-- docref: begin src=sys/notify/notify.go#New:9cbfe737 -->
`New` returns the notifier over the injected Runner; a nil Runner is rejected.
The message is delivered through `wall`, so it reaches users on a TTY; the title
and body are passed as data, not spliced into a shell command.
<!-- docref: end -->

## Related

- [Desktop & sessions](/capabilities/desktop) — run a command in a user's
  graphical session, beyond a TTY broadcast.
- [Reboot](/capabilities/reboot) — `Schedule` already broadcasts its own wall
  message.
