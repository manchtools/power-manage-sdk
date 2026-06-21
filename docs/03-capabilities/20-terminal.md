---
title: Terminal
label: Terminal
description: Open an interactive PTY session as a target user — a real pseudo-terminal with a privilege drop.
icon: "⌨️"
---

# Terminal

`sys/terminal` opens an interactive pseudo-terminal session as a target user.
It is what a remote shell into a managed host is built on: it allocates a real
PTY and drops privilege to the requested account.

## Open a session

`terminal.New` takes no Runner — it performs the fork, PTY allocation, and
privilege drop itself:

```go
m, err := terminal.New()
if err != nil {
    return err
}
sess, err := m.Open(ctx, terminal.SessionConfig{
    User: "alice",
    Rows: 24,
    Cols: 80,
})
if err != nil {
    return err
}
// sess wires the PTY's input/output for the caller to stream.
```

<!-- docref: begin src=sys/terminal/terminal.go#manager.Open:392b4e8f -->
`Open` allocates a real pseudo-terminal and starts the user's shell behind it,
dropping privilege to the target account with `setresuid`/`setresgid` (and its
supplementary groups) before `exec` — so the shell runs with exactly that user's
identity, never root's. The requested rows/cols are validated and applied to the
PTY window size.
<!-- docref: end -->

{% callout type="warning" title="Interactive and privileged" %}
A terminal session is a live shell as another user. In the agent it is a signed,
authorized command for exactly this reason — gate who can open one.
{% /callout %}

## Related

- [Desktop & sessions](/capabilities/desktop) — run a *single* command as a
  user, when you don't need an interactive shell.
- [Identity](/capabilities/identity) — the accounts a terminal opens as.
