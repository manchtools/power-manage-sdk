---
title: Firewall
label: Firewall
description: Apply, remove, and list allow/deny packet-filter rules through nftables or firewalld.
icon: "🧱"
---

# Firewall

`sys/firewall` manages a small set of allow/deny rules — by protocol, port, and
source/destination — through nftables or firewalld. It owns a dedicated
namespace (an nftables table / a firewalld zone) so it never clobbers rules it
didn't create.

## Construct a manager

```go
r, err := exec.NewRunner(exec.Sudo) // rule changes need root
if err != nil {
    return err
}

for _, b := range firewall.Detect(ctx) { // Nftables if nft; Firewalld if firewall-cmd
    _ = b
}
m, err := firewall.New(firewall.Nftables, r)
if err != nil {
    return err
}
```

## Apply, remove, list rules

```go
err := m.ApplyRule(ctx, firewall.Rule{
    ID:       "allow-ssh",
    Allow:    true,
    Protocol: firewall.TCP,
    Port:     22,
    Source:   "10.0.0.0/8", // empty = any
})

err = m.RemoveRule(ctx, "allow-ssh")

rules, err := m.List(ctx) // only rules in this manager's namespace
```

<!-- docref: begin src=sys/firewall/firewall.go#Rule:ca82cb6a -->
A `Rule` is identified by a stable `ID` (used to remove or replace it), and is
either allow (`Allow: true`) or deny. `Protocol`/`Port`/`Source`/`Dest` narrow
what it matches; an empty `Source`/`Dest` or a zero `Port` means "any". Rules
are scoped to the manager's own namespace, so listing and removal never touch
the host's other firewall state.
<!-- docref: end -->

{% callout type="info" title="Round-trip fidelity" %}
`List` decodes each rule's full match — protocol, port, **and** source/destination
address — back out of the live ruleset, so what you read reflects exactly what
was applied. (An earlier nftables decoder dropped the source/destination on
read; that's covered now by a real-`nft` round-trip test.)
{% /callout %}

## Related

- [Network interfaces](/capabilities/netconfig) — addresses and routes the
  firewall rules reference.
- [Architecture](/concepts/architecture) — the Runner / Backend / Manager model.
