---
title: Firewall
label: Firewall
description: Apply, remove, and list allow/deny packet-filter rules through nftables or firewalld.
icon: "🧱"
---

# Firewall

<!-- docref: begin src=sys/firewall/nftables.go#nftables:1d3ee6dd,sys/firewall/firewalld.go#firewalldServiceName:19892a3a -->
`sys/firewall` manages a small set of allow/deny rules — by protocol, port, and
source/destination — through nftables or firewalld. It owns a dedicated
namespace (a dedicated `inet <namespace>_filter` nftables table, or
`<namespace>-` prefixed firewalld service definitions in the default zone) so
it never clobbers rules it didn't create.
<!-- docref: end -->

## Construct a manager

```go
r, err := exec.NewRunner(exec.Sudo) // rule changes need root
if err != nil {
    return err
}

for _, b := range firewall.Detect(ctx) { // Nftables if nft; Firewalld if firewall-cmd
    _ = b
}
m, err := firewall.New(firewall.Nftables, "powermanage", r) // namespace isolates this app's tables/chains
if err != nil {
    return err
}
```

## Apply, remove, list rules

```go
err := m.ApplyRule(ctx, firewall.Rule{
    ID:       "allow-ssh",
    Allow:    true,
    Protocol: firewall.ProtocolTCP,
    Port:     22,
    Source:   "10.0.0.0/8", // empty = any
})

err = m.RemoveRule(ctx, "allow-ssh")

rules, err := m.List(ctx) // only rules in this manager's namespace
```

<!-- docref: begin src=sys/firewall/nftables.go#nftables.List:6b96ce82 -->
`List` decodes each rule's full match — protocol, port, **and** source/destination
address — back out of the live nftables ruleset, so what you read reflects
exactly what was applied. A namespace that was never provisioned (its table does
not exist yet) is reported as an explicit absence: `List` returns a wrapped
`fs.ErrNotExist`, never an empty slice, so you can't mistake "never set up" for
"set up, currently empty". Branch on it with `errors.Is(err, fs.ErrNotExist)`
when you want to treat a missing namespace as zero rules.
<!-- docref: end -->

<!-- docref: begin src=sys/firewall/firewall.go#Rule:ca82cb6a -->
A `Rule` is identified by a stable `ID` (used to remove or replace it), and is
either allow (`Allow: true`) or deny. `Protocol`/`Port`/`Source`/`Dest` narrow
what it matches; an empty `Source`/`Dest` or a zero `Port` means "any". Rules
are scoped to the manager's own namespace, so listing and removal never touch
the host's other firewall state.
<!-- docref: end -->

{% callout type="info" title="Backend scope" %}
<!-- docref: begin src=sys/firewall/firewalld.go#firewalldValidateRule:398b9411 -->
The **firewalld** backend is deliberately narrow in v1: allow rules with a
concrete protocol and port only. A deny rule or source/destination scoping is
rejected with `ErrInvalidRule` and a hint naming the unsupported field — use
the **nftables** backend for those.
<!-- docref: end -->
{% /callout %}

## Related

- [Network interfaces](/capabilities/netconfig) — addresses and routes the
  firewall rules reference.
- [Architecture](/concepts/architecture) — the Runner / Backend / Manager model.
