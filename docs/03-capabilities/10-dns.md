---
title: DNS
label: DNS
description: Read and apply a host's resolver configuration (nameservers and search domains) via systemd-resolved or NetworkManager.
icon: "🧭"
---

# DNS

`sys/dns` reads and configures the host resolver (nameservers and search
domains) through systemd-resolved or NetworkManager.

## Construct a manager

```go
r, err := exec.NewRunner(exec.Sudo) // Apply mutates resolver config; root
if err != nil {
    return err
}

for _, b := range dns.Detect(ctx) { // Resolved if resolvectl present; NM if nmcli
    _ = b
}
m, err := dns.New(dns.Resolved, r)
if err != nil {
    return err
}
```

<!-- docref: begin src=sys/dns/dns.go#New:36342405 -->
`New` validates the backend and rejects a nil Runner up front; the zero-value
and any unimplemented backend are `ErrUnknownBackend`. It is pure: it does not
probe the host, so use `Detect` to learn which backends are usable here.
<!-- docref: end -->

## Read the active resolver

```go
st, err := m.Get(ctx)
fmt.Println(st.Nameservers, st.SearchDomains)
```

<!-- docref: begin src=sys/dns/resolved.go#resolvedManager.Get:e72d8b51 -->
`Get` reads systemd-resolved's generated `resolv.conf` and parses the active
nameservers and search domains out of it, so it reflects what the resolver is
actually using, not just what was last applied.
<!-- docref: end -->

## Apply a configuration

```go
err := m.Apply(ctx, dns.Config{
    Nameservers:   []string{"1.1.1.1", "2606:4700:4700::1111"},
    SearchDomains: []string{"corp.example"},
    // Interface: "eth0", // scope to one link; empty = host-global (Resolved only)
})
```

<!-- docref: begin src=sys/dns/resolved.go#resolvedManager.Apply:8a4c7c2d -->
`Apply` validates the whole `Config` (rejecting non-IP nameservers, malformed or
flag-shaped search domains, and bad interface names) *before* it touches any
backend, so an invalid configuration has no side effects. On the Resolved
backend a host-global apply (empty `Interface`) writes the managed
`resolved.conf.d` drop-in and restarts the service; a set `Interface` uses
per-link runtime settings.
<!-- docref: end -->

{% callout type="info" title="Backend scope" %}
The **Resolved** backend supports host-global config (empty `Interface`).
**NetworkManager** is connection-scoped — it configures DNS on a specific
interface's active connection, so `Interface` is required there. For host-wide
DNS, use Resolved.
{% /callout %}

## Related

- [Network interfaces](/capabilities/netconfig) — IP/routing config, which also
  carries per-interface DNS.
- [Architecture](/concepts/architecture) — the Runner / Backend / Manager model.
