---
title: Network interfaces
label: Network interfaces
description: Configure an interface's addressing — DHCP or static IPs, gateway, routes, MTU, DNS — and read it back.
icon: "🔌"
---

# Network interfaces

`sys/netconfig` configures a single interface's addressing: DHCP or static IPs,
a gateway, extra routes, MTU, and per-interface DNS. The read path parses real
`ip -j` (iproute2) JSON; the write path uses the `Backend` you name (currently
NetworkManager or systemd-networkd).

## Construct a manager

```go
r, err := exec.NewRunner(exec.Sudo) // applying interface config needs root
if err != nil {
    return err
}
m, err := netconfig.New(netconfig.NetworkManager, r)
if err != nil {
    return err
}
```

## Read an interface

The read path is unprivileged (`ip -j addr/route show`):

```go
cfg, err := m.Get(ctx, "eth0")
fmt.Println(cfg.Addresses, cfg.Gateway, cfg.Routes)
```

<!-- docref: begin src=sys/netconfig/ip.go#base.Get:19ab7d19 -->
`Get` parses `ip -j addr`/`route` JSON for the interface, so the read path is the
same unprivileged iproute2 query regardless of which write backend you chose.
<!-- docref: end -->

## Apply addressing

```go
// Static:
err := m.Apply(ctx, netconfig.InterfaceConfig{
    Name:      "eth0",
    Mode:      netconfig.Static,
    Addresses: []string{"192.0.2.10/24"},
    Gateway:   "192.0.2.1",
    DNS:       []string{"1.1.1.1"},
    MTU:       1500,
})

// DHCP:
err = m.Apply(ctx, netconfig.InterfaceConfig{Name: "eth0", Mode: netconfig.DHCP})
```

<!-- docref: begin src=sys/netconfig/netconfig.go#InterfaceConfig:ad3f8ece -->
`Mode` (DHCP or Static) governs addressing only and is required. `Addresses`
and `Gateway` apply in static mode (the gateway's family must match an address);
`DNS`, `MTU`, and `Routes` apply in both modes. A static config with no
addresses, or a gateway in a family no address covers, is rejected before any
change is made.
<!-- docref: end -->

{% callout type="info" title="DNS lives in two places" %}
`InterfaceConfig.DNS` sets resolvers on the interface as a convenience.
Host-wide DNS policy — global nameservers, search domains — is the proper job of
[`sys/dns`](/capabilities/dns).
{% /callout %}

## Related

- [DNS](/capabilities/dns) — host-global resolver configuration.
- [Wi-Fi](/capabilities/network) — Wi-Fi profiles (the wireless side of
  networking).
