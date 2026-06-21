---
title: CA trust
label: CA trust
description: Install, remove, and list system CA trust anchors via update-ca-certificates or p11-kit.
icon: "📜"
---

# CA trust

`sys/catrust` manages the system's CA trust store — the anchors every TLS client
on the host validates against. Install a corporate root, remove one, list what's
trusted, across the Debian (`update-ca-certificates`) and Red Hat / SUSE
(`p11-kit`) flows.

## Construct a manager

```go
r, err := exec.NewRunner(exec.Sudo) // writing the trust store needs root
if err != nil {
    return err
}
for _, b := range catrust.Detect(ctx) { // CaCertificates and/or P11Kit
    _ = b
}
m, err := catrust.New(catrust.CaCertificates, r)
if err != nil {
    return err
}
```

<!-- docref: begin src=sys/catrust/detect.go#Detect:0d85bd62 -->
`Detect` reports the trust-store backends usable on this host: `CaCertificates`
or `SuseCaCertificates` when `update-ca-certificates` is on `PATH` (the two are
disambiguated by the anchors directory — Debian vs openSUSE), and `P11Kit` when
`update-ca-trust` is. A caller picks the flow this host actually supports.
<!-- docref: end -->

## Install, remove, list

```go
err := m.Install(ctx, "corp-root", certPEM) // certPEM is one PEM certificate
err = m.Remove(ctx, "corp-root")
anchors, err := m.List(ctx) // the trusted anchors this manager can see
```

<!-- docref: begin src=sys/catrust/catrust.go#manager.Install:c6b15d2f -->
`Install` writes the anchor under the backend's local-anchors directory and runs
the store-rebuild tool (`update-ca-certificates` / `update-ca-trust`) so the new
root takes effect host-wide. The name identifies the anchor for later removal,
and the certificate is validated as a single PEM certificate before it is
written.
<!-- docref: end -->

{% callout type="warning" title="Trust is host-wide" %}
A CA installed here is trusted by *every* TLS client on the host. Install only
roots you control; a rogue anchor silently validates a man-in-the-middle.
{% /callout %}

## Related

- [Backends](/concepts/backends) — `catrust` is the worked example of the
  `Backend` + `Detect` model.
- [Remote sources](/capabilities/remote) — HTTPS fetches that validate against
  this trust store.
