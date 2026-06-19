---
title: Backends & detection
label: Backends
description: How a capability's backend is chosen explicitly, how to discover what a host supports, and when a package uses a per-call interface instead.
---

# Backends & detection

A *backend* is one concrete way to do a job: `apt` vs `dnf` for packages,
`systemd` vs another init for services, `ca-certificates` vs `p11-kit` for CA
trust. Capabilities with more than one implementation take a `Backend` value
at construction.

## One backend per host, chosen explicitly

<!-- docref: begin src=sys/catrust/catrust.go#CaCertificates:15a42eb7 -->
A `Backend` is a small enum whose first real value is one (`iota + 1`), so its
zero value is intentionally invalid — there is no implicit default, and a
caller must name the backend it wants:
<!-- docref: end -->

```go
m, err := catrust.New(catrust.CaCertificates, r) // Debian/Ubuntu flow
// catrust.New(catrust.P11Kit, r)                // Fedora/RHEL/SUSE flow
```

An unrecognized backend is rejected at `New` with `ErrUnknownBackend` rather
than silently doing nothing — a capability gap is a loud, matchable error, not
a no-op.

## Discovering what a host supports

You usually know the target platform, but when you don't, `Detect` reports the
backends usable on *this* host so the caller can pick one:

<!-- docref: begin src=sys/catrust/detect.go#Detect:047f0669 -->
`Detect` probes the host (typically by looking for each backend's tools on
`PATH`) and returns the list of backends that are usable here. It reports what
is available; it does not choose or activate anything — the caller passes one
of the returned values to `New`.
<!-- docref: end -->

```go
backends := catrust.Detect(ctx)
if len(backends) == 0 {
    return errors.New("no CA-trust backend on this host")
}
m, err := catrust.New(backends[0], r)
```

Detection *informs* an explicit choice; it never silently swaps a backend
behind your back the way call-site auto-detection would.

## When a package uses a per-call interface instead

The `Backend`-enum shape fits "this host has exactly one right answer, fixed
for the process" — package managers, init systems, encryption tools.

`sys/remote` deliberately departs from it. An agent may fetch a tarball over
HTTPS, clone a Git repo, and read an S3 prefix in the same cycle, driven by
different actions — there is no single "active source" for the process. So
`sys/remote` exposes a `Source` interface with one constructor per kind
(`NewHTTP`, `NewGit`, `NewS3`), each validating its own config. The choice is
**per call**, not per host.

{% callout type="info" title="Rule of thumb" %}
If the answer to "which backend?" is *"whichever this machine has"* (one per
host, one per boot), it's a `Backend` enum passed to `New`. If it's
*"whatever the caller asked for this time"* (several concurrent, chosen per
call), it's an interface with a constructor per implementation.
{% /callout %}
