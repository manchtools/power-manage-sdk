---
title: Antivirus
label: Antivirus
description: Scan paths for malware, refresh signatures, and read engine/signature versions via ClamAV.
icon: "🛡️"
---

# Antivirus

`sys/antivirus` drives ClamAV: scan a path for malware, refresh the signature
database, and read the engine and signature versions. It is the
configure-and-operate half of AV management — on-access protection and cloud EDR
engines are out of scope.

## Construct a manager

```go
r, err := exec.NewRunner(exec.Sudo) // a full scan needs root to read every file
if err != nil {
    return err
}
m, err := antivirus.New(antivirus.ClamAV, r)
if err != nil {
    return err
}
```

## Scan

```go
res, err := m.Scan(ctx, "/home")
if err != nil {
    return err // an engine failure (not "found a virus")
}
if !res.Clean() {
    for _, inf := range res.Infected {
        fmt.Println(inf.File, inf.Signature)
    }
}
```

<!-- docref: begin src=sys/antivirus/clamav.go#clamavManager.Scan:a0689834 -->
`Scan` runs `clamscan` and reads its exit code the way ClamAV means it: `0` is
clean and `1` is "found something" — **neither is a failure**. Both parse the
`<file>: <signature> FOUND` lines into the result; only exit `2` (or a Runner
failure) is returned as an error. So a detected infection is a normal result you
inspect, not an error you handle.
<!-- docref: end -->

## Update signatures and read versions

```go
err := m.UpdateSignatures(ctx)      // freshclam — refresh the signature DB
ver, err := m.Version(ctx)          // engine + signature-DB versions
fmt.Println(ver.Engine, ver.Signature)
```

<!-- docref: begin src=sys/antivirus/clamav.go#clamavManager.UpdateSignatures:72c8afac -->
`UpdateSignatures` runs `freshclam` to refresh the signature database; a non-zero
exit surfaces as an error rather than being swallowed.
<!-- docref: end -->

{% callout type="info" title="Version needs a signature DB" %}
`Version` reports the engine *and* signature-database version, so it expects a
real ClamAV signature DB to be present. A freshly-installed ClamAV that has never
run `freshclam` has no signature version to report.
{% /callout %}

## Related

- [Architecture](/concepts/architecture) — the Runner / Backend / Manager model.
- [osquery](/capabilities/osquery) — host queries for a broader compliance posture.
