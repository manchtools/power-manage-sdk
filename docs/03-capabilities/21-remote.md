---
title: Remote sources
label: Remote sources
description: Fetch artifacts over HTTPS, Git, or S3 through a per-call Source interface, into a confined destination on disk.
icon: "📥"
---

# Remote sources

`sys/remote` fetches an artifact — a release tarball, a config repo, a signed
blob — from HTTPS, Git, or S3. It is the one capability that does **not** take a
Runner: there is no host tool to drive, so each source is a small Go client you
construct per call and ask to `Fetch`.

## The Source interface

<!-- docref: begin src=sys/remote/remote.go#Source:2cfeaa37 -->
Every backend implements one method: `Fetch(ctx, dest)` downloads the source's
content into `dest` and returns a `Result`. You build the `Source` for the
transport you want (HTTPS / Git / S3) and call `Fetch` — the shape is identical
regardless of where the bytes come from.
<!-- docref: end -->

```go
src, err := remote.NewHTTP(remote.HTTPConfig{
    URL:            "https://releases.example.com/agent-2026.2.0.tar.gz",
    ChecksumSHA256: "9f86d08…", // verified before the bytes are trusted
})
if err != nil {
    return err
}
res, err := src.Fetch(ctx, "/var/lib/power-manage/release")
if err != nil {
    return err
}
_ = res
```

## Three transports

```go
http, err := remote.NewHTTP(remote.HTTPConfig{URL: "https://…", ChecksumSHA256: "…"})
git, err  := remote.NewGit(remote.GitConfig{URL: "https://…", Ref: "v1.2.3"})
s3, err   := remote.NewS3(remote.S3Config{Bucket: "artifacts", Key: "agent/latest"})
```

<!-- docref: begin src=sys/remote/http.go#NewHTTP:9089d62f,sys/remote/git.go#NewGit:0a6c132d,sys/remote/s3.go#NewS3:78a4b3e6 -->
Each constructor validates its configuration up front and returns an error for a
malformed one, so a bad URL, missing checksum, or unusable S3 config fails at
construction rather than mid-download. The returned value is a `Source` — the
caller holds the interface, not the concrete client.
<!-- docref: end -->

## Following redirects

<!-- docref: begin src=sys/remote/http.go#RedirectSameOrigin:9f1477bb,sys/remote/http.go#RedirectCrossOrigin:9f1477bb -->
By default an HTTP fetch follows only same-origin redirects: a hop that changes
host or scheme is refused. A source behind a CDN that bounces to another host —
GitHub release downloads redirect `github.com` to
`release-assets.githubusercontent.com` — needs `RedirectCrossOrigin`:
<!-- docref: end -->

```go
src, err := remote.NewHTTP(remote.HTTPConfig{
    URL:            "https://github.com/org/app/releases/download/v1/app-linux-amd64",
    ChecksumSHA256: "9f86d08…",          // integrity rests on the pin, not the host
    Redirect:       remote.RedirectCrossOrigin,
})
```

<!-- docref: begin src=sys/remote/http.go#RedirectPolicy:1f1fa7c7,sys/remote/http.go#redirectPolicy:a59120a4 -->
`Redirect` selects one of three ordered levels. `RedirectSameOrigin` — the zero
value — follows only same-scheme, same-host redirects. `RedirectNone` refuses
every redirect. `RedirectCrossOrigin` additionally follows host changes and
`http → https` upgrades, leaving integrity to the `ChecksumSHA256` pin rather
than to host-pinning. At every level an `https → http` downgrade is refused — a
redirect must never strip TLS — and the chain is bounded to 10 hops. The policy
governs the default client only; a caller-supplied `Client` owns its own.
<!-- docref: end -->

## Fetch into memory

<!-- docref: begin src=sys/remote/fetch_bytes.go#FetchBytes:c8e91045 -->
When the payload is small and you want the bytes in hand rather than a file on
disk — a `SHA256SUMS` manifest, a GPG key, a short JSON descriptor — `FetchBytes`
fetches an HTTPS source into memory and returns the bytes:
<!-- docref: end -->

```go
data, err := remote.FetchBytes(ctx, remote.HTTPConfig{
    URL:            "https://releases.example.com/SHA256SUMS",
    ChecksumSHA256: "9f86d08…", // optional; verified before the bytes are returned
})
```

<!-- docref: begin src=sys/remote/fetch_bytes.go#FetchBytes:c8e91045 -->
`FetchBytes` applies the same guards as `Fetch` — URL/scheme validation, the size
cap, and the optional sha256 pin — but bounded for RAM because the whole body is
buffered. The cap defaults to 64 MiB (not the 2 GiB file default) unless you
raise `MaxBytes`; a body past the cap fails closed with `ErrIntegrity` and
returns no data. A set `ChecksumSHA256` is verified before the bytes are handed
back, and the archive-oriented `Extract` / `Prune` options are rejected — they
have no meaning for a single in-memory payload. It is for small payloads; use
`Fetch` (streamed, atomic, to a file) for large artifacts.
<!-- docref: end -->

## Destinations are confined

The destination is not a free-for-all path. `Fetch` refuses to write outside the
locations the SDK is allowed to manage:

<!-- docref: begin src=sys/remote/paths.go#validateDestination:e25e0621 -->
A destination is rejected unless it falls under a managed root (e.g.
`/var/lib/power-manage`, `/etc/power-manage`); a write that would land in a
sensitive system location — `/etc/cron.d`, `/usr/bin`, a user's `~/.ssh` — is
refused before any bytes are fetched. The check is a subtree test with a
trailing-slash boundary, so `/etc/power-manage-evil` cannot masquerade as being
under `/etc/power-manage`.
<!-- docref: end -->

{% callout type="info" title="Reference" %}
Config fields and the `Result` shape are generated API docs on
[pkg.go.dev](https://pkg.go.dev/github.com/manchtools/power-manage-sdk/sys/remote).
See also [Backends](/concepts/backends) for the per-call Source model vs. the
Runner/Backend model the other capabilities use.
{% /callout %}

## Related

- [Backends](/concepts/backends) — why `remote` is per-call `Source` rather than
  a Runner-driven Manager.
- [Packages](/capabilities/packages) — install software from a managed source
  rather than fetching raw artifacts.
