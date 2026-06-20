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
    URL:    "https://releases.example.com/agent-2026.2.0.tar.gz",
    Sha256: "9f86d08…", // verified before the bytes are trusted
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
http, err := remote.NewHTTP(remote.HTTPConfig{URL: "https://…", Sha256: "…"})
git, err  := remote.NewGit(remote.GitConfig{URL: "https://…", Ref: "v1.2.3"})
s3, err   := remote.NewS3(remote.S3Config{Bucket: "artifacts", Key: "agent/latest"})
```

<!-- docref: begin src=sys/remote/http.go#NewHTTP:d4d3f602,sys/remote/git.go#NewGit:0a6c132d,sys/remote/s3.go#NewS3:8a5701dc -->
Each constructor validates its configuration up front and returns an error for a
malformed one, so a bad URL, missing checksum, or unusable S3 config fails at
construction rather than mid-download. The returned value is a `Source` — the
caller holds the interface, not the concrete client.
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
- [Packages](/capabilities/packages) / [Repositories](/capabilities/repositories)
  — install software from a managed source rather than fetching raw artifacts.
