---
title: Filesystem
label: Filesystem
description: Read, write, and manage files and directories with permissions and ownership — TOCTOU-safe, never following a symlink out of bounds.
icon: "💾"
---

# Filesystem

`sys/fs` is the SDK's file primitive: read, write, copy, remove, set
mode/ownership, and remount-rw — done safely. It is a single-tool capability, so
`New` takes only a Runner, no Backend.

## Construct a manager

```go
r, err := exec.NewRunner(exec.Sudo) // writes to root-owned paths need root
if err != nil {
    return err
}
m, err := fs.New(r)
if err != nil {
    return err
}
```

## Read and write

```go
data, err := m.ReadFile(ctx, "/etc/hostname")
err = m.WriteFile(ctx, "/etc/power-manage/agent.conf", []byte(cfg), fs.WriteOptions{
    Mode:  0o644,
    Owner: "root",
    Group: "root",
})
ok, err := m.Exists(ctx, "/etc/power-manage")
entries, err := m.ReadDir(ctx, "/etc/power-manage")
```

<!-- docref: begin src=sys/fs/write.go#manager.WriteFile:d23eed7b -->
`WriteFile` creates or replaces the file and applies the requested mode, owner,
and group in one call, through the same privilege-keyed safe backend described
below.
<!-- docref: end -->

## Directories, permissions, ownership

```go
err := m.Mkdir(ctx, "/var/lib/power-manage/state", fs.MkdirOptions{Mode: 0o750, Recursive: true})
err = m.SetMode(ctx, "/var/lib/power-manage/state", 0o700)
err = m.SetOwnership(ctx, "/var/lib/power-manage/state", "power-manage", "power-manage")
err = m.Remove(ctx, "/var/lib/power-manage/state/stale.tmp")
```

## Why use this instead of `os`

<!-- docref: begin src=sys/fs/fs.go#New:3ac54444 -->
`New` returns the filesystem Manager over the injected Runner; a nil Runner is
rejected.
<!-- docref: end -->

<!-- docref: begin src=sys/fs/fs.go#manager.direct:9e4adeb0 -->
The operations are privilege-backend-keyed: as root (a `Direct` Runner) they
take a TOCTOU-safe, fd-anchored path — each step operates on an open directory
handle, so a symlink swapped in mid-operation can't redirect a write or delete
out of bounds; when escalation is via sudo, the same operations are driven
through the escalated tool.
<!-- docref: end -->

{% callout type="info" title="Read-only roots" %}
<!-- docref: begin src=sys/fs/mount.go#manager.IsReadOnly:1edb9acd,sys/fs/mount.go#manager.RemountRW:3eadcb2c,sys/fs/protected.go#IsUnderProtectedPrefix:4231d9a0 -->
`IsReadOnly` (an unprivileged `findmnt` probe) and `RemountRW` (an escalated
`mount -o remount,rw`) handle the immutable-root case (ostree, a read-only
`/usr`): check, remount read-write for the change. There is no remount-ro
helper — restoring the read-only state afterwards is the caller's job.
Mutations refuse to write into protected system subtrees they don't own.
<!-- docref: end -->
{% /callout %}

## Related

- [Architecture](/concepts/architecture) — the injected Runner this builds on.
- [Remote sources](/capabilities/remote) — fetch a file from HTTPS/Git/S3 into a
  managed path.
