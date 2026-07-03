---
title: Disk encryption
label: Disk encryption
description: Manage LUKS volumes — detect encryption, add/remove/kill key slots, verify passphrases — with all key material handled as secrets.
icon: "🔒"
---

# Disk encryption

`sys/encryption` manages LUKS volumes via `cryptsetup`: detect whether a device
is encrypted, manage its key slots, and verify passphrases. Every piece of key
material is an [`exec.Secret`](/concepts/architecture).

## Construct a manager

```go
r, err := exec.NewRunner(exec.Sudo) // cryptsetup needs root
if err != nil {
    return err
}
m, err := encryption.New(encryption.LUKS, r)
if err != nil {
    return err
}
```

## Detect and verify

```go
enc, err := m.IsEncrypted(ctx, "/dev/sda2")
ok, err := m.VerifyPassphrase(ctx, "/dev/sda2", existing) // existing is an exec.Secret
vol, err := m.DetectVolume(ctx)                            // the system's LUKS volume
```

<!-- docref: begin src=sys/encryption/luks.go#luks.VerifyPassphrase:55af258e -->
`VerifyPassphrase` is a read-only probe: a wrong passphrase returns
`(false, nil)`, not an error, so testing a guess never looks like a failure.
<!-- docref: end -->

## Manage key slots

```go
existing, _ := exec.NewSecret("current passphrase")
newKey, _   := exec.NewSecret("rotated passphrase")

err := m.AddKey(ctx, "/dev/sda2", existing, newKey, encryption.AddKeyOptions{})
err = m.RemoveKey(ctx, "/dev/sda2", newKey)
err = m.KillSlot(ctx, "/dev/sda2", 3, existing) // slot index 0..7
```

<!-- docref: begin src=sys/encryption/encryption.go#New:ba4f9552 -->
`New` validates the backend (only `LUKS` is implemented) and rejects a nil
Runner before returning a Manager.
<!-- docref: end -->

The key-slot operations take their key material as `exec.Secret`, so a passphrase
is never rendered into a log or a panic:

<!-- docref: begin src=sys/encryption/luks.go#luks.AddKey:ba80fabe -->
`AddKey` rejects empty key material up front (`ErrEmptyKeyMaterial`) — both an
empty new key (which would create an empty-passphrase unlock slot) and an empty
authenticating passphrase — before `cryptsetup` is ever run.
<!-- docref: end -->

{% callout type="warning" title="Key-slot operations are destructive" %}
<!-- docref: begin src=sys/encryption/luks.go#luks.KillSlot:8e6852ce,sys/encryption/luks.go#luks.RemoveKey:b9040d71 -->
`KillSlot` erases a specific key slot, authenticating with an existing
passphrase; `RemoveKey` removes the slot matching a passphrase.
Removing the last usable key makes the volume unopenable — the SDK validates
inputs, but the *policy* of which slot is safe to remove is the caller's.
<!-- docref: end -->
{% /callout %}

## Related

- [Filesystem](/capabilities/filesystem) — read/write the mounted volume once
  it's open.
- [Architecture](/concepts/architecture) — why key material is `exec.Secret`.
