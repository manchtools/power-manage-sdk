---
title: Services
label: Services
description: Manage init units — enable, start, restart, mask, and install unit files — through systemctl behind one Manager.
icon: "⚙️"
---

# Services

`sys/service` manages init units behind a `Manager`. You name the init-system
`Backend` explicitly (currently systemd, driven through `systemctl`). It covers
the full lifecycle: query state, enable/start, write and remove unit files, and
mask a unit so nothing can start it.

## Construct a manager

```go
r, err := exec.NewRunner(exec.Sudo) // unit mutations need root
if err != nil {
    return err
}

if len(service.Detect(ctx)) == 0 {
    return errors.New("systemd not available on this host")
}
m, err := service.New(service.Systemd, r)
if err != nil {
    return err
}
```

<!-- docref: begin src=sys/service/service.go#Detect:2e00d699 -->
`Detect` reports whether the systemd backend is usable on this host; it lists,
it never picks. An empty result means there is no supported service manager —
the caller decides what to do, the SDK never guesses.
<!-- docref: end -->

<!-- docref: begin src=sys/service/service.go#New:91064f53 -->
`New` is fail-closed: only the implemented `Systemd` backend is accepted, and a
nil Runner is rejected, before a Manager is returned. The OpenRC/Runit/S6
scaffolds were deliberately removed rather than shipped half-working, so an
unimplemented backend is an explicit error, not a silent no-op.
<!-- docref: end -->

## Query unit state

<!-- docref: begin src=sys/service/systemd.go#systemd.query:f8774d53,sys/service/systemd.go#systemd.mutate:985e7091 -->
Reads are unprivileged — the query verbs run `systemctl` without escalation,
while every mutation goes through the escalated path:
<!-- docref: end -->

```go
st, err := m.Status(ctx, "sshd.service") // active state, sub-state, …
on, err := m.IsActive(ctx, "sshd.service")
en, err := m.IsEnabled(ctx, "sshd.service")
masked, err := m.IsMasked(ctx, "sshd.service")
```

## Enable, start, restart

```go
err := m.EnableNow(ctx, "nginx.service")  // enable + start in one step
err = m.Restart(ctx, "nginx.service")
err = m.Stop(ctx, "nginx.service")
err = m.DisableNow(ctx, "nginx.service")  // disable + stop
```

<!-- docref: begin src=sys/service/systemd.go#systemd.EnableNow:a4971314,sys/service/systemd.go#systemd.DisableNow:ae65bab2 -->
`EnableNow`/`DisableNow` fold the boot-time setting and the running state into a
single call so the unit's "should it run now" and "should it run at boot" never
drift apart in your code.
<!-- docref: end -->

## Install a unit file

```go
const unit = `[Unit]
Description=Power Manage agent
[Service]
ExecStart=/usr/bin/pm-agent
[Install]
WantedBy=multi-user.target
`
err := m.WriteUnit(ctx, "pm-agent.service", unit)
err = m.DaemonReload(ctx)            // re-read unit files
err = m.EnableNow(ctx, "pm-agent.service")
```

<!-- docref: begin src=sys/service/systemd.go#systemd.WriteUnit:cbdc6014,sys/service/unitcontent.go#ErrUnsafeUnitContent:ee7dfadb -->
`WriteUnit` validates the unit name *and* the unit body before the root-owned
file is created under `/etc/systemd/system/`. A unit runs as root under PID 1,
so content that would turn it into a dropper is refused with
`ErrUnsafeUnitContent`: an `Exec*` directive that shells out via `sh -c`, runs
a binary from a world-writable directory (`/tmp`, `/var/tmp`, `/dev/shm`), or
an `Environment=` that injects a dynamic-linker override (`LD_PRELOAD` and
friends).
<!-- docref: end -->

## Mask a unit

```go
err := m.Mask(ctx, "bluetooth.service")   // symlink to /dev/null — cannot start
err = m.Unmask(ctx, "bluetooth.service")
```

<!-- docref: begin src=sys/service/systemd.go#systemd.Mask:3c1e097a -->
Masking is stronger than disabling: `Mask` symlinks the unit to `/dev/null`, so
it cannot be started at all, even as a dependency of another unit. `Unmask`
reverses it.
<!-- docref: end -->

{% callout type="info" title="Reference" %}
The full method set is generated API docs on
[pkg.go.dev](https://pkg.go.dev/github.com/manchtools/power-manage-sdk/sys/service).
{% /callout %}

## Related

- [Reboot](/capabilities/reboot) — detect and schedule reboots after updates.
- [Architecture](/concepts/architecture) — the Runner / Backend / Manager model.
