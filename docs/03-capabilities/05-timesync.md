---
title: Time sync
label: Time sync
description: Read the host's time-synchronization status via systemd-timesyncd (timedatectl) or chrony.
icon: "🕐"
---

# Time sync

`sys/timesync` reports whether the host's clock is synchronized, through
systemd's `timedatectl` or `chronyc`.

## Construct a manager

```go
r, err := exec.NewRunner(exec.Direct) // status is an unprivileged read
if err != nil {
    return err
}
for _, b := range timesync.Detect(ctx) { // Timedatectl and/or Chrony
    _ = b
}
m, err := timesync.New(timesync.Timedatectl, r)
if err != nil {
    return err
}
```

## Read status

```go
st, err := m.Status(ctx)
fmt.Println(st.Synchronized) // is the clock in sync?
```

<!-- docref: begin src=sys/timesync/timesync.go#New:021d678b -->
`New` validates the backend and rejects a nil Runner. The two backends report
slightly different things: Timedatectl reports synchronized plus whether the
time service is enabled; Chrony reports synchronized plus the reference source.
Both answer the core question — *is this clock trustworthy?*
<!-- docref: end -->

## Related

- [Services](/capabilities/services) — enable/start the time-sync daemon itself.
- [Logs](/capabilities/log) — correlate events once the clock is trusted.
