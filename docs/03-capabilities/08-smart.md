---
title: Drive health
label: Drive health
description: Read S.M.A.R.T. disk health — scan devices and report health, temperature, and power-on hours — via smartctl.
icon: "🩺"
---

# Drive health

`sys/smart` reads S.M.A.R.T. disk health through `smartctl` (smartmontools): list
the inspectable devices, then read each one's health, temperature, and power-on
hours. It is a single-tool capability, so `New` takes only a Runner, no Backend.

## Construct a collector

```go
r, err := exec.NewRunner(exec.Sudo) // smartctl needs root to open a device
if err != nil {
    return err
}
c, err := smart.New(r)
if err != nil {
    return err
}
```

## Scan and read

```go
devs, err := c.Scan(ctx) // smartctl --scan: [{Name:"/dev/sda", Type:"sat"}, …]
for _, d := range devs {
    info, err := c.Device(ctx, d.Name)
    if err != nil {
        continue // a device that can't be inspected is surfaced as an error
    }
    fmt.Println(info.Name, info.Healthy, info.TemperatureC, info.PowerOnHours)
}
```

<!-- docref: begin src=sys/smart/smart.go#collector.Device:7abe0da4 -->
`Device` validates the device path (it must be a `/dev/*` path with no `..`
traversal) before running `smartctl`, then reads `smartctl -j -a`. smartctl
encodes failure in an exit-status *bitmask*, not just a non-zero exit, so
`Device` inspects the fatal bits: a device it could not inspect is returned as
an error rather than a bogus "healthy" reading.
<!-- docref: end -->

{% callout type="info" title="Needs real hardware" %}
A VM or container usually has no SMART-capable disk, so `Scan` returns an empty
list there. On real hardware you get the health bit (`smart_status.passed`),
temperature, and power-on hours.
{% /callout %}

## Related

- [Filesystem](/capabilities/filesystem) / [Disk encryption](/capabilities/encryption)
  — the storage layers above the physical drive.
