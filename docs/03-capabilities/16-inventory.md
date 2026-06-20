---
title: Inventory
label: Inventory
description: Collect structured hardware and software facts — CPU, memory, OS, disks, network interfaces — from the running host.
icon: "📋"
---

# Inventory

`sys/inventory` reports structured facts about the host: CPU and memory, the OS
release, block devices, and network interfaces. It is a read-only, single-tool
capability, so `New` takes only a Runner, no Backend.

## Construct a collector

```go
r, err := exec.NewRunner(exec.Direct) // reads are unprivileged
if err != nil {
    return err
}
c, err := inventory.New(r)
if err != nil {
    return err
}
```

## Collect facts

```go
sys, err := c.System(ctx)             // hostname, CPU model/cores, total memory, kernel
os, err := c.OS()                     // distro ID, name, version, arch
disks, err := c.Disks(ctx)            // block devices (lsblk)
ifaces, err := c.NetworkInterfaces(ctx) // interfaces + addresses (ip -j)
```

<!-- docref: begin src=sys/inventory/inventory.go#New:5a179869 -->
`New` returns the Collector over the injected Runner; a nil Runner is rejected.
The collectors read the host directly — `/proc/cpuinfo` and `/proc/meminfo`,
`/etc/os-release`, `lsblk --json`, `ip -j addr` — so the facts reflect the live
system, not a cached snapshot.
<!-- docref: end -->

{% callout type="info" title="Reads, not changes" %}
Inventory is purely observational; nothing here mutates the host. Combine it
with the action capabilities to decide *what* to change based on *what's there*.
{% /callout %}

## Related

- [osquery](/capabilities/osquery) — ad-hoc SQL queries when the fixed inventory
  facts aren't enough.
- [Drive health](/capabilities/smart) — SMART health for the disks inventory
  lists.
