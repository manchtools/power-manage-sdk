---
title: Reboot
label: Reboot
description: Detect whether a reboot is needed after updates, and schedule or cancel one via shutdown.
icon: "🔁"
---

# Reboot

`sys/reboot` answers two questions a patching workflow needs — does this host
need a reboot, and how to schedule one (politely) when it does.

## Construct a manager

```go
r, err := exec.NewRunner(exec.Sudo) // scheduling a reboot needs root
if err != nil {
    return err
}
rb, err := reboot.New(r)
if err != nil {
    return err
}
```

## Is a reboot required?

The probe is unprivileged, so a `Direct` Runner is enough to *read*:

```go
need, err := rb.IsRequired(ctx)
if need {
    // a package update left the host needing a restart
}
```

<!-- docref: begin src=sys/reboot/reboot.go#rebooter.IsRequired:acb46152 -->
`IsRequired` checks the Debian/Ubuntu `/var/run/reboot-required` marker and, on
RHEL/Fedora, `needs-restarting -r`. A host with neither signal returns
`(false, nil)` — the *absence* of a detection mechanism is not an error. Only a
genuinely unexpected condition (a non-ENOENT stat error, or a `needs-restarting`
run failure that isn't "tool absent") surfaces as an error, so a caller can tell
"no reboot needed" from "I couldn't tell."
<!-- docref: end -->

## Schedule and cancel

```go
err := rb.Schedule(ctx, reboot.ScheduleOptions{
    Delay:   "+5",                     // shutdown(8) TIME spec
    Message: "Patching — back in 5m",  // broadcast to logged-in users
})

// Changed your mind:
err = rb.Cancel(ctx)
```

<!-- docref: begin src=sys/reboot/reboot.go#ScheduleOptions:b3cc2d01 -->
`ScheduleOptions.Delay` is a `shutdown(8)` TIME spec (`"+5"`, `"now"`,
`"23:00"`); an empty `Delay` defaults to `"+1"` (one minute), never an instant
reboot by accident. The fields are named (not positional) so a caller can't
transpose the delay and the wall message.
<!-- docref: end -->

{% callout type="warning" title="Schedule really reboots" %}
`Schedule` calls the host's real `shutdown -r`. It is not a dry run — the host
will reboot at the requested time unless you `Cancel` first.
{% /callout %}

## Related

- [Services](/capabilities/services) — restart individual units without a full
  reboot.
- [Packages](/capabilities/packages) — the updates that set the
  reboot-required marker in the first place.
