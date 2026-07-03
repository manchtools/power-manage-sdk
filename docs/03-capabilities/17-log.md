---
title: Logs
label: Logs
description: Read host logs with unit, priority, time-range, and grep filters — from the systemd journal or classic syslog files.
icon: "📜"
---

# Logs

`sys/log` reads host logs through the systemd journal (`journalctl`) or classic
syslog files (`/var/log/{syslog,messages}`), with filters for unit, priority,
time range, and a grep pattern.

## Construct a source

```go
r, err := exec.NewRunner(exec.Direct)
if err != nil {
    return err
}
for _, b := range log.Detect(ctx) { // Journald if journalctl; Syslog if a file exists
    _ = b
}
s, err := log.New(log.Journald, r)
if err != nil {
    return err
}
```

<!-- docref: begin src=sys/log/detect.go#Detect:462234b3 -->
`Detect` reports `Journald` when `journalctl` is on `PATH` and `Syslog` when a
classic log file exists; it lists what's usable and the caller picks, rather than
the SDK choosing silently.
<!-- docref: end -->

## Query

```go
lines, err := s.Query(ctx, log.Query{
    Unit:     "sshd.service", // journald only
    Priority: "warning",      // journald only
    Grep:     "Failed password",
    Kernel:   false,          // true → kernel ring only (-k); journald only
    Lines:    200,            // cap; <=0 defaults to 100
})
```

<!-- docref: begin src=sys/log/journald.go#journaldSource.Query:44fcc941 -->
`Query` builds the `journalctl` invocation with every dynamic value as an
option-argument (`-u <unit>`, `--grep <pat>`, `-k`, …), never a positional operand, so
none can be reinterpreted as a flag. Two real-journald behaviours it normalises:
journalctl status markers (`-- No entries --`, `-- Boot … --`) are dropped — they
are not log entries — and a `--grep` that matches nothing (which `journalctl`
signals with exit 1 and an empty stderr) returns an empty result, not an error,
so a caller can tell "no logs matched" from "journalctl broke".
<!-- docref: end -->

{% callout type="info" title="Backend differences" %}
<!-- docref: begin src=sys/log/syslog.go#syslogSource:e33f14f6 -->
`Unit`, `Since`, `Until`, `Priority`, and `Kernel` are journald-only — the
Syslog backend still validates them (a bad value errors) but does not apply
them. The Syslog backend tails the log file and applies `Grep`/`Lines`
in-process, filtering within the tail window. For unit- or priority-scoped
queries, use Journald.
<!-- docref: end -->
{% /callout %}

## Related

- [Services](/capabilities/services) — the units whose logs you're reading.
- [Architecture](/concepts/architecture) — the Runner / Backend / Source model.
