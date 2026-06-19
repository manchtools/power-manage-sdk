---
title: Errors
label: Errors
description: How the SDK surfaces failure — sentinel errors matched with errors.Is, a typed command error matched with errors.As, and a fail-closed default.
---

# Errors

The SDK returns errors you can branch on programmatically, not just strings to
log. Two mechanisms cover almost everything.

## Sentinels — match with errors.Is

Construction and capability-gap failures are sentinel values, so a caller can
distinguish *what* went wrong and fail closed:

```go
m, err := svc.New(svc.SomeBackend, r)
if errors.Is(err, svc.ErrUnknownBackend) {
    // the requested backend isn't implemented on this build
}
```

Each multi-backend package exports `ErrUnknownBackend`.

<!-- docref: begin src=sys/exec/command_error.go#@escalation-sentinels:89446e95 -->
The `exec` package adds sentinels for the escalation path —
`ErrEscalationUnavailable` (sudo/doas not installed) and `ErrEscalationDenied`
(escalation would need a password, which the agent can't supply) — so a runner
that can't escalate fails fast instead of hanging.
<!-- docref: end -->

## Command failures — inspect with errors.As

A non-zero exit code is **not** automatically an error. The Runner reports the
exit code in its result and leaves the judgement to the capability layer,
because some non-zero codes are meaningful answers (a `cryptsetup` probe
returning "not a LUKS device", for example). When a capability does decide a
command failed, it wraps the details in a typed error:

<!-- docref: begin src=sys/exec/command_error.go#CommandError:c48644e3 -->
`CommandError` is the typed error the capability layer wraps a failed command
in. It carries the command name, the exit code, and the captured stderr, so a
caller can branch on the specific code via `errors.As` without importing any
internals.
<!-- docref: end -->

```go
var cmdErr *exec.CommandError
if errors.As(err, &cmdErr) && cmdErr.ExitCode == 100 {
    // branch on the tool's specific exit code
}
```

## Fail closed

The default everywhere is to fail closed: an unknown backend, a missing
escalation tool, an unparseable result, or a validation failure returns an
error rather than guessing or silently doing nothing. Validation runs at the
top of a call, before any host state is touched, so a rejected request changes
nothing.
