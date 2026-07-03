---
title: Architecture
label: Architecture
description: The dependency-injected design model — build a Runner, choose a Backend, get a Manager. No global state, no hidden detection.
---

# Architecture

Every system-management capability follows the same three-part shape:

{% steps %}
  {% step title="Build a Runner" %}
  <!-- docref: begin src=sys/exec/runner.go#Runner:7679445f,sys/exec/runner.go#PrivilegeBackend:01258357 -->
  A `Runner` is how commands reach the host — directly (the process is
  already root), or escalated through `sudo` / `doas`. You construct it once
  and inject it everywhere.
  <!-- docref: end -->
  {% /step %}
  {% step title="Choose a Backend" %}
  <!-- docref: begin src=sys/service/service.go#Systemd:ff233171,sys/user/user.go#ShadowUtils:936a2cbe -->
  Capabilities that drive a *family* of tools (package managers, init systems,
  encryption tools) take an explicit `Backend` value — the caller always names
  it, even when only one backend is implemented today (`service.Systemd`,
  `user.ShadowUtils`), and the SDK never auto-detects. Single-tool capabilities
  (`smartctl`, `osqueryi`) take only a Runner.
  <!-- docref: end -->
  {% /step %}
  {% step title="Get a Manager" %}
  `New` returns a handle whose methods do the work. The handle holds the
  injected Runner and the chosen backend; calling code never reaches for a
  global.
  {% /step %}
{% /steps %}

```go
r, err := exec.NewRunner(exec.Sudo) // or exec.Direct / exec.Doas
if err != nil {
    return err
}
m, err := pkg.New(pkg.Apt, r)
if err != nil {
    return err
}
// Mutations return the command output (exec.Result: exit code, stdout, stderr)
// so the caller can surface what the package manager actually did.
res, err := m.Install(ctx, pkg.InstallOptions{}, "vim", "git")
_ = res
```

## Why it's shaped this way

An earlier version of the SDK hard-coded `sudo` at every call site and
selected backends through process-global setters. Adding `doas`, or testing a
call path without a real host, meant touching dozens of files. The injected
model fixes that, and the shape is deliberate:

- **Explicit over clever.** The caller chooses the privilege tool and the
  backend. Behaviour never depends on what happens to be installed on disk.
- **No global state.** Backend selection lives on the instance you built, not
  in a package variable — so two callers can't fight over it and a stray
  zero-value can't regress a configured one.
- **Testable without a host.** Because the Runner is injected, tests pass a
  fake one (`exectest.FakeRunner`) and assert the exact commands that would
  have run — no container, no `sudo`, no network.
- **Uniform.** A reader who understands one capability understands them all;
  adding a capability is a copy of the same small shape.

<!-- docref: begin src=archtest/no_global_backend_test.go#TestNoGlobalBackendState:65a4d3bf -->
The no-global-state rule is enforced by an architectural test, not just
convention: the build fails if any capability reintroduces a process-global
backend selector or setter.
<!-- docref: end -->

{% callout type="info" title="Reference" %}
The exact method sets per package are generated API docs on
[pkg.go.dev](https://pkg.go.dev/), not repeated here. These pages explain the
model; the reference lists the surface.
{% /callout %}

## Construction validates before it works

<!-- docref: begin src=sys/catrust/catrust.go#New:78dcd9a7 -->
`New` is pure and fail-closed: it rejects a nil Runner and an unrecognized
Backend, returning an error, before constructing a usable handle. A successful
call gives you a Manager that is ready to use.
<!-- docref: end -->

This means a misconfigured caller fails at construction, loudly, rather than at
some later method call with a confusing message.
