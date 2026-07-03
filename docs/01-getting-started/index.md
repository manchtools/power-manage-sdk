---
title: Power Manage SDK
label: Getting started
description: The Go SDK for building on Power Manage — proto types, signing/crypto helpers, and an idiomatic Linux system-management library.
icon: "🚀"
---

# Power Manage SDK

The Power Manage SDK is the shared Go (and TypeScript) library the agent,
control server, gateway, and web UI build on. It ships three things:

<!-- docref: begin src=crypto/csr.go#GenerateCSR:4a9d84de,verify/verify.go#ActionVerifier.Verify:c3b3df3c,crypto/cert.go#CAFingerprintFromPEM:5a8bdd28 -->
- **Protocol types** — the generated protobuf / Connect-RPC code for the
  Power Manage wire format.
- **Crypto & signing helpers** — CSR generation, certificate utilities, and
  action-payload signature verification.
- **A Linux system-management library** — package managers, users, services,
  filesystems, disk encryption, networking, antivirus, CA trust, and more,
  behind one consistent, dependency-injected API.
<!-- docref: end -->

These pages are the **narrative** docs — concepts, recipes, and the
contributor workflow. The **API reference** is generated and lives on
[pkg.go.dev](https://pkg.go.dev/) for the published module; this site does
not duplicate it.

{% callout type="info" title="Pre-1.0" %}
The SDK is on a `v0.x` line: the public API is still settling and minor
bumps can carry breaking changes. See [Release coordination](/contributing/release-coordination)
for how downstream repos pin and bump it.
{% /callout %}

## Where to go next

{% cards %}
  {% card title="Concepts" href="/concepts" icon="🧩" %}
  The design model: an injected Runner, an explicit Backend, and a Manager
  handle per capability — plus how errors are surfaced.
  {% /card %}
  {% card title="Capabilities" href="/capabilities" icon="🧰" %}
  The system-management packages and what each one manages.
  {% /card %}
  {% card title="Contributing" href="/contributing" icon="🛠️" %}
  How SDK changes reach the agent and server, and the release flow.
  {% /card %}
{% /cards %}
