---
title: Concepts
description: The design model behind the SDK's system-management library — dependency-injected Runner, explicit Backend, per-capability Manager, and the error model.
icon: "🧩"
---

# Concepts

The system-management packages (`sys/*`, `pkg`) all share one shape, so once
you understand a single capability you understand them all. These pages cover
that shape, the conventions that hold across every package, and the two
cross-cutting surfaces the agent and servers build on: the crypto helpers and
the streaming client with its signed-command model.

{% cards %}
  {% card title="Architecture" href="/concepts/architecture" icon="🏗️" %}
  The dependency-injected model: you build a Runner, choose a Backend, and get
  a Manager handle. No global state, no hidden auto-detection.
  {% /card %}
  {% card title="Backends & detection" href="/concepts/backends" icon="🔌" %}
  Why a capability's backend is chosen explicitly, how to discover what a host
  supports, and when a package uses a per-call interface instead.
  {% /card %}
  {% card title="Errors" href="/concepts/errors" icon="⚠️" %}
  Sentinel errors you match with errors.Is, the typed command error, and the
  fail-closed default.
  {% /card %}
  {% card title="Crypto helpers" href="/concepts/crypto" icon="🔑" %}
  Mandatory domain separation on every AEAD and seal, X25519 sealing past a
  low-trust relay, and the CSR / CA-continuity rules.
  {% /card %}
  {% card title="Client & signing" href="/concepts/client" icon="📡" %}
  The agent's bidirectional stream, dispatch robustness against a hostile
  relay, fail-closed command signatures, and maintenance windows.
  {% /card %}
{% /cards %}
