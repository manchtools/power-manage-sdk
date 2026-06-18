---
title: Contributing
description: How to work on the SDK — the multi-repo release flow and how changes reach the agent and server.
icon: "🛠️"
---

# Contributing

The SDK is consumed by the agent, control server, gateway, and web UI. Because
those live in separate repositories, the thing most worth understanding before
you change the SDK is how a change *propagates* without breaking everyone.

{% cards %}
  {% card title="Release coordination" href="/contributing/release-coordination" icon="🚦" %}
  How downstream repos pin the SDK, how to bump them, the workspace trick for
  cross-cutting work, and the tagging conventions.
  {% /card %}
{% /cards %}

## Keeping these docs honest

This documentation is anchored to the code with
[docref](https://github.com/manchtools/open-docref): prose and snippets that
describe a symbol carry a hash of what the author last saw, and `docref check`
(run in CI) fails when the code drifts from the docs. After changing anchored
code, refresh snippets and re-approve claims in the same change. The authoring
rules and the docref workflow are in [`docs/AGENTS.md`](https://github.com/manchtools/power-manage-sdk/blob/main/docs/AGENTS.md).
