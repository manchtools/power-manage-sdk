---
title: Capabilities
description: The system-management packages — package managers, users, services, storage, networking, security, and host information — and what each manages.
icon: "🧰"
---

# Capabilities

Each capability is a package that follows the [architecture](/concepts/architecture):
build a Runner, choose a `Backend` where the capability takes one, get a Manager.
The groups below are the areas the SDK covers.

{% callout type="info" title="Reference vs. recipes" %}
Per-package **method signatures** are generated API docs on
[pkg.go.dev](https://pkg.go.dev/) — this site does not duplicate them. Each
capability below has a task-oriented **recipe** page (in the sidebar); the
behavioural claims on them are anchored to the code with
[docref](/contributing), so they fail CI if the code drifts.
{% /callout %}

{% cards %}
  {% card title="Packages" icon="📦" %}
  `pkg` — install, remove, and upgrade software across apt, dnf, pacman,
  zypper, and flatpak behind one Manager.
  {% /card %}
  {% card title="Identity" icon="👤" %}
  `sys/user` — users and groups, password handling, and account state.
  {% /card %}
  {% card title="Services & boot" icon="⚙️" %}
  `sys/service` (init units), `sys/reboot` (reboot scheduling), `sys/timesync`
  (time synchronization).
  {% /card %}
  {% card title="Storage & filesystem" icon="💾" %}
  `sys/fs` (symlink-safe reads/writes, permissions, ownership),
  `sys/encryption` (disk encryption), `sys/smart` (drive health).
  {% /card %}
  {% card title="Networking" icon="🌐" %}
  `sys/network` (Wi-Fi profiles), `sys/dns` (resolver config), `sys/netconfig`
  (IP/routing/DHCP), `sys/firewall` (packet filtering).
  {% /card %}
  {% card title="Security & trust" icon="🔐" %}
  `sys/catrust` (system CA trust anchors), `sys/antivirus` (ClamAV scanning),
  `sys/osquery` (host queries).
  {% /card %}
  {% card title="Host information" icon="📊" %}
  `sys/inventory` (hardware/software facts), `sys/log` (journald/syslog reads).
  {% /card %}
  {% card title="Desktop & sessions" icon="🖥️" %}
  `sys/notify` (desktop notifications), `sys/desktop` (desktop integration),
  `sys/terminal` (PTY sessions).
  {% /card %}
  {% card title="Remote sources" icon="📥" %}
  `sys/remote` — fetch artifacts over HTTPS, Git, or S3 (a per-call `Source`
  interface; see [Backends](/concepts/backends)).
  {% /card %}
{% /cards %}
