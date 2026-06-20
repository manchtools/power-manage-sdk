---
title: Wi-Fi
label: Wi-Fi
description: Create, update, and remove NetworkManager Wi-Fi connection profiles — with the PSK handled as a secret, never on a command line.
icon: "📶"
---

# Wi-Fi

`sys/network` manages Wi-Fi connection *profiles* (currently through the
NetworkManager `Backend`), both WPA-PSK and EAP-TLS. The credential (the WPA
passphrase, the EAP-TLS private key) is an
[`exec.Secret`](/concepts/architecture), so it never reaches a command line.

## Construct a manager

```go
r, err := exec.NewRunner(exec.Sudo) // writing a connection profile needs root
if err != nil {
    return err
}
if len(network.Detect(ctx)) == 0 {
    return errors.New("NetworkManager (nmcli) not available")
}
m, err := network.New(network.NetworkManager, r)
if err != nil {
    return err
}
```

## Apply a WPA-PSK profile

```go
psk, err := exec.NewSecret("correct horse battery staple")
if err != nil {
    return err
}
changed, err := m.Apply(ctx, network.Profile{
    Name:        "corp-wifi",
    SSID:        "Corp",
    AuthType:    network.AuthPSK,
    PSK:         psk,
    AutoConnect: true,
})
```

<!-- docref: begin src=sys/network/keyfile.go#buildPSKKeyfile:c291b90a -->
The PSK is written into a NetworkManager *keyfile* — a `0600` file under
`/etc/NetworkManager/system-connections/` with the `psk=` line — and never
passed as an `nmcli` argument. Running `nmcli connection modify wifi-sec.psk
<value>` would put the passphrase on the argv, where any process could read it
from `/proc`. Writing the keyfile is the only place the SDK reveals the secret.
<!-- docref: end -->

## Inspect, update, remove

```go
exists, err := m.ConnectionExists(ctx, "corp-wifi")
settings, err := m.Settings(ctx, "corp-wifi") // nmcli con show, parsed

// Re-applying the same name updates it; Apply reports whether anything changed.
changed, err := m.Apply(ctx, profile)

err = m.Delete(ctx, "corp-wifi", network.DeleteOptions{})
```

<!-- docref: begin src=sys/network/network.go#validateProfile:44f2efac -->
`Apply` validates the profile before doing anything: a PSK profile must carry a
non-empty PSK with no embedded newline (which would corrupt the keyfile), and an
EAP-TLS profile must carry its client key. An invalid profile is rejected with
no side effect.
<!-- docref: end -->

{% callout type="info" title="EAP-TLS" %}
For enterprise networks, set `AuthType: network.AuthEAPTLS` and provide the
client certificate and key; the key is written to a cert file under the
connection's directory, again never on the command line.
{% /callout %}

## Related

- [Network interfaces](/capabilities/netconfig) — wired addressing and routes.
- [Architecture](/concepts/architecture) — why credentials are `exec.Secret`.
