# sys/_planned

Holding area for `sys/*` packages that have a stable public surface
but no concrete implementation yet — every public function returns
`ErrBackendNotSupported` because no agent or server consumer has
materialised. Per `docs/backend-pattern.md`, the Backend selector +
sentinel error pattern is shipped from day one so adding the first
real backend is not a 71-file rename; until then the packages live
here.

The leading `_` excludes the directory from `go build ./...` /
`go vet ./...` (see [go/cmd/go/internal/load/pkg.go](https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns)),
so no consumer can accidentally import a stub. To promote a package
back to `go/sys/<name>`, move the directory and audit the import
paths in the new consumer.

Promotion criteria:

- A second consumer (cross-component, per the SDK's "shared helpers
  go in SDK" rule) has surfaced — typically server adopting the
  helper alongside the agent.
- At least one concrete backend has been implemented and tested
  against a real CLI / dbus interface.

Currently parked here:

- `dns/` — resolved.conf / NetworkManager / systemd-networkd DNS
  config. Awaiting a managed-resolver action type.
- `firewall/` — nftables / firewalld / iptables abstraction.
  Awaiting a managed-firewall-rule action type.
- `netconfig/` — IP / route / interface configuration. Awaiting a
  managed-network action type.

See `TECH_DEBT_AUDIT.md` finding F016 for history.
