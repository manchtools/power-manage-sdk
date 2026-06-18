// Package netconfig manages a host's per-interface IP / routing / MTU
// configuration through an injected exec.Runner.
//
// It is distinct from sys/network (WiFi connection profiles) and sys/dns
// (resolver policy): a device can use different tools for each concern
// (NetworkManager for WiFi auth, systemd-networkd for interface IPs, etc.).
//
//	r, _ := exec.NewRunner(exec.Direct)
//	m, err := netconfig.New(netconfig.SystemdNetworkd, r)
//	if err != nil { ... }
//	err = m.Apply(ctx, netconfig.InterfaceConfig{
//	    Name: "eth0", Mode: netconfig.Static,
//	    Addresses: []string{"192.0.2.10/24"}, Gateway: "192.0.2.1",
//	})
//
// Two backends are implemented: NetworkManager (nmcli, connection-scoped) and
// SystemdNetworkd (writes /etc/systemd/network/<name>.network via the fs.Manager
// and reloads networkd). Apply is declarative desired-state — routes are folded
// into InterfaceConfig and applied atomically with the interface, matching both
// backends' models. Get reads the EFFECTIVE kernel state via `ip -j`
// (backend-agnostic). Mutations escalate through the Runner; the read does not.
package netconfig

import (
	"context"
	"errors"
	"fmt"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/fs"
)

// Backend selects the tool that manages interface IP configuration. The zero
// value is invalid (New → ErrUnknownBackend); valid values start at 1. Only
// implemented backends exist (netplan/dhcpcd/ifupdown are intentionally absent,
// not stubbed).
type Backend int

const (
	// NetworkManager configures the active connection via nmcli.
	NetworkManager Backend = iota + 1
	// SystemdNetworkd writes /etc/systemd/network/<name>.network.
	SystemdNetworkd
)

// String renders the backend as its canonical tool name.
func (b Backend) String() string {
	switch b {
	case NetworkManager:
		return "networkmanager"
	case SystemdNetworkd:
		return "systemd-networkd"
	default:
		return fmt.Sprintf("Backend(%d)", int(b))
	}
}

// ErrUnknownBackend is returned by New for the zero value or any Backend the SDK
// does not implement.
var ErrUnknownBackend = errors.New("netconfig: unknown backend")

// AddressMode selects DHCP vs static addressing. The zero value is invalid so a
// caller must choose explicitly (a forgotten Mode never silently defaults).
type AddressMode int

const (
	// DHCP requests addresses dynamically.
	DHCP AddressMode = iota + 1
	// Static uses the Addresses/Gateway from the config.
	Static
)

// Route is a routing-table entry applied with an interface.
type Route struct {
	// Destination is a CIDR (e.g. "10.0.0.0/8") or the literal "default".
	Destination string
	// Gateway is the next-hop IP. Required.
	Gateway string
	// Metric is the route priority (0 = backend default).
	Metric int
}

// InterfaceConfig is the desired state of a network interface.
//
// Mode governs ADDRESSING only: Addresses and Gateway are honoured solely in
// Static mode (under DHCP the server supplies them, so they are not emitted —
// though still validated if present). DNS, MTU, and Routes are independent of the
// addressing mode and ARE applied in both modes — a common, valid setup is a
// DHCP address plus a static route to a management subnet, or a static DNS
// override on a DHCP link.
type InterfaceConfig struct {
	Name      string      // interface name, e.g. eth0
	Mode      AddressMode // DHCP or Static (required) — governs addressing only
	Addresses []string    // CIDR list, static mode only, e.g. ["192.0.2.10/24"]
	Gateway   string      // default gateway, static mode only (family must match an address)
	DNS       []string    // resolver IPs (applied in both modes; sys/dns is DNS policy's proper home)
	MTU       int         // 0 = backend default (applied in both modes)
	Routes    []Route     // additional static routes (applied in both modes)
}

// Manager is the interface-configuration surface.
type Manager interface {
	// Apply validates cfg and installs it as the interface's desired state
	// (addresses/gateway/DNS/MTU/routes). Validation runs before any backend
	// mutation, so an invalid config has no side effects.
	Apply(ctx context.Context, cfg InterfaceConfig) error
	// Get reads the EFFECTIVE kernel state of the named interface via `ip -j`
	// (addresses, gateway, MTU, routes). Mode and DNS are not recoverable from
	// the kernel and are left at their zero values.
	Get(ctx context.Context, name string) (InterfaceConfig, error)
}

// fsManager is the narrow slice of fs.Manager the networkd backend uses to write
// the .network file; a small interface so tests inject a fake via newFS.
type fsManager interface {
	WriteFile(ctx context.Context, path string, data []byte, opts fs.WriteOptions) error
}

// newFS builds the fs.Manager (over the same injected Runner) used by the
// networkd backend. A package var so tests can substitute a fake.
var newFS = func(r exec.Runner) (fsManager, error) { return fs.New(r) }

// base holds the injected Runner and provides the backend-agnostic Get (via
// `ip`). Both backends embed it.
type base struct {
	r exec.Runner
}

// New returns a Manager for the named backend, driven by runner. Pure: validates
// the backend is known; does not probe the host (use Detect). The zero value and
// any unimplemented backend are rejected with ErrUnknownBackend; a nil runner is
// rejected.
func New(b Backend, runner exec.Runner) (Manager, error) {
	if runner == nil {
		return nil, fmt.Errorf("netconfig: %w", exec.ErrRunnerRequired)
	}
	switch b {
	case NetworkManager:
		return &nmBackend{base{r: runner}}, nil
	case SystemdNetworkd:
		fsm, err := newFS(runner)
		if err != nil {
			return nil, err
		}
		return &networkdBackend{base: base{r: runner}, fsm: fsm}, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownBackend, int(b))
	}
}

// runPriv runs an escalated mutation and maps a non-zero exit (or exec failure)
// into an error.
func runPriv(ctx context.Context, r exec.Runner, name string, args ...string) error {
	res, err := r.Run(ctx, exec.Command{Name: name, Args: args, Escalate: true})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return &exec.CommandError{Name: name, ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return nil
}

// runRead runs an unprivileged query and returns its stdout, mapping a non-zero
// exit (or exec failure) into an error.
func runRead(ctx context.Context, r exec.Runner, name string, args ...string) (string, error) {
	res, err := r.Run(ctx, exec.Command{Name: name, Args: args})
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", &exec.CommandError{Name: name, ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return res.Stdout, nil
}
