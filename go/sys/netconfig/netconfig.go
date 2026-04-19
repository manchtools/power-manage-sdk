// Package netconfig is a forward-compat extension point for interface
// IP / routing / DHCP configuration. Distinct from sys/network, which
// handles WiFi connection profiles — a device can use different tools
// for the two concerns (NetworkManager for WiFi auth, systemd-networkd
// for interface IPs, etc.).
//
// Backend selector is in place; implementations land as features ship.
// See docs/backend-pattern.md for the pattern this package follows.
package netconfig

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
)

// Backend identifies which tool manages IP / routing / DHCP.
type Backend int

const (
	// BackendNetworkManager wraps nmcli connection modify. Default.
	BackendNetworkManager Backend = 0
	// BackendSystemdNetworkd writes /etc/systemd/network/*.network.
	BackendSystemdNetworkd Backend = 1
	// BackendNetplan writes /etc/netplan/*.yaml (Ubuntu Server).
	BackendNetplan Backend = 2
	// BackendDhcpcd manages /etc/dhcpcd.conf (Alpine, OpenBSD).
	BackendDhcpcd Backend = 3
	// BackendIfupdown writes /etc/network/interfaces (classic Debian).
	BackendIfupdown Backend = 4
)

// ErrBackendNotSupported is returned when a caller invokes an operation
// on a backend that has no concrete implementation yet.
var ErrBackendNotSupported = errors.New("netconfig backend not supported")

var backend atomic.Int32

// SetBackend selects the active backend. Unknown values are ignored.
func SetBackend(b Backend) {
	switch b {
	case BackendNetworkManager, BackendSystemdNetworkd, BackendNetplan, BackendDhcpcd, BackendIfupdown:
		backend.Store(int32(b))
	}
}

// CurrentBackend returns the active backend.
func CurrentBackend() Backend {
	return Backend(backend.Load())
}

// String renders the backend as its canonical tool name.
func (b Backend) String() string {
	switch b {
	case BackendNetworkManager:
		return "networkmanager"
	case BackendSystemdNetworkd:
		return "systemd-networkd"
	case BackendNetplan:
		return "netplan"
	case BackendDhcpcd:
		return "dhcpcd"
	case BackendIfupdown:
		return "ifupdown"
	default:
		return fmt.Sprintf("unknown(%d)", int(b))
	}
}

func unsupported(op string) error {
	return fmt.Errorf("%w: %s on backend %s", ErrBackendNotSupported, op, CurrentBackend())
}

// AddressMode selects DHCP vs static IP per interface.
type AddressMode int

const (
	ModeDHCP   AddressMode = 0
	ModeStatic AddressMode = 1
)

// InterfaceConfig describes the desired state of a network interface.
// Static fields (Addresses/Gateway/DNS) are ignored when Mode is DHCP.
type InterfaceConfig struct {
	Name      string      // Interface name, e.g. eth0, wlan0
	Mode      AddressMode // DHCP or static
	Addresses []string    // CIDR list for static, e.g. ["192.0.2.10/24"]
	Gateway   string      // Default gateway
	DNS       []string    // Resolver addresses (optional; sys/dns is the proper home for DNS policy)
	MTU       int         // 0 = backend default
}

// Route describes an entry in the routing table.
type Route struct {
	Destination string // CIDR; "default" means the default route
	Gateway     string
	Interface   string
	Metric      int
}

// ApplyInterface installs or updates the interface's IP configuration.
func ApplyInterface(ctx context.Context, cfg InterfaceConfig) error {
	switch CurrentBackend() {
	default:
		return unsupported("ApplyInterface")
	}
}

// AddRoute adds or updates a route.
func AddRoute(ctx context.Context, r Route) error {
	switch CurrentBackend() {
	default:
		return unsupported("AddRoute")
	}
}

// RemoveRoute removes a route by destination.
func RemoveRoute(ctx context.Context, destination string) error {
	switch CurrentBackend() {
	default:
		return unsupported("RemoveRoute")
	}
}
