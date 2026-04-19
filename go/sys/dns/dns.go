// Package dns is a forward-compat extension point for DNS-resolver
// management. Backend selector is in place; implementations land as
// features ship.
//
// See docs/backend-pattern.md for why every sys/* package that
// abstracts over multiple implementations follows this same shape.
package dns

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
)

// Backend identifies which resolver framework the SDK targets.
type Backend int

const (
	// BackendResolved is systemd-resolved (resolvectl). Default.
	BackendResolved Backend = 0
	// BackendResolvconf is the classic /etc/resolv.conf flow, managed
	// either directly or via resolvconf(8).
	BackendResolvconf Backend = 1
	// BackendDnsmasq is a local dnsmasq instance.
	BackendDnsmasq Backend = 2
	// BackendNetworkManager delegates DNS to NetworkManager.
	BackendNetworkManager Backend = 3
)

// ErrBackendNotSupported is returned when a caller invokes an
// operation on a backend that has no concrete implementation yet.
var ErrBackendNotSupported = errors.New("dns backend not supported")

var backend atomic.Int32

// SetBackend selects the active backend. Unknown values are ignored.
func SetBackend(b Backend) {
	switch b {
	case BackendResolved, BackendResolvconf, BackendDnsmasq, BackendNetworkManager:
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
	case BackendResolved:
		return "resolved"
	case BackendResolvconf:
		return "resolvconf"
	case BackendDnsmasq:
		return "dnsmasq"
	case BackendNetworkManager:
		return "networkmanager"
	default:
		return fmt.Sprintf("unknown(%d)", int(b))
	}
}

func unsupported(op string) error {
	return fmt.Errorf("%w: %s on backend %s", ErrBackendNotSupported, op, CurrentBackend())
}

// Config describes the desired resolver state.
type Config struct {
	Nameservers   []string // IPv4/IPv6 addresses; order preserved as preference
	SearchDomains []string // Search suffixes
	Interface     string   // Scope to a specific interface if the backend supports it; empty = global
}

// State is the current resolver configuration observed on the device.
type State struct {
	Nameservers   []string
	SearchDomains []string
}

// Apply installs or updates the resolver configuration.
func Apply(ctx context.Context, cfg Config) error {
	switch CurrentBackend() {
	default:
		return unsupported("Apply")
	}
}

// Get reads the current resolver configuration.
func Get(ctx context.Context) (State, error) {
	switch CurrentBackend() {
	default:
		return State{}, unsupported("Get")
	}
}
