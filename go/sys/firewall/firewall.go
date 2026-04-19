// Package firewall is a forward-compat extension point for packet-
// filter management. Backend selector is in place; implementations
// land as features ship.
//
// See docs/backend-pattern.md for why every sys/* package that
// abstracts over multiple implementations follows this same shape.
package firewall

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
)

// Backend identifies which packet-filter framework the SDK targets.
type Backend int

const (
	// BackendNftables is Linux nftables via nft(8). Default — the modern
	// Linux firewall framework that iptables is migrating toward.
	BackendNftables Backend = 0
	// BackendIptables is Linux iptables (iptables-legacy or iptables-nft
	// translation shim).
	BackendIptables Backend = 1
	// BackendFirewalld is the firewalld wrapper common on Red Hat family.
	BackendFirewalld Backend = 2
	// BackendUFW is Debian/Ubuntu's ufw wrapper.
	BackendUFW Backend = 3
	// BackendPF is the BSD packet filter.
	BackendPF Backend = 4
)

// ErrBackendNotSupported is returned when a caller invokes an
// operation on a backend that has no concrete implementation yet.
var ErrBackendNotSupported = errors.New("firewall backend not supported")

var backend atomic.Int32

// SetBackend selects the active backend. Call once at startup. Unknown
// values are ignored so a zero-valued proto enum cannot silently
// regress an explicitly-set backend.
func SetBackend(b Backend) {
	switch b {
	case BackendNftables, BackendIptables, BackendFirewalld, BackendUFW, BackendPF:
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
	case BackendNftables:
		return "nftables"
	case BackendIptables:
		return "iptables"
	case BackendFirewalld:
		return "firewalld"
	case BackendUFW:
		return "ufw"
	case BackendPF:
		return "pf"
	default:
		return fmt.Sprintf("unknown(%d)", int(b))
	}
}

func unsupported(op string) error {
	return fmt.Errorf("%w: %s on backend %s", ErrBackendNotSupported, op, CurrentBackend())
}

// Protocol names a network protocol for rule matching.
type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
	ProtocolAny Protocol = ""
)

// Rule describes a single allow-or-deny decision. The cross-backend
// surface stays intentionally minimal — implementations translate
// into the backend's native grammar (chains + priorities for nft,
// zones for firewalld, numbered rules for ufw, etc.).
type Rule struct {
	Name     string   // Stable identifier so rules can be updated/removed idempotently
	Allow    bool     // true = allow, false = deny
	Protocol Protocol // tcp / udp / any
	Port     int      // 0 = any
	Source   string   // CIDR or address; empty = any
	Dest     string   // CIDR or address; empty = any
	Comment  string   // Written into the backend's comment field where supported
}

// ApplyRule installs or updates a rule. Identified by Rule.Name so
// reapplying the same rule is idempotent.
func ApplyRule(ctx context.Context, rule Rule) error {
	switch CurrentBackend() {
	default:
		return unsupported("ApplyRule")
	}
}

// RemoveRule removes a rule by name. Missing rules are a no-op.
func RemoveRule(ctx context.Context, name string) error {
	switch CurrentBackend() {
	default:
		return unsupported("RemoveRule")
	}
}

// Reload re-applies the active ruleset. Useful after bulk changes.
func Reload(ctx context.Context) error {
	switch CurrentBackend() {
	default:
		return unsupported("Reload")
	}
}
