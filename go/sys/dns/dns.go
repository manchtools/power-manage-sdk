// Package dns manages a host's DNS resolver configuration through an injected
// exec.Runner.
//
// Build a Manager for an explicit backend and call its methods:
//
//	r, _ := exec.NewRunner(exec.Direct) // the agent runs as root
//	m, err := dns.New(dns.Resolved, r)
//	if err != nil { ... }
//	err = m.Apply(ctx, dns.Config{Nameservers: []string{"1.1.1.1"}, SearchDomains: []string{"corp.example"}})
//
// Two backends are implemented:
//
//   - Resolved (systemd-resolved via resolvectl) — supports a host-global config
//     (an empty Config.Interface writes the managed /etc/systemd/resolved.conf.d
//     drop-in and restarts the service) and per-link config (a set Interface
//     uses runtime `resolvectl dns/domain <iface>`).
//   - NetworkManager (nmcli) — connection-scoped: it configures DNS on the
//     active connection of Config.Interface, so Interface is REQUIRED. There is
//     no clean host-global DNS via nmcli; use the Resolved backend for that.
//
// Mutations escalate through the Runner; reads are unprivileged. Detect lists
// the backends whose tool is present on PATH; the consumer picks one and passes
// it to New (no auto-detection, no global state).
package dns

import (
	"context"
	"errors"
	"fmt"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/fs"
)

// Backend selects the resolver framework a Manager drives. The zero value is
// invalid (New → ErrUnknownBackend); valid values start at 1. Only implemented
// backends exist — a new value is appended if and when a real implementation is
// written (resolvconf/dnsmasq are intentionally absent, not stubbed).
type Backend int

const (
	// Resolved is systemd-resolved (resolvectl + resolved.conf.d drop-in).
	Resolved Backend = iota + 1
	// NetworkManager configures DNS on a connection via nmcli.
	NetworkManager
)

// String renders the backend as its canonical tool/framework name.
func (b Backend) String() string {
	switch b {
	case Resolved:
		return "resolved"
	case NetworkManager:
		return "networkmanager"
	default:
		return fmt.Sprintf("Backend(%d)", int(b))
	}
}

// ErrUnknownBackend is returned by New for the zero value or any Backend the SDK
// does not implement.
var ErrUnknownBackend = errors.New("dns: unknown backend")

// Config is the desired resolver configuration to Apply.
type Config struct {
	// Nameservers are resolver IP addresses (v4 or v6 literals).
	Nameservers []string
	// SearchDomains are DNS search domains.
	SearchDomains []string
	// Interface scopes the configuration to one link. Empty means host-global
	// (supported only by the Resolved backend; NetworkManager requires it).
	Interface string
}

// State is the resolver configuration read back from the host.
type State struct {
	Nameservers   []string
	SearchDomains []string
}

// Manager is the DNS configuration surface. Every method takes a context.
type Manager interface {
	// Get reads the active resolver configuration.
	Get(ctx context.Context) (State, error)
	// Apply installs cfg. It validates cfg (rejecting non-IP nameservers,
	// malformed/flag-shaped search domains, and bad interface names) before
	// touching any backend, so an invalid config has no side effects.
	Apply(ctx context.Context, cfg Config) error
}

// fsManager is the narrow slice of fs.Manager the Resolved backend uses to write
// the resolved.conf.d drop-in; a small interface so tests inject a fake via the
// newFS seam.
type fsManager interface {
	WriteFile(ctx context.Context, path string, data []byte, opts fs.WriteOptions) error
	Mkdir(ctx context.Context, path string, opts fs.MkdirOptions) error
}

// newFS builds the fs.Manager (over the same injected Runner) used by the
// Resolved backend. A package var so tests can substitute a fake.
var newFS = func(r exec.Runner) (fsManager, error) { return fs.New(r) }

// New returns a Manager for the named backend, driven by runner. Pure: it
// validates the backend is known and does NOT probe the host (use Detect). The
// zero value and any unimplemented backend are rejected with ErrUnknownBackend;
// a nil runner is rejected.
func New(b Backend, runner exec.Runner) (Manager, error) {
	if runner == nil {
		return nil, errors.New("dns: runner is required")
	}
	switch b {
	case Resolved:
		fsm, err := newFS(runner)
		if err != nil {
			return nil, err
		}
		return &resolvedManager{r: runner, fsm: fsm}, nil
	case NetworkManager:
		return &nmManager{r: runner}, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownBackend, int(b))
	}
}

// runPriv runs an escalated mutation through the Runner and maps a non-zero exit
// (or a failure to execute) into an error — the "err != nil ⇒ the tool failed"
// contract the backends rely on.
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

// runRead runs an unprivileged query through the Runner and returns its stdout,
// mapping a non-zero exit (or exec failure) into an error.
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
