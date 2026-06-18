// Package desktop discovers active graphical desktop sessions on the host so
// user-scoped actions (Flatpak --user installs, shell scripts that need a real
// $HOME and DBus session bus, etc.) can fan out to every currently-signed-in
// user instead of running under the agent's own root context.
//
//	r, _ := exec.NewRunner(exec.Direct) // the agent runs as root
//	m, err := desktop.New(r)
//	if err != nil { ... }
//	sessions, err := m.ActiveSessions(ctx)
//
// The discovery contract is intentionally narrow: only sessions that
//   - are local (Remote=no)
//   - are graphical (Type ∈ {x11, wayland, mir})
//   - are active (Active=yes)
//
// count. SSH sessions, getty TTYs, headless sessions, and inactive graphical
// sessions are filtered out — they don't have a usable XDG_RUNTIME_DIR / DBus
// session bus that user-scoped commands need.
//
// desktop is a single-implementation capability (design §3.8): it exposes the
// Manager interface for shape-uniformity with the rest of the SDK. There is no
// Backend argument — only the required Runner.
//
// # Locale handling
//
// The loginctl PROBES (ActiveSessions and its helpers) run through the injected
// Runner, which forces the C locale; this is deliberate — the SDK parses
// loginctl's stderr to distinguish "no logind here" from a real fault, and that
// matching must be locale-stable. RunAsCommand is the opposite case: it builds a
// command that runs ON BEHALF OF a signed-in user (a Flatpak install, a user
// script) whose output the SDK does NOT parse, so it does NOT go through the
// Runner and does NOT force C — the user keeps their own locale.
package desktop

import (
	"context"
	"fmt"
	osexec "os/exec"
	"os/user"

	pmexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// defaultHomeRoot is the directory HomeUsers enumerates unless overridden with
// WithHomeRoot.
const defaultHomeRoot = "/home"

// loginctlPath is the absolute path to the loginctl binary. Pinned to
// /usr/bin/loginctl because that's where systemd installs it on every supported
// distro and absolute paths sidestep PATH-injection concerns when the agent
// runs as root.
const loginctlPath = "/usr/bin/loginctl"

// runuserPath pins the absolute path to runuser. Like loginctlPath, pinning
// sidesteps PATH-injection concerns when the agent runs as root and matches what
// every supported distro ships.
const runuserPath = "/usr/sbin/runuser"

// Test seams. They default to the real lookups and are overridden only by tests
// to exercise branches that are otherwise host-dependent (loginctl absent, a
// passwd entry that does not resolve or carries a non-numeric uid/gid).
// Production never reassigns them.
var (
	lookPath   = osexec.LookPath
	lookupID   = user.LookupId
	lookupUser = user.Lookup
)

// RunAsOptions carries the optional inputs to Manager.RunAsCommand.
type RunAsOptions struct {
	// ExtraEnv is merged on top of the per-user desktop environment. Entries win
	// over the defaults on a duplicate key (Go's exec honours the last
	// occurrence) — except PATH, which RunAsCommand always re-applies last with
	// the curated UserPath so an action cannot override it.
	ExtraEnv []string
}

// Manager is the desktop discovery + user-scoped-command surface.
type Manager interface {
	// ActiveSessions returns every active local graphical session on the host,
	// ready for fanning a user-scoped command out to each. It returns an empty
	// slice (not an error) when loginctl is missing or no logind is reachable.
	ActiveSessions(ctx context.Context) ([]Session, error)
	// HomeUsers enumerates every Linux account whose home lives directly under
	// the configured home root (default /home). It is the primitive for
	// "do something for every offline user".
	HomeUsers(ctx context.Context) ([]Session, error)
	// UsersWithFlatpakInstall returns the subset of HomeUsers whose per-user
	// Flatpak repository contains appID.
	UsersWithFlatpakInstall(ctx context.Context, appID string) ([]Session, error)
	// RunAsCommand builds (but does not run) an *exec.Cmd that runs name+args as
	// the user owning s, with the per-user desktop environment. See the package
	// doc for why this path keeps the user's locale rather than forcing C.
	RunAsCommand(ctx context.Context, s Session, opts RunAsOptions, name string, args ...string) (*osexec.Cmd, error)
}

// manager is the single Manager implementation.
type manager struct {
	r        pmexec.Runner
	homeRoot string
}

// Option configures a Manager at construction.
type Option func(*manager)

// WithHomeRoot overrides the directory HomeUsers enumerates (default /home).
// Primarily for tests; production uses the default.
func WithHomeRoot(dir string) Option {
	return func(m *manager) { m.homeRoot = dir }
}

// New builds a desktop Manager driven by runner. A nil runner is rejected
// (fail-closed). New is pure — it does not probe the host.
func New(runner pmexec.Runner, opts ...Option) (Manager, error) {
	if runner == nil {
		return nil, fmt.Errorf("desktop: %w", pmexec.ErrRunnerRequired)
	}
	m := &manager{r: runner, homeRoot: defaultHomeRoot}
	for _, opt := range opts {
		if opt != nil { // tolerate a nil option rather than panicking the agent
			opt(m)
		}
	}
	return m, nil
}

// ensure the single implementation satisfies the interface.
var _ Manager = (*manager)(nil)
