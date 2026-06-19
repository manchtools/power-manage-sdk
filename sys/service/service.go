// Package service manages init/service units through an injected exec.Runner.
//
// Build a Manager for an explicit backend (systemd is the only one today) and a
// Runner, then call its methods. Query verbs (is-enabled/is-active) run
// unprivileged; mutations escalate through the Runner.
//
//	r, _ := exec.NewRunner(exec.Direct)
//	svc, _ := service.New(service.Systemd, r)
//	_ = svc.EnableNow(ctx, "nginx.service")
//
// Detect reports whether systemd is usable on the host so a consumer can choose
// a backend explicitly.
package service

import (
	"context"
	"fmt"
	"os"
	osexec "os/exec"
	"time"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/fs"
)

// Backend selects the service-manager implementation. Passed explicitly even
// though systemd is the only value today; the zero value is invalid
// (New → ErrUnknownBackend). The deleted OpenRC/Runit/S6 scaffolds — which only
// ever returned "not supported" — are not ported; a real second backend is
// appended here when actually written.
type Backend int

// Systemd wraps systemctl.
const Systemd Backend = iota + 1

// ErrUnknownBackend is returned by New for the zero value or any Backend the SDK
// does not implement (fail-closed).
var ErrUnknownBackend = fmt.Errorf("service: unknown backend")

// UnitStatus is a unit's current state.
type UnitStatus struct {
	Enabled bool // explicitly enabled (systemctl enable), not boot-via-dependency
	Active  bool
	Masked  bool
	Static  bool // starts at boot via deps but cannot be enabled/disabled
}

// Manager is the service-manager contract.
type Manager interface {
	Status(ctx context.Context, unit string) (UnitStatus, error)
	IsEnabled(ctx context.Context, unit string) (bool, error)
	IsActive(ctx context.Context, unit string) (bool, error)
	IsMasked(ctx context.Context, unit string) (bool, error)
	Enable(ctx context.Context, unit string) error
	Disable(ctx context.Context, unit string) error
	EnableNow(ctx context.Context, unit string) error
	DisableNow(ctx context.Context, unit string) error
	Start(ctx context.Context, unit string) error
	Stop(ctx context.Context, unit string) error
	Restart(ctx context.Context, unit string) error
	Mask(ctx context.Context, unit string) error
	Unmask(ctx context.Context, unit string) error
	DaemonReload(ctx context.Context) error
	WriteUnit(ctx context.Context, unit, content string) error
	RemoveUnit(ctx context.Context, unit string) error
}

// Option is the functional-option type for backend-specific knobs (none today).
type Option func(*systemd)

// New returns a Manager for the named backend, driven by runner. Pure: validates
// the backend is known; it does not probe the host (use Detect). The zero value
// and any unimplemented backend are rejected with ErrUnknownBackend.
func New(b Backend, runner exec.Runner, _ ...Option) (Manager, error) {
	if b != Systemd {
		return nil, fmt.Errorf("%w: %d", ErrUnknownBackend, int(b))
	}
	if runner == nil {
		return nil, fmt.Errorf("service: %w", exec.ErrRunnerRequired)
	}
	fsm, err := newFS(runner)
	if err != nil {
		return nil, err
	}
	return &systemd{r: runner, fsm: fsm}, nil
}

// Detect reports the service backends usable on THIS host: Systemd when both
// systemctl is on PATH and /run/systemd/system exists (systemd is PID 1). It
// lists; it never picks. An empty slice means no usable service manager.
func Detect(ctx context.Context) []Backend {
	_ = ctx
	if _, err := lookPath("systemctl"); err != nil {
		return nil
	}
	if _, err := os.Stat(systemdRunMarker); err != nil {
		return nil
	}
	return []Backend{Systemd}
}

const systemctlQueryTimeout = 30 * time.Second

// ensureCtx applies the query timeout when the caller's context has no deadline.
func ensureCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, systemctlQueryTimeout)
}

// fsManager is the narrow slice of fs.Manager the systemd backend uses to write
// and remove unit files; a small interface so tests inject a fake via newFS.
type fsManager interface {
	WriteFile(ctx context.Context, path string, data []byte, opts fs.WriteOptions) error
	Remove(ctx context.Context, path string) error
}

// Package-var seams. lookPath + systemdRunMarker make Detect deterministically
// testable; newFS builds the fs.Manager (over the same injected Runner) that
// WriteUnit/RemoveUnit write through, and tests override it to stay hermetic.
var (
	lookPath         = osexec.LookPath
	systemdRunMarker = "/run/systemd/system"
	newFS            = func(r exec.Runner) (fsManager, error) { return fs.New(r) }
)
