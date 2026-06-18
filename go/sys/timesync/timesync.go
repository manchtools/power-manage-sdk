// Package timesync reads a host's clock-synchronization status through an
// injected exec.Runner.
//
//	r, _ := exec.NewRunner(exec.Direct)
//	m, err := timesync.New(timesync.Chrony, r)
//	if err != nil { ... }
//	st, _ := m.Status(ctx)
//	fmt.Println(st.Synchronized, st.Source, st.OffsetSeconds)
//
// Two backends are implemented: Timedatectl (systemd; reports synchronized +
// service-enabled) and Chrony (chronyc; reports synchronized + reference source
// + estimated offset). Reads are unprivileged. Detect lists the tools on PATH;
// the consumer picks one and passes it to New (no auto-detection, no globals).
package timesync

import (
	"context"
	"errors"
	"fmt"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// Backend selects the time-sync daemon to query. The zero value is invalid; only
// implemented backends exist (ntpd/openntpd are intentionally absent).
type Backend int

const (
	// Timedatectl queries systemd via `timedatectl show`.
	Timedatectl Backend = iota + 1
	// Chrony queries chrony via `chronyc -c tracking`.
	Chrony
)

// String renders the backend as its canonical tool name.
func (b Backend) String() string {
	switch b {
	case Timedatectl:
		return "timedatectl"
	case Chrony:
		return "chrony"
	default:
		return fmt.Sprintf("Backend(%d)", int(b))
	}
}

// ErrUnknownBackend is returned by New for the zero value or any unimplemented
// backend.
var ErrUnknownBackend = errors.New("timesync: unknown backend")

// Status is a snapshot of the host clock's synchronization state. Fields a
// backend cannot report are left at their zero value (Timedatectl does not
// expose source/offset; both are populated by Chrony).
type Status struct {
	Synchronized  bool    // the clock is currently disciplined to a source
	Enabled       bool    // a time-sync service is enabled/running
	Source        string  // reference source (server name/IP)
	OffsetSeconds float64 // estimated offset from true time (signed)
}

// Manager is the time-sync read surface.
type Manager interface {
	// Status reads the current synchronization state.
	Status(ctx context.Context) (Status, error)
}

// New returns a Manager for the named backend, driven by runner. Pure: validates
// the backend; does not probe (use Detect). Nil runner and unknown backend are
// rejected.
func New(b Backend, runner exec.Runner) (Manager, error) {
	if runner == nil {
		return nil, fmt.Errorf("timesync: %w", exec.ErrRunnerRequired)
	}
	switch b {
	case Timedatectl:
		return &timedatectlManager{r: runner}, nil
	case Chrony:
		return &chronyManager{r: runner}, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownBackend, int(b))
	}
}

// runRead runs an unprivileged query and returns stdout, mapping a non-zero exit
// (or exec failure) into an error.
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
