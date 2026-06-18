// Package antivirus manages an on-host antivirus engine through an injected
// exec.Runner.
//
//	r, _ := exec.NewRunner(exec.Direct) // a full scan / signature update needs root
//	m, err := antivirus.New(antivirus.ClamAV, r)
//	if err != nil { ... }
//	res, _ := m.Scan(ctx, "/home")
//	for _, inf := range res.Infected { fmt.Println(inf.File, inf.Signature) }
//
// V1 implements the ClamAV backend (clamscan / freshclam). This is the
// configure/operate half of AV management — scan on demand, update signatures,
// read engine/signature versions — complementary to the alert-ingestion path
// (a SIEM / compliance-event forwarder). On-access / real-time protection
// (ClamAV's clamonacc) and EDR engines (Defender/Falcon/SentinelOne, which use
// cloud APIs rather than a CLI) are out of V1 scope.
//
// Reads (Version) run unprivileged; Scan and UpdateSignatures escalate.
package antivirus

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// Backend selects the AV engine. The zero value is invalid; only implemented
// backends exist.
type Backend int

// ClamAV is the clamscan/freshclam backend.
const ClamAV Backend = iota + 1

// String renders the backend as its canonical name.
func (b Backend) String() string {
	switch b {
	case ClamAV:
		return "clamav"
	default:
		return fmt.Sprintf("Backend(%d)", int(b))
	}
}

// ErrUnknownBackend is returned by New for the zero value or any unimplemented
// backend.
var ErrUnknownBackend = errors.New("antivirus: unknown backend")

// ErrInvalidPath is returned when a scan path is unsafe (empty, NUL, or
// flag-shaped).
var ErrInvalidPath = errors.New("antivirus: invalid scan path")

// Infection is one detected threat.
type Infection struct {
	File      string // the infected file path
	Signature string // the signature/threat name that matched
}

// ScanResult is the outcome of a Scan.
type ScanResult struct {
	Path     string      // the path that was scanned
	Infected []Infection // detected threats (empty ⇒ clean)
}

// Clean reports whether the scan found no threats.
func (r ScanResult) Clean() bool { return len(r.Infected) == 0 }

// Version describes the installed engine + signature database.
type Version struct {
	Engine    string // engine version, e.g. "1.0.1"
	Signature string // signature DB version, e.g. "27000"
}

// Manager is the antivirus surface.
type Manager interface {
	// Scan scans path recursively and returns any detected infections. A clean
	// scan and an infected scan both succeed (inspect ScanResult); only an engine
	// failure returns an error.
	Scan(ctx context.Context, path string) (ScanResult, error)
	// UpdateSignatures refreshes the engine's signature database.
	UpdateSignatures(ctx context.Context) error
	// Version reports the engine and signature-database versions.
	Version(ctx context.Context) (Version, error)
}

// New returns a Manager for the named backend, driven by runner. Pure: validates
// the backend; nil runner and unknown backend are rejected.
func New(b Backend, runner exec.Runner) (Manager, error) {
	if runner == nil {
		return nil, fmt.Errorf("antivirus: %w", exec.ErrRunnerRequired)
	}
	switch b {
	case ClamAV:
		return &clamavManager{r: runner}, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownBackend, int(b))
	}
}

// validatePath rejects a scan path that is unsafe as a positional argument.
func validatePath(path string) error {
	if path == "" || strings.HasPrefix(path, "-") || strings.ContainsRune(path, 0) {
		return fmt.Errorf("%w: %q", ErrInvalidPath, path)
	}
	return nil
}
