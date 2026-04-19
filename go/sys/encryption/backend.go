package encryption

// EncryptionBackend is the extension point for supporting disk-encryption
// tools beyond LUKS. The current implementation only targets LUKS2 via
// cryptsetup; the other values exist so implementations for other
// platforms (FreeBSD GELI, NetBSD CGD) can land later without another
// proto / package rename.
//
// Callers should rely on the public functions in this package rather
// than branching on the backend directly; most of today's API is LUKS-
// specific (device-bound keyslots, TPM binding) and will need
// backend-specific analogs rather than a one-to-one mapping.

import (
	"errors"
	"fmt"
	"sync/atomic"
)

// Backend identifies which disk-encryption implementation the SDK targets.
type Backend int

const (
	// BackendLUKS is cryptsetup/LUKS2. Default.
	BackendLUKS Backend = 0
	// BackendGELI is FreeBSD GELI (not yet implemented).
	BackendGELI Backend = 1
	// BackendCGD is NetBSD CGD (not yet implemented).
	BackendCGD Backend = 2
)

// ErrBackendNotSupported is returned when a caller invokes an
// operation on a backend that has no concrete implementation yet.
var ErrBackendNotSupported = errors.New("encryption backend not supported")

var backend atomic.Int32

// SetBackend selects the active backend. Call this once at startup
// from agent code. Unknown values are ignored so a zero-valued proto
// enum can never silently regress an explicitly-set backend.
func SetBackend(b Backend) {
	switch b {
	case BackendLUKS, BackendGELI, BackendCGD:
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
	case BackendLUKS:
		return "luks"
	case BackendGELI:
		return "geli"
	case BackendCGD:
		return "cgd"
	default:
		return fmt.Sprintf("unknown(%d)", int(b))
	}
}

// requireBackend returns ErrBackendNotSupported when CurrentBackend is
// not the expected implementation. Used by the LUKS-specific helpers
// to refuse running against a GELI/CGD selection rather than
// accidentally touching the wrong device.
func requireBackend(want Backend, op string) error {
	got := CurrentBackend()
	if got != want {
		return fmt.Errorf("%w: %s requires backend %s, active backend is %s",
			ErrBackendNotSupported, op, want, got)
	}
	return nil
}
