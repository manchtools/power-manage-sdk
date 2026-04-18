// Package service provides service-manager operations that dispatch
// through a configurable backend. The default backend is systemd; call
// SetServiceBackend at agent startup to select a different one. The
// public API is stable across backends — an implementation that lacks
// a particular capability returns ErrBackendNotSupported so callers
// can surface a clear error rather than silently misbehaving.
package service

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
)

// ServiceBackend identifies which service-manager the SDK targets.
type ServiceBackend int

const (
	// ServiceBackendSystemd wraps systemctl. Default.
	ServiceBackendSystemd ServiceBackend = 0
	// ServiceBackendOpenRC wraps rc-service / rc-update.
	ServiceBackendOpenRC ServiceBackend = 1
	// ServiceBackendRunit wraps sv / update-service.
	ServiceBackendRunit ServiceBackend = 2
	// ServiceBackendS6 wraps s6-rc.
	ServiceBackendS6 ServiceBackend = 3
)

// ErrBackendNotSupported is returned when the caller requests an
// operation on a backend that has not been implemented yet. Callers
// can errors.Is against this sentinel to decide whether to fall back
// or surface a clear diagnostic.
var ErrBackendNotSupported = errors.New("service backend not supported")

// UnitStatus is the cross-backend view of a unit's current state.
// Implementations fill in whichever subset of these fields their
// backend can answer and leave the rest false.
type UnitStatus struct {
	Enabled bool
	Active  bool
	Masked  bool
	Static  bool
}

var backend atomic.Int32

// SetServiceBackend selects the active backend. Call this once at
// startup from agent code. Unknown values are ignored so a zero-valued
// proto enum can never regress an explicitly-set backend.
func SetServiceBackend(b ServiceBackend) {
	switch b {
	case ServiceBackendSystemd, ServiceBackendOpenRC, ServiceBackendRunit, ServiceBackendS6:
		backend.Store(int32(b))
	}
}

// CurrentServiceBackend returns the active backend. Useful for agent
// code that needs to render backend-specific paths or log output.
func CurrentServiceBackend() ServiceBackend {
	return ServiceBackend(backend.Load())
}

// unsupported returns a descriptive error for any backend without a
// concrete implementation for the given operation.
func unsupported(op string) error {
	return fmt.Errorf("%w: %s on backend %s", ErrBackendNotSupported, op, CurrentServiceBackend())
}

// String renders the backend as its canonical CLI name.
func (b ServiceBackend) String() string {
	switch b {
	case ServiceBackendSystemd:
		return "systemd"
	case ServiceBackendOpenRC:
		return "openrc"
	case ServiceBackendRunit:
		return "runit"
	case ServiceBackendS6:
		return "s6"
	default:
		return fmt.Sprintf("unknown(%d)", int(b))
	}
}

// =============================================================================
// Public API — dispatches to the active backend
// =============================================================================

// Status retrieves the current status of a unit. Returns
// ErrBackendNotSupported if the active backend has no implementation,
// or a validation error if the unit name is not well-formed.
func Status(unitName string) (UnitStatus, error) {
	switch CurrentServiceBackend() {
	case ServiceBackendSystemd:
		if err := validateUnitNameSystemd(unitName); err != nil {
			return UnitStatus{}, err
		}
		return statusSystemd(unitName), nil
	default:
		return UnitStatus{}, unsupported("Status")
	}
}

// IsEnabled reports whether a unit is enabled (or in a state where
// enabling is not needed, for backends that track that distinction).
// Returns ErrBackendNotSupported if the active backend has no
// implementation, or a validation error if the unit name is not
// well-formed.
func IsEnabled(unitName string) (bool, error) {
	switch CurrentServiceBackend() {
	case ServiceBackendSystemd:
		if err := validateUnitNameSystemd(unitName); err != nil {
			return false, err
		}
		return isEnabledSystemd(unitName), nil
	default:
		return false, unsupported("IsEnabled")
	}
}

// IsMasked reports whether a unit is masked. Returns
// ErrBackendNotSupported on backends without a masking concept so
// callers can distinguish "not masked" from "backend cannot tell",
// or a validation error if the unit name is not well-formed.
func IsMasked(unitName string) (bool, error) {
	switch CurrentServiceBackend() {
	case ServiceBackendSystemd:
		if err := validateUnitNameSystemd(unitName); err != nil {
			return false, err
		}
		return isMaskedSystemd(unitName), nil
	default:
		return false, unsupported("IsMasked")
	}
}

// IsActive reports whether a unit is currently active (running).
// Returns ErrBackendNotSupported if the active backend has no
// implementation, or a validation error if the unit name is not
// well-formed.
func IsActive(unitName string) (bool, error) {
	switch CurrentServiceBackend() {
	case ServiceBackendSystemd:
		if err := validateUnitNameSystemd(unitName); err != nil {
			return false, err
		}
		return isActiveSystemd(unitName), nil
	default:
		return false, unsupported("IsActive")
	}
}

// DaemonReload reloads the service manager's on-disk configuration.
func DaemonReload(ctx context.Context) error {
	switch CurrentServiceBackend() {
	case ServiceBackendSystemd:
		return daemonReloadSystemd(ctx)
	default:
		return unsupported("DaemonReload")
	}
}

// Enable enables a unit (persistent across reboots).
func Enable(ctx context.Context, unitName string) error {
	switch CurrentServiceBackend() {
	case ServiceBackendSystemd:
		return enableSystemd(ctx, unitName)
	default:
		return unsupported("Enable")
	}
}

// Disable disables a unit.
func Disable(ctx context.Context, unitName string) error {
	switch CurrentServiceBackend() {
	case ServiceBackendSystemd:
		return disableSystemd(ctx, unitName)
	default:
		return unsupported("Disable")
	}
}

// Start starts a unit.
func Start(ctx context.Context, unitName string) error {
	switch CurrentServiceBackend() {
	case ServiceBackendSystemd:
		return startSystemd(ctx, unitName)
	default:
		return unsupported("Start")
	}
}

// Stop stops a unit.
func Stop(ctx context.Context, unitName string) error {
	switch CurrentServiceBackend() {
	case ServiceBackendSystemd:
		return stopSystemd(ctx, unitName)
	default:
		return unsupported("Stop")
	}
}

// Restart restarts a unit.
func Restart(ctx context.Context, unitName string) error {
	switch CurrentServiceBackend() {
	case ServiceBackendSystemd:
		return restartSystemd(ctx, unitName)
	default:
		return unsupported("Restart")
	}
}

// Mask masks a unit, preventing it from being started.
// Not all backends support masking; those that don't return
// ErrBackendNotSupported.
func Mask(ctx context.Context, unitName string) error {
	switch CurrentServiceBackend() {
	case ServiceBackendSystemd:
		return maskSystemd(ctx, unitName)
	default:
		return unsupported("Mask")
	}
}

// Unmask unmasks a unit.
func Unmask(ctx context.Context, unitName string) error {
	switch CurrentServiceBackend() {
	case ServiceBackendSystemd:
		return unmaskSystemd(ctx, unitName)
	default:
		return unsupported("Unmask")
	}
}

// EnableNow enables and starts a unit.
func EnableNow(ctx context.Context, unitName string) error {
	switch CurrentServiceBackend() {
	case ServiceBackendSystemd:
		return enableNowSystemd(ctx, unitName)
	default:
		return unsupported("EnableNow")
	}
}

// DisableNow disables and stops a unit.
func DisableNow(ctx context.Context, unitName string) error {
	switch CurrentServiceBackend() {
	case ServiceBackendSystemd:
		return disableNowSystemd(ctx, unitName)
	default:
		return unsupported("DisableNow")
	}
}

// ValidateUnitName validates the unit name per the active backend's
// naming rules (e.g., systemd requires a type suffix). Returns an
// error describing the violation.
func ValidateUnitName(unitName string) error {
	switch CurrentServiceBackend() {
	case ServiceBackendSystemd:
		return validateUnitNameSystemd(unitName)
	default:
		return unsupported("ValidateUnitName")
	}
}

// WriteUnit writes the unit file content to the backend's conventional
// location (/etc/systemd/system for systemd, /etc/init.d for openrc, etc.).
// content is passed through verbatim.
func WriteUnit(ctx context.Context, unitName, content string) error {
	switch CurrentServiceBackend() {
	case ServiceBackendSystemd:
		return writeUnitSystemd(ctx, unitName, content)
	default:
		return unsupported("WriteUnit")
	}
}

// RemoveUnit deletes the unit file from the backend's location.
// Returns an error if the unit name is invalid for the active backend
// or if the backend has no implementation; the filesystem removal
// itself remains best-effort.
func RemoveUnit(ctx context.Context, unitName string) error {
	switch CurrentServiceBackend() {
	case ServiceBackendSystemd:
		return removeUnitSystemd(ctx, unitName)
	default:
		return unsupported("RemoveUnit")
	}
}
