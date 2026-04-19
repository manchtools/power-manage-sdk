package network

// WiFi backend selector. The package today only implements the
// NetworkManager (nmcli) backend; the other values exist so
// implementations for connman, direct wpa_supplicant, and iwd can
// land later without another proto / package rename.

import (
	"errors"
	"fmt"
	"sync/atomic"
)

// WifiBackend identifies which WiFi-management tool the SDK targets.
type WifiBackend int

const (
	// WifiBackendNetworkManager wraps nmcli. Default.
	WifiBackendNetworkManager WifiBackend = 0
	// WifiBackendConnman wraps connmanctl (not yet implemented).
	WifiBackendConnman WifiBackend = 1
	// WifiBackendWpaSupplicant manages wpa_supplicant.conf directly (not yet implemented).
	WifiBackendWpaSupplicant WifiBackend = 2
	// WifiBackendIwd wraps iwctl (not yet implemented).
	WifiBackendIwd WifiBackend = 3
)

// ErrWifiBackendNotSupported is returned when the active WifiBackend
// lacks a concrete implementation for the requested operation.
var ErrWifiBackendNotSupported = errors.New("wifi backend not supported")

var wifiBackend atomic.Int32

// SetWifiBackend selects the active backend. Call once at startup.
// Unknown values are ignored so a zero-valued proto enum can never
// silently regress an explicitly-set backend.
func SetWifiBackend(b WifiBackend) {
	switch b {
	case WifiBackendNetworkManager, WifiBackendConnman, WifiBackendWpaSupplicant, WifiBackendIwd:
		wifiBackend.Store(int32(b))
	}
}

// CurrentWifiBackend returns the active backend.
func CurrentWifiBackend() WifiBackend {
	return WifiBackend(wifiBackend.Load())
}

// String renders the backend as its canonical tool name.
func (b WifiBackend) String() string {
	switch b {
	case WifiBackendNetworkManager:
		return "networkmanager"
	case WifiBackendConnman:
		return "connman"
	case WifiBackendWpaSupplicant:
		return "wpa_supplicant"
	case WifiBackendIwd:
		return "iwd"
	default:
		return fmt.Sprintf("unknown(%d)", int(b))
	}
}

// requireWifiBackend returns ErrWifiBackendNotSupported when
// CurrentWifiBackend doesn't match the expected implementation.
// Used by the NetworkManager-specific code in wifi.go to refuse
// running against a selection it can't service.
func requireWifiBackend(want WifiBackend, op string) error {
	got := CurrentWifiBackend()
	if got != want {
		return fmt.Errorf("%w: %s requires backend %s, active backend is %s",
			ErrWifiBackendNotSupported, op, want, got)
	}
	return nil
}
