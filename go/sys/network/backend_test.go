package network

import (
	"context"
	"errors"
	"testing"
)

func TestWifiBackend_DefaultIsNetworkManager(t *testing.T) {
	SetWifiBackend(WifiBackendNetworkManager)
	if got := CurrentWifiBackend(); got != WifiBackendNetworkManager {
		t.Errorf("default backend = %v, want %v", got, WifiBackendNetworkManager)
	}
}

func TestWifiBackend_IgnoresUnknown(t *testing.T) {
	t.Cleanup(func() { SetWifiBackend(WifiBackendNetworkManager) })
	SetWifiBackend(WifiBackendIwd)
	SetWifiBackend(WifiBackend(99))
	if got := CurrentWifiBackend(); got != WifiBackendIwd {
		t.Errorf("unknown value leaked through: got %v, want %v", got, WifiBackendIwd)
	}
}

func TestCreateOrUpdate_RejectsNonNMBackend(t *testing.T) {
	t.Cleanup(func() { SetWifiBackend(WifiBackendNetworkManager) })
	SetWifiBackend(WifiBackendConnman)
	_, err := CreateOrUpdate(context.Background(), WiFiProfile{
		Name: "pm-wifi-test", SSID: "x", AuthType: WiFiAuthPSK, PSK: "12345678",
	})
	if err == nil || !errors.Is(err, ErrWifiBackendNotSupported) {
		t.Errorf("want ErrWifiBackendNotSupported, got %v", err)
	}
}

func TestIsAvailable_ReportsFalseOnUnsupportedBackend(t *testing.T) {
	t.Cleanup(func() { SetWifiBackend(WifiBackendNetworkManager) })
	SetWifiBackend(WifiBackendConnman)
	if IsAvailable() {
		t.Error("IsAvailable should return false when no implementation for the active backend")
	}
}

func TestWifiBackendString(t *testing.T) {
	tests := []struct {
		b    WifiBackend
		want string
	}{
		{WifiBackendNetworkManager, "networkmanager"},
		{WifiBackendConnman, "connman"},
		{WifiBackendWpaSupplicant, "wpa_supplicant"},
		{WifiBackendIwd, "iwd"},
		{WifiBackend(42), "unknown(42)"},
	}
	for _, tt := range tests {
		if got := tt.b.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.b, got, tt.want)
		}
	}
}
