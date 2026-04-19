package netconfig

import (
	"context"
	"errors"
	"testing"
)

func TestBackend_DefaultIsNetworkManager(t *testing.T) {
	SetBackend(BackendNetworkManager)
	if got := CurrentBackend(); got != BackendNetworkManager {
		t.Errorf("default = %v, want %v", got, BackendNetworkManager)
	}
}

func TestBackend_IgnoresUnknown(t *testing.T) {
	t.Cleanup(func() { SetBackend(BackendNetworkManager) })
	SetBackend(BackendNetplan)
	SetBackend(Backend(99))
	if got := CurrentBackend(); got != BackendNetplan {
		t.Errorf("unknown leaked through: got %v, want %v", got, BackendNetplan)
	}
}

func TestApplyInterface_ReturnsSentinel(t *testing.T) {
	err := ApplyInterface(context.Background(), InterfaceConfig{Name: "eth0", Mode: ModeDHCP})
	if err == nil || !errors.Is(err, ErrBackendNotSupported) {
		t.Errorf("want ErrBackendNotSupported, got %v", err)
	}
}

func TestBackendString(t *testing.T) {
	tests := []struct {
		b    Backend
		want string
	}{
		{BackendNetworkManager, "networkmanager"},
		{BackendSystemdNetworkd, "systemd-networkd"},
		{BackendNetplan, "netplan"},
		{BackendDhcpcd, "dhcpcd"},
		{BackendIfupdown, "ifupdown"},
		{Backend(42), "unknown(42)"},
	}
	for _, tt := range tests {
		if got := tt.b.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.b, got, tt.want)
		}
	}
}
