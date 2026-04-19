package dns

import (
	"context"
	"errors"
	"testing"
)

func TestBackend_DefaultIsResolved(t *testing.T) {
	SetBackend(BackendResolved)
	if got := CurrentBackend(); got != BackendResolved {
		t.Errorf("default = %v, want %v", got, BackendResolved)
	}
}

func TestBackend_IgnoresUnknown(t *testing.T) {
	t.Cleanup(func() { SetBackend(BackendResolved) })
	SetBackend(BackendDnsmasq)
	SetBackend(Backend(99))
	if got := CurrentBackend(); got != BackendDnsmasq {
		t.Errorf("unknown leaked through: got %v, want %v", got, BackendDnsmasq)
	}
}

func TestApply_ReturnsSentinel(t *testing.T) {
	err := Apply(context.Background(), Config{Nameservers: []string{"1.1.1.1"}})
	if err == nil || !errors.Is(err, ErrBackendNotSupported) {
		t.Errorf("want ErrBackendNotSupported, got %v", err)
	}
}

func TestBackendString(t *testing.T) {
	tests := []struct {
		b    Backend
		want string
	}{
		{BackendResolved, "resolved"},
		{BackendResolvconf, "resolvconf"},
		{BackendDnsmasq, "dnsmasq"},
		{BackendNetworkManager, "networkmanager"},
		{Backend(42), "unknown(42)"},
	}
	for _, tt := range tests {
		if got := tt.b.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.b, got, tt.want)
		}
	}
}
