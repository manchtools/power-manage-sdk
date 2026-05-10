package firewall

import (
	"context"
	"errors"
	"testing"
)

func TestBackend_DefaultIsNftables(t *testing.T) {
	SetBackend(BackendNftables)
	if got := CurrentBackend(); got != BackendNftables {
		t.Errorf("default = %v, want %v", got, BackendNftables)
	}
}

func TestBackend_IgnoresUnknown(t *testing.T) {
	t.Cleanup(func() { SetBackend(BackendNftables) })
	SetBackend(BackendPF)
	SetBackend(Backend(99))
	if got := CurrentBackend(); got != BackendPF {
		t.Errorf("unknown value leaked through: got %v, want %v", got, BackendPF)
	}
}

func TestApplyRule_ReturnsSentinel(t *testing.T) {
	ctx := context.Background()
	err := ApplyRule(ctx, Rule{Name: "test", Allow: true, Protocol: ProtocolTCP, Port: 22})
	if err == nil || !errors.Is(err, ErrBackendNotSupported) {
		t.Errorf("want ErrBackendNotSupported, got %v", err)
	}
}

func TestBackendString(t *testing.T) {
	tests := []struct {
		b    Backend
		want string
	}{
		{BackendNftables, "nftables"},
		{BackendIptables, "iptables"},
		{BackendFirewalld, "firewalld"},
		{BackendUFW, "ufw"},
		{BackendPF, "pf"},
		{Backend(42), "unknown(42)"},
	}
	for _, tt := range tests {
		if got := tt.b.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.b, got, tt.want)
		}
	}
}
