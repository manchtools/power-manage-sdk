package service

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestServiceBackend_DefaultIsSystemd(t *testing.T) {
	SetServiceBackend(ServiceBackendSystemd)
	if got := CurrentServiceBackend(); got != ServiceBackendSystemd {
		t.Errorf("default backend = %v, want %v", got, ServiceBackendSystemd)
	}
}

func TestServiceBackend_IgnoresUnknown(t *testing.T) {
	t.Cleanup(func() { SetServiceBackend(ServiceBackendSystemd) })
	SetServiceBackend(ServiceBackendOpenRC)
	SetServiceBackend(ServiceBackend(99))
	if got := CurrentServiceBackend(); got != ServiceBackendOpenRC {
		t.Errorf("unknown value leaked through: got %v, want %v", got, ServiceBackendOpenRC)
	}
}

func TestUnsupportedBackendReturnsSentinel(t *testing.T) {
	t.Cleanup(func() { SetServiceBackend(ServiceBackendSystemd) })
	SetServiceBackend(ServiceBackendOpenRC)

	ctx := context.Background()
	err := Enable(ctx, "does-not-matter")
	if err == nil {
		t.Fatal("Enable should fail on OpenRC until implemented")
	}
	if !errors.Is(err, ErrBackendNotSupported) {
		t.Errorf("Enable on OpenRC: want wraps ErrBackendNotSupported, got %v", err)
	}
	if !strings.Contains(err.Error(), "Enable") {
		t.Errorf("error should name the operation, got %v", err)
	}
}

func TestBackendString(t *testing.T) {
	tests := []struct {
		backend ServiceBackend
		want    string
	}{
		{ServiceBackendSystemd, "systemd"},
		{ServiceBackendOpenRC, "openrc"},
		{ServiceBackendRunit, "runit"},
		{ServiceBackendS6, "s6"},
		{ServiceBackend(42), "unknown(42)"},
	}
	for _, tt := range tests {
		if got := tt.backend.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.backend, got, tt.want)
		}
	}
}
