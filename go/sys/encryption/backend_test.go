package encryption

import (
	"errors"
	"testing"
)

func TestEncryptionBackend_DefaultIsLUKS(t *testing.T) {
	SetBackend(BackendLUKS)
	if got := CurrentBackend(); got != BackendLUKS {
		t.Errorf("default backend = %v, want %v", got, BackendLUKS)
	}
}

func TestEncryptionBackend_IgnoresUnknown(t *testing.T) {
	t.Cleanup(func() { SetBackend(BackendLUKS) })
	SetBackend(BackendGELI)
	SetBackend(Backend(99))
	if got := CurrentBackend(); got != BackendGELI {
		t.Errorf("unknown value leaked through: got %v, want %v", got, BackendGELI)
	}
}

func TestRequireBackend(t *testing.T) {
	t.Cleanup(func() { SetBackend(BackendLUKS) })
	SetBackend(BackendLUKS)
	if err := requireBackend(BackendLUKS, "op"); err != nil {
		t.Errorf("requireBackend on matching: unexpected error %v", err)
	}
	SetBackend(BackendGELI)
	err := requireBackend(BackendLUKS, "op")
	if err == nil || !errors.Is(err, ErrBackendNotSupported) {
		t.Errorf("requireBackend on mismatch: want wraps ErrBackendNotSupported, got %v", err)
	}
}

func TestBackendString(t *testing.T) {
	tests := []struct {
		b    Backend
		want string
	}{
		{BackendLUKS, "luks"},
		{BackendGELI, "geli"},
		{BackendCGD, "cgd"},
		{Backend(42), "unknown(42)"},
	}
	for _, tt := range tests {
		if got := tt.b.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.b, got, tt.want)
		}
	}
}
