// Package remote tests. Each slice in the implementation plan adds one
// behaviour group here; this file holds the cross-cutting interface and
// sentinel-error contract tests that every concrete source has to honour.
package remote

import (
	"context"
	"errors"
	"testing"
)

// TestErrorsAreNonNil locks the exported sentinels in place. Callers use
// `errors.Is(err, remote.ErrSomething)` to branch on failure modes — if any
// of these were renamed or accidentally shadowed by a typed alias, the
// branch would silently miss.
func TestErrorsAreNonNil(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrInvalidConfig", ErrInvalidConfig},
		{"ErrUnsafeDestination", ErrUnsafeDestination},
		{"ErrIntegrity", ErrIntegrity},
		{"ErrToolMissing", ErrToolMissing},
		{"ErrBackendNotFound", ErrBackendNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatalf("%s is nil", tt.name)
			}
			if tt.err.Error() == "" {
				t.Fatalf("%s has empty Error() string", tt.name)
			}
			// Sentinel identity must survive wrapping — the canonical
			// downstream pattern is `errors.Is(wrapped, ErrFoo)`.
			wrapped := errors.Join(errors.New("ctx"), tt.err)
			if !errors.Is(wrapped, tt.err) {
				t.Fatalf("%s loses identity through errors.Join", tt.name)
			}
		})
	}
}

// stubSource exists solely to freeze the Source interface signature. If a
// future change to the interface (new method, different shape) breaks the
// assertion below at compile time, the slice that did it must update this
// stub explicitly — i.e. the breakage is intentional, not accidental.
type stubSource struct{}

func (stubSource) Fetch(ctx context.Context, dest string) (Result, error) {
	return Result{}, nil
}
func (stubSource) Wipe(ctx context.Context, dest string) error { return nil }
func (stubSource) String() string                              { return "stub" }

func TestSourceInterfaceCompiles(t *testing.T) {
	var _ Source = (*stubSource)(nil)
}
