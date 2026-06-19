package remote

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// stubVCBackend is the minimum-viable VersionControlBackend used by
// every Slice-8 test. Records the calls it received so the assertion
// surface stays small.
type stubVCBackend struct {
	mu     sync.Mutex
	tag    string // identifies which stub registration handled the call
	syncs  int
	resolv int
}

func (s *stubVCBackend) CloneOrSync(_ context.Context, _ GitConfig, _ string) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncs++
	return Result{Revision: "stub:" + s.tag, Changed: true}, nil
}

func (s *stubVCBackend) Resolve(_ context.Context, _ GitConfig) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resolv++
	return "stub:" + s.tag, nil
}

// withSnapshotRegistry runs body with a clean version-control registry
// and restores whatever was registered before on return. Lets the
// tests in this file overwrite "go-git" or register junk without
// leaking state into the rest of the suite.
func withSnapshotRegistry(t *testing.T, body func()) {
	t.Helper()
	vcRegistry.mu.Lock()
	snapshot := make(map[string]VersionControlBackend, len(vcRegistry.m))
	for k, v := range vcRegistry.m {
		snapshot[k] = v
	}
	vcRegistry.mu.Unlock()
	t.Cleanup(func() {
		vcRegistry.mu.Lock()
		vcRegistry.m = snapshot
		vcRegistry.mu.Unlock()
	})
	body()
}

// TestRegisterVersionControlBackend_LookupAndOverride — round-trips a
// new registration, then re-registers under the same name and asserts
// the second registration wins. Override is a useful property for
// tests that need to swap in a fake backend.
func TestRegisterVersionControlBackend_LookupAndOverride(t *testing.T) {
	withSnapshotRegistry(t, func() {
		first := &stubVCBackend{tag: "first"}
		RegisterVersionControlBackend("stub", first)

		got, err := versionControlBackend("stub")
		if err != nil {
			t.Fatalf("versionControlBackend(stub): %v", err)
		}
		if got != first {
			t.Fatalf("lookup returned wrong backend; got %p want %p", got, first)
		}

		second := &stubVCBackend{tag: "second"}
		RegisterVersionControlBackend("stub", second)
		got2, err := versionControlBackend("stub")
		if err != nil {
			t.Fatalf("versionControlBackend(stub) after override: %v", err)
		}
		if got2 != second {
			t.Fatalf("override didn't win; got %p want %p", got2, second)
		}
	})
}

// TestRegisterVersionControlBackend_IgnoresEmptyNameOrNil — calling
// Register with an empty name or nil backend is a no-op (no panic, no
// stored entry). A later lookup of "" returns ErrBackendNotFound, the
// sentinel callers branch on.
func TestRegisterVersionControlBackend_IgnoresEmptyNameOrNil(t *testing.T) {
	withSnapshotRegistry(t, func() {
		// Don't crash.
		RegisterVersionControlBackend("", &stubVCBackend{tag: "ignored"})
		RegisterVersionControlBackend("nilcheck", nil)

		if _, err := versionControlBackend(""); !errors.Is(err, ErrBackendNotFound) {
			t.Fatalf("versionControlBackend(``) = %v; want ErrBackendNotFound", err)
		}
		if _, err := versionControlBackend("nilcheck"); !errors.Is(err, ErrBackendNotFound) {
			t.Fatalf("versionControlBackend(nilcheck) = %v; want ErrBackendNotFound (nil ignored)", err)
		}
	})
}

// TestVersionControlBackend_UnknownDriver — looking up a driver that
// nobody registered must surface as ErrBackendNotFound. That's the
// error NewGit will translate into a config-time failure in Slice 9.
func TestVersionControlBackend_UnknownDriver(t *testing.T) {
	withSnapshotRegistry(t, func() {
		_, err := versionControlBackend("never-registered")
		if !errors.Is(err, ErrBackendNotFound) {
			t.Fatalf("versionControlBackend(never-registered) = %v; want ErrBackendNotFound", err)
		}
	})
}

// TestRegisterVersionControlBackend_ConcurrentLookup — sanity check
// that concurrent Register + lookup don't race. Run under -race in CI.
func TestRegisterVersionControlBackend_ConcurrentLookup(t *testing.T) {
	withSnapshotRegistry(t, func() {
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				RegisterVersionControlBackend("race", &stubVCBackend{tag: "r"})
			}()
			go func() {
				defer wg.Done()
				_, _ = versionControlBackend("race")
			}()
		}
		wg.Wait()
	})
}
