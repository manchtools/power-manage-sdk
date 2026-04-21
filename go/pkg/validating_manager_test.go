package pkg

import (
	"errors"
	"testing"
)

// fakeManager is a minimal Manager stub that records whether its
// entry points were reached, so the tests can assert that
// validatingManager short-circuits on invalid names.
type fakeManager struct {
	Manager
	installCalled bool
	removeCalled  bool
	pinCalled     bool
}

func (f *fakeManager) Install(names ...string) (*CommandResult, error) {
	f.installCalled = true
	return &CommandResult{Success: true}, nil
}
func (f *fakeManager) Remove(names ...string) (*CommandResult, error) {
	f.removeCalled = true
	return &CommandResult{Success: true}, nil
}
func (f *fakeManager) InstallVersion(name string, _ InstallOptions) (*CommandResult, error) {
	f.installCalled = true
	return &CommandResult{Success: true}, nil
}
func (f *fakeManager) Upgrade(names ...string) (*CommandResult, error) {
	f.installCalled = true
	return &CommandResult{Success: true}, nil
}
func (f *fakeManager) Pin(names ...string) (*CommandResult, error) {
	f.pinCalled = true
	return &CommandResult{Success: true}, nil
}
func (f *fakeManager) Unpin(names ...string) (*CommandResult, error) {
	f.pinCalled = true
	return &CommandResult{Success: true}, nil
}
func (f *fakeManager) Show(string) (*Package, error)                   { return nil, errors.New("x") }
func (f *fakeManager) ListVersions(string) (*VersionInfo, error)       { return nil, errors.New("x") }
func (f *fakeManager) IsInstalled(string) (bool, error)                { return true, nil }
func (f *fakeManager) GetInstalledVersion(string) (string, error)      { return "1.0", nil }
func (f *fakeManager) IsPinned(string) (bool, error)                   { return false, nil }

// TestValidatingManager_BlocksInjection asserts that every entry
// point that accepts a package name refuses option-injection shapes
// BEFORE dispatching to the underlying Manager. Reaching the fake
// means the wrapper failed closed.
func TestValidatingManager_BlocksInjection(t *testing.T) {
	inner := &fakeManager{}
	v := WithValidation(inner)

	if _, err := v.Install("-y"); err == nil {
		t.Error("Install('-y'): expected rejection")
	}
	if inner.installCalled {
		t.Error("Install reached underlying manager despite bad name")
	}

	if _, err := v.Remove("--force"); err == nil {
		t.Error("Remove('--force'): expected rejection")
	}
	if inner.removeCalled {
		t.Error("Remove reached underlying manager despite bad name")
	}

	if _, err := v.Pin("pkg;rm -rf /"); err == nil {
		t.Error("Pin(shell injection): expected rejection")
	}
	if inner.pinCalled {
		t.Error("Pin reached underlying manager despite bad name")
	}
}

// TestValidatingManager_ForwardsValid asserts the happy path: a
// legitimate package name flows through to the underlying manager.
func TestValidatingManager_ForwardsValid(t *testing.T) {
	inner := &fakeManager{}
	v := WithValidation(inner)

	if _, err := v.Install("nginx"); err != nil {
		t.Errorf("Install('nginx'): unexpected error: %v", err)
	}
	if !inner.installCalled {
		t.Error("Install did not reach underlying manager")
	}
}

// TestWithValidation_IsIdempotent asserts double-wrapping is a
// no-op — New()/Detect() returning an already-wrapped Manager
// should not re-wrap on every call through a caller's defensive
// WithValidation.
func TestWithValidation_IsIdempotent(t *testing.T) {
	inner := &fakeManager{}
	once := WithValidation(inner)
	twice := WithValidation(once)
	if once != twice {
		t.Errorf("WithValidation(WithValidation(m)) should be same instance")
	}
}

func TestWithValidation_NilPassthrough(t *testing.T) {
	if got := WithValidation(nil); got != nil {
		t.Errorf("WithValidation(nil) = %v, want nil", got)
	}
}
