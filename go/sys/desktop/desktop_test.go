package desktop

import (
	"errors"
	"os/user"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

// newManager builds a Manager backed by a fresh FakeRunner and returns both so
// a test can Push loginctl results and inspect recorded calls.
func newManager(t *testing.T, opts ...Option) (*manager, *exectest.FakeRunner) {
	t.Helper()
	r := exectest.New(exec.Direct)
	m, err := New(r, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m.(*manager), r
}

// stubLookPath makes lookPath report loginctl present (found=true) or absent,
// restoring the previous value on cleanup.
func stubLookPath(t *testing.T, found bool) {
	t.Helper()
	prev := lookPath
	t.Cleanup(func() { lookPath = prev })
	lookPath = func(string) (string, error) {
		if found {
			return loginctlPath, nil
		}
		return "", errors.New("loginctl: not found")
	}
}

// stubLookupID overrides the passwd-by-uid lookup for the duration of t.
func stubLookupID(t *testing.T, fn func(string) (*user.User, error)) {
	t.Helper()
	prev := lookupID
	t.Cleanup(func() { lookupID = prev })
	lookupID = fn
}

// stubLookupUser overrides the passwd-by-name lookup for the duration of t.
func stubLookupUser(t *testing.T, fn func(string) (*user.User, error)) {
	t.Helper()
	prev := lookupUser
	t.Cleanup(func() { lookupUser = prev })
	lookupUser = fn
}

func TestNew_NilRunner(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Error("New(nil) returned nil error; a nil runner must be rejected")
	}
}

func TestNew_DefaultHomeRoot(t *testing.T) {
	m, _ := newManager(t)
	if m.homeRoot != defaultHomeRoot {
		t.Errorf("default homeRoot = %q, want %q", m.homeRoot, defaultHomeRoot)
	}
}

func TestNew_WithHomeRoot(t *testing.T) {
	m, _ := newManager(t, WithHomeRoot("/custom/home"))
	if m.homeRoot != "/custom/home" {
		t.Errorf("WithHomeRoot homeRoot = %q, want /custom/home", m.homeRoot)
	}
}
