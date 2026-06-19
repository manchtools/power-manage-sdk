package desktop

import (
	"errors"
	"os/user"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
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
	if _, err := New(nil); !errors.Is(err, exec.ErrRunnerRequired) {
		t.Errorf("New(_, nil) error = %v, want ErrRunnerRequired", err)
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

// TestNew_NilOptionIgnored pins that a nil entry in opts... is skipped rather
// than panicking the constructor (and the agent process with it); a non-nil
// option in the same call still applies.
func TestNew_NilOptionIgnored(t *testing.T) {
	m, err := New(exectest.New(exec.Direct), nil, WithHomeRoot("/custom/home"), nil)
	if err != nil {
		t.Fatalf("New with a nil option returned error: %v", err)
	}
	if m.(*manager).homeRoot != "/custom/home" {
		t.Errorf("a nil option must be skipped and the real one applied; homeRoot = %q", m.(*manager).homeRoot)
	}
}
