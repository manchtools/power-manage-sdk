package osquery

import (
	"context"
	"errors"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

// TestFindOsqueryBinary_DiscoveryOrder pins the resolution order of
// findOsqueryBinary: every entry in osqueryPaths is tried first (in
// declaration order), then a bare "osqueryi" PATH lookup as fallback.
// The fallback matters for Homebrew / Nix / manual installs that put
// osqueryi outside the canonical /usr/{,local/}bin paths.
func TestFindOsqueryBinary_DiscoveryOrder(t *testing.T) {
	cases := []struct {
		name      string
		installed map[string]string // path → resolved path; missing = not installed
		want      string
	}{
		{
			name:      "nothing installed",
			installed: nil,
			want:      "",
		},
		{
			name: "first canonical path wins",
			installed: map[string]string{
				"/usr/bin/osqueryi":         "/usr/bin/osqueryi",
				"/usr/local/bin/osqueryi":   "/usr/local/bin/osqueryi",
				"/opt/osquery/bin/osqueryi": "/opt/osquery/bin/osqueryi",
			},
			want: "/usr/bin/osqueryi",
		},
		{
			name: "second canonical path when first missing",
			installed: map[string]string{
				"/usr/local/bin/osqueryi": "/usr/local/bin/osqueryi",
			},
			want: "/usr/local/bin/osqueryi",
		},
		{
			name: "third canonical path when first two missing",
			installed: map[string]string{
				"/opt/osquery/bin/osqueryi": "/opt/osquery/bin/osqueryi",
			},
			want: "/opt/osquery/bin/osqueryi",
		},
		{
			// PATH fallback returns whatever LookPath resolved to,
			// which is the absolute path on a real system. Canonical-
			// path matches above return the canonical input verbatim
			// (LookPath verified existence but findOsqueryBinary
			// discards the resolved value); the asymmetry is
			// intentional — operators expect the canonical paths in
			// logs.
			name: "PATH fallback when no canonical path matches",
			installed: map[string]string{
				"osqueryi": "/home/linuxbrew/.linuxbrew/bin/osqueryi",
			},
			want: "/home/linuxbrew/.linuxbrew/bin/osqueryi",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restore := lookPath
			defer func() { lookPath = restore }()
			lookPath = func(name string) (string, error) {
				resolved, ok := tc.installed[name]
				if !ok {
					return "", errors.New("not found")
				}
				return resolved, nil
			}

			got := findOsqueryBinary()
			if got != tc.want {
				t.Errorf("findOsqueryBinary() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestNew_NotInstalled covers the eager fail-closed probe: when no
// osqueryi binary is reachable, New must return ErrNotInstalled rather
// than a half-constructed Querier, so a caller learns at construction
// that osquery is unavailable.
func TestNew_NotInstalled(t *testing.T) {
	restore := lookPath
	defer func() { lookPath = restore }()
	lookPath = func(string) (string, error) {
		return "", errors.New("not found")
	}

	q, err := New(exectest.New(exec.Direct))
	if !errors.Is(err, ErrNotInstalled) {
		t.Errorf("New: want ErrNotInstalled, got %v", err)
	}
	if q != nil {
		t.Errorf("New: want nil Querier on failure, got %+v", q)
	}
}

func TestNew_NilRunner(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, exec.ErrRunnerRequired) {
		t.Error("New(nil) returned nil error")
	}
}

func TestNew_Success(t *testing.T) {
	restore := lookPath
	defer func() { lookPath = restore }()
	lookPath = func(name string) (string, error) {
		if name == "/usr/bin/osqueryi" {
			return name, nil
		}
		return "", errors.New("not found")
	}
	q, err := New(exectest.New(exec.Direct))
	if err != nil || q == nil {
		t.Fatalf("New = (%v,%v), want a Querier", q, err)
	}
	c, ok := q.(*client)
	if !ok {
		t.Fatalf("New returned %T, want *client", q)
	}
	if c.binaryPath != "/usr/bin/osqueryi" {
		t.Errorf("binaryPath = %q", c.binaryPath)
	}
}

// TestIsInstalled exercises the live re-probe contract: IsInstalled
// re-resolves the binary on every call (it does NOT trust the path
// captured at New), so a binary removed during the agent's lifetime is
// reported as absent and a later re-install is picked up.
func TestIsInstalled(t *testing.T) {
	restore := lookPath
	defer func() { lookPath = restore }()
	// Construct directly so the test can drive IsInstalled across both
	// states without New's eager probe gating construction.
	c := &client{binaryPath: "/usr/bin/osqueryi", r: exectest.New(exec.Direct)}
	ctx := context.Background()

	lookPath = func(string) (string, error) {
		return "", errors.New("not found")
	}
	if c.IsInstalled(ctx) {
		t.Errorf("IsInstalled() = true with no installed paths (removal not detected)")
	}

	lookPath = func(name string) (string, error) {
		if name == "/usr/bin/osqueryi" {
			return name, nil
		}
		return "", errors.New("not found")
	}
	if !c.IsInstalled(ctx) {
		t.Errorf("IsInstalled() = false with /usr/bin/osqueryi installed")
	}
}
