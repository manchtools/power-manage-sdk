package osquery

import (
	"errors"
	"testing"
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

// TestNewClient_NotInstalled covers the lazy-init failure path: when
// no osqueryi binary is reachable, NewClient must return ErrNotInstalled
// rather than a half-constructed Client.
func TestNewClient_NotInstalled(t *testing.T) {
	restore := lookPath
	defer func() { lookPath = restore }()
	lookPath = func(string) (string, error) {
		return "", errors.New("not found")
	}

	c, err := NewClient()
	if !errors.Is(err, ErrNotInstalled) {
		t.Errorf("NewClient: want ErrNotInstalled, got %v", err)
	}
	if c != nil {
		t.Errorf("NewClient: want nil client on failure, got %+v", c)
	}
}

// TestIsInstalled mirrors NewClient_NotInstalled but exercises the
// pure-bool entry point that callers (e.g. inventory collectors) use
// to gate optional osquery features without paying for client init.
func TestIsInstalled(t *testing.T) {
	restore := lookPath
	defer func() { lookPath = restore }()

	lookPath = func(string) (string, error) {
		return "", errors.New("not found")
	}
	if IsInstalled() {
		t.Errorf("IsInstalled() = true with no installed paths")
	}

	lookPath = func(name string) (string, error) {
		if name == "/usr/bin/osqueryi" {
			return name, nil
		}
		return "", errors.New("not found")
	}
	if !IsInstalled() {
		t.Errorf("IsInstalled() = false with /usr/bin/osqueryi installed")
	}
}
