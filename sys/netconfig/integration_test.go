//go:build integration

package netconfig_test

import (
	"context"
	"os/exec"
	"testing"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/netconfig"
)

// READ-ONLY integration checks: these never call Apply (which would rewrite the
// host's real interface config). They assert Detect reflects the host and that
// Get parses real `ip -j` output for the loopback interface without error.

func TestDetect_Integration(t *testing.T) {
	for _, b := range netconfig.Detect(context.Background()) {
		if b != netconfig.NetworkManager && b != netconfig.SystemdNetworkd {
			t.Errorf("Detect returned an unexpected backend %v", b)
		}
	}
}

func TestGet_Integration(t *testing.T) {
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("iproute2 `ip` not present; Get not exercisable here")
	}
	r, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	// Either backend's Get is the shared `ip` reader; loopback always exists.
	m, err := netconfig.New(netconfig.SystemdNetworkd, r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	st, err := m.Get(context.Background(), "lo")
	if err != nil {
		t.Fatalf("Get(lo) against real `ip -j`: %v", err)
	}
	if st.Name != "lo" {
		t.Errorf("Get(lo).Name = %q, want lo", st.Name)
	}
}
