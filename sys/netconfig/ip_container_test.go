//go:build container

// Container-based real-execution test for the iproute2 read path. Get parses
// `ip -j addr/route show dev <name>` (JSON). The fake-runner unit tests feed a
// captured JSON blob; this runs the REAL `ip` binary against a real interface in
// the container's network namespace, so a future iproute2 that changes its `-j`
// JSON shape is caught here. Anti-rot guard. Needs CAP_NET_ADMIN (to add the
// test address). Self-skips when `ip` is absent.
package netconfig

import (
	"context"
	osexec "os/exec"
	"strings"
	"testing"
	"time"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

func TestGet_ParsesRealIpJSON_Container(t *testing.T) {
	if _, err := osexec.LookPath("ip"); err != nil {
		t.Skip("iproute2 `ip` not on PATH")
	}

	const testAddr = "192.0.2.5"
	// Add a deterministic test address to loopback (always present, no module
	// dependency) and clean it up.
	if out, err := osexec.Command("ip", "addr", "add", testAddr+"/32", "dev", "lo").CombinedOutput(); err != nil {
		t.Skipf("cannot add test address (need CAP_NET_ADMIN?): %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_ = osexec.Command("ip", "addr", "del", testAddr+"/32", "dev", "lo").Run()
	})

	r, err := exec.NewRunner(exec.Direct)
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	m, err := New(SystemdNetworkd, r) // Get is backend-independent (just runs `ip`); no daemon needed
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg, err := m.Get(ctx, "lo")
	if err != nil {
		t.Fatalf("Get(lo): %v", err)
	}
	found := false
	for _, a := range cfg.Addresses {
		if strings.HasPrefix(a, testAddr) {
			found = true
		}
	}
	if !found {
		t.Errorf("Get(lo).Addresses = %v; want one starting %q (real `ip -j addr` parse drifted?)", cfg.Addresses, testAddr)
	}
}
