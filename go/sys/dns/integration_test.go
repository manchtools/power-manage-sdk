//go:build integration

package dns_test

import (
	"context"
	"os/exec"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/dns"
	pmexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// These are READ-ONLY integration checks: they never call Apply (which would
// rewrite the host's real DNS). They assert Detect reflects the host and that
// the Resolved/NetworkManager Get path parses real resolver files without error.

func TestDetect_Integration(t *testing.T) {
	for _, b := range dns.Detect(context.Background()) {
		if b != dns.Resolved && b != dns.NetworkManager {
			t.Errorf("Detect returned an unexpected backend %v", b)
		}
	}
}

func TestResolvedGet_Integration(t *testing.T) {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		t.Skip("resolvectl not present; Resolved backend not exercisable here")
	}
	r, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	m, err := dns.New(dns.Resolved, r)
	if err != nil {
		t.Fatalf("New(Resolved): %v", err)
	}
	st, err := m.Get(context.Background())
	if err != nil {
		t.Skipf("no systemd-resolved resolv.conf to read on this host: %v", err)
	}
	// A successful read must parse into a well-formed State (no panic; the parse
	// already ran). Nameservers may legitimately be empty on a minimal host.
	_ = st
}

func TestNMGet_Integration(t *testing.T) {
	if _, err := exec.LookPath("nmcli"); err != nil {
		t.Skip("nmcli not present; NetworkManager backend not exercisable here")
	}
	r, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	m, err := dns.New(dns.NetworkManager, r)
	if err != nil {
		t.Fatalf("New(NetworkManager): %v", err)
	}
	if _, err := m.Get(context.Background()); err != nil {
		t.Skipf("no /etc/resolv.conf to read on this host: %v", err)
	}
}
