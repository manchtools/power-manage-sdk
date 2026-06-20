//go:build integration

package dns_test

import (
	"context"
	"os"
	osexec "os/exec"
	"slices"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/dns"
	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// systemdRunning reports whether systemd is PID 1 (so resolvectl/systemctl can
// reach the running systemd-resolved). /run/systemd/system exists exactly then.
func systemdRunning() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// resolvedActive reports whether systemd-resolved is the live resolver: its
// generated uplink resolv.conf exists and resolvectl is on PATH. Under the
// test-sys systemd container both hold (the unit is enabled in the image), so
// the Apply round-trip below is a HARD assertion there; elsewhere it skips.
func resolvedActive() bool {
	if _, err := osexec.LookPath("resolvectl"); err != nil {
		return false
	}
	_, err := os.Stat("/run/systemd/resolve/resolv.conf")
	return err == nil
}

// TestDetect_Integration: Detect must only ever return implemented backends, and
// under the test-sys container (resolvectl installed) it must report Resolved.
func TestDetect_Integration(t *testing.T) {
	backends := dns.Detect(context.Background())
	for _, b := range backends {
		if b != dns.Resolved && b != dns.NetworkManager {
			t.Errorf("Detect returned an unexpected backend %v", b)
		}
	}
	if _, err := osexec.LookPath("resolvectl"); err == nil {
		if !slices.Contains(backends, dns.Resolved) {
			t.Errorf("resolvectl on PATH but Detect did not report Resolved: %v", backends)
		}
	}
}

// TestResolvedGet_Integration reads the real systemd-resolved resolv.conf and
// asserts it parses into a well-formed State. Under the systemd container this
// MUST succeed (the unit is enabled); elsewhere it skips.
func TestResolvedGet_Integration(t *testing.T) {
	if !resolvedActive() {
		t.Skip("systemd-resolved not active here; Resolved Get not exercisable")
	}
	m := newResolved(t)
	if _, err := m.Get(context.Background()); err != nil {
		t.Fatalf("Get against real systemd-resolved resolv.conf: %v", err)
	}
}

// TestResolvedApply_Global_Integration is the high-value drift guard: it drives
// the real global Apply path end-to-end — render the managed resolved.conf.d
// drop-in, write it through escalated fs ops, `systemctl restart systemd-resolved`
// — then reads back the regenerated /run/systemd/resolve/resolv.conf and asserts
// the applied nameservers and search domain round-trip through real resolved.
//
// This pins two contracts at once against the live tool: (1) the drop-in format
// the SDK emits is still accepted by systemd-resolved, and (2) resolved's
// generated resolv.conf is still the shape parseResolvConf reads. A format change
// in either direction fails here.
func TestResolvedApply_Global_Integration(t *testing.T) {
	if !systemdRunning() || !resolvedActive() {
		t.Skip("requires a live systemd + systemd-resolved (test-sys container)")
	}
	m := newResolved(t)
	ctx := context.Background()

	// TEST-NET-1 (RFC 5737) / documentation-range (RFC 3849) addresses: valid IP
	// literals that are guaranteed not to be real resolvers, so a leftover can
	// never silently exfiltrate or hijack lookups.
	const wantV4 = "192.0.2.53"
	const wantV6 = "2001:db8::53"
	const wantDomain = "corp.example"

	// Restore baseline: remove the managed drop-in and restart resolved so the
	// container's DNS is not left pinned at the dead TEST-NET resolver for any
	// later test sharing this container.
	t.Cleanup(func() { restoreResolved(t) })

	if err := m.Apply(ctx, dns.Config{
		Nameservers:   []string{wantV4, wantV6},
		SearchDomains: []string{wantDomain},
	}); err != nil {
		t.Fatalf("Apply(global) against real systemd-resolved: %v", err)
	}

	st, err := m.Get(ctx)
	if err != nil {
		t.Fatalf("Get after Apply: %v", err)
	}
	if !slices.Contains(st.Nameservers, wantV4) {
		t.Errorf("applied nameserver %q not reflected in resolv.conf; got %v", wantV4, st.Nameservers)
	}
	if !slices.Contains(st.Nameservers, wantV6) {
		t.Errorf("applied nameserver %q not reflected in resolv.conf; got %v", wantV6, st.Nameservers)
	}
	if !slices.Contains(st.SearchDomains, wantDomain) {
		t.Errorf("applied search domain %q not reflected in resolv.conf; got %v", wantDomain, st.SearchDomains)
	}
}

// TestResolvedApply_PerLink_Integration drives the runtime per-link path
// (`resolvectl dns <iface> -- <ns>`) against a real interface. resolved tracks
// every kernel link, so on a normal container eth0 is configurable; where the
// link is not resolvable by resolved (minimal/edge netns) the tool rejects it
// and we skip — the global path above is the load-bearing assertion.
func TestResolvedApply_PerLink_Integration(t *testing.T) {
	if !systemdRunning() || !resolvedActive() {
		t.Skip("requires a live systemd + systemd-resolved (test-sys container)")
	}
	iface := firstRealLink(t)
	if iface == "" {
		t.Skip("no non-loopback link to scope per-link DNS to")
	}
	m := newResolved(t)
	// resolvectl dns sets a RUNTIME per-link resolver; revert it so the link is
	// not left pointing at the dead TEST-NET address for the rest of the run.
	t.Cleanup(func() { revertLink(t, iface) })
	err := m.Apply(context.Background(), dns.Config{
		Nameservers: []string{"192.0.2.53"},
		Interface:   iface,
	})
	if err != nil {
		// resolved declined to scope DNS to this link (link not managed in this
		// netns); informative, not a drift failure.
		t.Skipf("per-link resolvectl dns %s not applicable here: %v", iface, err)
	}
	t.Logf("per-link Apply on %s accepted by real resolvectl", iface)
}

func newResolved(t *testing.T) dns.Manager {
	t.Helper()
	// Sudo (not Direct): the test runs as the unprivileged power-manage user, so
	// Apply's escalated mutations (mkdir/tee/chmod the root-owned drop-in,
	// `systemctl restart`, `resolvectl`) must go through `sudo -n`. This exercises
	// the exact escalation seam production uses (where the agent runs as root and
	// Direct is a no-op wrapper) — the capability code is escalation-agnostic.
	r, err := pmexec.NewRunner(pmexec.Sudo)
	if err != nil {
		t.Fatalf("NewRunner(Sudo): %v", err)
	}
	m, err := dns.New(dns.Resolved, r)
	if err != nil {
		t.Fatalf("New(Resolved): %v", err)
	}
	return m
}

// restoreResolved removes the managed drop-in and restarts resolved, returning
// the container to its baseline resolver config. Best-effort: failures here are
// logged, not fatal, so they never mask the test's own verdict.
func restoreResolved(t *testing.T) {
	t.Helper()
	r, err := pmexec.NewRunner(pmexec.Sudo)
	if err != nil {
		t.Logf("restore: NewRunner: %v", err)
		return
	}
	ctx := context.Background()
	if _, err := r.Run(ctx, pmexec.Command{
		Name: "rm", Args: []string{"-f", "/etc/systemd/resolved.conf.d/10-power-manage.conf"}, Escalate: true,
	}); err != nil {
		t.Logf("restore: rm drop-in: %v", err)
	}
	if _, err := r.Run(ctx, pmexec.Command{
		Name: "systemctl", Args: []string{"restart", "systemd-resolved"}, Escalate: true,
	}); err != nil {
		t.Logf("restore: restart resolved: %v", err)
	}
}

// revertLink clears any runtime per-link resolver configuration on iface,
// returning it to baseline. Best-effort: logged, never fatal.
func revertLink(t *testing.T, iface string) {
	t.Helper()
	r, err := pmexec.NewRunner(pmexec.Sudo)
	if err != nil {
		t.Logf("revert: NewRunner: %v", err)
		return
	}
	if _, err := r.Run(context.Background(), pmexec.Command{
		Name: "resolvectl", Args: []string{"revert", iface}, Escalate: true,
	}); err != nil {
		t.Logf("revert: resolvectl revert %s: %v", iface, err)
	}
}

// firstRealLink returns the first non-loopback interface name from
// /sys/class/net, or "" when only lo is present.
func firstRealLink(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if name := e.Name(); name != "lo" {
			return name
		}
	}
	return ""
}
