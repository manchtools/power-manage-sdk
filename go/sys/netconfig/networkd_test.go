package netconfig

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

func newNetworkd(t *testing.T, ff *fakeFS) (*networkdBackend, *exectest.FakeRunner) {
	t.Helper()
	withFakeFS(t, ff)
	r := exectest.New(exec.Direct)
	m, err := New(SystemdNetworkd, r)
	if err != nil {
		t.Fatalf("New(SystemdNetworkd): %v", err)
	}
	return m.(*networkdBackend), r
}

func TestNetworkd_ApplyStatic(t *testing.T) {
	ff := &fakeFS{}
	m, r := newNetworkd(t, ff)
	r.Push(exec.Result{}, nil) // networkctl reload
	err := m.Apply(context.Background(), InterfaceConfig{
		Name: "eth0", Mode: Static,
		Addresses: []string{"192.0.2.10/24", "2001:db8::10/64"},
		Gateway:   "192.0.2.1", DNS: []string{"1.1.1.1"}, MTU: 1500,
		Routes: []Route{{Destination: "10.0.0.0/8", Gateway: "192.0.2.254", Metric: 100}, {Destination: "default", Gateway: "203.0.113.1"}},
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(ff.writes) != 1 || ff.writes[0].path != networkDir+"/eth0.network" {
		t.Fatalf("writes = %v, want one at %s/eth0.network", ff.writes, networkDir)
	}
	body := string(ff.writes[0].data)
	for _, want := range []string{
		"[Match]\nName=eth0",
		"Address=192.0.2.10/24", "Address=2001:db8::10/64",
		"Gateway=192.0.2.1", "DNS=1.1.1.1",
		"[Link]\nMTUBytes=1500",
		"[Route]\nDestination=10.0.0.0/8\nGateway=192.0.2.254\nMetric=100",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("unit missing %q\n%s", want, body)
		}
	}
	// The default route omits Destination (networkd infers it per gateway family).
	if !strings.Contains(body, "[Route]\nGateway=203.0.113.1") {
		t.Errorf("default route should be a Destination-less [Route]:\n%s", body)
	}
	if strings.Contains(body, "DHCP=yes") {
		t.Errorf("static config must not emit DHCP=yes:\n%s", body)
	}
	if ff.writes[0].opts.Mode != 0o644 || ff.writes[0].opts.Owner != "root" {
		t.Errorf("write opts = %+v, want mode 0644 root", ff.writes[0].opts)
	}
	// reload escalated.
	last := r.Calls()
	if len(last) != 1 || strings.Join(last[0].Args, " ") != "reload" || last[0].Name != "networkctl" || !last[0].Escalate {
		t.Errorf("reload call = %v, want escalated `networkctl reload`", last)
	}
}

func TestNetworkd_ApplyDHCP(t *testing.T) {
	ff := &fakeFS{}
	m, r := newNetworkd(t, ff)
	r.Push(exec.Result{}, nil)
	if err := m.Apply(context.Background(), InterfaceConfig{Name: "eth0", Mode: DHCP, DNS: []string{"9.9.9.9"}}); err != nil {
		t.Fatal(err)
	}
	body := string(ff.writes[0].data)
	if !strings.Contains(body, "DHCP=yes") {
		t.Errorf("DHCP config must emit DHCP=yes:\n%s", body)
	}
	if strings.Contains(body, "Address=") || strings.Contains(body, "Gateway=") {
		t.Errorf("DHCP config must not emit Address/Gateway:\n%s", body)
	}
	if !strings.Contains(body, "DNS=9.9.9.9") {
		t.Errorf("DNS applies under DHCP too:\n%s", body)
	}
}

// Routes (and DNS/MTU) are independent of the addressing mode: a DHCP interface
// with a static route emits the [Route] alongside DHCP=yes.
func TestNetworkd_ApplyDHCPWithRoute(t *testing.T) {
	ff := &fakeFS{}
	m, r := newNetworkd(t, ff)
	r.Push(exec.Result{}, nil)
	err := m.Apply(context.Background(), InterfaceConfig{
		Name: "eth0", Mode: DHCP,
		Routes: []Route{{Destination: "10.0.0.0/8", Gateway: "192.0.2.254"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := string(ff.writes[0].data)
	if !strings.Contains(body, "DHCP=yes") || !strings.Contains(body, "[Route]\nDestination=10.0.0.0/8\nGateway=192.0.2.254") {
		t.Errorf("DHCP + static route must emit both DHCP=yes and the [Route]:\n%s", body)
	}
}

func TestNetworkd_ApplyRejectsInvalidConfig(t *testing.T) {
	m, r := newNetworkd(t, &fakeFS{})
	if err := m.Apply(context.Background(), InterfaceConfig{Name: "eth0", Mode: Static}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("err = %v, want ErrInvalidConfig (static needs an address)", err)
	}
	if len(r.Calls()) != 0 {
		t.Error("validate-before-act: invalid config runs nothing")
	}
}

func TestNetworkd_ApplyWriteFailurePropagates(t *testing.T) {
	m, _ := newNetworkd(t, &fakeFS{writeErr: errors.New("read-only fs")})
	if err := m.Apply(context.Background(), InterfaceConfig{Name: "eth0", Mode: DHCP}); err == nil {
		t.Error("a failed WriteFile must propagate")
	}
}

func TestNetworkd_ApplyReloadFailurePropagates(t *testing.T) {
	m, r := newNetworkd(t, &fakeFS{})
	r.Push(exec.Result{ExitCode: 1, Stderr: "reload failed"}, nil)
	if err := m.Apply(context.Background(), InterfaceConfig{Name: "eth0", Mode: DHCP}); err == nil {
		t.Error("a failed networkctl reload must propagate")
	}
}

func TestNetworkd_Get(t *testing.T) {
	// Get is the shared base impl over `ip`; here just confirm networkd wires it.
	ff := &fakeFS{}
	m, r := newNetworkd(t, ff)
	r.Push(exec.Result{Stdout: fixtureAddrJSON}, nil)
	r.Push(exec.Result{Stdout: fixtureRouteJSON}, nil)
	st, err := m.Get(context.Background(), "eth0")
	if err != nil || st.MTU != 1500 {
		t.Fatalf("Get via networkd = (%+v,%v)", st, err)
	}
}
