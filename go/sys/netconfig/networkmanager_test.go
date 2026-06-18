package netconfig

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

func newNM(t *testing.T) (*nmBackend, *exectest.FakeRunner) {
	t.Helper()
	r := exectest.New(exec.Direct)
	m, err := New(NetworkManager, r)
	if err != nil {
		t.Fatalf("New(NetworkManager): %v", err)
	}
	return m.(*nmBackend), r
}

func TestNM_ApplyRejectsInvalidConfig(t *testing.T) {
	m, r := newNM(t)
	if err := m.Apply(context.Background(), InterfaceConfig{Name: "eth0", Mode: Static}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("err = %v, want ErrInvalidConfig", err)
	}
	if len(r.Calls()) != 0 {
		t.Error("validate-before-act: invalid config runs nothing")
	}
}

func TestNM_ApplyNoActiveConnection(t *testing.T) {
	m, r := newNM(t)
	r.Push(exec.Result{Stdout: "--\n"}, nil)
	if err := m.Apply(context.Background(), InterfaceConfig{Name: "eth0", Mode: DHCP}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("err = %v, want ErrInvalidConfig for no active connection", err)
	}
	if len(r.Calls()) != 1 {
		t.Errorf("should stop after the resolve probe, got %d", len(r.Calls()))
	}
}

func TestNM_ApplyStaticSuccess(t *testing.T) {
	m, r := newNM(t)
	r.Push(exec.Result{Stdout: "Wired connection 1\n"}, nil) // resolve
	r.Push(exec.Result{}, nil)                               // modify
	r.Push(exec.Result{}, nil)                               // up
	err := m.Apply(context.Background(), InterfaceConfig{
		Name: "eth0", Mode: Static,
		Addresses: []string{"192.0.2.10/24", "2001:db8::10/64"},
		Gateway:   "192.0.2.1", DNS: []string{"1.1.1.1", "2001:db8::1"}, MTU: 1400,
		Routes: []Route{{Destination: "10.0.0.0/8", Gateway: "192.0.2.254", Metric: 100}, {Destination: "default", Gateway: "2001:db8::1"}},
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	calls := r.Calls()
	if len(calls) != 3 {
		t.Fatalf("got %d calls, want 3", len(calls))
	}
	if got := strings.Join(calls[0].Args, " "); got != "-g GENERAL.CONNECTION device show eth0" || calls[0].Escalate {
		t.Errorf("resolve argv = %q (escalate=%v), want unescalated probe", got, calls[0].Escalate)
	}
	mod := strings.Join(calls[1].Args, " ")
	for _, want := range []string{
		"connection modify Wired connection 1",
		"ipv4.method manual ipv4.addresses 192.0.2.10/24 ipv4.gateway 192.0.2.1",
		"ipv6.method manual ipv6.addresses 2001:db8::10/64",
		"ipv4.dns 1.1.1.1", "ipv6.dns 2001:db8::1",
		"802-3-ethernet.mtu 1400",
		"ipv4.routes 10.0.0.0/8 192.0.2.254 100",
		"ipv6.routes ::/0 2001:db8::1",
	} {
		if !strings.Contains(mod, want) {
			t.Errorf("modify argv missing %q\n  got: %q", want, mod)
		}
	}
	if !calls[1].Escalate {
		t.Error("modify must escalate")
	}
	if got := strings.Join(calls[2].Args, " "); got != "connection up Wired connection 1" || !calls[2].Escalate {
		t.Errorf("up argv = %q, want escalated `connection up Wired connection 1`", got)
	}
}

func TestNM_ApplyDHCPClearsManual(t *testing.T) {
	m, r := newNM(t)
	r.Push(exec.Result{Stdout: "conn\n"}, nil)
	r.Push(exec.Result{}, nil)
	r.Push(exec.Result{}, nil)
	if err := m.Apply(context.Background(), InterfaceConfig{Name: "eth0", Mode: DHCP}); err != nil {
		t.Fatal(err)
	}
	mod := strings.Join(r.Calls()[1].Args, " ")
	for _, want := range []string{"ipv4.method auto", "ipv4.addresses", "ipv4.gateway", "ipv6.method auto"} {
		if !strings.Contains(mod, want) {
			t.Errorf("DHCP modify missing %q\n  got: %q", want, mod)
		}
	}
}

// Routes are independent of addressing mode: a DHCP interface with a static
// route still emits ipv4.routes.
func TestNM_ApplyDHCPWithRoute(t *testing.T) {
	m, r := newNM(t)
	r.Push(exec.Result{Stdout: "conn\n"}, nil)
	r.Push(exec.Result{}, nil)
	r.Push(exec.Result{}, nil)
	err := m.Apply(context.Background(), InterfaceConfig{
		Name: "eth0", Mode: DHCP,
		Routes: []Route{{Destination: "10.0.0.0/8", Gateway: "192.0.2.254"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mod := strings.Join(r.Calls()[1].Args, " ")
	if !strings.Contains(mod, "ipv4.method auto") || !strings.Contains(mod, "ipv4.routes 10.0.0.0/8 192.0.2.254") {
		t.Errorf("DHCP + static route must emit auto method AND ipv4.routes:\n%q", mod)
	}
}

func TestNM_ApplyV4OnlyStatic(t *testing.T) {
	m, r := newNM(t)
	r.Push(exec.Result{Stdout: "conn\n"}, nil)
	r.Push(exec.Result{}, nil)
	r.Push(exec.Result{}, nil)
	if err := m.Apply(context.Background(), InterfaceConfig{Name: "eth0", Mode: Static, Addresses: []string{"192.0.2.10/24"}}); err != nil {
		t.Fatal(err)
	}
	mod := strings.Join(r.Calls()[1].Args, " ")
	if strings.Contains(mod, "ipv6.method manual") {
		t.Errorf("a v4-only static config must not set ipv6 manual: %q", mod)
	}
}

func TestNM_ApplyModifyFailurePropagates(t *testing.T) {
	m, r := newNM(t)
	r.Push(exec.Result{Stdout: "conn\n"}, nil)
	r.Push(exec.Result{ExitCode: 1, Stderr: "bad property"}, nil)
	if err := m.Apply(context.Background(), InterfaceConfig{Name: "eth0", Mode: DHCP}); err == nil {
		t.Error("a failed modify must propagate")
	}
}

func TestNM_ApplyUpFailurePropagates(t *testing.T) {
	m, r := newNM(t)
	r.Push(exec.Result{Stdout: "conn\n"}, nil)
	r.Push(exec.Result{}, nil)
	r.Push(exec.Result{ExitCode: 4, Stderr: "activation failed"}, nil)
	if err := m.Apply(context.Background(), InterfaceConfig{Name: "eth0", Mode: DHCP}); err == nil {
		t.Error("a failed up must propagate")
	}
}

func TestNM_ApplyResolveFailurePropagates(t *testing.T) {
	m, r := newNM(t)
	r.Push(exec.Result{}, errors.New("nmcli gone"))
	if err := m.Apply(context.Background(), InterfaceConfig{Name: "eth0", Mode: DHCP}); err == nil {
		t.Error("a failed resolve probe must propagate")
	}
}

func TestNM_Get(t *testing.T) {
	m, r := newNM(t)
	r.Push(exec.Result{Stdout: fixtureAddrJSON}, nil)
	r.Push(exec.Result{Stdout: fixtureRouteJSON}, nil)
	st, err := m.Get(context.Background(), "eth0")
	if err != nil || st.Gateway != "192.0.2.1" {
		t.Fatalf("Get via NM = (%+v,%v)", st, err)
	}
}

// nmRoutesByFamily: a "default" destination becomes the family-correct default
// CIDR (0.0.0.0/0 for a v4 gateway, ::/0 for a v6 gateway), bucketed by family.
func TestNMRoutesByFamily_DefaultPerFamily(t *testing.T) {
	v4, v6 := nmRoutesByFamily([]Route{
		{Destination: "default", Gateway: "192.0.2.1"},
		{Destination: "default", Gateway: "2001:db8::1"},
		{Destination: "10.0.0.0/8", Gateway: "192.0.2.254", Metric: 5},
	})
	if strings.Join(v4, "|") != "0.0.0.0/0 192.0.2.1|10.0.0.0/8 192.0.2.254 5" {
		t.Errorf("v4 routes = %v", v4)
	}
	if strings.Join(v6, "|") != "::/0 2001:db8::1" {
		t.Errorf("v6 routes = %v", v6)
	}
}

// nmModifyArgs unit: a v6-gateway-only static config routes the gateway to
// ipv6.gateway, not ipv4.
func TestNMModifyArgs_V6Gateway(t *testing.T) {
	args := strings.Join(nmModifyArgs(InterfaceConfig{
		Mode: Static, Addresses: []string{"2001:db8::10/64"}, Gateway: "2001:db8::1",
	}), " ")
	if !strings.Contains(args, "ipv6.gateway 2001:db8::1") {
		t.Errorf("v6 gateway must map to ipv6.gateway: %q", args)
	}
	if strings.Contains(args, "ipv4.gateway") {
		t.Errorf("must not emit ipv4.gateway for a v6-only config: %q", args)
	}
}
