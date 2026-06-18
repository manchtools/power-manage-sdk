package netconfig

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

const (
	fixtureAddrJSON = `[{"ifname":"eth0","mtu":1500,"addr_info":[` +
		`{"family":"inet","local":"192.0.2.10","prefixlen":24,"scope":"global"},` +
		`{"family":"inet6","local":"2001:db8::10","prefixlen":64,"scope":"global"},` +
		`{"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"}]}]`
	fixtureRouteJSON = `[{"dst":"default","gateway":"192.0.2.1","metric":100},` +
		`{"dst":"10.0.0.0/8","gateway":"192.0.2.254","metric":50},` +
		`{"dst":"192.0.2.0/24"}]`
)

func TestGet_Success(t *testing.T) {
	r := exectest.New(exec.Direct)
	r.Push(exec.Result{Stdout: fixtureAddrJSON}, nil)  // ip addr
	r.Push(exec.Result{Stdout: fixtureRouteJSON}, nil) // ip route
	got, err := base{r: r}.Get(context.Background(), "eth0")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if strings.Join(got.Addresses, ",") != "192.0.2.10/24,2001:db8::10/64" {
		t.Errorf("addresses = %v (fe80 link-scope must be skipped)", got.Addresses)
	}
	if got.MTU != 1500 {
		t.Errorf("MTU = %d, want 1500", got.MTU)
	}
	if got.Gateway != "192.0.2.1" {
		t.Errorf("gateway = %q, want 192.0.2.1 (from the default route)", got.Gateway)
	}
	if len(got.Routes) != 1 || got.Routes[0].Destination != "10.0.0.0/8" || got.Routes[0].Gateway != "192.0.2.254" || got.Routes[0].Metric != 50 {
		t.Errorf("routes = %+v, want one 10.0.0.0/8 route (connected route skipped)", got.Routes)
	}
	// The reads are unprivileged and use `ip -j`.
	for _, c := range r.Calls() {
		if c.Escalate {
			t.Errorf("Get must not escalate: %+v", c)
		}
		if c.Name != "ip" || c.Args[0] != "-j" {
			t.Errorf("Get must use `ip -j`, got %s %v", c.Name, c.Args)
		}
	}
}

func TestGet_BadInterfaceName(t *testing.T) {
	r := exectest.New(exec.Direct)
	if _, err := (base{r: r}).Get(context.Background(), "-evil"); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("err = %v, want ErrInvalidConfig", err)
	}
	if len(r.Calls()) != 0 {
		t.Error("a bad interface name must run no commands")
	}
}

func TestGet_AddrReadError(t *testing.T) {
	r := exectest.New(exec.Direct)
	r.Push(exec.Result{ExitCode: 1, Stderr: "device does not exist"}, nil)
	if _, err := (base{r: r}).Get(context.Background(), "eth0"); err == nil {
		t.Error("a failed `ip addr` must surface")
	}
}

func TestGet_RouteReadError(t *testing.T) {
	r := exectest.New(exec.Direct)
	r.Push(exec.Result{Stdout: fixtureAddrJSON}, nil)
	r.Push(exec.Result{}, errors.New("ip gone"))
	if _, err := (base{r: r}).Get(context.Background(), "eth0"); err == nil {
		t.Error("a failed `ip route` must surface")
	}
}

func TestParseIPState_BadJSON(t *testing.T) {
	if _, err := parseIPState("eth0", "not json", "[]"); err == nil {
		t.Error("bad addr JSON must error")
	}
	if _, err := parseIPState("eth0", "[]", "not json"); err == nil {
		t.Error("bad route JSON must error")
	}
}

func TestParseIPState_EmptyLink(t *testing.T) {
	// `ip addr` for a nonexistent-but-zero result: empty array → no addresses/MTU,
	// no panic.
	cfg, err := parseIPState("eth0", "[]", "[]")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Addresses) != 0 || cfg.MTU != 0 || cfg.Gateway != "" || len(cfg.Routes) != 0 {
		t.Errorf("empty state = %+v, want zero-valued", cfg)
	}
}
