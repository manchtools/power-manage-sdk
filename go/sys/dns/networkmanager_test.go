package dns

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

func newNM(t *testing.T) (*nmManager, *exectest.FakeRunner) {
	t.Helper()
	r := exectest.New(exec.Direct)
	m, err := New(NetworkManager, r)
	if err != nil {
		t.Fatalf("New(NetworkManager): %v", err)
	}
	return m.(*nmManager), r
}

func TestNM_ApplyRequiresInterface(t *testing.T) {
	m, r := newNM(t)
	if err := m.Apply(context.Background(), Config{Nameservers: []string{"1.1.1.1"}}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("err = %v, want ErrInvalidConfig (NM requires an interface)", err)
	}
	if len(r.Calls()) != 0 {
		t.Error("missing interface must run no commands")
	}
}

func TestNM_ApplyRejectsInvalidConfig(t *testing.T) {
	m, r := newNM(t)
	if err := m.Apply(context.Background(), Config{Interface: "eth0", Nameservers: []string{"bad"}}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("err = %v, want ErrInvalidConfig", err)
	}
	if len(r.Calls()) != 0 {
		t.Error("validate-before-act: an invalid config must run nothing")
	}
}

func TestNM_ApplyNoActiveConnection(t *testing.T) {
	m, r := newNM(t)
	r.Push(exec.Result{Stdout: "--\n"}, nil) // device show → no connection
	if err := m.Apply(context.Background(), Config{Interface: "eth0", Nameservers: []string{"1.1.1.1"}}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("err = %v, want ErrInvalidConfig for an interface with no active connection", err)
	}
	if len(r.Calls()) != 1 {
		t.Errorf("should stop after the resolve probe, got %d calls", len(r.Calls()))
	}
}

func TestNM_ApplySuccess(t *testing.T) {
	m, r := newNM(t)
	r.Push(exec.Result{Stdout: "Wired connection 1\n"}, nil) // device show → conn name
	r.Push(exec.Result{}, nil)                               // connection modify
	r.Push(exec.Result{}, nil)                               // connection up
	err := m.Apply(context.Background(), Config{
		Interface:     "eth0",
		Nameservers:   []string{"1.1.1.1", "2001:db8::1"},
		SearchDomains: []string{"corp.example", "lan"},
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	calls := r.Calls()
	if len(calls) != 3 {
		t.Fatalf("got %d calls, want 3 (resolve+modify+up): %v", len(calls), calls)
	}
	// resolve probe: unescalated read of GENERAL.CONNECTION.
	if got := strings.Join(calls[0].Args, " "); got != "-g GENERAL.CONNECTION device show eth0" || calls[0].Escalate {
		t.Errorf("resolve argv = %q (escalate=%v), want unescalated `-g GENERAL.CONNECTION device show eth0`", got, calls[0].Escalate)
	}
	// modify: v4 + v6 dns + dns-search on both families; escalated.
	mod := strings.Join(calls[1].Args, " ")
	for _, want := range []string{
		"connection modify Wired connection 1",
		"ipv4.dns 1.1.1.1",
		"ipv6.dns 2001:db8::1",
		"ipv4.dns-search corp.example,lan",
		"ipv6.dns-search corp.example,lan",
	} {
		if !strings.Contains(mod, want) {
			t.Errorf("modify argv missing %q\n  got: %q", want, mod)
		}
	}
	if !calls[1].Escalate {
		t.Error("connection modify must escalate")
	}
	// up: reactivate, escalated.
	if got := strings.Join(calls[2].Args, " "); got != "connection up Wired connection 1" || !calls[2].Escalate {
		t.Errorf("up argv = %q (escalate=%v), want escalated `connection up Wired connection 1`", got, calls[2].Escalate)
	}
}

func TestNM_ApplyV4OnlySkipsV6(t *testing.T) {
	m, r := newNM(t)
	r.Push(exec.Result{Stdout: "conn\n"}, nil)
	r.Push(exec.Result{}, nil)
	r.Push(exec.Result{}, nil)
	if err := m.Apply(context.Background(), Config{Interface: "eth0", Nameservers: []string{"1.1.1.1"}}); err != nil {
		t.Fatal(err)
	}
	mod := strings.Join(r.Calls()[1].Args, " ")
	if strings.Contains(mod, "ipv6.dns") {
		t.Errorf("v4-only config must not set ipv6.dns: %q", mod)
	}
	if strings.Contains(mod, "dns-search") {
		t.Errorf("no search domains must not set dns-search: %q", mod)
	}
}

func TestNM_ApplyModifyFailurePropagates(t *testing.T) {
	m, r := newNM(t)
	r.Push(exec.Result{Stdout: "conn\n"}, nil)
	r.Push(exec.Result{ExitCode: 1, Stderr: "invalid property"}, nil) // modify fails
	if err := m.Apply(context.Background(), Config{Interface: "eth0", Nameservers: []string{"1.1.1.1"}}); err == nil {
		t.Error("a failed connection modify must propagate")
	}
}

func TestNM_ApplyUpFailurePropagates(t *testing.T) {
	m, r := newNM(t)
	r.Push(exec.Result{Stdout: "conn\n"}, nil)
	r.Push(exec.Result{}, nil)                                         // modify ok
	r.Push(exec.Result{ExitCode: 4, Stderr: "activation failed"}, nil) // up fails
	if err := m.Apply(context.Background(), Config{Interface: "eth0", Nameservers: []string{"1.1.1.1"}}); err == nil {
		t.Error("a failed connection up must propagate")
	}
}

func TestNM_ApplyResolveProbeFailurePropagates(t *testing.T) {
	m, r := newNM(t)
	r.Push(exec.Result{}, errors.New("nmcli gone"))
	if err := m.Apply(context.Background(), Config{Interface: "eth0", Nameservers: []string{"1.1.1.1"}}); err == nil {
		t.Error("a failed resolve probe must propagate")
	}
}

func TestNM_Get(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver 9.9.9.9\nsearch corp.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := etcResolvConfPath
	t.Cleanup(func() { etcResolvConfPath = prev })
	etcResolvConfPath = path

	m, _ := newNM(t)
	st, err := m.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if strings.Join(st.Nameservers, ",") != "9.9.9.9" || strings.Join(st.SearchDomains, ",") != "corp.example" {
		t.Errorf("Get = %+v", st)
	}
}

func TestNM_GetReadError(t *testing.T) {
	prev := etcResolvConfPath
	t.Cleanup(func() { etcResolvConfPath = prev })
	etcResolvConfPath = filepath.Join(t.TempDir(), "missing")
	m, _ := newNM(t)
	if _, err := m.Get(context.Background()); err == nil {
		t.Error("Get must surface a read error")
	}
}
