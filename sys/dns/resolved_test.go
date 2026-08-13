package dns

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

func newResolved(t *testing.T, ff *fakeFS) (*resolvedManager, *exectest.FakeRunner) {
	t.Helper()
	withFakeFS(t, ff)
	r := exectest.New(exec.Direct)
	m, err := New(Resolved, r)
	if err != nil {
		t.Fatalf("New(Resolved): %v", err)
	}
	return m.(*resolvedManager), r
}

func TestResolved_ApplyScoped(t *testing.T) {
	m, r := newResolved(t, &fakeFS{})
	r.Push(exec.Result{}, nil) // resolvectl dns
	r.Push(exec.Result{}, nil) // resolvectl domain
	err := m.Apply(context.Background(), Config{
		Interface: "eth0", Nameservers: []string{"1.1.1.1", "8.8.8.8"}, SearchDomains: []string{"corp.example"},
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	calls := r.Calls()
	if len(calls) != 2 {
		t.Fatalf("got %d calls, want 2 (dns + domain): %v", len(calls), calls)
	}
	if got := strings.Join(calls[0].Args, " "); got != "dns eth0 -- 1.1.1.1 8.8.8.8" || !calls[0].Escalate {
		t.Errorf("dns argv = %q (escalate=%v), want `dns eth0 -- 1.1.1.1 8.8.8.8` escalated", got, calls[0].Escalate)
	}
	if got := strings.Join(calls[1].Args, " "); got != "domain eth0 -- corp.example" {
		t.Errorf("domain argv = %q, want `domain eth0 -- corp.example`", got)
	}
}

func TestResolved_ApplyScoped_NoDomainsSkipsDomainCall(t *testing.T) {
	m, r := newResolved(t, &fakeFS{})
	r.Push(exec.Result{}, nil) // only the dns call
	if err := m.Apply(context.Background(), Config{Interface: "eth0", Nameservers: []string{"1.1.1.1"}}); err != nil {
		t.Fatal(err)
	}
	if len(r.Calls()) != 1 {
		t.Errorf("no search domains must run exactly one (dns) call, got %d", len(r.Calls()))
	}
}

func TestResolved_ApplyScoped_DNSFailurePropagates(t *testing.T) {
	m, r := newResolved(t, &fakeFS{})
	r.Push(exec.Result{ExitCode: 1, Stderr: "link not found"}, nil)
	if err := m.Apply(context.Background(), Config{Interface: "eth0", Nameservers: []string{"1.1.1.1"}}); err == nil {
		t.Error("a failed resolvectl dns must propagate")
	}
}

func TestResolved_ApplyScoped_DomainFailurePropagates(t *testing.T) {
	m, r := newResolved(t, &fakeFS{})
	r.Push(exec.Result{}, nil)                                  // dns ok
	r.Push(exec.Result{ExitCode: 1, Stderr: "bad domain"}, nil) // domain fails
	if err := m.Apply(context.Background(), Config{Interface: "eth0", Nameservers: []string{"1.1.1.1"}, SearchDomains: []string{"corp.example"}}); err == nil {
		t.Error("a failed resolvectl domain must propagate")
	}
}

// TestResolved_ApplyScoped_DomainFailureResetsTheLink pins that a scoped Apply
// does not leave a half-applied link. `resolvectl dns` lands first, so a failing
// `resolvectl domain` used to return an error while the new nameservers stayed
// applied — the caller was told the config was rejected while the box had
// already switched resolvers, with the OLD search domains.
//
// Apply issues `resolvectl revert <iface>`, which resets the link to
// systemd-resolved's per-link DEFAULTS. That is deliberately not a restore of
// the pre-call state — see the comment on Apply — so this asserts the reset was
// issued and the original failure preserved, NOT that prior settings came back.
func TestResolved_ApplyScoped_DomainFailureResetsTheLink(t *testing.T) {
	m, r := newResolved(t, &fakeFS{})
	r.Push(exec.Result{}, nil)                                  // dns ok
	r.Push(exec.Result{ExitCode: 1, Stderr: "bad domain"}, nil) // domain fails
	r.Push(exec.Result{}, nil)                                  // revert
	err := m.Apply(context.Background(), Config{Interface: "eth0", Nameservers: []string{"1.1.1.1"}, SearchDomains: []string{"corp.example"}})
	if err == nil {
		t.Fatal("a failed resolvectl domain must propagate")
	}
	calls := r.Calls()
	if len(calls) != 3 {
		t.Fatalf("got %d calls, want 3 (dns, domain, revert): %v", len(calls), calls)
	}
	if got := strings.Join(calls[2].Args, " "); got != "revert eth0" {
		t.Errorf("reset argv = %q, want `revert eth0`", got)
	}
	if !calls[2].Escalate {
		t.Error("the reset must escalate like the calls it undoes")
	}
	// The reset is the remedy, not the news: the operator still needs the
	// domain failure that caused it.
	if !strings.Contains(err.Error(), "bad domain") {
		t.Errorf("err = %v, want the original resolvectl domain failure preserved", err)
	}
	// And the message must not oversell what revert did — an operator reading
	// "reverted" as "your previous per-link settings are back" would be wrong.
	if !strings.Contains(err.Error(), "default") {
		t.Errorf("err = %v, want it to say the link was reset to systemd-resolved's per-link defaults rather than restored", err)
	}
}

// The rollback is best-effort: when the revert ALSO fails the link is left in
// the half-applied state, and the error must say so instead of pretending the
// link was restored.
func TestResolved_ApplyScoped_RevertFailureIsReported(t *testing.T) {
	m, r := newResolved(t, &fakeFS{})
	r.Push(exec.Result{}, nil)                                     // dns ok
	r.Push(exec.Result{ExitCode: 1, Stderr: "bad domain"}, nil)    // domain fails
	r.Push(exec.Result{ExitCode: 1, Stderr: "revert failed"}, nil) // revert fails too
	err := m.Apply(context.Background(), Config{Interface: "eth0", Nameservers: []string{"1.1.1.1"}, SearchDomains: []string{"corp.example"}})
	if err == nil {
		t.Fatal("a failed resolvectl domain must propagate")
	}
	calls := r.Calls()
	if len(calls) != 3 {
		t.Fatalf("got %d calls, want 3 (dns, domain, attempted revert): %v", len(calls), calls)
	}
	if got := strings.Join(calls[2].Args, " "); got != "revert eth0" {
		t.Fatalf("rollback argv = %q, want `revert eth0`", got)
	}
	if !strings.Contains(err.Error(), "bad domain") {
		t.Errorf("err = %v, want the original resolvectl domain failure preserved", err)
	}
	// A failed revert leaves the link half-configured, which is a materially
	// different operator situation from a clean rollback — the message must not
	// read the same as the successful-revert one.
	if !strings.Contains(err.Error(), "revert failed") {
		t.Errorf("err = %v, want the revert's own failure surfaced so the operator knows the link is still half-configured", err)
	}
}

// A scoped Apply whose calls all succeed must NOT revert — the positive control
// for the rollback above.
func TestResolved_ApplyScoped_SuccessDoesNotRevert(t *testing.T) {
	m, r := newResolved(t, &fakeFS{})
	r.Push(exec.Result{}, nil) // dns
	r.Push(exec.Result{}, nil) // domain
	if err := m.Apply(context.Background(), Config{Interface: "eth0", Nameservers: []string{"1.1.1.1"}, SearchDomains: []string{"corp.example"}}); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Calls() {
		if len(c.Args) > 0 && c.Args[0] == "revert" {
			t.Errorf("a successful Apply must not revert the link: %v", r.Calls())
		}
	}
}

func TestResolved_ApplyGlobal(t *testing.T) {
	ff := &fakeFS{}
	m, r := newResolved(t, ff)
	r.Push(exec.Result{}, nil) // systemctl restart
	err := m.Apply(context.Background(), Config{
		Nameservers: []string{"1.1.1.1", "2001:db8::1"}, SearchDomains: []string{"corp.example", "lan"},
	})
	if err != nil {
		t.Fatalf("Apply global: %v", err)
	}
	// Mkdir then WriteFile of the drop-in.
	if len(ff.mkdirs) != 1 || ff.mkdirs[0] != resolvedDropInDir {
		t.Errorf("mkdirs = %v, want [%s]", ff.mkdirs, resolvedDropInDir)
	}
	if len(ff.writes) != 1 || ff.writes[0].path != resolvedDropInPath {
		t.Fatalf("writes = %v, want one at %s", ff.writes, resolvedDropInPath)
	}
	body := string(ff.writes[0].data)
	for _, want := range []string{"[Resolve]", "DNS=1.1.1.1 2001:db8::1", "Domains=corp.example lan"} {
		if !strings.Contains(body, want) {
			t.Errorf("drop-in missing %q\n%s", want, body)
		}
	}
	if ff.writes[0].opts.Mode != 0o644 || ff.writes[0].opts.Owner != "root" {
		t.Errorf("drop-in opts = %+v, want mode 0644 owner root", ff.writes[0].opts)
	}
	// Then a restart of resolved.
	last := r.Calls()
	if len(last) != 1 || strings.Join(last[0].Args, " ") != "restart systemd-resolved" || !last[0].Escalate {
		t.Errorf("restart call = %v, want escalated `systemctl restart systemd-resolved`", last)
	}
}

func TestResolved_ApplyGlobal_MkdirFailurePropagates(t *testing.T) {
	m, _ := newResolved(t, &fakeFS{mkdirErr: errors.New("permission denied")})
	if err := m.Apply(context.Background(), Config{Nameservers: []string{"1.1.1.1"}}); err == nil {
		t.Error("a failed Mkdir must propagate")
	}
}

func TestResolved_ApplyGlobal_WriteFailurePropagates(t *testing.T) {
	m, _ := newResolved(t, &fakeFS{writeErr: errors.New("disk full")})
	if err := m.Apply(context.Background(), Config{Nameservers: []string{"1.1.1.1"}}); err == nil {
		t.Error("a failed WriteFile must propagate")
	}
}

func TestResolved_ApplyGlobal_RestartFailurePropagates(t *testing.T) {
	m, r := newResolved(t, &fakeFS{})
	r.Push(exec.Result{ExitCode: 1, Stderr: "unit failed"}, nil) // restart fails
	if err := m.Apply(context.Background(), Config{Nameservers: []string{"1.1.1.1"}}); err == nil {
		t.Error("a failed systemctl restart must propagate")
	}
}

func TestResolved_ApplyRejectsInvalidConfig(t *testing.T) {
	m, r := newResolved(t, &fakeFS{})
	if err := m.Apply(context.Background(), Config{Nameservers: []string{"not-an-ip"}}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("err = %v, want ErrInvalidConfig", err)
	}
	if len(r.Calls()) != 0 {
		t.Error("an invalid config must run no commands (validate-before-act)")
	}
}

// TestResolved_ApplyGlobal_RenderErrorPropagates covers the defensive
// render-error branch in Apply (unreachable in production because validateConfig
// runs first) by overriding the renderDropIn seam.
func TestResolved_ApplyGlobal_RenderErrorPropagates(t *testing.T) {
	prev := renderDropIn
	t.Cleanup(func() { renderDropIn = prev })
	sentinel := errors.New("render boom")
	renderDropIn = func(Config) ([]byte, error) { return nil, sentinel }

	m, _ := newResolved(t, &fakeFS{})
	if err := m.Apply(context.Background(), Config{Nameservers: []string{"1.1.1.1"}}); !errors.Is(err, sentinel) {
		t.Errorf("Apply err = %v, want the render error surfaced", err)
	}
}

func TestResolved_Get(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	content := "# comment\n; also comment\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nsearch a.example b.example\noptions edns0\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := resolvConfPath
	t.Cleanup(func() { resolvConfPath = prev })
	resolvConfPath = path

	m, _ := newResolved(t, &fakeFS{})
	st, err := m.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if strings.Join(st.Nameservers, ",") != "1.1.1.1,8.8.8.8" {
		t.Errorf("nameservers = %v", st.Nameservers)
	}
	if strings.Join(st.SearchDomains, ",") != "a.example,b.example" {
		t.Errorf("search domains = %v", st.SearchDomains)
	}
}

func TestResolved_GetReadError(t *testing.T) {
	prev := resolvConfPath
	t.Cleanup(func() { resolvConfPath = prev })
	resolvConfPath = filepath.Join(t.TempDir(), "does-not-exist")
	m, _ := newResolved(t, &fakeFS{})
	if _, err := m.Get(context.Background()); err == nil {
		t.Error("Get must surface a read error for a missing resolv.conf")
	}
}

// parseResolvConf: the last search/domain line wins (resolver(5)); `domain`
// is treated like `search`.
func TestParseResolvConf_LastSearchWins(t *testing.T) {
	st := parseResolvConf([]byte("search first.example\ndomain second.example\nnameserver 9.9.9.9\n"))
	if strings.Join(st.SearchDomains, ",") != "second.example" {
		t.Errorf("search domains = %v, want [second.example] (last wins)", st.SearchDomains)
	}
	if strings.Join(st.Nameservers, ",") != "9.9.9.9" {
		t.Errorf("nameservers = %v", st.Nameservers)
	}
}

// parseResolvConf strips inline comments so a hand-edited line like
// `search corp.example # note` does not leak comment tokens into the State.
func TestParseResolvConf_StripsInlineComments(t *testing.T) {
	st := parseResolvConf([]byte("nameserver 1.1.1.1 # primary\nsearch corp.example lan ; trailing\n"))
	if strings.Join(st.Nameservers, ",") != "1.1.1.1" {
		t.Errorf("nameservers = %v, want [1.1.1.1] (inline comment stripped)", st.Nameservers)
	}
	if strings.Join(st.SearchDomains, ",") != "corp.example,lan" {
		t.Errorf("search domains = %v, want [corp.example lan] (inline comment stripped)", st.SearchDomains)
	}
	// A line that is only a keyword followed immediately by a comment yields no
	// values (and must not panic).
	st = parseResolvConf([]byte("search # nothing here\n"))
	if len(st.SearchDomains) != 0 {
		t.Errorf("search-only-comment domains = %v, want empty", st.SearchDomains)
	}
}

func TestRenderResolvedDropIn_NewlineGuard(t *testing.T) {
	// Defense-in-depth: a value carrying a newline is refused (validateConfig
	// already prevents this, but the renderer fails closed regardless).
	if _, err := renderResolvedDropIn(Config{Nameservers: []string{"1.1.1.1\nDNS=evil"}}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("nameserver newline: err = %v, want ErrInvalidConfig", err)
	}
	if _, err := renderResolvedDropIn(Config{SearchDomains: []string{"a\nDomains=evil"}}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("domain newline: err = %v, want ErrInvalidConfig", err)
	}
	// Empty config renders just the header + section (no DNS/Domains lines).
	body, err := renderResolvedDropIn(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "DNS=") || strings.Contains(string(body), "Domains=") {
		t.Errorf("empty config must not emit DNS/Domains lines:\n%s", body)
	}
}
