package firewall

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// recordingRunner is the test exec.Runner: it records each Command (so a test can
// assert the exact tool argv + stdin) and scripts the Run results FIFO. A default
// result (exit 0, empty) is returned once the script is exhausted.
type recordingRunner struct {
	mu      sync.Mutex
	calls   []capturedCall
	results []scripted
}

type capturedCall struct {
	cmd   exec.Command
	stdin string
}

type scripted struct {
	res exec.Result
	err error
}

func (r *recordingRunner) push(res exec.Result, err error) {
	r.results = append(r.results, scripted{res, err})
}

// pushOut is a convenience for the common "exit 0 with this stdout" case.
func (r *recordingRunner) pushOut(stdout string) { r.push(exec.Result{Stdout: stdout}, nil) }

func (r *recordingRunner) record(c exec.Command) (exec.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cc := capturedCall{cmd: c}
	if c.Stdin != nil {
		b, _ := io.ReadAll(c.Stdin)
		cc.stdin = string(b)
	}
	r.calls = append(r.calls, cc)
	if len(r.results) == 0 {
		return exec.Result{}, nil
	}
	s := r.results[0]
	r.results = r.results[1:]
	return s.res, s.err
}

func (r *recordingRunner) Run(ctx context.Context, c exec.Command) (exec.Result, error) {
	return r.record(c)
}
func (r *recordingRunner) Stream(ctx context.Context, c exec.Command, _ exec.OutputCallback) (exec.Result, error) {
	return r.record(c)
}
func (r *recordingRunner) Backend() exec.PrivilegeBackend { return exec.Direct }

var _ exec.Runner = (*recordingRunner)(nil)

// argvOf returns the joined argv of the n-th recorded call.
func (r *recordingRunner) argvOf(n int) string {
	if n >= len(r.calls) {
		return ""
	}
	return r.calls[n].cmd.Name + " " + strings.Join(r.calls[n].cmd.Args, " ")
}

func newMgr(t *testing.T, b Backend, ns string, r exec.Runner) Manager {
	t.Helper()
	m, err := New(b, ns, r)
	if err != nil {
		t.Fatalf("New(%d, %q): %v", b, ns, err)
	}
	return m
}

// --- New ---

func TestNew_FailClosed(t *testing.T) {
	r := &recordingRunner{}
	for _, b := range []Backend{0, Backend(-1), Backend(99)} {
		if _, err := New(b, "app", r); !errors.Is(err, ErrUnknownBackend) {
			t.Errorf("New(%d) err = %v, want ErrUnknownBackend", b, err)
		}
	}
	if _, err := New(Nftables, "app", nil); !errors.Is(err, exec.ErrRunnerRequired) {
		t.Errorf("New(_, nil) error = %v, want ErrRunnerRequired", err)
	}
	for _, b := range []Backend{Nftables, Firewalld, UFW} {
		m, err := New(b, "app", r)
		if err != nil {
			t.Fatalf("New(%d) err = %v, want nil", b, err)
		}
		if m.Namespace() != "app" {
			t.Errorf("Namespace() = %q, want app", m.Namespace())
		}
	}
}

func TestNew_AcceptsValidNamespace(t *testing.T) {
	r := &recordingRunner{}
	for _, ns := range []string{"app", "pm_firewall", "a", "some_app_42", strings.Repeat("a", 31)} {
		if _, err := New(Nftables, ns, r); err != nil {
			t.Errorf("New(%q) = %v, want nil", ns, err)
		}
	}
}

func TestNew_RejectsInvalidNamespace(t *testing.T) {
	r := &recordingRunner{}
	bad := []string{
		"",                      // empty
		"-leading-hyphen",       // leading char not a letter
		"1leading-digit",        // leading digit
		"UPPER",                 // uppercase
		"has space",             // whitespace
		"with-hyphen",           // hyphens reserved as separator
		"with:colon",            // colons reserved as separator
		strings.Repeat("a", 32), // 32 > 31 cap
	}
	for _, ns := range bad {
		if _, err := New(Nftables, ns, r); !errors.Is(err, ErrInvalidNamespace) {
			t.Errorf("New(%q) = %v, want ErrInvalidNamespace", ns, err)
		}
	}
}

// --- Detect ---

func TestDetect(t *testing.T) {
	orig := lookPath
	defer func() { lookPath = orig }()

	t.Run("all present", func(t *testing.T) {
		lookPath = func(string) (string, error) { return "/usr/sbin/tool", nil }
		got := Detect(context.Background())
		want := []Backend{Nftables, Firewalld, UFW}
		if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
			t.Errorf("Detect = %v, want %v", got, want)
		}
	})
	t.Run("only ufw", func(t *testing.T) {
		lookPath = func(name string) (string, error) {
			if name == "ufw" {
				return "/usr/sbin/ufw", nil
			}
			return "", os.ErrNotExist
		}
		got := Detect(context.Background())
		if len(got) != 1 || got[0] != UFW {
			t.Errorf("Detect = %v, want [UFW]", got)
		}
	})
	t.Run("none", func(t *testing.T) {
		lookPath = func(string) (string, error) { return "", os.ErrNotExist }
		if got := Detect(context.Background()); len(got) != 0 {
			t.Errorf("Detect = %v, want empty", got)
		}
	})
}

// --- entry-path Rule.ID validation (backend-independent, dispatched through a
// real backend with a recordingRunner so we prove validation precedes any exec) ---

func TestApplyRule_RejectsInvalidID(t *testing.T) {
	bad := []string{
		"", " ", "with space", "UPPER", "-leading-hyphen",
		"quote\"in", "tick'in", "newline\nin", "semicolon;in", "pipe|in",
		"backtick`in", "dollar$in", "way-too-long-" + strings.Repeat("x", 64),
	}
	for _, b := range []Backend{Nftables, Firewalld, UFW} {
		for _, id := range bad {
			r := &recordingRunner{}
			m := newMgr(t, b, "app", r)
			err := m.ApplyRule(context.Background(), Rule{ID: id, Allow: true, Protocol: ProtocolTCP, Port: 22})
			if !errors.Is(err, ErrInvalidRule) {
				t.Errorf("backend %d ApplyRule(id=%q) = %v, want ErrInvalidRule", b, id, err)
			}
			if len(r.calls) != 0 {
				t.Errorf("backend %d ran %d command(s) for an invalid ID; validation must precede exec", b, len(r.calls))
			}
		}
	}
}

func TestApplyRule_AcceptsValidID(t *testing.T) {
	good := []string{
		"ssh-in", "allow-22", "web_https", "a",
		"01jxr5qxa3pn5g9b7tvyf2h4nm-allow-22", "01jxr5qxa3pn5g9b7tvyf2h4nm",
	}
	for _, id := range good {
		r := &recordingRunner{}
		// nft list returns exit 1 (no table) then the add succeeds.
		r.push(exec.Result{ExitCode: 1}, nil)
		r.pushOut("")
		m := newMgr(t, Nftables, "app", r)
		if err := m.ApplyRule(context.Background(), Rule{ID: id, Allow: true, Protocol: ProtocolTCP, Port: 22}); errors.Is(err, ErrInvalidRule) {
			t.Errorf("ApplyRule(id=%q) rejected a valid ID: %v", id, err)
		}
	}
}

func TestRemoveRule_RejectsInvalidID(t *testing.T) {
	for _, b := range []Backend{Nftables, Firewalld, UFW} {
		r := &recordingRunner{}
		m := newMgr(t, b, "app", r)
		if err := m.RemoveRule(context.Background(), "id with space"); !errors.Is(err, ErrInvalidRule) {
			t.Errorf("backend %d RemoveRule(invalid) = %v, want ErrInvalidRule", b, err)
		}
		if len(r.calls) != 0 {
			t.Errorf("backend %d ran a command for an invalid remove ID", b)
		}
	}
}

func TestBackendString(t *testing.T) {
	for _, tt := range []struct {
		b    Backend
		want string
	}{
		{Nftables, "nftables"},
		{Firewalld, "firewalld"},
		{UFW, "ufw"},
		{Backend(42), "unknown(42)"},
	} {
		if got := tt.b.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.b, got, tt.want)
		}
	}
}
