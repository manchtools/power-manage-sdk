package encryption

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// recordingRunner is an exec.Runner that captures each Command and, crucially,
// snapshots the contents of any /dev/shm key file referenced in the argv and any
// stdin — taken DURING Run, before the caller's deferred cleanup wipes them. It
// lets the tests prove the right Secret reaches the right key file / stdin and
// never the argv. Scripts results FIFO (default: clean success).
type recordingRunner struct {
	mu      sync.Mutex
	calls   []capturedCall
	results []scripted
}

type capturedCall struct {
	cmd      exec.Command
	keyFiles map[string]string // arg path under keyFileDir → file content
	stdin    string
}

type scripted struct {
	res exec.Result
	err error
}

func (r *recordingRunner) push(res exec.Result, err error) {
	r.results = append(r.results, scripted{res, err})
}

func (r *recordingRunner) record(c exec.Command) (exec.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cc := capturedCall{cmd: c, keyFiles: map[string]string{}}
	for _, a := range c.Args {
		if strings.HasPrefix(a, keyFileDir) {
			if b, err := os.ReadFile(a); err == nil {
				cc.keyFiles[a] = string(b)
			}
		}
	}
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

func mgr(t *testing.T, r exec.Runner) Manager {
	t.Helper()
	m, err := New(LUKS, r)
	if err != nil {
		t.Fatalf("New(LUKS): %v", err)
	}
	return m
}

func mustSecret(t *testing.T, s string) exec.Secret {
	t.Helper()
	sec, err := exec.NewSecret(s)
	if err != nil {
		t.Fatalf("NewSecret(%q): %v", s, err)
	}
	return sec
}

func ptr(i int) *int { return &i }

// assertNoPlaintextInArgv fails if any arg contains a secret plaintext.
func assertNoPlaintextInArgv(t *testing.T, args []string, secrets ...string) {
	t.Helper()
	for _, a := range args {
		for _, s := range secrets {
			if strings.Contains(a, s) {
				t.Errorf("secret plaintext %q leaked into argv: %q", s, a)
			}
		}
	}
}

func TestNew_FailClosed(t *testing.T) {
	r := &recordingRunner{}
	for _, b := range []Backend{0, Backend(-1), Backend(99)} {
		if _, err := New(b, r); !errors.Is(err, ErrUnknownBackend) {
			t.Errorf("New(%d) err = %v, want ErrUnknownBackend", b, err)
		}
	}
	if _, err := New(LUKS, nil); !errors.Is(err, exec.ErrRunnerRequired) {
		t.Errorf("New(_, nil) error = %v, want ErrRunnerRequired", err)
	}
	if _, err := New(LUKS, r); err != nil {
		t.Errorf("New(LUKS, runner) err = %v, want nil", err)
	}
}

func TestIsEncrypted(t *testing.T) {
	t.Run("is luks (exit 0)", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{ExitCode: 0}, nil)
		ok, err := mgr(t, r).IsEncrypted(context.Background(), "/dev/sda2")
		if err != nil || !ok {
			t.Fatalf("IsEncrypted = (%v,%v), want (true,nil)", ok, err)
		}
		c := r.calls[0].cmd
		if c.Name != "cryptsetup" || !c.Escalate || strings.Join(c.Args, " ") != "isLuks /dev/sda2" {
			t.Errorf("command = %+v, want escalated `cryptsetup isLuks /dev/sda2`", c)
		}
	})
	// The exit-code → result mapping (exit 1 → not-LUKS, exit 4 → error) is no
	// longer asserted here against a FABRICATED exit code: TestIsEncrypted_Container
	// (build tag `container`) now proves it against REAL cryptsetup, which is the
	// only thing that establishes a real LUKS / non-LUKS / missing device actually
	// yields exit 0 / 1 / 4. This subtest keeps only the argv-shape pin (above) and
	// the path-validation pin (below) — both unobservable through real cryptsetup.
	t.Run("invalid device path rejected before runner", func(t *testing.T) {
		r := &recordingRunner{}
		if _, err := mgr(t, r).IsEncrypted(context.Background(), "-rf"); err == nil {
			t.Error("accepted a non-/dev device path")
		}
		if len(r.calls) != 0 {
			t.Error("ran cryptsetup for an invalid device path")
		}
	})
}

func TestAddKey(t *testing.T) {
	t.Run("auto slot: golden argv, secrets via key files only", func(t *testing.T) {
		r := &recordingRunner{}
		if err := mgr(t, r).AddKey(context.Background(), "/dev/sda2", mustSecret(t, "oldpass"), mustSecret(t, "newpass"), AddKeyOptions{}); err != nil {
			t.Fatal(err)
		}
		cc := r.calls[0]
		c := cc.cmd
		if c.Name != "cryptsetup" || !c.Escalate {
			t.Fatalf("command = %+v, want escalated cryptsetup", c)
		}
		// luksAddKey <dev> <newFile> --key-file <existingFile> --batch-mode
		if c.Args[0] != "luksAddKey" || c.Args[1] != "/dev/sda2" || c.Args[3] != "--key-file" || c.Args[len(c.Args)-1] != "--batch-mode" {
			t.Fatalf("argv shape wrong: %v", c.Args)
		}
		newFile, existingFile := c.Args[2], c.Args[4]
		assertNoPlaintextInArgv(t, c.Args, "oldpass", "newpass")
		if cc.keyFiles[newFile] != "newpass" {
			t.Errorf("new key file content = %q, want newpass", cc.keyFiles[newFile])
		}
		if cc.keyFiles[existingFile] != "oldpass" {
			t.Errorf("existing key file content = %q, want oldpass (no swap)", cc.keyFiles[existingFile])
		}
	})

	t.Run("explicit slot adds --key-slot", func(t *testing.T) {
		r := &recordingRunner{}
		if err := mgr(t, r).AddKey(context.Background(), "/dev/sda2", mustSecret(t, "old"), mustSecret(t, "new"), AddKeyOptions{Slot: ptr(3)}); err != nil {
			t.Fatal(err)
		}
		args := strings.Join(r.calls[0].cmd.Args, " ")
		if !strings.Contains(args, "--key-slot 3") {
			t.Errorf("argv %q missing --key-slot 3", args)
		}
	})

	t.Run("slot out of range rejected before runner", func(t *testing.T) {
		r := &recordingRunner{}
		err := mgr(t, r).AddKey(context.Background(), "/dev/sda2", mustSecret(t, "o"), mustSecret(t, "n"), AddKeyOptions{Slot: ptr(8)})
		if !errors.Is(err, ErrInvalidKeySlot) {
			t.Errorf("err = %v, want ErrInvalidKeySlot", err)
		}
		if len(r.calls) != 0 {
			t.Error("ran cryptsetup for an out-of-range slot")
		}
	})

	t.Run("cryptsetup failure decoded", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{ExitCode: 2}, nil) // no key available
		err := mgr(t, r).AddKey(context.Background(), "/dev/sda2", mustSecret(t, "o"), mustSecret(t, "n"), AddKeyOptions{})
		if err == nil || !strings.Contains(err.Error(), "no key available") {
			t.Errorf("err = %v, want a decoded exit-2 message", err)
		}
	})
}

func TestRemoveKey(t *testing.T) {
	r := &recordingRunner{}
	if err := mgr(t, r).RemoveKey(context.Background(), "/dev/sda2", mustSecret(t, "secretpass")); err != nil {
		t.Fatal(err)
	}
	cc := r.calls[0]
	if cc.cmd.Args[0] != "luksRemoveKey" || cc.cmd.Args[1] != "/dev/sda2" || cc.cmd.Args[2] != "--key-file" {
		t.Fatalf("argv = %v", cc.cmd.Args)
	}
	assertNoPlaintextInArgv(t, cc.cmd.Args, "secretpass")
	if cc.keyFiles[cc.cmd.Args[3]] != "secretpass" {
		t.Errorf("key file content = %q, want secretpass", cc.keyFiles[cc.cmd.Args[3]])
	}
}

func TestKillSlot(t *testing.T) {
	t.Run("golden", func(t *testing.T) {
		r := &recordingRunner{}
		if err := mgr(t, r).KillSlot(context.Background(), "/dev/sda2", 2, mustSecret(t, "auth")); err != nil {
			t.Fatal(err)
		}
		args := r.calls[0].cmd.Args
		if args[0] != "luksKillSlot" || args[1] != "/dev/sda2" || args[2] != "2" || args[3] != "--key-file" {
			t.Fatalf("argv = %v", args)
		}
		assertNoPlaintextInArgv(t, args, "auth")
	})
	t.Run("slot out of range", func(t *testing.T) {
		r := &recordingRunner{}
		if err := mgr(t, r).KillSlot(context.Background(), "/dev/sda2", -1, mustSecret(t, "auth")); !errors.Is(err, ErrInvalidKeySlot) {
			t.Errorf("err = %v, want ErrInvalidKeySlot", err)
		}
		if len(r.calls) != 0 {
			t.Error("ran cryptsetup for an out-of-range slot")
		}
	})
}

func TestVerifyPassphrase(t *testing.T) {
	t.Run("correct (exit 0)", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{ExitCode: 0}, nil)
		ok, err := mgr(t, r).VerifyPassphrase(context.Background(), "/dev/sda2", mustSecret(t, "right"))
		if err != nil || !ok {
			t.Fatalf("VerifyPassphrase = (%v,%v), want (true,nil)", ok, err)
		}
		args := r.calls[0].cmd.Args
		if args[0] != "open" || args[1] != "--test-passphrase" || args[2] != "/dev/sda2" {
			t.Errorf("argv = %v", args)
		}
		assertNoPlaintextInArgv(t, args, "right")
	})
	t.Run("wrong (exit 2)", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{ExitCode: 2}, nil)
		if ok, err := mgr(t, r).VerifyPassphrase(context.Background(), "/dev/sda2", mustSecret(t, "wrong")); err != nil || ok {
			t.Errorf("VerifyPassphrase = (%v,%v), want (false,nil)", ok, err)
		}
	})
	t.Run("error (exit 4)", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{ExitCode: 4}, nil)
		if _, err := mgr(t, r).VerifyPassphrase(context.Background(), "/dev/sda2", mustSecret(t, "x")); err == nil {
			t.Error("VerifyPassphrase(exit 4) returned nil error")
		}
	})
}

func TestTPMAccessor(t *testing.T) {
	enr, ok := mgr(t, &recordingRunner{}).TPM()
	if !ok || enr == nil {
		t.Fatalf("TPM() = (%v,%v), want a non-nil enroller, true", enr, ok)
	}
}

// Self-discovering per-parameter guard: for every Manager method taking a device
// string, a non-/dev path "-rf" must never reach the Runner.
func TestEveryDeviceMethodRejectsUnsafePathBeforeRunner(t *testing.T) {
	const unsafe = "-rf"
	mt := reflect.TypeOf((*Manager)(nil)).Elem()
	ctxType := reflect.TypeOf((*context.Context)(nil)).Elem()
	secretType := reflect.TypeOf(exec.Secret{})
	checked := 0

	for i := 0; i < mt.NumMethod(); i++ {
		name := mt.Method(i).Name
		ft := reflect.ValueOf(mgr(t, &recordingRunner{})).MethodByName(name).Type()
		hasString := false
		for p := 0; p < ft.NumIn(); p++ {
			if ft.In(p).Kind() == reflect.String {
				hasString = true
			}
		}
		if !hasString {
			continue
		}
		r := &recordingRunner{}
		fn := reflect.ValueOf(mgr(t, r)).MethodByName(name)
		args := make([]reflect.Value, ft.NumIn())
		for p := 0; p < ft.NumIn(); p++ {
			pt := ft.In(p)
			switch {
			case pt == ctxType:
				args[p] = reflect.ValueOf(context.Background())
			case pt.Kind() == reflect.String:
				args[p] = reflect.ValueOf(unsafe)
			case pt == secretType:
				args[p] = reflect.ValueOf(exec.Secret{})
			default:
				args[p] = reflect.Zero(pt)
			}
		}
		fn.Call(args)
		if n := len(r.calls); n != 0 {
			t.Errorf("%s ran %d command(s) for an unsafe device path %q", name, n, unsafe)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("matches-zero guard: no device-taking methods exercised")
	}
}
