package encryption

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// --- P0.5: cleanupKeyFile must never block, and never scrub a non-regular file ---

// TestCleanupKeyFile_DoesNotHangOnFIFO pins the live FIFO-hang bug: if the
// key-file path is replaced by a FIFO between write and cleanup (a TOCTOU swap
// in /dev/shm), opening it O_WRONLY without O_NONBLOCK blocks forever waiting
// for a reader — the passphrase file is never scrubbed and the LUKS op wedges.
// O_NOFOLLOW does NOT help (a FIFO is not a symlink). Uses the REAL openKeyFile.
func TestCleanupKeyFile_DoesNotHangOnFIFO(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "key-fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo unsupported on this platform: %v", err)
	}

	done := make(chan struct{})
	go func() { defer close(done); cleanupKeyFile(p) }()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cleanupKeyFile blocked on a FIFO key-file path — openKeyFile must set O_NONBLOCK so a TOCTOU FIFO swap cannot wedge the scrub")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("cleanupKeyFile must still unlink the FIFO; stat err = %v", err)
	}
}

// pipeScrub is a scrubFile whose Stat reports a non-regular (named pipe) mode
// and records whether WriteAt was called.
type pipeScrub struct{ wrote bool }

func (p *pipeScrub) Stat() (os.FileInfo, error)             { return pipeInfo{}, nil }
func (p *pipeScrub) WriteAt(b []byte, _ int64) (int, error) { p.wrote = true; return len(b), nil }
func (p *pipeScrub) Close() error                           { return nil }

type pipeInfo struct{}

func (pipeInfo) Name() string       { return "fifo" }
func (pipeInfo) Size() int64        { return 16 }
func (pipeInfo) Mode() fs.FileMode  { return fs.ModeNamedPipe | 0o600 }
func (pipeInfo) ModTime() time.Time { return time.Time{} }
func (pipeInfo) IsDir() bool        { return false }
func (pipeInfo) Sys() any           { return nil }

// TestCleanupKeyFile_RefusesToScrubNonRegular — defence-in-depth for the case
// where the open DOES succeed on a non-regular target (a FIFO that has a reader,
// or a device node): cleanupKeyFile must refuse to WriteAt zeros to it (which
// would write into a pipe/device) and still unlink the path.
func TestCleanupKeyFile_RefusesToScrubNonRegular(t *testing.T) {
	defer swapKeyFileSeams(t)()
	f := &pipeScrub{}
	openKeyFile = func(string) (scrubFile, error) { return f, nil }
	removed := false
	removeFile = func(string) error { removed = true; return nil }

	cleanupKeyFile("/dev/shm/pm-luks/key-x")

	if f.wrote {
		t.Error("cleanupKeyFile wrote zeros to a non-regular (FIFO/device) file; it must refuse non-regular scrub targets")
	}
	if !removed {
		t.Error("cleanupKeyFile must still unlink a non-regular path")
	}
}

// --- P0.6: mutating LUKS/TPM ops must reject an empty passphrase BEFORE exec ---

// emptySecret is a valid, empty Secret (NewSecret permits empty).
func emptySecret(t *testing.T) exec.Secret {
	t.Helper()
	s, err := exec.NewSecret("")
	if err != nil {
		t.Fatalf("NewSecret(\"\"): %v", err)
	}
	if !s.IsZero() {
		t.Fatal("expected NewSecret(\"\") to be zero/empty")
	}
	return s
}

// TestAddKey_RejectsEmptyNewKey is the security-critical case: adding an EMPTY
// new key would enroll a LUKS slot that unlocks with no passphrase. It must be
// refused before cryptsetup runs.
func TestAddKey_RejectsEmptyNewKey(t *testing.T) {
	r := &recordingRunner{}
	m := mgr(t, r)
	err := m.AddKey(context.Background(), "/dev/sda1", mustSecret(t, "current"), emptySecret(t), AddKeyOptions{})
	if !errors.Is(err, ErrEmptyKeyMaterial) {
		t.Fatalf("AddKey(emptyNewKey) err = %v; want ErrEmptyKeyMaterial (would create an empty-passphrase slot)", err)
	}
	if n := len(r.calls); n != 0 {
		t.Fatalf("AddKey(emptyNewKey) ran cryptsetup %d time(s); it must reject BEFORE exec", n)
	}
}

// TestMutatingOps_RejectEmptyAuth — an empty authenticating passphrase for a
// mutating operation is never a legitimate request and must be refused before
// any cryptsetup/cryptenroll exec. (VerifyPassphrase is deliberately excluded:
// probing an empty passphrase is a legitimate read-only query.)
func TestMutatingOps_RejectEmptyAuth(t *testing.T) {
	ctx := context.Background()
	dev := "/dev/sda1"

	// Each op takes the SUBTEST's *testing.T so a t.Skip (no TPM hardware)
	// skips only that subtest, not the parent — the closures must not capture
	// the outer t.
	ops := map[string]func(t *testing.T, m Manager) error{
		"AddKey/existing": func(t *testing.T, m Manager) error {
			return m.AddKey(ctx, dev, emptySecret(t), mustSecret(t, "new"), AddKeyOptions{})
		},
		"RemoveKey": func(t *testing.T, m Manager) error {
			return m.RemoveKey(ctx, dev, emptySecret(t))
		},
		"KillSlot": func(t *testing.T, m Manager) error {
			return m.KillSlot(ctx, dev, 1, emptySecret(t))
		},
		"TPM.Enroll": func(t *testing.T, m Manager) error {
			tpm, ok := m.TPM()
			if !ok {
				t.Skip("LUKS backend reports no TPM support")
			}
			return tpm.Enroll(ctx, dev, emptySecret(t))
		},
		"TPM.Wipe": func(t *testing.T, m Manager) error {
			tpm, ok := m.TPM()
			if !ok {
				t.Skip("LUKS backend reports no TPM support")
			}
			return tpm.Wipe(ctx, dev, emptySecret(t))
		},
	}

	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			r := &recordingRunner{}
			m := mgr(t, r)
			if err := op(t, m); !errors.Is(err, ErrEmptyKeyMaterial) {
				t.Fatalf("%s(emptyAuth) err = %v; want ErrEmptyKeyMaterial", name, err)
			}
			if n := len(r.calls); n != 0 {
				t.Fatalf("%s(emptyAuth) ran the tool %d time(s); it must reject BEFORE exec", name, n)
			}
		})
	}
}
