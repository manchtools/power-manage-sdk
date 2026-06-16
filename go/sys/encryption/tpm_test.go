package encryption

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

func tpm(t *testing.T, r exec.Runner) TPMEnroller {
	t.Helper()
	enr, ok := mgr(t, r).TPM()
	if !ok {
		t.Fatal("TPM() ok = false, want true for LUKS")
	}
	return enr
}

func TestTPM_Available(t *testing.T) {
	orig := tpmDevicePaths
	defer func() { tpmDevicePaths = orig }()

	t.Run("present", func(t *testing.T) {
		dev := filepath.Join(t.TempDir(), "tpmrm0")
		if err := os.WriteFile(dev, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		tpmDevicePaths = []string{"/nope/tpm0", dev}
		ok, err := tpm(t, &recordingRunner{}).Available(context.Background())
		if err != nil || !ok {
			t.Errorf("Available = (%v,%v), want (true,nil)", ok, err)
		}
	})
	t.Run("absent", func(t *testing.T) {
		tpmDevicePaths = []string{filepath.Join(t.TempDir(), "missing")}
		ok, _ := tpm(t, &recordingRunner{}).Available(context.Background())
		if ok {
			t.Error("Available = true with no TPM device node")
		}
	})
}

func TestTPM_Enroll(t *testing.T) {
	r := &recordingRunner{}
	if err := tpm(t, r).Enroll(context.Background(), "/dev/sda2", mustSecret(t, "authkey")); err != nil {
		t.Fatal(err)
	}
	cc := r.calls[0]
	if cc.cmd.Name != "systemd-cryptenroll" || !cc.cmd.Escalate {
		t.Fatalf("command = %+v, want escalated systemd-cryptenroll", cc.cmd)
	}
	if got := strings.Join(cc.cmd.Args, " "); got != "--tpm2-device=auto --tpm2-pcrs=7+14 /dev/sda2" {
		t.Errorf("argv = %q", got)
	}
	assertNoPlaintextInArgv(t, cc.cmd.Args, "authkey")
	if cc.stdin != "authkey" {
		t.Errorf("stdin = %q, want the passphrase piped via stdin", cc.stdin)
	}
}

func TestTPM_Wipe(t *testing.T) {
	r := &recordingRunner{}
	if err := tpm(t, r).Wipe(context.Background(), "/dev/sda2", mustSecret(t, "authkey")); err != nil {
		t.Fatal(err)
	}
	cc := r.calls[0]
	if got := strings.Join(cc.cmd.Args, " "); got != "--wipe-slot=tpm2 /dev/sda2" {
		t.Errorf("argv = %q", got)
	}
	assertNoPlaintextInArgv(t, cc.cmd.Args, "authkey")
	if cc.stdin != "authkey" {
		t.Errorf("stdin = %q, want the passphrase via stdin", cc.stdin)
	}
}

func TestTPM_ErrorMapping(t *testing.T) {
	r := &recordingRunner{}
	r.push(exec.Result{ExitCode: 1, Stderr: "Failed to enroll TPM2"}, nil)
	err := tpm(t, r).Enroll(context.Background(), "/dev/sda2", mustSecret(t, "k"))
	var ce *exec.CommandError
	if !errors.As(err, &ce) || ce.ExitCode != 1 {
		t.Errorf("Enroll err = %v, want *exec.CommandError exit 1", err)
	}
}

func TestTPM_RejectsInvalidDevicePath(t *testing.T) {
	r := &recordingRunner{}
	if err := tpm(t, r).Enroll(context.Background(), "-rf", mustSecret(t, "k")); err == nil {
		t.Error("Enroll accepted a non-/dev device path")
	}
	if err := tpm(t, r).Wipe(context.Background(), "../etc", mustSecret(t, "k")); err == nil {
		t.Error("Wipe accepted a traversal device path")
	}
	if len(r.calls) != 0 {
		t.Error("ran systemd-cryptenroll for an invalid device path")
	}
}
