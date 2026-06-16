package encryption

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// exitCodeDetail translates every documented cryptsetup return code.
func TestExitCodeDetail(t *testing.T) {
	for code, want := range map[int]string{
		1: "wrong parameters",
		2: "no key available",
		3: "out of memory",
		4: "wrong device",
		5: "device already exists",
		9: "unexpected error",
	} {
		if got := exitCodeDetail(code); !strings.Contains(got, want) {
			t.Errorf("exitCodeDetail(%d) = %q, want it to contain %q", code, got, want)
		}
	}
}

// cryptsetupError prefers real stderr when present, else the decoded exit code.
func TestCryptsetupError(t *testing.T) {
	withStderr := cryptsetupError("luksAddKey", exec.Result{ExitCode: 1, Stderr: "  Device /dev/sda2 is busy.\n"})
	if !strings.Contains(withStderr.Error(), "Device /dev/sda2 is busy") {
		t.Errorf("err = %v, want it to surface stderr", withStderr)
	}
	noStderr := cryptsetupError("luksAddKey", exec.Result{ExitCode: 2})
	if !strings.Contains(noStderr.Error(), "no key available") {
		t.Errorf("err = %v, want the decoded exit-2 message", noStderr)
	}
}

// validateDevicePath rejects a regex-passing path that contains "..".
func TestValidateDevicePath_RejectsTraversal(t *testing.T) {
	if err := validateDevicePath("/dev/../etc/shadow"); err == nil {
		t.Error("accepted a /dev/.. traversal path")
	}
	if err := validateDevicePath("/dev/sda2"); err != nil {
		t.Errorf("rejected a valid device path: %v", err)
	}
}

// When /dev/shm is unavailable, key-file creation fails closed (never disk) and
// every passphrase op surfaces the error without running cryptsetup.
func TestKeyFileFailClosed(t *testing.T) {
	orig := keyFileDir
	// Parent is a regular file (a temp file), so MkdirAll under it must fail.
	tmp := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(tmp, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	keyFileDir = filepath.Join(tmp, "pm-luks")
	defer func() { keyFileDir = orig }()

	ops := map[string]func(Manager, *recordingRunner) error{
		"AddKey": func(m Manager, _ *recordingRunner) error {
			return m.AddKey(context.Background(), "/dev/sda2", mustSecret(t, "a"), mustSecret(t, "b"), AddKeyOptions{})
		},
		"RemoveKey": func(m Manager, _ *recordingRunner) error {
			return m.RemoveKey(context.Background(), "/dev/sda2", mustSecret(t, "a"))
		},
		"KillSlot": func(m Manager, _ *recordingRunner) error {
			return m.KillSlot(context.Background(), "/dev/sda2", 1, mustSecret(t, "a"))
		},
		"VerifyPassphrase": func(m Manager, _ *recordingRunner) error {
			_, e := m.VerifyPassphrase(context.Background(), "/dev/sda2", mustSecret(t, "a"))
			return e
		},
	}
	for name, op := range ops {
		r := &recordingRunner{}
		if err := op(mgr(t, r), r); err == nil {
			t.Errorf("%s: expected a key-file failure when /dev/shm is unavailable", name)
		}
		if len(r.calls) != 0 {
			t.Errorf("%s: ran cryptsetup despite key-file failure", name)
		}
	}
}

// Runner exec errors (e.g. cryptsetup not installed) surface from every op.
func TestExecErrorsSurface(t *testing.T) {
	ops := map[string]func(Manager) error{
		"IsEncrypted": func(m Manager) error { _, e := m.IsEncrypted(context.Background(), "/dev/sda2"); return e },
		"AddKey": func(m Manager) error {
			return m.AddKey(context.Background(), "/dev/sda2", mustSecret(t, "a"), mustSecret(t, "b"), AddKeyOptions{})
		},
		"RemoveKey": func(m Manager) error { return m.RemoveKey(context.Background(), "/dev/sda2", mustSecret(t, "a")) },
		"KillSlot":  func(m Manager) error { return m.KillSlot(context.Background(), "/dev/sda2", 1, mustSecret(t, "a")) },
		"VerifyPassphrase": func(m Manager) error {
			_, e := m.VerifyPassphrase(context.Background(), "/dev/sda2", mustSecret(t, "a"))
			return e
		},
	}
	for name, op := range ops {
		r := &recordingRunner{}
		r.push(exec.Result{}, exec.ErrEscalationUnavailable)
		if err := op(mgr(t, r)); err == nil {
			t.Errorf("%s: nil error on a Runner exec failure", name)
		}
	}
}

func TestTPM_RunExecError(t *testing.T) {
	r := &recordingRunner{}
	r.push(exec.Result{}, exec.ErrEscalationUnavailable)
	if err := tpm(t, r).Enroll(context.Background(), "/dev/sda2", mustSecret(t, "k")); err == nil {
		t.Error("Enroll returned nil on a Runner exec failure")
	}
}

func TestDetect_LsblkErrorPropagates(t *testing.T) {
	t.Run("DetectVolume", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{}, exec.ErrEscalationUnavailable)
		if _, err := mgr(t, r).DetectVolume(context.Background()); err == nil {
			t.Error("DetectVolume ignored an lsblk failure")
		}
	})
	t.Run("DetectVolumeByKey", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{}, exec.ErrEscalationUnavailable)
		if _, err := mgr(t, r).DetectVolumeByKey(context.Background(), mustSecret(t, "p")); err == nil {
			t.Error("DetectVolumeByKey ignored an lsblk failure")
		}
	})
}
