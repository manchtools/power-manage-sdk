package reboot

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// withSeams snapshots and restores the package-level injection points so
// tests can override them safely.
func withSeams(t *testing.T) {
	t.Helper()
	origStat, origLookPath, origRunCmd := statFunc, lookPathFunc, runCmdFunc
	t.Cleanup(func() {
		statFunc = origStat
		lookPathFunc = origLookPath
		runCmdFunc = origRunCmd
	})
}

// assertNeedsRestartingArgs fails the test if the runCmdFunc invocation does
// not match the expected `needs-restarting -r` call. Used by Fedora-path
// tests to catch regressions that would invoke the wrong binary or drop the
// -r flag.
func assertNeedsRestartingArgs(t *testing.T, name string, args []string) {
	t.Helper()
	if name != "/usr/bin/needs-restarting" {
		t.Errorf("runCmd called with name=%q, want %q", name, "/usr/bin/needs-restarting")
	}
	if len(args) != 1 || args[0] != "-r" {
		t.Errorf("runCmd called with args=%v, want [-r]", args)
	}
}

// exitErrCode returns an *exec.ExitError that reports the given exit code,
// produced by actually running a tiny shell command. Constructing one
// directly isn't portable since ProcessState is OS-specific. Skips the test
// if /bin/sh is not available in PATH (e.g. minimal containers).
func exitErrCode(t *testing.T, code int) error {
	t.Helper()
	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("skipping test: sh not found in PATH: %v", err)
	}
	cmd := exec.Command(shPath, "-c", "exit "+itoa(code))
	if err := cmd.Run(); err != nil {
		return err
	}
	t.Fatalf("expected exit %d to produce an error", code)
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func TestIsRequired_DebianFileExists(t *testing.T) {
	withSeams(t)
	dir := t.TempDir()
	fakeFile := filepath.Join(dir, "reboot-required")
	if err := os.WriteFile(fakeFile, []byte("*** System restart required ***\n"), 0644); err != nil {
		t.Fatal(err)
	}

	statFunc = func(name string) (os.FileInfo, error) {
		if name == "/var/run/reboot-required" {
			return os.Stat(fakeFile)
		}
		return os.Stat(name)
	}

	if !IsRequired() {
		t.Error("expected IsRequired() = true when reboot-required file exists")
	}
}

func TestIsRequired_DebianFileAbsent(t *testing.T) {
	withSeams(t)
	statFunc = func(name string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	lookPathFunc = func(file string) (string, error) {
		return "", exec.ErrNotFound
	}

	if IsRequired() {
		t.Error("expected IsRequired() = false when no detection method available")
	}
}

// An unexpected stat error (e.g. EACCES) must NOT short-circuit to true and
// must fall through to the needs-restarting branch.
func TestIsRequired_DebianStatUnexpectedError(t *testing.T) {
	withSeams(t)
	statFunc = func(name string) (os.FileInfo, error) {
		return nil, os.ErrPermission
	}
	lookPathFunc = func(file string) (string, error) {
		return "", exec.ErrNotFound
	}

	if IsRequired() {
		t.Error("expected IsRequired() = false when stat fails with permission error and no fallback")
	}
}

func TestIsRequired_FedoraRebootNeeded(t *testing.T) {
	withSeams(t)
	statFunc = func(name string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	lookPathFunc = func(file string) (string, error) {
		if file == "needs-restarting" {
			return "/usr/bin/needs-restarting", nil
		}
		return "", exec.ErrNotFound
	}
	runCmdFunc = func(name string, args ...string) error {
		assertNeedsRestartingArgs(t, name, args)
		return exitErrCode(t, 1)
	}

	if !IsRequired() {
		t.Error("expected IsRequired() = true when needs-restarting exits 1")
	}
}

func TestIsRequired_FedoraNoReboot(t *testing.T) {
	withSeams(t)
	statFunc = func(name string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	lookPathFunc = func(file string) (string, error) {
		return "/usr/bin/needs-restarting", nil
	}
	runCmdFunc = func(name string, args ...string) error {
		assertNeedsRestartingArgs(t, name, args)
		return nil // exit 0
	}

	if IsRequired() {
		t.Error("expected IsRequired() = false when needs-restarting exits 0")
	}
}

// needs-restarting exit codes other than 0 and 1 must NOT be interpreted as
// "reboot needed" — only exit 1 means that.
func TestIsRequired_FedoraOtherExitCode(t *testing.T) {
	withSeams(t)
	statFunc = func(name string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	lookPathFunc = func(file string) (string, error) {
		return "/usr/bin/needs-restarting", nil
	}
	runCmdFunc = func(name string, args ...string) error {
		assertNeedsRestartingArgs(t, name, args)
		return exitErrCode(t, 2)
	}

	if IsRequired() {
		t.Error("expected IsRequired() = false when needs-restarting exits with code 2")
	}
}

// If runCmd returns a non-ExitError (e.g. *exec.Error wrapping ENOENT), we
// must NOT report a reboot — log and return false.
func TestIsRequired_FedoraRunCmdNonExitError(t *testing.T) {
	withSeams(t)
	statFunc = func(name string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	lookPathFunc = func(file string) (string, error) {
		return "/usr/bin/needs-restarting", nil
	}
	runCmdFunc = func(name string, args ...string) error {
		assertNeedsRestartingArgs(t, name, args)
		return &exec.Error{Name: name, Err: errors.New("permission denied")}
	}

	if IsRequired() {
		t.Error("expected IsRequired() = false when needs-restarting fails to execute")
	}
}

func TestIsRequired_LiveSystem(t *testing.T) {
	result := IsRequired()
	t.Logf("IsRequired() = %v (live system)", result)
}
