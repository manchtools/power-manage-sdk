package reboot

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIsRequired_DebianFileExists(t *testing.T) {
	dir := t.TempDir()
	fakeFile := filepath.Join(dir, "reboot-required")
	os.WriteFile(fakeFile, []byte("*** System restart required ***\n"), 0644)

	origStat := statFunc
	statFunc = func(name string) (os.FileInfo, error) {
		if name == "/var/run/reboot-required" {
			return os.Stat(fakeFile)
		}
		return os.Stat(name)
	}
	defer func() { statFunc = origStat }()

	if !IsRequired() {
		t.Error("expected IsRequired() = true when reboot-required file exists")
	}
}

func TestIsRequired_DebianFileAbsent(t *testing.T) {
	origStat := statFunc
	origLookPath := lookPathFunc
	statFunc = func(name string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	lookPathFunc = func(file string) (string, error) {
		return "", exec.ErrNotFound
	}
	defer func() { statFunc = origStat; lookPathFunc = origLookPath }()

	if IsRequired() {
		t.Error("expected IsRequired() = false when no detection method available")
	}
}

func TestIsRequired_FedoraRebootNeeded(t *testing.T) {
	origStat := statFunc
	origLookPath := lookPathFunc
	origRunCmd := runCmdFunc
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
		// Simulate needs-restarting exit code 1 (reboot needed)
		cmd := exec.Command("sh", "-c", "exit 1")
		cmd.Run()
		return &exec.ExitError{ProcessState: cmd.ProcessState}
	}
	defer func() { statFunc = origStat; lookPathFunc = origLookPath; runCmdFunc = origRunCmd }()

	if !IsRequired() {
		t.Error("expected IsRequired() = true when needs-restarting exits 1")
	}
}

func TestIsRequired_FedoraNoReboot(t *testing.T) {
	origStat := statFunc
	origLookPath := lookPathFunc
	origRunCmd := runCmdFunc
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
		return nil // exit 0 = no reboot needed
	}
	defer func() { statFunc = origStat; lookPathFunc = origLookPath; runCmdFunc = origRunCmd }()

	if IsRequired() {
		t.Error("expected IsRequired() = false when needs-restarting exits 0")
	}
}

func TestIsRequired_LiveSystem(t *testing.T) {
	result := IsRequired()
	t.Logf("IsRequired() = %v (live system)", result)
}
