package luks

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// IsLuks checks if a device is a LUKS-encrypted volume.
func IsLuks(ctx context.Context, devicePath string) (bool, error) {
	result, err := exec.Sudo(ctx, "cryptsetup", "isLuks", devicePath)
	if err != nil {
		if result != nil && result.ExitCode == 1 {
			return false, nil
		}
		return false, fmt.Errorf("cryptsetup isLuks failed: %w", err)
	}
	return true, nil
}

// AddKey adds a new passphrase to a LUKS volume using an existing key for authentication.
func AddKey(ctx context.Context, devicePath, existingKey, newKey string) error {
	existingFile, err := writeKeyFile(existingKey)
	if err != nil {
		return err
	}
	defer cleanupKeyFile(existingFile)

	newFile, err := writeKeyFile(newKey)
	if err != nil {
		return err
	}
	defer cleanupKeyFile(newFile)

	result, err := exec.Sudo(ctx, "cryptsetup", "luksAddKey", devicePath, newFile, "--key-file", existingFile, "--batch-mode")
	if err != nil {
		return cryptsetupError("luksAddKey", result, err)
	}
	return nil
}

// AddKeyToSlot adds a new passphrase to a specific LUKS slot.
func AddKeyToSlot(ctx context.Context, devicePath string, slot int, existingKey, newKey string) error {
	existingFile, err := writeKeyFile(existingKey)
	if err != nil {
		return err
	}
	defer cleanupKeyFile(existingFile)

	newFile, err := writeKeyFile(newKey)
	if err != nil {
		return err
	}
	defer cleanupKeyFile(newFile)

	result, err := exec.Sudo(ctx, "cryptsetup", "luksAddKey", devicePath, newFile,
		"--key-file", existingFile, "--key-slot", strconv.Itoa(slot), "--batch-mode")
	if err != nil {
		return cryptsetupError(fmt.Sprintf("luksAddKey (slot %d)", slot), result, err)
	}
	return nil
}

// RemoveKey removes a passphrase from a LUKS volume.
func RemoveKey(ctx context.Context, devicePath, key string) error {
	keyFile, err := writeKeyFile(key)
	if err != nil {
		return err
	}
	defer cleanupKeyFile(keyFile)

	result, err := exec.Sudo(ctx, "cryptsetup", "luksRemoveKey", devicePath, "--key-file", keyFile, "--batch-mode")
	if err != nil {
		return cryptsetupError("luksRemoveKey", result, err)
	}
	return nil
}

// KillSlot removes a specific LUKS slot using an existing key for authentication.
func KillSlot(ctx context.Context, devicePath string, slot int, existingKey string) error {
	keyFile, err := writeKeyFile(existingKey)
	if err != nil {
		return err
	}
	defer cleanupKeyFile(keyFile)

	result, err := exec.Sudo(ctx, "cryptsetup", "luksKillSlot", devicePath, strconv.Itoa(slot),
		"--key-file", keyFile, "--batch-mode")
	if err != nil {
		return cryptsetupError(fmt.Sprintf("luksKillSlot %d", slot), result, err)
	}
	return nil
}

// cryptsetupError builds a descriptive error from a cryptsetup result.
// cryptsetup --batch-mode suppresses stderr, so we translate known exit codes.
func cryptsetupError(cmd string, result *exec.Result, err error) error {
	detail := exitCodeDetail(result)
	if result != nil && result.Stderr != "" {
		detail = strings.TrimSpace(result.Stderr)
	}
	slog.Warn("cryptsetup command failed",
		"command", cmd,
		"exit_code", exitCode(result),
		"detail", detail,
		"stderr", trimmedStderr(result),
	)
	return fmt.Errorf("cryptsetup %s failed: %s (exit code %d)", cmd, detail, exitCode(result))
}

func exitCode(r *exec.Result) int {
	if r != nil {
		return r.ExitCode
	}
	return -1
}

func trimmedStderr(r *exec.Result) string {
	if r != nil {
		return strings.TrimSpace(r.Stderr)
	}
	return ""
}

// exitCodeDetail translates cryptsetup exit codes to human-readable messages.
// See cryptsetup(8) RETURN CODES.
func exitCodeDetail(r *exec.Result) string {
	if r == nil {
		return "unknown error"
	}
	switch r.ExitCode {
	case 1:
		return "wrong parameters"
	case 2:
		return "no key available with this passphrase"
	case 3:
		return "out of memory"
	case 4:
		return "wrong device specified or device does not exist"
	case 5:
		return "device already exists or device is busy"
	default:
		return fmt.Sprintf("unexpected error (exit code %d)", r.ExitCode)
	}
}

// keyFileDir is the private directory for ephemeral key files.
// /dev/shm is a tmpfs mount (RAM-backed) — files never touch disk.
const keyFileDir = "/dev/shm/pm-luks"

// TestPassphrase checks if a passphrase is valid for a LUKS volume without unlocking it.
// Returns true if the passphrase is accepted, false if rejected.
func TestPassphrase(ctx context.Context, devicePath, passphrase string) (bool, error) {
	keyFile, err := writeKeyFile(passphrase)
	if err != nil {
		return false, err
	}
	defer cleanupKeyFile(keyFile)

	result, err := exec.Sudo(ctx, "cryptsetup", "open", "--test-passphrase", devicePath,
		"--key-file", keyFile, "--batch-mode")
	if err != nil {
		if result != nil && result.ExitCode == 2 {
			return false, nil // Wrong passphrase
		}
		slog.Warn("cryptsetup test-passphrase failed",
			"exit_code", exitCode(result),
			"detail", exitCodeDetail(result),
			"stderr", trimmedStderr(result),
		)
		return false, fmt.Errorf("cryptsetup test-passphrase failed: %s (exit code %d)", exitCodeDetail(result), exitCode(result))
	}
	return true, nil
}

// writeKeyFile writes a key to a temporary file in /dev/shm (RAM only).
// The private directory has mode 0700 to prevent other users from listing files.
// Returns an error if /dev/shm is not available — never falls back to disk.
func writeKeyFile(key string) (string, error) {
	if err := os.MkdirAll(keyFileDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create key file directory %s: %w", keyFileDir, err)
	}

	f, err := os.CreateTemp(keyFileDir, "key-*")
	if err != nil {
		return "", fmt.Errorf("failed to create key file: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(key); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("failed to write key file: %w", err)
	}

	return f.Name(), nil
}

// cleanupKeyFile overwrites a key file with zeros and removes it.
func cleanupKeyFile(path string) {
	if path == "" {
		return
	}
	info, err := os.Stat(path)
	if err == nil {
		// Overwrite with zeros before removing
		zeros := strings.Repeat("\x00", int(info.Size()))
		_ = os.WriteFile(path, []byte(zeros), 0600)
	}
	os.Remove(path)
}
