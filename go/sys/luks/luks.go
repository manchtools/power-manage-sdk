package luks

import (
	"context"
	"fmt"
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

	_, err = exec.Sudo(ctx, "cryptsetup", "luksAddKey", devicePath, newFile, "--key-file", existingFile, "--batch-mode")
	if err != nil {
		return fmt.Errorf("cryptsetup luksAddKey failed: %w", err)
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

	_, err = exec.Sudo(ctx, "cryptsetup", "luksAddKey", devicePath, newFile,
		"--key-file", existingFile, "--key-slot", strconv.Itoa(slot), "--batch-mode")
	if err != nil {
		return fmt.Errorf("cryptsetup luksAddKey (slot %d) failed: %w", slot, err)
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

	_, err = exec.Sudo(ctx, "cryptsetup", "luksRemoveKey", devicePath, "--key-file", keyFile, "--batch-mode")
	if err != nil {
		return fmt.Errorf("cryptsetup luksRemoveKey failed: %w", err)
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

	_, err = exec.Sudo(ctx, "cryptsetup", "luksKillSlot", devicePath, strconv.Itoa(slot),
		"--key-file", keyFile, "--batch-mode")
	if err != nil {
		return fmt.Errorf("cryptsetup luksKillSlot %d failed: %w", slot, err)
	}
	return nil
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
		if result != nil && result.ExitCode != 0 {
			return false, nil // Wrong passphrase
		}
		return false, fmt.Errorf("cryptsetup test-passphrase failed: %w", err)
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
