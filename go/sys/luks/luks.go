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

// writeKeyFile writes a key to a temporary file with mode 0600.
// Uses /dev/shm (tmpfs) if available to avoid writing to disk.
func writeKeyFile(key string) (string, error) {
	dir := "/dev/shm"
	if _, err := os.Stat(dir); err != nil {
		dir = os.TempDir()
	}

	f, err := os.CreateTemp(dir, "pm-luks-key-*")
	if err != nil {
		return "", fmt.Errorf("failed to create key file: %w", err)
	}
	defer f.Close()

	if err := f.Chmod(0600); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("failed to set key file permissions: %w", err)
	}

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
