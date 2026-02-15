package luks

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// HasTPM2 checks if a TPM2 device is available on the system.
func HasTPM2(_ context.Context) (bool, error) {
	_, err := os.Stat("/dev/tpm0")
	if err == nil {
		return true, nil
	}
	_, err = os.Stat("/dev/tpmrm0")
	if err == nil {
		return true, nil
	}
	return false, nil
}

// EnrollTPM enrolls a TPM2 key for a LUKS volume using the managed passphrase
// for authentication. Uses PCRs 7+14 (Secure Boot + shim/MOK).
func EnrollTPM(ctx context.Context, devicePath, existingKey string) error {
	stdin := strings.NewReader(existingKey)
	_, err := exec.RunWithStdin(ctx, stdin, "systemd-cryptenroll",
		"--tpm2-device=auto", "--tpm2-pcrs=7+14", devicePath)
	if err != nil {
		return fmt.Errorf("systemd-cryptenroll TPM2 failed: %w", err)
	}
	return nil
}

// WipeTPM removes the TPM2 enrollment from a LUKS volume using the managed
// passphrase for authentication.
func WipeTPM(ctx context.Context, devicePath, existingKey string) error {
	stdin := strings.NewReader(existingKey)
	_, err := exec.RunWithStdin(ctx, stdin, "systemd-cryptenroll",
		"--wipe-slot=tpm2", devicePath)
	if err != nil {
		return fmt.Errorf("systemd-cryptenroll wipe TPM2 failed: %w", err)
	}
	return nil
}
