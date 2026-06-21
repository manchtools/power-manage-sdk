package encryption

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// luks is the cryptsetup/LUKS Manager. cryptsetup needs root, so every command
// is escalated through the injected Runner. Passphrases are written to an
// ephemeral /dev/shm key file and passed as --key-file, never in argv.
type luks struct {
	r exec.Runner
}

// LUKS2 (and LUKS1) support eight keyslots, 0..7. Rejecting out-of-range slots
// at the SDK boundary surfaces a clear reason instead of cryptsetup's opaque one.
const (
	LuksMinKeySlot = 0
	LuksMaxKeySlot = 7
)

// ErrInvalidKeySlot is returned for a slot index outside [LuksMinKeySlot, LuksMaxKeySlot].
var ErrInvalidKeySlot = errors.New("invalid LUKS keyslot")

// ErrEmptyKeyMaterial is returned by a mutating LUKS/TPM operation given an
// empty passphrase/key. It is refused before any cryptsetup/cryptenroll exec:
// an empty NEW key would enroll a slot that unlocks with no passphrase, and an
// empty AUTHENTICATING key for a mutating op is never a legitimate request.
// (VerifyPassphrase is intentionally exempt — probing an empty passphrase is a
// legitimate read-only query.)
var ErrEmptyKeyMaterial = errors.New("encryption: empty key material not permitted")

func validateKeySlot(slot int) error {
	if slot < LuksMinKeySlot || slot > LuksMaxKeySlot {
		return fmt.Errorf("%w: slot %d outside valid range %d..%d", ErrInvalidKeySlot, slot, LuksMinKeySlot, LuksMaxKeySlot)
	}
	return nil
}

// IsEncrypted reports whether dev is a LUKS volume.
func (l *luks) IsEncrypted(ctx context.Context, dev string) (bool, error) {
	if err := validateDevicePath(dev); err != nil {
		return false, err
	}
	res, err := l.r.Run(ctx, exec.Command{Name: "cryptsetup", Args: []string{"isLuks", dev}, Escalate: true})
	if err != nil {
		return false, fmt.Errorf("cryptsetup isLuks: %w", err)
	}
	switch res.ExitCode {
	case 0:
		return true, nil
	case 1:
		return false, nil // not a LUKS device
	default:
		return false, cryptsetupError("isLuks", res)
	}
}

// AddKey adds newKey to a LUKS volume, authenticating with existing. With
// opts.Slot nil cryptsetup auto-assigns a free slot; otherwise the given slot
// (0..7) is targeted.
func (l *luks) AddKey(ctx context.Context, dev string, existing, newKey exec.Secret, opts AddKeyOptions) error {
	if err := validateDevicePath(dev); err != nil {
		return err
	}
	if opts.Slot != nil {
		if err := validateKeySlot(*opts.Slot); err != nil {
			return err
		}
	}
	// Refuse before any cryptsetup exec: an empty NEW key would enroll a slot
	// that unlocks with no passphrase; an empty authenticating key is never a
	// legitimate add request.
	if newKey.IsZero() {
		return fmt.Errorf("%w: refusing to add an empty new key (would create an empty-passphrase unlock slot)", ErrEmptyKeyMaterial)
	}
	if existing.IsZero() {
		return fmt.Errorf("%w: empty authenticating passphrase", ErrEmptyKeyMaterial)
	}
	existingFile, err := writeKeyFile(existing)
	if err != nil {
		return err
	}
	defer cleanupKeyFile(existingFile)
	newFile, err := writeKeyFile(newKey)
	if err != nil {
		return err
	}
	defer cleanupKeyFile(newFile)

	args := []string{"luksAddKey", dev, newFile, "--key-file", existingFile}
	op := "luksAddKey"
	if opts.Slot != nil {
		args = append(args, "--key-slot", strconv.Itoa(*opts.Slot))
		op = fmt.Sprintf("luksAddKey (slot %d)", *opts.Slot)
	}
	args = append(args, "--batch-mode")
	return l.runCryptsetup(ctx, op, args)
}

// RemoveKey removes a passphrase from a LUKS volume.
func (l *luks) RemoveKey(ctx context.Context, dev string, key exec.Secret) error {
	if err := validateDevicePath(dev); err != nil {
		return err
	}
	if key.IsZero() {
		return fmt.Errorf("%w: empty passphrase", ErrEmptyKeyMaterial)
	}
	keyFile, err := writeKeyFile(key)
	if err != nil {
		return err
	}
	defer cleanupKeyFile(keyFile)
	return l.runCryptsetup(ctx, "luksRemoveKey",
		[]string{"luksRemoveKey", dev, "--key-file", keyFile, "--batch-mode"})
}

// KillSlot removes a specific keyslot, authenticating with existing.
func (l *luks) KillSlot(ctx context.Context, dev string, slot int, existing exec.Secret) error {
	if err := validateDevicePath(dev); err != nil {
		return err
	}
	if err := validateKeySlot(slot); err != nil {
		return err
	}
	if existing.IsZero() {
		return fmt.Errorf("%w: empty authenticating passphrase", ErrEmptyKeyMaterial)
	}
	keyFile, err := writeKeyFile(existing)
	if err != nil {
		return err
	}
	defer cleanupKeyFile(keyFile)
	return l.runCryptsetup(ctx, fmt.Sprintf("luksKillSlot %d", slot),
		[]string{"luksKillSlot", dev, strconv.Itoa(slot), "--key-file", keyFile, "--batch-mode"})
}

// VerifyPassphrase reports whether p unlocks dev, without unlocking it.
func (l *luks) VerifyPassphrase(ctx context.Context, dev string, p exec.Secret) (bool, error) {
	if err := validateDevicePath(dev); err != nil {
		return false, err
	}
	keyFile, err := writeKeyFile(p)
	if err != nil {
		return false, err
	}
	defer cleanupKeyFile(keyFile)

	res, err := l.r.Run(ctx, exec.Command{
		Name:     "cryptsetup",
		Args:     []string{"open", "--test-passphrase", dev, "--key-file", keyFile, "--batch-mode"},
		Escalate: true,
	})
	if err != nil {
		return false, fmt.Errorf("cryptsetup test-passphrase: %w", err)
	}
	switch res.ExitCode {
	case 0:
		return true, nil
	case 2:
		return false, nil // wrong passphrase
	default:
		return false, cryptsetupError("test-passphrase", res)
	}
}

func (l *luks) TPM() (TPMEnroller, bool) {
	return &tpmEnroller{r: l.r}, true
}

// runCryptsetup runs an escalated cryptsetup command and maps a non-zero exit to
// a decoded error.
func (l *luks) runCryptsetup(ctx context.Context, op string, args []string) error {
	res, err := l.r.Run(ctx, exec.Command{Name: "cryptsetup", Args: args, Escalate: true})
	if err != nil {
		return fmt.Errorf("cryptsetup %s: %w", op, err)
	}
	if res.ExitCode != 0 {
		return cryptsetupError(op, res)
	}
	return nil
}

// cryptsetupError decodes a cryptsetup non-zero exit. --batch-mode suppresses
// most stderr, so known exit codes are translated (cryptsetup(8) RETURN CODES);
// any stderr present is preferred.
func cryptsetupError(op string, res exec.Result) error {
	detail := exitCodeDetail(res.ExitCode)
	if s := strings.TrimSpace(res.Stderr); s != "" {
		detail = s
	}
	slog.Warn("cryptsetup command failed", "command", op, "exit_code", res.ExitCode, "detail", detail)
	return fmt.Errorf("cryptsetup %s failed: %s (exit code %d)", op, detail, res.ExitCode)
}

func exitCodeDetail(code int) string {
	switch code {
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
		return fmt.Sprintf("unexpected error (exit code %d)", code)
	}
}

// keyFileDir is the private directory for ephemeral key files. /dev/shm is a
// tmpfs (RAM-backed) — files never touch disk. A var (not const) so tests can
// redirect it to exercise the fail-closed "no tmpfs" path.
var keyFileDir = "/dev/shm/pm-luks"

// keyFileHandle / scrubFile are the minimal subsets of *os.File the key-file
// helpers need. Behind package-var seams so tests can inject per-method I/O
// failures and exercise the fail-closed cleanup paths of this security-critical
// code; *os.File satisfies both.
type keyFileHandle interface {
	Name() string
	Chmod(os.FileMode) error
	WriteString(string) (int, error)
	Close() error
}

type scrubFile interface {
	Stat() (os.FileInfo, error)
	WriteAt([]byte, int64) (int, error)
	Close() error
}

var (
	mkdirAll      = os.MkdirAll
	createKeyFile = func(dir string) (keyFileHandle, error) { return os.CreateTemp(dir, "key-*") }
	removeFile    = os.Remove
	openKeyFile   = func(path string) (scrubFile, error) {
		// O_NOFOLLOW refuses a symlink swap; O_NONBLOCK refuses to BLOCK on a
		// FIFO swap (O_WRONLY on a readerless FIFO hangs forever otherwise — a
		// FIFO is not a symlink, so O_NOFOLLOW alone does not help). A regular
		// file ignores O_NONBLOCK.
		return os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	}
)

// cleanupKeyFileAfter removes a partially-written key file after a failure and
// folds any removal error into cause. The file holds plaintext key material
// (Reveal()'d into it), so a failed cleanup must surface rather than vanish — a
// dropped removal error would leave the secret on /dev/shm unnoticed. A file
// that is already gone is not a cleanup failure.
func cleanupKeyFileAfter(stage, name string, cause error) error {
	if rmErr := removeFile(name); rmErr != nil && !os.IsNotExist(rmErr) {
		return fmt.Errorf("%s: %w (key file cleanup failed, plaintext key may remain at %s: %v)", stage, cause, name, rmErr)
	}
	return fmt.Errorf("%s: %w", stage, cause)
}

// writeKeyFile writes a Secret to a 0600 temp file in /dev/shm and returns its
// path. Reveal() here is the single sanctioned key-file sink. Never falls back
// to disk: an unavailable /dev/shm is a hard error.
func writeKeyFile(key exec.Secret) (string, error) {
	if err := mkdirAll(keyFileDir, 0o700); err != nil {
		return "", fmt.Errorf("create key file directory %s: %w", keyFileDir, err)
	}
	f, err := createKeyFile(keyFileDir)
	if err != nil {
		return "", fmt.Errorf("create key file: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return "", cleanupKeyFileAfter("set key file permissions", f.Name(), err)
	}
	if _, err := f.WriteString(key.Reveal()); err != nil {
		_ = f.Close()
		return "", cleanupKeyFileAfter("write key file", f.Name(), err)
	}
	if err := f.Close(); err != nil {
		return "", cleanupKeyFileAfter("close key file", f.Name(), err)
	}
	return f.Name(), nil
}

// cleanupKeyFile zero-overwrites and removes a key file. O_NOFOLLOW rejects a
// symlink that may have replaced the path (TOCTOU); a failed scrub is logged but
// the unlink still proceeds best-effort.
func cleanupKeyFile(path string) {
	if path == "" {
		return
	}
	f, err := openKeyFile(path)
	if err != nil {
		if rmErr := removeFile(path); rmErr != nil && !os.IsNotExist(rmErr) {
			slog.Warn("luks: removing unscrubbed key file failed", "path", path, "error", rmErr)
		}
		return
	}
	if info, err := f.Stat(); err == nil && !info.Mode().IsRegular() {
		// A non-regular fd (FIFO with a reader, device node) must never be
		// written to — zeroing it would push bytes into a pipe/device, not
		// scrub a file. Refuse the scrub; the unlink below still proceeds.
		slog.Warn("luks: refusing to scrub a non-regular key file (possible TOCTOU swap)", "path", path, "mode", info.Mode().String())
	} else if err == nil && info.Size() > 0 {
		zeros := make([]byte, info.Size())
		if _, werr := f.WriteAt(zeros, 0); werr != nil {
			slog.Warn("luks: scrubbing key file before unlink failed; passphrase bytes may persist", "path", path, "error", werr)
		}
	}
	if cerr := f.Close(); cerr != nil {
		slog.Warn("luks: closing key file failed", "path", path, "error", cerr)
	}
	if rmErr := removeFile(path); rmErr != nil && !os.IsNotExist(rmErr) {
		slog.Warn("luks: removing key file failed", "path", path, "error", rmErr)
	}
}
