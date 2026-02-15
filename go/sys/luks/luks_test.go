package luks

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// ─── GeneratePassphrase tests ────────────────────────────────────────────────

func TestGeneratePassphrase_MinWords(t *testing.T) {
	pass, err := GeneratePassphrase(5)
	if err != nil {
		t.Fatalf("GeneratePassphrase(5) failed: %v", err)
	}

	words := strings.Split(pass, "-")
	if len(words) < 5 {
		t.Errorf("expected at least 5 words, got %d: %q", len(words), pass)
	}
}

func TestGeneratePassphrase_MinLength32(t *testing.T) {
	for i := 0; i < 50; i++ {
		pass, err := GeneratePassphrase(3)
		if err != nil {
			t.Fatalf("GeneratePassphrase(3) failed: %v", err)
		}
		if len(pass) < 32 {
			t.Errorf("passphrase too short (%d chars): %q", len(pass), pass)
		}
	}
}

func TestGeneratePassphrase_ClampsBelowThree(t *testing.T) {
	// minWords < 3 should be clamped to 3
	pass, err := GeneratePassphrase(1)
	if err != nil {
		t.Fatalf("GeneratePassphrase(1) failed: %v", err)
	}
	words := strings.Split(pass, "-")
	if len(words) < 3 {
		t.Errorf("expected at least 3 words (clamped), got %d", len(words))
	}
}

func TestGeneratePassphrase_Format(t *testing.T) {
	pass, err := GeneratePassphrase(5)
	if err != nil {
		t.Fatalf("GeneratePassphrase(5) failed: %v", err)
	}

	words := strings.Split(pass, "-")
	for _, w := range words {
		if len(w) == 0 {
			t.Error("empty word in passphrase")
			continue
		}
		// First letter should be uppercase
		if w[0] < 'A' || w[0] > 'Z' {
			t.Errorf("word %q does not start with uppercase letter", w)
		}
	}
}

func TestGeneratePassphrase_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		pass, err := GeneratePassphrase(5)
		if err != nil {
			t.Fatalf("GeneratePassphrase failed: %v", err)
		}
		if seen[pass] {
			t.Fatal("generated duplicate passphrase")
		}
		seen[pass] = true
	}
}

func TestGeneratePassphrase_WordsFromWordList(t *testing.T) {
	wordSet := make(map[string]bool, len(wordList))
	for _, w := range wordList {
		wordSet[w] = true
	}

	pass, err := GeneratePassphrase(5)
	if err != nil {
		t.Fatalf("GeneratePassphrase(5) failed: %v", err)
	}

	for _, w := range strings.Split(pass, "-") {
		if !wordSet[w] {
			t.Errorf("word %q not in wordList", w)
		}
	}
}

// ─── ValidatePassphrase tests ────────────────────────────────────────────────

func TestValidatePassphrase_TooShort(t *testing.T) {
	msg := ValidatePassphrase("short", 16, ComplexityNone)
	if msg == "" {
		t.Error("expected error for short passphrase")
	}
	if !strings.Contains(msg, "16") {
		t.Errorf("error should mention min length 16, got: %s", msg)
	}
}

func TestValidatePassphrase_LongEnough_NoComplexity(t *testing.T) {
	msg := ValidatePassphrase("abcdefghijklmnop", 16, ComplexityNone)
	if msg != "" {
		t.Errorf("expected no error, got: %s", msg)
	}
}

func TestValidatePassphrase_Alphanumeric_LettersOnly(t *testing.T) {
	msg := ValidatePassphrase("abcdefghijklmnopqr", 16, ComplexityAlphanumeric)
	if msg == "" {
		t.Error("expected error for letters-only with alphanumeric complexity")
	}
}

func TestValidatePassphrase_Alphanumeric_DigitsOnly(t *testing.T) {
	msg := ValidatePassphrase("1234567890123456", 16, ComplexityAlphanumeric)
	if msg == "" {
		t.Error("expected error for digits-only with alphanumeric complexity")
	}
}

func TestValidatePassphrase_Alphanumeric_Valid(t *testing.T) {
	msg := ValidatePassphrase("abcdef1234567890", 16, ComplexityAlphanumeric)
	if msg != "" {
		t.Errorf("expected no error, got: %s", msg)
	}
}

func TestValidatePassphrase_Complex_MissingSpecial(t *testing.T) {
	msg := ValidatePassphrase("abcdef1234567890", 16, ComplexityComplex)
	if msg == "" {
		t.Error("expected error for missing special chars with complex complexity")
	}
}

func TestValidatePassphrase_Complex_MissingDigit(t *testing.T) {
	msg := ValidatePassphrase("abcdefghijklmn!@", 16, ComplexityComplex)
	if msg == "" {
		t.Error("expected error for missing digits with complex complexity")
	}
}

func TestValidatePassphrase_Complex_MissingLetter(t *testing.T) {
	msg := ValidatePassphrase("123456789012345!", 16, ComplexityComplex)
	if msg == "" {
		t.Error("expected error for missing letters with complex complexity")
	}
}

func TestValidatePassphrase_Complex_Valid(t *testing.T) {
	msg := ValidatePassphrase("abcdef123456789!", 16, ComplexityComplex)
	if msg != "" {
		t.Errorf("expected no error, got: %s", msg)
	}
}

// ─── HashPassphrase tests ────────────────────────────────────────────────────

func TestHashPassphrase_Deterministic(t *testing.T) {
	h1 := HashPassphrase("test-passphrase")
	h2 := HashPassphrase("test-passphrase")
	if h1 != h2 {
		t.Errorf("same input should produce same hash: %s != %s", h1, h2)
	}
}

func TestHashPassphrase_CorrectSHA256(t *testing.T) {
	input := "Apple-Tower-Kitchen"
	expected := sha256.Sum256([]byte(input))
	expectedHex := hex.EncodeToString(expected[:])
	got := HashPassphrase(input)
	if got != expectedHex {
		t.Errorf("hash mismatch: expected %s, got %s", expectedHex, got)
	}
}

func TestHashPassphrase_DifferentInputs(t *testing.T) {
	h1 := HashPassphrase("passphrase-one")
	h2 := HashPassphrase("passphrase-two")
	if h1 == h2 {
		t.Error("different inputs should produce different hashes")
	}
}

// ─── IsRecentlyUsed tests ────────────────────────────────────────────────────

func TestIsRecentlyUsed_Match(t *testing.T) {
	hash := HashPassphrase("my-secret")
	if !IsRecentlyUsed("my-secret", []string{hash}) {
		t.Error("expected match for recently used passphrase")
	}
}

func TestIsRecentlyUsed_NoMatch(t *testing.T) {
	hash := HashPassphrase("other-secret")
	if IsRecentlyUsed("my-secret", []string{hash}) {
		t.Error("should not match different passphrase")
	}
}

func TestIsRecentlyUsed_EmptyList(t *testing.T) {
	if IsRecentlyUsed("my-secret", nil) {
		t.Error("should not match empty list")
	}
	if IsRecentlyUsed("my-secret", []string{}) {
		t.Error("should not match empty slice")
	}
}

func TestIsRecentlyUsed_MultipleHashes(t *testing.T) {
	hashes := []string{
		HashPassphrase("old-1"),
		HashPassphrase("old-2"),
		HashPassphrase("old-3"),
	}
	if !IsRecentlyUsed("old-2", hashes) {
		t.Error("expected match for passphrase in list")
	}
	if IsRecentlyUsed("never-used", hashes) {
		t.Error("should not match passphrase not in list")
	}
}

// ─── findLuksVolumes / detection parsing tests ───────────────────────────────

func strPtr(s string) *string { return &s }

func TestFindLuksVolumes_SingleVolume(t *testing.T) {
	devices := []lsblkDevice{
		{
			Name:   "sda",
			Type:   "disk",
			FSType: nil,
			Children: []lsblkDevice{
				{
					Name:   "sda1",
					Type:   "part",
					FSType: strPtr("vfat"),
				},
				{
					Name:   "sda2",
					Type:   "part",
					FSType: strPtr("crypto_LUKS"),
					Children: []lsblkDevice{
						{
							Name:       "luks-abcd",
							Type:       "crypt",
							MountPoint: strPtr("/"),
						},
					},
				},
			},
		},
	}

	var volumes []Volume
	findLuksVolumes(&devices, &volumes)

	if len(volumes) != 1 {
		t.Fatalf("expected 1 volume, got %d", len(volumes))
	}
	if volumes[0].DevicePath != "/dev/sda2" {
		t.Errorf("expected /dev/sda2, got %s", volumes[0].DevicePath)
	}
	if volumes[0].MapperName != "luks-abcd" {
		t.Errorf("expected mapper luks-abcd, got %s", volumes[0].MapperName)
	}
	if volumes[0].MountPoint != "/" {
		t.Errorf("expected mountpoint /, got %s", volumes[0].MountPoint)
	}
}

func TestFindLuksVolumes_NoVolumes(t *testing.T) {
	devices := []lsblkDevice{
		{
			Name:   "sda",
			Type:   "disk",
			FSType: nil,
			Children: []lsblkDevice{
				{
					Name:   "sda1",
					Type:   "part",
					FSType: strPtr("ext4"),
				},
			},
		},
	}

	var volumes []Volume
	findLuksVolumes(&devices, &volumes)

	if len(volumes) != 0 {
		t.Errorf("expected 0 volumes, got %d", len(volumes))
	}
}

func TestFindLuksVolumes_MultipleVolumes(t *testing.T) {
	devices := []lsblkDevice{
		{
			Name:   "sda",
			Type:   "disk",
			FSType: nil,
			Children: []lsblkDevice{
				{
					Name:   "sda1",
					Type:   "part",
					FSType: strPtr("crypto_LUKS"),
					Children: []lsblkDevice{
						{
							Name:       "luks-root",
							Type:       "crypt",
							MountPoint: strPtr("/"),
						},
					},
				},
				{
					Name:   "sda2",
					Type:   "part",
					FSType: strPtr("crypto_LUKS"),
					Children: []lsblkDevice{
						{
							Name:       "luks-home",
							Type:       "crypt",
							MountPoint: strPtr("/home"),
						},
					},
				},
			},
		},
	}

	var volumes []Volume
	findLuksVolumes(&devices, &volumes)

	if len(volumes) != 2 {
		t.Fatalf("expected 2 volumes, got %d", len(volumes))
	}
}

func TestFindLuksVolumes_LockedVolume(t *testing.T) {
	devices := []lsblkDevice{
		{
			Name:   "sda1",
			Type:   "part",
			FSType: strPtr("crypto_LUKS"),
			// No children — volume is locked
		},
	}

	var volumes []Volume
	findLuksVolumes(&devices, &volumes)

	if len(volumes) != 1 {
		t.Fatalf("expected 1 volume, got %d", len(volumes))
	}
	if volumes[0].MapperName != "" {
		t.Errorf("locked volume should have empty mapper, got %s", volumes[0].MapperName)
	}
	if volumes[0].MountPoint != "" {
		t.Errorf("locked volume should have empty mountpoint, got %s", volumes[0].MountPoint)
	}
}

func TestFindLuksVolumes_LVMOnLuks(t *testing.T) {
	// LUKS → crypt → LVM logical volume with mountpoint
	devices := []lsblkDevice{
		{
			Name:   "nvme0n1p3",
			Type:   "part",
			FSType: strPtr("crypto_LUKS"),
			Children: []lsblkDevice{
				{
					Name: "luks-xyz",
					Type: "crypt",
					Children: []lsblkDevice{
						{
							Name:       "vg-root",
							Type:       "lvm",
							MountPoint: strPtr("/"),
						},
						{
							Name:       "vg-home",
							Type:       "lvm",
							MountPoint: strPtr("/home"),
						},
					},
				},
			},
		},
	}

	var volumes []Volume
	findLuksVolumes(&devices, &volumes)

	if len(volumes) != 1 {
		t.Fatalf("expected 1 volume, got %d", len(volumes))
	}
	if volumes[0].DevicePath != "/dev/nvme0n1p3" {
		t.Errorf("expected /dev/nvme0n1p3, got %s", volumes[0].DevicePath)
	}
	if volumes[0].MapperName != "luks-xyz" {
		t.Errorf("expected luks-xyz, got %s", volumes[0].MapperName)
	}
	// Last grandchild mountpoint wins
	if volumes[0].MountPoint != "/home" {
		t.Errorf("expected /home (last grandchild), got %s", volumes[0].MountPoint)
	}
}

// ─── DetectVolume priority tests (via exported function with mock data) ──────

func TestDetectVolumePriority_PrefersHome(t *testing.T) {
	// Simulate multiple volumes — DetectVolume prioritizes /home > / > first
	// We test the selection logic directly since DetectAllVolumes calls lsblk
	volumes := []Volume{
		{DevicePath: "/dev/sda1", MountPoint: "/"},
		{DevicePath: "/dev/sda2", MountPoint: "/home"},
	}

	// Replicate DetectVolume's selection logic
	selected := selectBestVolume(volumes)
	if selected.DevicePath != "/dev/sda2" {
		t.Errorf("expected /dev/sda2 (/home), got %s", selected.DevicePath)
	}
}

func TestDetectVolumePriority_FallsBackToRoot(t *testing.T) {
	volumes := []Volume{
		{DevicePath: "/dev/sda1", MountPoint: "/data"},
		{DevicePath: "/dev/sda2", MountPoint: "/"},
	}

	selected := selectBestVolume(volumes)
	if selected.DevicePath != "/dev/sda2" {
		t.Errorf("expected /dev/sda2 (/), got %s", selected.DevicePath)
	}
}

func TestDetectVolumePriority_FallsBackToFirst(t *testing.T) {
	volumes := []Volume{
		{DevicePath: "/dev/sda1", MountPoint: "/data"},
		{DevicePath: "/dev/sda2", MountPoint: "/var"},
	}

	selected := selectBestVolume(volumes)
	if selected.DevicePath != "/dev/sda1" {
		t.Errorf("expected /dev/sda1 (first), got %s", selected.DevicePath)
	}
}

// selectBestVolume replicates DetectVolume's selection logic for testing
// without calling lsblk.
func selectBestVolume(volumes []Volume) *Volume {
	if len(volumes) == 1 {
		return &volumes[0]
	}
	for i := range volumes {
		if volumes[i].MountPoint == "/home" {
			return &volumes[i]
		}
	}
	for i := range volumes {
		if volumes[i].MountPoint == "/" {
			return &volumes[i]
		}
	}
	return &volumes[0]
}
