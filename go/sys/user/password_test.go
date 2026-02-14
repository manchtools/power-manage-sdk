package user_test

import (
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/user"
)

func TestGeneratePassword(t *testing.T) {
	pwd, err := user.GeneratePassword(16, false)
	if err != nil {
		t.Fatalf("GeneratePassword failed: %v", err)
	}
	if len(pwd) != 16 {
		t.Errorf("expected length 16, got %d", len(pwd))
	}

	// Should only contain alphanumeric
	for _, c := range pwd {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			t.Errorf("unexpected character %q in non-complex password", c)
		}
	}
}

func TestGeneratePasswordComplex(t *testing.T) {
	// Generate several complex passwords and check that at least one contains a special char
	hasSpecial := false
	specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"

	for i := 0; i < 20; i++ {
		pwd, err := user.GeneratePassword(32, true)
		if err != nil {
			t.Fatalf("GeneratePassword failed: %v", err)
		}
		for _, c := range pwd {
			if strings.ContainsRune(specialChars, c) {
				hasSpecial = true
				break
			}
		}
		if hasSpecial {
			break
		}
	}

	if !hasSpecial {
		t.Error("expected at least one complex password to contain special characters")
	}
}

func TestGeneratePasswordLength(t *testing.T) {
	// Test minimum
	_, err := user.GeneratePassword(7, false)
	if err == nil {
		t.Error("expected error for length < 8")
	}

	// Test at minimum
	pwd, err := user.GeneratePassword(8, false)
	if err != nil {
		t.Fatalf("GeneratePassword(8) failed: %v", err)
	}
	if len(pwd) != 8 {
		t.Errorf("expected length 8, got %d", len(pwd))
	}

	// Test maximum
	pwd, err = user.GeneratePassword(128, false)
	if err != nil {
		t.Fatalf("GeneratePassword(128) failed: %v", err)
	}
	if len(pwd) != 128 {
		t.Errorf("expected length 128, got %d", len(pwd))
	}

	// Test over maximum
	_, err = user.GeneratePassword(129, false)
	if err == nil {
		t.Error("expected error for length > 128")
	}
}

func TestGeneratePasswordUniqueness(t *testing.T) {
	passwords := make(map[string]bool)
	for i := 0; i < 100; i++ {
		pwd, err := user.GeneratePassword(16, false)
		if err != nil {
			t.Fatalf("GeneratePassword failed: %v", err)
		}
		if passwords[pwd] {
			t.Fatal("generated duplicate password")
		}
		passwords[pwd] = true
	}
}
