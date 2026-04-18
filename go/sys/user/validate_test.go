package user

import (
	"context"
	"strings"
	"testing"
)

// TestPrivilegedFunctions_RejectMaliciousUsername covers the
// flag-injection + chpasswd-newline-injection vectors for every
// privileged helper that takes a username. Each call should fail
// validation and therefore never reach exec.Privileged; we can
// assert that by using a cancelled context — if validation doesn't
// short-circuit first, the call would observe ctx.Err() instead
// of our "invalid username" error.
func TestPrivilegedFunctions_RejectMaliciousUsername(t *testing.T) {
	badNames := []string{
		"-o",            // would become a useradd flag
		"--help",        // systemctl/groupadd flag
		"",              // empty
		"RootUser",      // uppercase — violates convention
		"alice\nroot",   // newline — chpasswd stdin injection
		"alice:root",    // colon — chpasswd field separator
		"user with spaces",
		"alice/..",      // path traversal characters
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, name := range badNames {
		t.Run(name, func(t *testing.T) {
			if _, err := Create(ctx, name); err == nil || !strings.Contains(err.Error(), "invalid username") {
				t.Errorf("Create(%q): want validation error, got %v", name, err)
			}
			if _, err := Modify(ctx, name); err == nil || !strings.Contains(err.Error(), "invalid username") {
				t.Errorf("Modify(%q): want validation error, got %v", name, err)
			}
			if _, err := Delete(ctx, name, false); err == nil || !strings.Contains(err.Error(), "invalid username") {
				t.Errorf("Delete(%q): want validation error, got %v", name, err)
			}
			if _, err := Lock(ctx, name); err == nil || !strings.Contains(err.Error(), "invalid username") {
				t.Errorf("Lock(%q): want validation error, got %v", name, err)
			}
			if _, err := Unlock(ctx, name); err == nil || !strings.Contains(err.Error(), "invalid username") {
				t.Errorf("Unlock(%q): want validation error, got %v", name, err)
			}
			if _, err := SetPassword(ctx, name, "TestPass123!"); err == nil || !strings.Contains(err.Error(), "invalid username") {
				t.Errorf("SetPassword(%q): want validation error, got %v", name, err)
			}
			if _, err := ExpirePassword(ctx, name); err == nil || !strings.Contains(err.Error(), "invalid username") {
				t.Errorf("ExpirePassword(%q): want validation error, got %v", name, err)
			}

			if err := GroupCreate(ctx, name); err == nil || !strings.Contains(err.Error(), "invalid username") {
				t.Errorf("GroupCreate(%q): want validation error, got %v", name, err)
			}
			if err := GroupDelete(ctx, name); err == nil || !strings.Contains(err.Error(), "invalid username") {
				t.Errorf("GroupDelete(%q): want validation error, got %v", name, err)
			}
		})
	}
}

func TestSetPassword_RejectsNewlineInPassword(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Valid username, crafted password — must be rejected by the
	// password check, not slip through to chpasswd stdin.
	badPasswords := []string{
		"pass\nroot:attackerpass",
		"pass\r\nroot:attackerpass",
		"\npayload",
	}
	for _, pw := range badPasswords {
		if _, err := SetPassword(ctx, "alice", pw); err == nil || !strings.Contains(err.Error(), "invalid password") {
			t.Errorf("SetPassword(valid, %q): want invalid-password error, got %v", pw, err)
		}
	}
}

func TestGroupMembership_RejectsMaliciousNames(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Either argument being malicious must cause rejection before
	// exec.Privileged is called.
	if err := GroupAddUser(ctx, "-o", "wheel"); err == nil || !strings.Contains(err.Error(), "invalid username") {
		t.Errorf("GroupAddUser(bad user): got %v", err)
	}
	if err := GroupAddUser(ctx, "alice", "-o"); err == nil || !strings.Contains(err.Error(), "invalid username") {
		t.Errorf("GroupAddUser(bad group): got %v", err)
	}
	if err := GroupRemoveUser(ctx, "-o", "wheel"); err == nil || !strings.Contains(err.Error(), "invalid username") {
		t.Errorf("GroupRemoveUser(bad user): got %v", err)
	}
	if err := GroupRemoveUser(ctx, "alice", "-o"); err == nil || !strings.Contains(err.Error(), "invalid username") {
		t.Errorf("GroupRemoveUser(bad group): got %v", err)
	}
}
