package user

import (
	"context"
	"testing"
)

func TestSetHiddenOnLoginScreen_InvalidUsername(t *testing.T) {
	err := SetHiddenOnLoginScreen(context.Background(), "", true)
	if err == nil {
		t.Error("expected error for empty username")
	}

	err = SetHiddenOnLoginScreen(context.Background(), "Bad-User!", true)
	if err == nil {
		t.Error("expected error for invalid username")
	}
}

func TestSetHiddenOnLoginScreen_RequiresPrivileges(t *testing.T) {
	// SetHiddenOnLoginScreen requires sudo and AccountsService. Skip in unit tests.
	t.Skip("SetHiddenOnLoginScreen requires root privileges and AccountsService")
}
