package user

import (
	"context"
	"testing"
)

func TestKillSessions_InvalidUsername(t *testing.T) {
	err := KillSessions(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty username")
	}

	err = KillSessions(context.Background(), "../root")
	if err == nil {
		t.Error("expected error for invalid username")
	}
}

func TestKillSessions_RequiresPrivileges(t *testing.T) {
	// KillSessions requires sudo. Skip in unprivileged tests.
	t.Skip("KillSessions requires root privileges")
}
