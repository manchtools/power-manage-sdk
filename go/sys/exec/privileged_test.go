package exec

import (
	"testing"
)

func TestPrivilegeBackend_DefaultIsSudo(t *testing.T) {
	// Reset in case a prior test flipped it.
	SetPrivilegeBackend(Sudo)
	if got := CurrentPrivilegeBackend(); got != Sudo {
		t.Errorf("default backend = %d, want %d", got, Sudo)
	}
	if got := privilegeTool(); got != "sudo" {
		t.Errorf("privilegeTool() = %q, want %q", got, "sudo")
	}
}

func TestPrivilegeBackend_SetDoas(t *testing.T) {
	t.Cleanup(func() { SetPrivilegeBackend(Sudo) })
	SetPrivilegeBackend(Doas)
	if got := CurrentPrivilegeBackend(); got != Doas {
		t.Errorf("after SetPrivilegeBackend(Doas), backend = %d, want %d", got, Doas)
	}
	if got := privilegeTool(); got != "doas" {
		t.Errorf("privilegeTool() = %q, want %q", got, "doas")
	}
}

func TestPrivilegeBackend_IgnoresUnknown(t *testing.T) {
	t.Cleanup(func() { SetPrivilegeBackend(Sudo) })
	SetPrivilegeBackend(Doas)
	// An unknown value must NOT silently reset to sudo. Callers that
	// pass an uninitialised proto enum value shouldn't change behaviour
	// once the backend has been explicitly set.
	SetPrivilegeBackend(PrivilegeBackend(99))
	if got := CurrentPrivilegeBackend(); got != Doas {
		t.Errorf("unknown backend value leaked through: got %d, want %d", got, Doas)
	}
}
