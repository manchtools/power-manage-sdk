package exec

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"sync/atomic"
)

// PrivilegeBackend selects which privilege-escalation tool Privileged
// and PrivilegedWithStdin dispatch through. The SDK defaults to the
// sudo backend; agents running on doas-only hosts call
// SetPrivilegeBackend(PrivilegeBackendDoas) once at startup.
type PrivilegeBackend int

const (
	// PrivilegeBackendSudo wraps commands with `sudo -n`. Default.
	PrivilegeBackendSudo PrivilegeBackend = 0
	// PrivilegeBackendDoas wraps commands with `doas -n`.
	PrivilegeBackendDoas PrivilegeBackend = 1
)

// backend stores the active PrivilegeBackend as an int32. Access is
// via atomic load/store so the setter is safe to call concurrently
// with any in-flight Privileged call (though in practice the setter
// runs once at startup).
var backend atomic.Int32

// SetPrivilegeBackend selects which escalation tool Privileged and
// PrivilegedWithStdin use. Call this once at startup from the agent's
// main() based on configuration. Valid values are PrivilegeBackendSudo
// (default) and PrivilegeBackendDoas; unknown values are ignored so
// callers don't accidentally silence the dispatch by passing 0 from a
// zero-valued proto enum.
func SetPrivilegeBackend(b PrivilegeBackend) {
	switch b {
	case PrivilegeBackendSudo, PrivilegeBackendDoas:
		backend.Store(int32(b))
	}
}

// CurrentPrivilegeBackend returns the active backend. Useful for tests
// and for agent code that needs to render backend-specific file paths
// (e.g. /etc/sudoers.d vs /etc/doas.d).
func CurrentPrivilegeBackend() PrivilegeBackend {
	return PrivilegeBackend(backend.Load())
}

// privilegeTool returns the CLI name for the active backend.
func privilegeTool() string {
	if CurrentPrivilegeBackend() == PrivilegeBackendDoas {
		return "doas"
	}
	return "sudo"
}

// Privileged runs name with args under the configured privilege backend
// (sudo by default, doas when SetPrivilegeBackend has been called). The
// command is resolved to an absolute path so it matches sudoers/doas.conf
// rules. The backend is invoked with `-n` to fail immediately rather
// than prompting — agents never get a terminal to enter a password.
func Privileged(ctx context.Context, name string, args ...string) (*Result, error) {
	absPath, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("command not found: %s", name)
	}
	tool := privilegeTool()
	if _, err := exec.LookPath(tool); err != nil {
		return nil, fmt.Errorf("privilege backend not installed: %s", tool)
	}
	wrapped := append([]string{"-n", absPath}, args...)
	return Run(ctx, tool, wrapped...)
}

// PrivilegedWithStdin is the stdin-accepting variant of Privileged.
func PrivilegedWithStdin(ctx context.Context, stdin io.Reader, name string, args ...string) (*Result, error) {
	absPath, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("command not found: %s", name)
	}
	tool := privilegeTool()
	if _, err := exec.LookPath(tool); err != nil {
		return nil, fmt.Errorf("privilege backend not installed: %s", tool)
	}
	wrapped := append([]string{"-n", absPath}, args...)
	return RunWithStdin(ctx, stdin, tool, wrapped...)
}
