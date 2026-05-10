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
// SetPrivilegeBackend(PrivilegeBackendDoas) once at startup, and
// agents running as root (post sudoers-removal architecture) call
// SetPrivilegeBackend(PrivilegeBackendRoot) so the dispatch becomes
// a direct exec instead of a sudo/doas wrap.
type PrivilegeBackend int

const (
	// PrivilegeBackendSudo wraps commands with `sudo -n`. Default.
	PrivilegeBackendSudo PrivilegeBackend = 0
	// PrivilegeBackendDoas wraps commands with `doas -n`.
	PrivilegeBackendDoas PrivilegeBackend = 1
	// PrivilegeBackendRoot runs commands directly with no escalation
	// wrapper. Use when the agent process is already root — sudo's
	// "root needs to be in sudoers" check varies by distro (opensuse
	// rejects it by default), and rolling our own no-op pass-through
	// avoids both that quirk and the cost of forking sudo just to
	// re-exec the same binary.
	PrivilegeBackendRoot PrivilegeBackend = 2
)

// backend stores the active PrivilegeBackend as an int32. Access is
// via atomic load/store so the setter is safe to call concurrently
// with any in-flight Privileged call (though in practice the setter
// runs once at startup).
var backend atomic.Int32

// SetPrivilegeBackend selects which escalation tool Privileged,
// PrivilegedWithStdin, and PrivilegedStreaming use. Call this once
// at startup from the agent's main() based on configuration. Valid
// values are PrivilegeBackendSudo (default), PrivilegeBackendDoas,
// and PrivilegeBackendRoot; unknown values are ignored so callers
// don't accidentally silence the dispatch by passing 0 from a
// zero-valued proto enum.
func SetPrivilegeBackend(b PrivilegeBackend) {
	switch b {
	case PrivilegeBackendSudo, PrivilegeBackendDoas, PrivilegeBackendRoot:
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
// Returns the empty string for PrivilegeBackendRoot, which signals
// the dispatchers to skip the wrapper entirely.
func privilegeTool() string {
	switch CurrentPrivilegeBackend() {
	case PrivilegeBackendDoas:
		return "doas"
	case PrivilegeBackendRoot:
		return ""
	default:
		return "sudo"
	}
}

// Privileged runs name with args under the configured privilege backend
// (sudo by default, doas when SetPrivilegeBackend has been called, or
// directly with no wrapper when the backend is root). The command is
// resolved to an absolute path so it matches sudoers/doas.conf rules.
// The backend is invoked with `-n` to fail immediately rather than
// prompting — agents never get a terminal to enter a password.
func Privileged(ctx context.Context, name string, args ...string) (*Result, error) {
	absPath, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("command not found: %s", name)
	}
	tool := privilegeTool()
	if tool == "" {
		// Root backend — direct exec, no wrapper.
		return Run(ctx, absPath, args...)
	}
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
	if tool == "" {
		return RunWithStdin(ctx, stdin, absPath, args...)
	}
	if _, err := exec.LookPath(tool); err != nil {
		return nil, fmt.Errorf("privilege backend not installed: %s", tool)
	}
	wrapped := append([]string{"-n", absPath}, args...)
	return RunWithStdin(ctx, stdin, tool, wrapped...)
}

// PrivilegedStreaming is the streaming variant of Privileged. Same
// privilege wrapping as Privileged (absolute-path resolution, `-n`
// flag, backend-installed check) but dispatches through
// RunStreaming so callers can observe stdout/stderr lines as they
// arrive via the OutputCallback.
//
// Used by agent action types that produce long-running output
// (shell scripts under sudo, package-manager streaming) where
// buffering the entire output before returning would delay the
// operator's view of progress and could push large results past
// MaxOutputBytes.
func PrivilegedStreaming(ctx context.Context, name string, args []string, envVars []string, dir string, callback OutputCallback) (*Result, error) {
	absPath, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("command not found: %s", name)
	}
	tool := privilegeTool()
	if tool == "" {
		return RunStreaming(ctx, absPath, args, envVars, dir, callback)
	}
	if _, err := exec.LookPath(tool); err != nil {
		return nil, fmt.Errorf("privilege backend not installed: %s", tool)
	}
	wrapped := append([]string{"-n", absPath}, args...)
	return RunStreaming(ctx, tool, wrapped, envVars, dir, callback)
}
