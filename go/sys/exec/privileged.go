package exec

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"sync/atomic"
)

// This file is the LEGACY process-global privilege path. It is retained, and
// still load-bearing, only while the capability packages are migrated onto the
// injected Runner (see runner.go / sdk-rework-design.md Decision 2). It is
// deleted in the final cleanup PR once no caller reads the global. New code must
// use NewRunner, never SetPrivilegeBackend.
//
// The PrivilegeBackend type and the Sudo/Doas/Direct values are defined in
// runner.go (the ratified, fail-closed enum). The global below preserves the
// historical default-to-sudo behaviour for not-yet-migrated callers: an unset
// global (the invalid zero value) still resolves to sudo via privilegeTool.

// backend stores the active PrivilegeBackend as an int32. Access is via atomic
// load/store so the setter is safe to call concurrently with any in-flight
// Privileged call (though in practice the setter runs once at startup).
var backend atomic.Int32

// SetPrivilegeBackend selects which escalation tool the legacy Privileged,
// PrivilegedWithStdin, and PrivilegedStreaming dispatch through. Call once at
// startup. Valid values are Sudo, Doas, and Direct; unknown values are ignored
// so a caller can't silence the dispatch by passing an uninitialised value.
//
// Prefer NewRunner and inject the Runner. This global is removed once
// the capability migration is complete.
func SetPrivilegeBackend(b PrivilegeBackend) {
	switch b {
	case Sudo, Doas, Direct:
		backend.Store(int32(b))
	}
}

// CurrentPrivilegeBackend returns the active legacy backend. Used by code that
// renders backend-specific paths (e.g. /etc/sudoers.d vs /etc/doas.d) and by
// fs's privilege-keyed write/delete path during the migration window.
//
// Prefer Runner.Backend() on an injected Runner.
func CurrentPrivilegeBackend() PrivilegeBackend {
	return PrivilegeBackend(backend.Load())
}

// privilegeTool returns the CLI name for the active legacy backend. Direct
// returns "" (skip the wrapper). The unset/zero value resolves to sudo, the
// historical default for callers that never called SetPrivilegeBackend.
func privilegeTool() string {
	switch CurrentPrivilegeBackend() {
	case Doas:
		return "doas"
	case Direct:
		return ""
	default:
		return "sudo"
	}
}

// Privileged runs name with args under the configured legacy privilege backend
// (sudo by default, doas when set, or directly with no wrapper when Direct).
// The command is resolved to an absolute path so it matches sudoers/doas.conf
// rules. The backend is invoked with `-n` to fail immediately rather than
// prompting — agents never get a terminal to enter a password.
//
// Prefer Runner.Run with Command{Escalate: true}.
func Privileged(ctx context.Context, name string, args ...string) (*Result, error) {
	absPath, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("command not found: %s", name)
	}
	tool := privilegeTool()
	if tool == "" {
		// Direct backend — direct exec, no wrapper.
		return Run(ctx, absPath, args...)
	}
	if _, err := exec.LookPath(tool); err != nil {
		return nil, fmt.Errorf("privilege backend not installed: %s", tool)
	}
	wrapped := append([]string{"-n", absPath}, args...)
	return Run(ctx, tool, wrapped...)
}

// PrivilegedWithStdin is the stdin-accepting variant of Privileged.
//
// Prefer Runner.Run with Command{Escalate: true, Stdin: r}.
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

// PrivilegedStreaming is the streaming variant of Privileged. Same privilege
// wrapping as Privileged (absolute-path resolution, `-n` flag, backend-installed
// check) but dispatches through RunStreaming so callers can observe stdout/stderr
// lines as they arrive via the OutputCallback.
//
// Prefer Runner.Stream with Command{Escalate: true}.
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
