package exec

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-cmd/cmd"
)

// This file holds the shared low-level execution core used by the injected
// Runner (runner.go). The legacy process-global entry points (Run/RunStreaming/
// Privileged/Query/SetPrivilegeBackend, …) were removed once every capability
// migrated onto the Runner; only the internals the Runner builds on remain here.

// killGrace bounds how long a cancelled child has to exit on SIGTERM before
// its process group is escalated to SIGKILL. A package var (not const) so
// tests can shorten it. WS16 #6: without escalation a SIGTERM-ignoring child
// pins the reaping goroutine until the child exits on its own — or forever.
var killGrace = 5 * time.Second

// awaitStatusOrKill waits for a cancelled command's final status. It SIGTERMs
// the process group (Stop, idempotent), and if the child has not exited within
// killGrace it escalates to SIGKILL on the whole group, then reads the status
// under a second bounded grace so a wedged child can never pin the caller
// forever. go-cmd starts children with Setpgid, so -pid targets the group.
func awaitStatusOrKill(c *cmd.Cmd, statusChan <-chan cmd.Status) cmd.Status {
	_ = c.Stop() // SIGTERM the process group (no-op if already stopped/exited)

	term := time.NewTimer(killGrace)
	defer term.Stop()
	select {
	case status := <-statusChan:
		return status
	case <-term.C:
	}

	if pid := c.Status().PID; pid > 0 {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}

	kill := time.NewTimer(killGrace)
	defer kill.Stop()
	select {
	case status := <-statusChan:
		return status
	case <-kill.C:
		// Even SIGKILL could not be reaped within grace (e.g. an
		// uninterruptible D-state). Return a best-effort snapshot rather
		// than block the caller forever.
		return c.Status()
	}
}

// validateEnvVars enforces the SDK env boundary: every entry must be
// KEY=VALUE and the key must not be on the BlockedEnvVars list (PATH,
// LD_PRELOAD, BASH_ENV, GCONV_PATH, LD_LIBRARY_PATH, …). This is the one
// place the audit-finding-#8 check lives; the Runner runs it (via
// buildChildEnv) before composing the child env.
func validateEnvVars(envVars []string) error {
	for _, e := range envVars {
		key, _, ok := strings.Cut(e, "=")
		if !ok {
			return fmt.Errorf("%w: env entry must be KEY=VALUE, got %q", ErrInvalidEnvVar, e)
		}
		if !IsAllowedEnvVar(key) {
			return fmt.Errorf("%w: refusing to forward env var %q to child (hijack-prone names like LD_PRELOAD, PATH, BASH_ENV are refused at this boundary)", ErrBlockedEnvVar, key)
		}
	}
	return nil
}

// composeEnv builds the child environment: a leading PATH=childPath (when
// childPath is non-empty) followed by the caller's already-validated env
// vars. PATH cannot appear in envVars (it is blocklisted), so the
// leading entry is the only PATH the child sees. The returned slice is
// always non-nil so callers can distinguish "isolated env" (this) from
// "inherit parent fully" (a nil env passed to runStreamingWithStdin).
func composeEnv(childPath string, envVars []string) []string {
	env := make([]string, 0, len(envVars)+1)
	if childPath != "" {
		env = append(env, "PATH="+childPath)
	}
	return append(env, envVars...)
}

// runStreamingWithStdin is the shared low-level execution core: line-buffered
// streaming with a per-stream MaxOutputBytes cap, ctx-cancel SIGTERM→SIGKILL
// process-group escalation, and non-zero-exit-is-NOT-an-error semantics (the
// exit code is in Result; the returned error is non-nil only on failure to
// execute or ctx cancellation). The injected Runner builds on it. A nil env
// inherits the parent environment fully; a non-nil env (even empty) replaces it.
func runStreamingWithStdin(ctx context.Context, name string, args []string, stdin io.Reader, env []string, dir string, callback OutputCallback) (*Result, error) {
	c := cmd.NewCmdOptions(cmd.Options{
		Buffered:       false,
		Streaming:      true,
		LineBufferSize: 4 * MaxOutputBytes,
	}, name, args...)

	if dir != "" {
		c.Dir = dir
	}
	if env != nil {
		c.Env = env
	}

	var statusChan <-chan cmd.Status
	if stdin != nil {
		statusChan = c.StartWithStdin(stdin)
	} else {
		statusChan = c.Start()
	}

	var stdoutSeq, stderrSeq int64
	var stdoutBuf, stderrBuf strings.Builder
	var stdoutBytes, stderrBytes int64

	// recordLine appends to the buffer (capped at MaxOutputBytes) and
	// fires the callback with a per-stream monotonic sequence number.
	// Extracted from the two near-identical select branches below
	// (F029 in TECH_DEBT_AUDIT.md). Pre-extraction the streaming
	// goroutine had eight call sites with identical bodies; the only
	// per-call variation is which stream the line came from.
	recordLine := func(stream StreamType, line string) {
		lineBytes := int64(len(line) + 1)
		if stream == StreamStdout {
			if atomic.AddInt64(&stdoutBytes, lineBytes) <= int64(MaxOutputBytes) {
				stdoutBuf.WriteString(line + "\n")
			}
			if callback != nil {
				callback(StreamStdout, line+"\n", atomic.AddInt64(&stdoutSeq, 1)-1)
			}
		} else {
			if atomic.AddInt64(&stderrBytes, lineBytes) <= int64(MaxOutputBytes) {
				stderrBuf.WriteString(line + "\n")
			}
			if callback != nil {
				callback(StreamStderr, line+"\n", atomic.AddInt64(&stderrSeq, 1)-1)
			}
		}
	}

	// drainRemaining drains a still-open channel after its sibling
	// closed. This is the "stdout closed first, stderr still pumping"
	// (or the symmetric stderr-first) cleanup phase.
	drainRemaining := func(ch <-chan string, stream StreamType) {
		for line := range ch {
			recordLine(stream, line)
		}
	}

	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			select {
			case line, ok := <-c.Stdout:
				if !ok {
					drainRemaining(c.Stderr, StreamStderr)
					return
				}
				recordLine(StreamStdout, line)
			case line, ok := <-c.Stderr:
				if !ok {
					drainRemaining(c.Stdout, StreamStdout)
					return
				}
				recordLine(StreamStderr, line)
			case <-ctx.Done():
				// Stop draining; awaitStatusOrKill below owns the SIGTERM →
				// SIGKILL escalation so a SIGTERM-ignoring child can't pin us.
				return
			}
		}
	}()

	var (
		status cmd.Status
		runErr error
	)
	select {
	case status = <-statusChan:
		runErr = status.Error
	case <-ctx.Done():
		status = awaitStatusOrKill(c, statusChan)
		runErr = ctx.Err()
	}
	<-done

	stdoutStr := stdoutBuf.String()
	stderrStr := stderrBuf.String()
	if atomic.LoadInt64(&stdoutBytes) > int64(MaxOutputBytes) {
		stdoutStr += "\n[output truncated]"
	}
	if atomic.LoadInt64(&stderrBytes) > int64(MaxOutputBytes) {
		stderrStr += "\n[output truncated]"
	}

	return &Result{
		ExitCode: status.Exit,
		Stdout:   stdoutStr,
		Stderr:   stderrStr,
	}, runErr
}
