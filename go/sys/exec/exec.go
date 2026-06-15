package exec

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-cmd/cmd"
)

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

// Run executes a command and returns its output.
func Run(ctx context.Context, name string, args ...string) (*Result, error) {
	return runWithOptions(ctx, name, args, nil, "")
}

// RunInDir executes a command in a specific directory.
func RunInDir(ctx context.Context, dir, name string, args ...string) (*Result, error) {
	return runWithOptions(ctx, name, args, nil, dir)
}

// RunWithStdin executes a command with stdin input.
func RunWithStdin(ctx context.Context, stdin io.Reader, name string, args ...string) (*Result, error) {
	return runWithOptions(ctx, name, args, stdin, "")
}

// RunWithCLocale runs a command with LC_ALL=C and LANG=C forced into
// the environment. Use this whenever the agent parses tool output
// that is not stable across locales — `last`, `getent`, `df`, `stat`,
// etc. emit translated date/error strings under a non-English LANG,
// which silently break English-only string parsers.
//
// PATH is preserved from the calling process so binary lookup keeps
// working; everything else from the caller's environment is dropped
// to keep the run reproducible. SDK helper for agent finding F025
// (LC_ALL=C for `last(1)` parsing).
func RunWithCLocale(ctx context.Context, name string, args ...string) (*Result, error) {
	// RunStreaming prepends a sanitized PATH= for us when envVars is
	// non-empty, so we only need to pass the deterministic-locale
	// pair. The previous explicit PATH+=os.Getenv("PATH") here would
	// now be redundant (PATH is on the blocklist for user-supplied
	// env, but the SDK-internal prepend is unaffected).
	return RunStreaming(ctx, name, args, []string{"LC_ALL=C", "LANG=C"}, "", nil)
}

// RunStreaming executes a command with real-time output streaming.
// The callback is called for each line of output as it's produced.
//
// SECURITY: every entry in envVars is validated against
// IsAllowedEnvVar before the child is spawned. Names that hijack
// process execution (LD_PRELOAD, PATH, BASH_ENV, GCONV_PATH,
// LD_LIBRARY_PATH, NODE_OPTIONS, PYTHONPATH, …) are refused with
// ErrBlockedEnvVar. Entries that aren't KEY=VALUE shaped are refused
// with ErrInvalidEnvVar. This is the SDK boundary — every caller
// (Privileged, PrivilegedStreaming, pkg/exec.runPM, …) inherits the
// check, so the audit-finding-#8 enforcement lives in one place.
func RunStreaming(ctx context.Context, name string, args []string, envVars []string, dir string, callback OutputCallback) (*Result, error) {
	if err := validateEnvVars(envVars); err != nil {
		return nil, err
	}
	// Backward-compatible env composition. When the caller supplies env
	// vars we compose [sanitized parent PATH] + their vars; when they
	// supply NONE we leave the child env nil so it inherits the parent
	// environment fully — the long-standing contract every Run*/
	// Privileged*/pkg caller relies on. (RunStreamingChildPath does NOT
	// share this fall-through; see its doc.)
	var finalEnv []string
	if len(envVars) > 0 {
		finalEnv = composeEnv(os.Getenv("PATH"), envVars)
	}
	return runStreamingWithEnv(ctx, name, args, finalEnv, dir, callback)
}

// RunStreamingChildPath is RunStreaming with an explicit, TRUSTED child
// PATH. PATH is on the BlockedEnvVars list so an untrusted caller can't
// smuggle it through envVars; this entry point lets a trusted caller
// (e.g. the agent's per-user runuser fan-out, which must run with the
// target user's PATH rather than root's) set the child PATH directly.
//
// SECURITY: unlike RunStreaming, the curated childPath is ALWAYS
// authoritative — the child env is composed as [PATH=childPath] + envVars
// even when envVars is EMPTY, and the parent environment is NEVER
// inherited. This is deliberate: the whole reason a caller reaches for a
// curated PATH is isolation, so an empty envVars must not silently fall
// back to inheriting the agent's (root's) full environment — the exact
// un-sandboxing the previous "childPath used only when envVars is
// non-empty" shape allowed. A caller that genuinely wants full parent
// inheritance must use RunStreaming, not this entry point.
func RunStreamingChildPath(ctx context.Context, name string, args []string, envVars []string, childPath string, dir string, callback OutputCallback) (*Result, error) {
	if err := validateEnvVars(envVars); err != nil {
		return nil, err
	}
	// Always a non-nil (composed) env: the curated PATH replaces, never
	// augments, the parent environment.
	return runStreamingWithEnv(ctx, name, args, composeEnv(childPath, envVars), dir, callback)
}

// validateEnvVars enforces the SDK env boundary: every entry must be
// KEY=VALUE and the key must not be on the BlockedEnvVars list (PATH,
// LD_PRELOAD, BASH_ENV, GCONV_PATH, LD_LIBRARY_PATH, …). This is the one
// place the audit-finding-#8 check lives; both streaming entry points run
// it before composing the child env.
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
// "inherit parent fully" (a nil env passed to runStreamingWithEnv).
func composeEnv(childPath string, envVars []string) []string {
	env := make([]string, 0, len(envVars)+1)
	if childPath != "" {
		env = append(env, "PATH="+childPath)
	}
	return append(env, envVars...)
}

// runStreamingWithEnv runs the command with a fully-composed child env.
// A nil env inherits the parent environment fully; a non-nil env (even an
// empty one) replaces it.
func runStreamingWithEnv(ctx context.Context, name string, args []string, env []string, dir string, callback OutputCallback) (*Result, error) {
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

	statusChan := c.Start()

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

func runWithOptions(ctx context.Context, name string, args []string, stdin io.Reader, dir string) (*Result, error) {
	c := cmd.NewCmd(name, args...)
	if dir != "" {
		c.Dir = dir
	}

	var statusChan <-chan cmd.Status
	if stdin != nil {
		statusChan = c.StartWithStdin(stdin)
	} else {
		statusChan = c.Start()
	}

	select {
	case status := <-statusChan:
		result := statusToResult(status)
		if status.Error != nil {
			return result, status.Error
		}
		if status.Exit != 0 {
			return result, fmt.Errorf("exit code %d", status.Exit)
		}
		return result, nil
	case <-ctx.Done():
		status := awaitStatusOrKill(c, statusChan)
		return statusToResult(status), ctx.Err()
	}
}

func statusToResult(status cmd.Status) *Result {
	stdout := strings.Join(status.Stdout, "\n")
	stderr := strings.Join(status.Stderr, "\n")

	if len(stdout) > MaxOutputBytes {
		stdout = stdout[:MaxOutputBytes] + "\n[output truncated]"
	}
	if len(stderr) > MaxOutputBytes {
		stderr = stderr[:MaxOutputBytes] + "\n[output truncated]"
	}

	return &Result{
		ExitCode: status.Exit,
		Stdout:   stdout,
		Stderr:   stderr,
	}
}
