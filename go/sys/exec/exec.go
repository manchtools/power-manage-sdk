package exec

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"

	"github.com/go-cmd/cmd"
)

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
	// Default child PATH is the agent's own (sanitized) PATH.
	return RunStreamingChildPath(ctx, name, args, envVars, os.Getenv("PATH"), dir, callback)
}

// RunStreamingChildPath is RunStreaming with an explicit, TRUSTED child
// PATH. PATH is on the BlockedEnvVars list so an untrusted caller can't
// smuggle it through envVars; this entry point lets a trusted caller
// (e.g. the agent's per-user runuser fan-out, which must run with the
// target user's PATH rather than root's) set the child PATH directly.
// childPath is used only when envVars is non-empty, matching
// RunStreaming's compose-env behavior.
func RunStreamingChildPath(ctx context.Context, name string, args []string, envVars []string, childPath string, dir string, callback OutputCallback) (*Result, error) {
	for _, e := range envVars {
		key, _, ok := strings.Cut(e, "=")
		if !ok {
			return nil, fmt.Errorf("%w: env entry must be KEY=VALUE, got %q", ErrInvalidEnvVar, e)
		}
		if !IsAllowedEnvVar(key) {
			return nil, fmt.Errorf("%w: refusing to forward env var %q to child (hijack-prone names like LD_PRELOAD, PATH, BASH_ENV are refused at this boundary)", ErrBlockedEnvVar, key)
		}
	}

	c := cmd.NewCmdOptions(cmd.Options{
		Buffered:       false,
		Streaming:      true,
		LineBufferSize: 4 * MaxOutputBytes,
	}, name, args...)

	if dir != "" {
		c.Dir = dir
	}
	if len(envVars) > 0 {
		// Compose final env: sanitized PATH (from the agent's own
		// environment, which the BlockedEnvVars check kept the caller
		// from supplying) + the validated user vars. Callers who
		// don't pass env vars keep the previous "inherit parent
		// fully" semantics — that path is unchanged for backward
		// compatibility.
		finalEnv := make([]string, 0, len(envVars)+1)
		if childPath != "" {
			finalEnv = append(finalEnv, "PATH="+childPath)
		}
		finalEnv = append(finalEnv, envVars...)
		c.Env = finalEnv
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
				c.Stop()
				return
			}
		}
	}()

	status := <-statusChan
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
	}, status.Error
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
		c.Stop()
		status := <-statusChan
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
