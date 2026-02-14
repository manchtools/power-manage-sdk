package exec

import (
	"context"
	"fmt"
	"io"
	"os/exec"
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

// Sudo wraps a command with sudo -n for privileged operations.
// The command is resolved to an absolute path so it matches sudoers rules.
func Sudo(ctx context.Context, name string, args ...string) (*Result, error) {
	absPath, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("command not found: %s", name)
	}
	sudoArgs := append([]string{"-n", absPath}, args...)
	return Run(ctx, "sudo", sudoArgs...)
}

// SudoWithStdin wraps a command with sudo and provides stdin input.
func SudoWithStdin(ctx context.Context, stdin io.Reader, name string, args ...string) (*Result, error) {
	absPath, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("command not found: %s", name)
	}
	sudoArgs := append([]string{"-n", absPath}, args...)
	return RunWithStdin(ctx, stdin, "sudo", sudoArgs...)
}

// RunStreaming executes a command with real-time output streaming.
// The callback is called for each line of output as it's produced.
func RunStreaming(ctx context.Context, name string, args []string, envVars []string, dir string, callback OutputCallback) (*Result, error) {
	c := cmd.NewCmdOptions(cmd.Options{
		Buffered:  false,
		Streaming: true,
	}, name, args...)

	if dir != "" {
		c.Dir = dir
	}
	if len(envVars) > 0 {
		c.Env = envVars
	}

	statusChan := c.Start()

	var stdoutSeq, stderrSeq int64
	var stdoutBuf, stderrBuf strings.Builder
	var stdoutBytes, stderrBytes int64

	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			select {
			case line, ok := <-c.Stdout:
				if !ok {
					for line := range c.Stderr {
						lineBytes := int64(len(line) + 1)
						if atomic.AddInt64(&stderrBytes, lineBytes) <= int64(MaxOutputBytes) {
							stderrBuf.WriteString(line + "\n")
						}
						if callback != nil {
							callback(2, line+"\n", atomic.AddInt64(&stderrSeq, 1)-1)
						}
					}
					return
				}
				lineBytes := int64(len(line) + 1)
				if atomic.AddInt64(&stdoutBytes, lineBytes) <= int64(MaxOutputBytes) {
					stdoutBuf.WriteString(line + "\n")
				}
				if callback != nil {
					callback(1, line+"\n", atomic.AddInt64(&stdoutSeq, 1)-1)
				}
			case line, ok := <-c.Stderr:
				if !ok {
					for line := range c.Stdout {
						lineBytes := int64(len(line) + 1)
						if atomic.AddInt64(&stdoutBytes, lineBytes) <= int64(MaxOutputBytes) {
							stdoutBuf.WriteString(line + "\n")
						}
						if callback != nil {
							callback(1, line+"\n", atomic.AddInt64(&stdoutSeq, 1)-1)
						}
					}
					return
				}
				lineBytes := int64(len(line) + 1)
				if atomic.AddInt64(&stderrBytes, lineBytes) <= int64(MaxOutputBytes) {
					stderrBuf.WriteString(line + "\n")
				}
				if callback != nil {
					callback(2, line+"\n", atomic.AddInt64(&stderrSeq, 1)-1)
				}
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
