//go:build integration

package exec_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

func TestRun(t *testing.T) {
	ctx := context.Background()
	result, err := exec.Run(ctx, "echo", "hello")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit 0, got %d", result.ExitCode)
	}
	if !strings.Contains(result.Stdout, "hello") {
		t.Errorf("expected stdout to contain 'hello', got %q", result.Stdout)
	}
}

func TestRunExitCode(t *testing.T) {
	ctx := context.Background()
	result, err := exec.Run(ctx, "false")
	if err == nil {
		t.Fatal("expected error for 'false' command")
	}
	if result.ExitCode != 1 {
		t.Errorf("expected exit 1, got %d", result.ExitCode)
	}
}

func TestRunInDir(t *testing.T) {
	ctx := context.Background()
	result, err := exec.RunInDir(ctx, "/tmp", "pwd")
	if err != nil {
		t.Fatalf("RunInDir failed: %v", err)
	}
	if !strings.Contains(result.Stdout, "/tmp") {
		t.Errorf("expected stdout to contain '/tmp', got %q", result.Stdout)
	}
}

func TestRunWithStdin(t *testing.T) {
	ctx := context.Background()
	input := "hello from stdin"
	result, err := exec.RunWithStdin(ctx, strings.NewReader(input), "cat")
	if err != nil {
		t.Fatalf("RunWithStdin failed: %v", err)
	}
	if !strings.Contains(result.Stdout, input) {
		t.Errorf("expected stdout to contain %q, got %q", input, result.Stdout)
	}
}

func TestRunContextCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := exec.Run(ctx, "sleep", "10")
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !strings.Contains(err.Error(), "context") {
		t.Errorf("expected context error, got: %v", err)
	}
}

func TestSudo(t *testing.T) {
	ctx := context.Background()
	result, err := exec.Sudo(ctx, "id", "-u")
	if err != nil {
		t.Fatalf("Sudo failed: %v", err)
	}
	if strings.TrimSpace(result.Stdout) != "0" {
		t.Errorf("expected uid '0' (root), got %q", strings.TrimSpace(result.Stdout))
	}
}

func TestSudoWithStdin(t *testing.T) {
	ctx := context.Background()
	result, err := exec.SudoWithStdin(ctx, strings.NewReader("test input"), "cat")
	if err != nil {
		t.Fatalf("SudoWithStdin failed: %v", err)
	}
	if !strings.Contains(result.Stdout, "test input") {
		t.Errorf("expected stdout to contain 'test input', got %q", result.Stdout)
	}
}

func TestSudoResolvesPath(t *testing.T) {
	// Verify that Sudo resolves the command to an absolute path
	// by running a command that exists in PATH
	ctx := context.Background()
	_, err := exec.Sudo(ctx, "id")
	if err != nil {
		t.Fatalf("Sudo path resolution failed: %v", err)
	}
}

func TestSudoCommandNotFound(t *testing.T) {
	ctx := context.Background()
	_, err := exec.Sudo(ctx, "nonexistent-command-12345")
	if err == nil {
		t.Fatal("expected error for non-existent command")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestRunStreaming(t *testing.T) {
	ctx := context.Background()
	var lineCount int64

	result, err := exec.RunStreaming(ctx, "seq", []string{"1", "100"}, nil, "", func(streamType int, line string, seq int64) {
		atomic.AddInt64(&lineCount, 1)
	})
	if err != nil {
		t.Fatalf("RunStreaming failed: %v", err)
	}

	count := atomic.LoadInt64(&lineCount)
	if count != 100 {
		t.Errorf("expected 100 callback invocations, got %d", count)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit 0, got %d", result.ExitCode)
	}
}

func TestRunStreamingEnvVars(t *testing.T) {
	ctx := context.Background()
	result, err := exec.RunStreaming(ctx, "sh", []string{"-c", "echo $TEST_VAR"}, []string{"TEST_VAR=hello_env"}, "", nil)
	if err != nil {
		t.Fatalf("RunStreaming with env failed: %v", err)
	}
	if !strings.Contains(result.Stdout, "hello_env") {
		t.Errorf("expected stdout to contain 'hello_env', got %q", result.Stdout)
	}
}

func TestQuery(t *testing.T) {
	out, err := exec.Query("echo", "hello")
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if strings.TrimSpace(out) != "hello" {
		t.Errorf("expected 'hello', got %q", strings.TrimSpace(out))
	}
}

func TestQueryOutput(t *testing.T) {
	stdout, exitCode, err := exec.QueryOutput("echo", "hello")
	if err != nil {
		t.Fatalf("QueryOutput failed: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d", exitCode)
	}
	if strings.TrimSpace(stdout) != "hello" {
		t.Errorf("expected 'hello', got %q", strings.TrimSpace(stdout))
	}
}

func TestQueryOutputNonZeroExit(t *testing.T) {
	_, exitCode, err := exec.QueryOutput("false")
	if err != nil {
		// go-cmd may or may not return an error for non-zero exit
		t.Logf("QueryOutput error (expected): %v", err)
	}
	if exitCode != 1 {
		t.Errorf("expected exit 1, got %d", exitCode)
	}
}

func TestQueryCommandNotFound(t *testing.T) {
	_, err := exec.Query("nonexistent-command-12345")
	if err == nil {
		t.Fatal("expected error for non-existent command")
	}
}

func TestCheck(t *testing.T) {
	if !exec.Check("true") {
		t.Error("expected Check('true') to return true")
	}
	if exec.Check("false") {
		t.Error("expected Check('false') to return false")
	}
}

func TestMaxOutputTruncation(t *testing.T) {
	ctx := context.Background()
	// Generate >1MiB of output: each line is ~7 bytes ("XXXXXX\n"), need ~150k lines
	result, err := exec.Run(ctx, "sh", "-c", "yes XXXXXX | head -n 200000")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if !strings.HasSuffix(result.Stdout, "[output truncated]") {
		t.Error("expected output to be truncated")
	}
}

func TestFormatError(t *testing.T) {
	// Test with stderr
	result := &exec.Result{Stderr: "permission denied"}
	msg := exec.FormatError(errorf("command failed"), result)
	if !strings.Contains(msg, "permission denied") {
		t.Errorf("expected 'permission denied' in formatted error, got %q", msg)
	}

	// Test with nil result
	msg = exec.FormatError(errorf("command failed"), nil)
	if msg != "command failed" {
		t.Errorf("expected 'command failed', got %q", msg)
	}

	// Test with empty stderr
	result = &exec.Result{Stderr: ""}
	msg = exec.FormatError(errorf("command failed"), result)
	if msg != "command failed" {
		t.Errorf("expected 'command failed', got %q", msg)
	}
}

type simpleError string

func (e simpleError) Error() string { return string(e) }

func errorf(msg string) error {
	return simpleError(msg)
}
