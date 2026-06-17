//go:build integration

package exec_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// These integration tests exercise REAL privilege escalation through the Runner
// (the leg the unit tests can only fake with a temp-dir sudo). They run in the
// CI integration container, which ships NOPASSWD sudo with id/cat/sh allowed
// (see test/Dockerfile.integration). The previous coverage lived in the deleted
// legacy exec_test.go's Privileged* tests; this is its Runner equivalent.

func sudoRunner(t *testing.T) pmexec.Runner {
	t.Helper()
	if _, err := exec.LookPath("sudo"); err != nil {
		t.Skip("sudo not on PATH; escalation integration leg not exercisable here")
	}
	r, err := pmexec.NewRunner(pmexec.Sudo)
	if err != nil {
		t.Fatalf("NewRunner(Sudo): %v", err)
	}
	return r
}

// An escalated command runs as root: `sudo -n id -u` reports uid 0.
func TestRunner_EscalatedRunsAsRoot_Integration(t *testing.T) {
	res, err := sudoRunner(t).Run(context.Background(), pmexec.Command{Name: "id", Args: []string{"-u"}, Escalate: true})
	if err != nil {
		t.Fatalf("escalated Run err = %v", err)
	}
	if got := strings.TrimSpace(res.Stdout); got != "0" {
		t.Errorf("escalated id -u = %q, want 0 (root)", got)
	}
}

// Escalated stdin is delivered to the privileged child.
func TestRunner_EscalatedStdin_Integration(t *testing.T) {
	res, err := sudoRunner(t).Run(context.Background(), pmexec.Command{
		Name: "cat", Escalate: true, Stdin: strings.NewReader("escalated-input"),
	})
	if err != nil {
		t.Fatalf("escalated stdin Run err = %v", err)
	}
	if !strings.Contains(res.Stdout, "escalated-input") {
		t.Errorf("escalated cat stdout = %q, want the piped input", res.Stdout)
	}
}

// Escalated streaming delivers each line through the callback.
func TestRunner_EscalatedStreaming_Integration(t *testing.T) {
	var lines []string
	res, err := sudoRunner(t).Stream(context.Background(),
		pmexec.Command{Name: "sh", Args: []string{"-c", "printf 'line1\\nline2\\nline3\\n'"}, Escalate: true},
		func(s pmexec.StreamType, line string, _ int64) {
			if s == pmexec.StreamStdout {
				lines = append(lines, strings.TrimRight(line, "\n"))
			}
		})
	if err != nil {
		t.Fatalf("escalated Stream err = %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit = %d (stderr=%q), want 0", res.ExitCode, res.Stderr)
	}
	if strings.Join(lines, ",") != "line1,line2,line3" {
		t.Errorf("streamed lines = %v, want [line1 line2 line3]", lines)
	}
}

// A nonexistent command is rejected (command-not-found) BEFORE escalation —
// resolveAbsolute fails, so the wrapper is never invoked.
func TestRunner_EscalatedCommandNotFound_Integration(t *testing.T) {
	_, err := sudoRunner(t).Run(context.Background(), pmexec.Command{Name: "nonexistent-command-12345", Escalate: true})
	if err == nil {
		t.Fatal("expected an error for a nonexistent escalated command")
	}
	if !strings.Contains(err.Error(), "command not found") {
		t.Errorf("err = %v, want a command-not-found failure", err)
	}
}
