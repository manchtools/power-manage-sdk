package exec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// WS16 finding #6: on ctx cancel/timeout both exec wrappers SIGTERM'd the
// child's process group but never escalated to SIGKILL, and then blocked
// reading the status channel. A SIGTERM-ignoring child therefore pinned the
// reaping goroutine until the child exited on its own (or forever). These
// tests pin that a cancelled, SIGTERM-ignoring child is SIGKILLed after a
// bounded grace and the call returns promptly — for BOTH wrappers
// (runStreamingWithEnv via RunStreaming, runWithOptions via Run).

// readChildPID reads the pgid-leader PID the child shell wrote ($$).
func readChildPID(t *testing.T, pidFile string) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		b, err := os.ReadFile(pidFile)
		if err == nil {
			if pid, perr := strconv.Atoi(strings.TrimSpace(string(b))); perr == nil && pid > 0 {
				return pid
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("child never wrote its PID to %s", pidFile)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// assertProcessGroupGone polls until kill(-pid, 0) reports ESRCH (the whole
// group is gone). SIGKILL delivery + reaping is asynchronous.
func assertProcessGroupGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := syscall.Kill(-pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("process group %d still alive after grace (kill(-pid,0)=%v) — SIGKILL never delivered", pid, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// sigtermIgnoringScript writes its pgid-leader PID, traps+ignores SIGTERM in
// the shell, and loops re-spawning sleep so the GROUP stays alive across a
// SIGTERM. A bare `sleep 30` would NOT work: the group SIGTERM also hits the
// sleep child (default disposition → it dies), the script completes and the
// shell exits — SIGKILL would never be exercised. The restart loop keeps the
// shell (which ignores SIGTERM) running until SIGKILL tears down the group.
func sigtermIgnoringScript(pidFile string) string {
	return fmt.Sprintf(`echo $$ > %s; trap "" TERM; while true; do sleep 30; done`, pidFile)
}

func TestRunStreaming_SIGKILLsChildThatIgnoresSIGTERM(t *testing.T) {
	restore := killGrace
	killGrace = 200 * time.Millisecond
	defer func() { killGrace = restore }()

	pidFile := t.TempDir() + "/pid"
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	type res struct{ err error }
	done := make(chan res, 1)
	start := time.Now()
	go func() {
		_, err := RunStreaming(ctx, "sh", []string{"-c", sigtermIgnoringScript(pidFile)}, nil, "", nil)
		done <- res{err}
	}()

	select {
	case r := <-done:
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("RunStreaming took %v; SIGTERM-ignoring child was not SIGKILLed after grace", elapsed)
		}
		if !errors.Is(r.err, context.DeadlineExceeded) {
			t.Errorf("err = %v, want context.DeadlineExceeded on cancel", r.err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("RunStreaming pinned on a SIGTERM-ignoring child — finding #6 (no SIGKILL escalation)")
	}

	assertProcessGroupGone(t, readChildPID(t, pidFile))
}

func TestRun_SIGKILLsChildThatIgnoresSIGTERM(t *testing.T) {
	restore := killGrace
	killGrace = 200 * time.Millisecond
	defer func() { killGrace = restore }()

	pidFile := t.TempDir() + "/pid"
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	type res struct{ err error }
	done := make(chan res, 1)
	start := time.Now()
	go func() {
		_, err := Run(ctx, "sh", "-c", sigtermIgnoringScript(pidFile))
		done <- res{err}
	}()

	select {
	case r := <-done:
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("Run took %v; SIGTERM-ignoring child was not SIGKILLed after grace", elapsed)
		}
		if !errors.Is(r.err, context.DeadlineExceeded) {
			t.Errorf("err = %v, want context.DeadlineExceeded on cancel", r.err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("Run pinned on a SIGTERM-ignoring child — finding #6 (no SIGKILL escalation)")
	}

	assertProcessGroupGone(t, readChildPID(t, pidFile))
}

// TestRun_WellBehavedChildReapsOnSIGTERM is the correct-path control: a child
// that honors SIGTERM reaps at cancel, well before the SIGKILL grace, and the
// call still returns ctx.Err().
func TestRun_WellBehavedChildReapsOnSIGTERM(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := Run(ctx, "sleep", "30") // default disposition: dies on SIGTERM
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("well-behaved child took %v to reap on SIGTERM", elapsed)
	}
}
