package terminal

import (
	"errors"
	"io"
	"os"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// isSandboxStartErr reports whether err looks like a sandbox/seccomp
// restriction that should cause the test to skip rather than fail. We
// match on EPERM/EACCES/ENOSYS so genuine bugs (panics, validation
// failures, missing shell) still surface as test failures.
func isSandboxStartErr(err error) bool {
	return errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.ENOSYS) ||
		errors.Is(err, os.ErrPermission)
}

// startSessionOrSkip is the canonical helper for tests that need a live
// session: it returns the Session on success, skips the test on a
// sandbox-related Start failure, and fatally fails the test on any other
// error so real bugs are not silently masked.
func startSessionOrSkip(t *testing.T, cfg SessionConfig) *Session {
	t.Helper()
	s, err := Start(cfg)
	if err != nil {
		if isSandboxStartErr(err) {
			t.Skipf("start session: sandbox restriction: %v", err)
		}
		t.Fatalf("start session: %v", err)
	}
	return s
}

func TestStart_EmptyUser(t *testing.T) {
	_, err := Start(SessionConfig{})
	if err == nil {
		t.Fatal("expected error for empty user")
	}
	if !strings.Contains(err.Error(), "user is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStart_UnknownUser(t *testing.T) {
	_, err := Start(SessionConfig{User: "this-user-definitely-does-not-exist-pm-12345"})
	if err == nil {
		t.Fatal("expected error for unknown user")
	}
	var unknownErr user.UnknownUserError
	if !errors.As(err, &unknownErr) {
		t.Errorf("expected user.UnknownUserError in chain, got: %v", err)
	}
}

func TestStart_MissingShell(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skipf("user.Current() failed: %v", err)
	}
	_, err = Start(SessionConfig{
		User:  cur.Username,
		Shell: "/no/such/shell/binary",
	})
	if err == nil {
		t.Fatal("expected error for missing shell")
	}
	if !strings.Contains(err.Error(), "stat shell") {
		t.Errorf("expected stat shell error, got: %v", err)
	}
}

func TestStart_ShellIsDirectory(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skipf("user.Current() failed: %v", err)
	}
	_, err = Start(SessionConfig{User: cur.Username, Shell: "/tmp"})
	if err == nil {
		t.Fatal("expected error when shell is a directory")
	}
	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("expected directory error, got: %v", err)
	}
}

func TestStart_ShellNotAbsolute(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skipf("user.Current() failed: %v", err)
	}
	_, err = Start(SessionConfig{User: cur.Username, Shell: "bash"})
	if err == nil {
		t.Fatal("expected error for non-absolute shell path")
	}
	if !strings.Contains(err.Error(), "absolute path") {
		t.Errorf("expected absolute-path error, got: %v", err)
	}
}

func TestStart_ShellNotExecutable(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skipf("user.Current() failed: %v", err)
	}
	// A regular non-executable file under our temp dir.
	dir := t.TempDir()
	notExec := dir + "/not-a-shell"
	if err := os.WriteFile(notExec, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Start(SessionConfig{User: cur.Username, Shell: notExec})
	if err == nil {
		t.Fatal("expected error for non-executable shell")
	}
	if !strings.Contains(err.Error(), "not executable") {
		t.Errorf("expected not-executable error, got: %v", err)
	}
}

// pickShell returns a usable shell on the current system or skips the test.
func pickShell(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{"/bin/bash", "/bin/sh", "/usr/bin/bash"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	t.Skip("no usable shell found in PATH")
	return ""
}

func TestSession_EchoAndExit(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("PTY tests are linux-only")
	}
	cur, err := user.Current()
	if err != nil {
		t.Skipf("user.Current() failed: %v", err)
	}

	s := startSessionOrSkip(t, SessionConfig{
		User:  cur.Username,
		Shell: pickShell(t),
		Cols:  80,
		Rows:  24,
	})
	defer s.Close()

	// Send a command and an exit.
	if _, err := io.WriteString(s, "echo PM-OK\nexit\n"); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Drain output until EOF (or the session closes).
	output := drain(t, s, 5*time.Second)
	if !strings.Contains(output, "PM-OK") {
		t.Errorf("expected output to contain PM-OK, got: %q", output)
	}

	// Wait for the shell to exit cleanly.
	code, _ := s.Wait()
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestSession_ResizeBeforeExit(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("PTY tests are linux-only")
	}
	cur, err := user.Current()
	if err != nil {
		t.Skipf("user.Current() failed: %v", err)
	}

	s := startSessionOrSkip(t, SessionConfig{User: cur.Username, Shell: pickShell(t)})
	defer s.Close()

	if err := s.Resize(120, 40); err != nil {
		t.Errorf("resize: %v", err)
	}

	// Make sure resize didn't break I/O.
	if _, err := io.WriteString(s, "exit\n"); err != nil {
		t.Errorf("write after resize: %v", err)
	}
	drain(t, s, 5*time.Second)
}

func TestSession_CloseUnblocksWait(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("PTY tests are linux-only")
	}
	cur, err := user.Current()
	if err != nil {
		t.Skipf("user.Current() failed: %v", err)
	}

	s := startSessionOrSkip(t, SessionConfig{User: cur.Username, Shell: pickShell(t)})

	// Wait in a goroutine; assert it returns within a reasonable window
	// after Close.
	done := make(chan struct{})
	go func() {
		_, _ = s.Wait()
		close(done)
	}()

	if err := s.Close(); err != nil {
		t.Errorf("close: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return within 5s after Close")
	}
}

func TestSession_CloseIsIdempotent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("PTY tests are linux-only")
	}
	cur, err := user.Current()
	if err != nil {
		t.Skipf("user.Current() failed: %v", err)
	}

	s := startSessionOrSkip(t, SessionConfig{User: cur.Username, Shell: pickShell(t)})

	if err := s.Close(); err != nil {
		t.Errorf("first close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second close should be no-op, got: %v", err)
	}
}

// TestSession_ReapClosesPTYWithoutExplicitClose verifies that a session
// which exits naturally (the shell ran to completion) releases the PTY
// fd even if the caller never calls Close. This protects against
// fd leaks from sloppy callers.
func TestSession_ReapClosesPTYWithoutExplicitClose(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("PTY tests are linux-only")
	}
	cur, err := user.Current()
	if err != nil {
		t.Skipf("user.Current() failed: %v", err)
	}

	s := startSessionOrSkip(t, SessionConfig{User: cur.Username, Shell: pickShell(t)})

	// Trigger a clean exit and wait for it.
	if _, err := io.WriteString(s, "exit\n"); err != nil {
		t.Fatalf("write exit: %v", err)
	}
	if _, err := s.Wait(); err != nil {
		// non-zero exit is fine, we just need the process gone
		t.Logf("wait returned: %v", err)
	}

	// PTY must already be closed by reap — a Read should fail with a
	// closed-pipe / use-of-closed-file error, NOT block forever.
	deadline := time.After(2 * time.Second)
	read := make(chan error, 1)
	go func() {
		_, err := s.Read(make([]byte, 64))
		read <- err
	}()
	select {
	case err := <-read:
		if err == nil {
			t.Error("expected Read to fail after reap closed the PTY")
		}
	case <-deadline:
		t.Error("Read blocked forever after process exit — reap did not close PTY")
	}
}

func TestSession_DoneChannel(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("PTY tests are linux-only")
	}
	cur, err := user.Current()
	if err != nil {
		t.Skipf("user.Current() failed: %v", err)
	}

	s := startSessionOrSkip(t, SessionConfig{User: cur.Username, Shell: pickShell(t)})

	// Done must not be closed yet.
	select {
	case <-s.Done():
		t.Fatal("Done() closed before session ended")
	default:
	}

	// Trigger a clean exit.
	if _, err := io.WriteString(s, "exit\n"); err != nil {
		t.Fatalf("write exit: %v", err)
	}

	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done() did not close within 5s after exit")
	}

	_ = s.Close()
}

func TestBuildEnv_DefaultsAndOverrides(t *testing.T) {
	u := &user.User{
		Username: "alice",
		HomeDir:  "/home/alice",
	}
	env := buildEnv([]string{"FOO=bar", "TERM=screen"}, u, "/bin/bash")
	m := envToMap(env)

	// Caller-supplied entries are preserved verbatim.
	if m["FOO"] != "bar" {
		t.Errorf("FOO = %q, want bar", m["FOO"])
	}
	// Caller wins on conflicts.
	if m["TERM"] != "screen" {
		t.Errorf("TERM = %q, want screen (caller override)", m["TERM"])
	}
	// Defaults are added when absent.
	if m["HOME"] != "/home/alice" {
		t.Errorf("HOME = %q, want /home/alice", m["HOME"])
	}
	if m["USER"] != "alice" {
		t.Errorf("USER = %q, want alice", m["USER"])
	}
	if m["LOGNAME"] != "alice" {
		t.Errorf("LOGNAME = %q, want alice", m["LOGNAME"])
	}
	if m["SHELL"] != "/bin/bash" {
		t.Errorf("SHELL = %q, want /bin/bash", m["SHELL"])
	}
	if m["PATH"] == "" {
		t.Error("PATH should be populated")
	}
}

func TestBuildEnv_NoEmptyDefaults(t *testing.T) {
	// User with no HomeDir — HOME should not be set to the empty string.
	u := &user.User{Username: "nobody", HomeDir: ""}
	env := buildEnv(nil, u, "/bin/sh")
	m := envToMap(env)
	if _, ok := m["HOME"]; ok {
		t.Errorf("HOME should not be set when HomeDir is empty, got %q", m["HOME"])
	}
}

func TestDefaultWorkDir_FallsBackToTmp(t *testing.T) {
	u := &user.User{Username: "ghost", HomeDir: "/no/such/home"}
	if got := defaultWorkDir(u); got != "/tmp" {
		t.Errorf("defaultWorkDir(missing home) = %q, want /tmp", got)
	}
}

func TestDefaultWorkDir_PrefersExistingHome(t *testing.T) {
	dir := t.TempDir()
	u := &user.User{Username: "test", HomeDir: dir}
	if got := defaultWorkDir(u); got != dir {
		t.Errorf("defaultWorkDir(existing home) = %q, want %q", got, dir)
	}
}

// drain reads from the session until the read loop returns EOF (or any
// other error from the closed PTY) and returns everything it collected.
// A timeout is treated as a hard test failure via t.Fatalf rather than
// silently returning an empty string, so a hang in Resize/Read/Close
// surfaces as a clear failure instead of a passing test that masks the
// bug.
func drain(t *testing.T, s *Session, timeout time.Duration) string {
	t.Helper()
	type chunk struct {
		buf []byte
		err error
	}
	out := make(chan chunk, 1)
	go func() {
		var collected []byte
		buf := make([]byte, 4096)
		for {
			n, err := s.Read(buf)
			if n > 0 {
				collected = append(collected, buf[:n]...)
			}
			if err != nil {
				out <- chunk{collected, err}
				return
			}
		}
	}()
	select {
	case c := <-out:
		return string(c.buf)
	case <-time.After(timeout):
		_ = s.Close()
		t.Fatalf("drain: read did not finish within %v", timeout)
		return "" // unreachable; t.Fatalf aborts
	}
}

func envToMap(env []string) map[string]string {
	m := map[string]string{}
	for _, e := range env {
		if i := strings.IndexByte(e, '='); i > 0 {
			m[e[:i]] = e[i+1:]
		}
	}
	return m
}
