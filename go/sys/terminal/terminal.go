// Package terminal provides PTY-based shell session management for remote
// terminal access. It allocates a pseudo-terminal, spawns a shell as a
// configured Linux user, and exposes a small API for stdin/stdout I/O plus
// out-of-band controls (resize, close, wait).
//
// This package is the SDK foundation for the remote terminal feature; the
// agent is responsible for wiring it to the bidirectional gateway stream
// and enforcing authentication, audit, and session limits.
package terminal

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/creack/pty"
)

// Defaults applied when SessionConfig fields are zero.
const (
	DefaultShell = "/bin/bash"
	DefaultCols  = 80
	DefaultRows  = 24
)

// SessionConfig configures a new PTY session.
type SessionConfig struct {
	// User is the Linux username to run the shell as. Required.
	User string

	// Shell is the absolute path of the shell binary. Defaults to
	// DefaultShell ("/bin/bash"). The binary must exist and be executable.
	Shell string

	// Cols and Rows are the initial terminal window size. Zero values are
	// replaced with DefaultCols and DefaultRows.
	Cols uint16
	Rows uint16

	// Env is the environment variables passed to the shell. HOME, USER,
	// LOGNAME, SHELL, TERM, and PATH are populated automatically if absent.
	Env []string

	// WorkDir is the working directory for the shell. Defaults to the
	// user's home directory if it exists, otherwise /tmp.
	WorkDir string
}

// Session represents a running PTY shell session. The zero value is not
// usable; obtain a Session via Start.
//
// Read, Write, and Resize are safe for concurrent use from independent
// goroutines (the typical reader+writer pattern). Close, Wait, and Done
// may be called from any goroutine and at any time.
type Session struct {
	cmd *exec.Cmd
	pty *os.File

	closeOnce sync.Once
	closeErr  error

	waitOnce sync.Once
	waitErr  error
	exitCode int

	done chan struct{}
}

// Start allocates a PTY, spawns a shell as cfg.User, and returns a Session.
// The caller must call Close (or Wait followed by reaping done) to release
// resources. Start returns an error if the user cannot be looked up, the
// shell binary is missing, or the PTY cannot be allocated.
func Start(cfg SessionConfig) (*Session, error) {
	if cfg.User == "" {
		return nil, errors.New("terminal: user is required")
	}
	u, err := user.Lookup(cfg.User)
	if err != nil {
		return nil, fmt.Errorf("terminal: lookup user %q: %w", cfg.User, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("terminal: parse uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("terminal: parse gid %q: %w", u.Gid, err)
	}

	shell := cfg.Shell
	if shell == "" {
		shell = DefaultShell
	}
	if info, err := os.Stat(shell); err != nil {
		return nil, fmt.Errorf("terminal: stat shell %q: %w", shell, err)
	} else if info.IsDir() {
		return nil, fmt.Errorf("terminal: shell %q is a directory", shell)
	}

	cols := cfg.Cols
	if cols == 0 {
		cols = DefaultCols
	}
	rows := cfg.Rows
	if rows == 0 {
		rows = DefaultRows
	}

	workDir := cfg.WorkDir
	if workDir == "" {
		workDir = defaultWorkDir(u)
	}

	cmd := exec.Command(shell, "-l")
	cmd.Dir = workDir
	cmd.Env = buildEnv(cfg.Env, u, shell)
	// Setsid is forced on by creack/pty, but we set it explicitly for
	// clarity since the process-group signalling in Close relies on the
	// shell being a process-group leader.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	// Only set Credential if we'd actually be switching UIDs. setresuid
	// to the current UID is a no-op on Linux but still requires the
	// syscall to be permitted; some sandboxes (no_new_privs/seccomp)
	// reject it. Skipping the call when not needed avoids that and
	// matches the common case where the caller is already the target
	// user (e.g., agent running as the TTY user directly).
	if uint32(uid) != uint32(os.Getuid()) || uint32(gid) != uint32(os.Getgid()) {
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		}
	}

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: cols, Rows: rows})
	if err != nil {
		return nil, fmt.Errorf("terminal: start pty: %w", err)
	}

	s := &Session{
		cmd:  cmd,
		pty:  ptmx,
		done: make(chan struct{}),
	}
	go s.reap()
	return s, nil
}

// reap blocks until the child process exits, captures the exit code,
// closes the PTY master to release the fd, and signals done. Closing the
// master here means callers that forget to call Close still don't leak
// the fd; the race with an explicit Close is harmless because Close
// swallows os.ErrClosed.
func (s *Session) reap() {
	err := s.cmd.Wait()
	s.waitOnce.Do(func() {
		s.waitErr = err
		if s.cmd.ProcessState != nil {
			s.exitCode = s.cmd.ProcessState.ExitCode()
		}
	})
	_ = s.pty.Close()
	close(s.done)
}

// Read reads from the PTY master (the shell's combined stdout/stderr).
// Returns io.EOF after the shell exits and Close has been called, or an
// underlying I/O error otherwise.
func (s *Session) Read(buf []byte) (int, error) {
	return s.pty.Read(buf)
}

// Write writes to the PTY master (the shell's stdin).
func (s *Session) Write(data []byte) (int, error) {
	return s.pty.Write(data)
}

// Resize changes the window size of the PTY. The shell receives SIGWINCH
// and applications using ncurses (vim, top, etc.) re-render accordingly.
func (s *Session) Resize(cols, rows uint16) error {
	if err := pty.Setsize(s.pty, &pty.Winsize{Cols: cols, Rows: rows}); err != nil {
		return fmt.Errorf("terminal: resize: %w", err)
	}
	return nil
}

// Close terminates the shell session. It sends SIGTERM to the shell's
// process group and closes the PTY master. Safe to call multiple times;
// subsequent calls return the same error (or nil).
//
// After Close, Read and Write return errors. Use Wait or Done to observe
// the actual exit.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		// Setsid above made the shell its own process-group leader, so a
		// negative pid signals the entire group (the shell plus any
		// children it forked). Best-effort: process may already be gone.
		if s.cmd.Process != nil {
			_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGTERM)
		}
		// Closing the master also sends SIGHUP to the group, which is
		// the polite shell-termination signal. ErrClosed is expected if
		// the reaper or a concurrent caller already closed it.
		if err := s.pty.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			s.closeErr = err
		}
	})
	return s.closeErr
}

// Wait blocks until the shell exits and returns its exit code. Calling
// Wait from multiple goroutines is safe; all callers see the same result.
// Wait returns the cmd.Wait error (typically *exec.ExitError) so callers
// can distinguish a non-zero exit from a wait failure if needed.
func (s *Session) Wait() (int, error) {
	<-s.done
	return s.exitCode, s.waitErr
}

// Done returns a channel that is closed when the shell process has exited
// and its exit code is available via Wait.
func (s *Session) Done() <-chan struct{} {
	return s.done
}

// defaultWorkDir picks a sensible starting directory for the shell:
// the user's home if it exists and is a directory, otherwise /tmp.
func defaultWorkDir(u *user.User) string {
	if u.HomeDir != "" {
		if info, err := os.Stat(u.HomeDir); err == nil && info.IsDir() {
			return u.HomeDir
		}
	}
	return "/tmp"
}

// buildEnv constructs the child shell's environment, layering sane
// defaults under any caller-supplied entries (caller wins on conflicts).
func buildEnv(extra []string, u *user.User, shell string) []string {
	have := map[string]struct{}{}
	out := make([]string, 0, len(extra)+6)
	for _, e := range extra {
		if i := strings.IndexByte(e, '='); i > 0 {
			have[e[:i]] = struct{}{}
		}
		out = append(out, e)
	}
	add := func(k, v string) {
		if v == "" {
			return
		}
		if _, ok := have[k]; ok {
			return
		}
		out = append(out, k+"="+v)
	}
	add("HOME", u.HomeDir)
	add("USER", u.Username)
	add("LOGNAME", u.Username)
	add("SHELL", shell)
	add("TERM", "xterm-256color")
	add("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	return out
}

// ensure io.ReadWriter compliance — Session embeds plumbing for both.
var _ io.ReadWriter = (*Session)(nil)
