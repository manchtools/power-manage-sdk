//go:build container

// Container-based real-execution test for the PTY terminal. The fake/unit tests
// can't exercise the real fork + setresuid + PTY allocation; this creates a real
// unprivileged user, opens a real login shell as that user, and proves — via the
// shell's own `id -un` over the PTY — that the privilege drop took effect. This
// is the path the audit flagged as never exercised (setresuid to a *different*
// user). Needs root (to create the user and switch to it). Self-skips when
// useradd is unavailable.
package terminal

import (
	"bytes"
	"context"
	osexec "os/exec"
	"strings"
	"testing"
	"time"
)

func TestOpenRunsShellAsTargetUser_Container(t *testing.T) {
	if _, err := osexec.LookPath("useradd"); err != nil {
		t.Skip("useradd not on PATH")
	}
	const u = "pmttytest"
	_ = osexec.Command("userdel", "-r", u).Run() // best-effort clean slate
	if out, err := osexec.Command("useradd", "-m", "-s", "/bin/bash", u).CombinedOutput(); err != nil {
		t.Skipf("cannot create test user (need root?): %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = osexec.Command("userdel", "-r", u).Run() })

	m, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sess, err := m.Open(ctx, SessionConfig{User: u})
	if err != nil {
		t.Fatalf("Open as %q: %v", u, err)
	}
	defer sess.Close()

	// Ask the shell who it is via a UNIQUE sentinel, then exit so the PTY reaches
	// EOF. A bare `id -un` would false-pass: the login-shell prompt (PS1 = \u@\h)
	// already prints the username, so `strings.Contains(out, u)` could match the
	// prompt even if the shell ran as the wrong user. The "PM_USER:" prefix only
	// appears in the command's OUTPUT (the echoed command text carries the
	// literal "$(id -un)", not its value), so matching "PM_USER:<u>" proves the
	// shell actually executed as u.
	if _, err := sess.Write([]byte("printf 'PM_USER:%s\\n' \"$(id -un)\"\nexit\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 4096)
		for {
			n, rerr := sess.Read(b)
			if n > 0 {
				buf.Write(b[:n])
			}
			if rerr != nil {
				return // EOF when the login shell exits
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatalf("timed out reading PTY output; got so far:\n%s", buf.String())
	}

	if marker := "PM_USER:" + u; !strings.Contains(buf.String(), marker) {
		t.Errorf("shell did not run as %q (sentinel %q absent from PTY output):\n%s", u, marker, buf.String())
	}
}
