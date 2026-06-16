package notify

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

func mgr(t *testing.T, r exec.Runner) Manager {
	t.Helper()
	m, err := New(r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// seamPresent makes notify-send "installed" and the D-Bus socket "present".
func seamPresent(t *testing.T) {
	t.Helper()
	ol, os_ := lookPath, statSocket
	t.Cleanup(func() { lookPath, statSocket = ol, os_ })
	lookPath = func(string) (string, error) { return "/usr/bin/notify-send", nil }
	statSocket = func(string) (os.FileInfo, error) { return nil, nil }
}

func argv(c exec.Command) string { return c.Name + " " + strings.Join(c.Args, " ") }

func TestNew_NilRunner(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Error("New(nil) returned nil error")
	}
}

func TestNotifyAll_FullGraphicalPath(t *testing.T) {
	seamPresent(t)
	r := exectest.New(exec.Sudo)
	r.Push(exec.Result{}, nil)                                                     // wall
	r.Push(exec.Result{Stdout: "c1 1000 alice seat0 -\nc2 1001 bob seat0 -"}, nil) // list-sessions
	r.Push(exec.Result{Stdout: "Type=wayland\nName=alice\nUser=1000"}, nil)        // show c1
	r.Push(exec.Result{Stdout: "Type=x11\nName=bob\nUser=1001"}, nil)              // show c2
	r.Push(exec.Result{}, nil)                                                     // env notify-send alice
	r.Push(exec.Result{}, nil)                                                     // env notify-send bob

	mgr(t, r).NotifyAll(context.Background(), "Maintenance", "Reboot soon")

	calls := r.Calls()
	if len(calls) != 6 {
		t.Fatalf("ran %d commands, want 6 (wall, list, 2× show, 2× env)", len(calls))
	}
	// wall carries the combined message on stdin, escalated.
	if calls[0].Name != "wall" || !calls[0].Escalate {
		t.Errorf("call0 = %+v, want escalated wall", calls[0])
	}
	if calls[0].Stdin == nil {
		t.Fatal("wall has no stdin")
	}
	if b, _ := io.ReadAll(calls[0].Stdin); string(b) != "Maintenance: Reboot soon" {
		t.Errorf("wall stdin = %q", b)
	}
	// the desktop notifications run as the target user with the title+message last.
	last := argv(calls[5])
	if !strings.Contains(last, "runuser -u bob") || !strings.Contains(last, "Maintenance Reboot soon") {
		t.Errorf("env argv = %q, want runuser bob + title/message", last)
	}
	if !strings.Contains(argv(calls[4]), "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus") {
		t.Errorf("alice env missing her dbus socket: %q", argv(calls[4]))
	}
}

func TestNotifyUsers_FiltersToNamedUsers(t *testing.T) {
	seamPresent(t)
	r := exectest.New(exec.Sudo)
	r.Push(exec.Result{}, nil)                                                     // wall
	r.Push(exec.Result{Stdout: "c1 1000 alice seat0 -\nc2 1001 bob seat0 -"}, nil) // list
	r.Push(exec.Result{Stdout: "Type=wayland\nName=alice\nUser=1000"}, nil)        // show c1
	r.Push(exec.Result{Stdout: "Type=wayland\nName=bob\nUser=1001"}, nil)          // show c2
	r.Push(exec.Result{}, nil)                                                     // env (alice only)

	mgr(t, r).NotifyUsers(context.Background(), []string{"alice"}, "T", "M")

	calls := r.Calls()
	// wall + list + 2× show + 1× env(alice). bob is filtered out.
	if len(calls) != 5 {
		t.Fatalf("ran %d commands, want 5 (bob filtered out)", len(calls))
	}
	if !strings.Contains(argv(calls[4]), "runuser -u alice") {
		t.Errorf("only alice should be notified, got %q", argv(calls[4]))
	}
}

func TestNotifyAll_NoNotifySendBinary(t *testing.T) {
	ol, os_ := lookPath, statSocket
	t.Cleanup(func() { lookPath, statSocket = ol, os_ })
	lookPath = func(string) (string, error) { return "", errors.New("not found") }
	statSocket = func(string) (os.FileInfo, error) { return nil, nil }

	r := exectest.New(exec.Sudo)
	mgr(t, r).NotifyAll(context.Background(), "T", "M")
	// Only wall runs; desktop dispatch short-circuits with no notify-send.
	if calls := r.Calls(); len(calls) != 1 || calls[0].Name != "wall" {
		t.Errorf("calls = %v, want just wall", calls)
	}
}

func TestSendWall_FailureIsBestEffort(t *testing.T) {
	seamPresent(t)
	r := exectest.New(exec.Sudo)
	r.Push(exec.Result{ExitCode: 1, Stderr: "wall: cannot"}, nil) // wall fails
	r.Push(exec.Result{Stdout: ""}, nil)                          // list-sessions empty
	// Must not panic; best-effort.
	mgr(t, r).NotifyAll(context.Background(), "T", "M")
	if r.Calls()[0].Name != "wall" {
		t.Error("wall not attempted")
	}
}

func TestListGraphicalSessions_Failures(t *testing.T) {
	t.Run("list-sessions fails → no desktop notifies", func(t *testing.T) {
		seamPresent(t)
		r := exectest.New(exec.Sudo)
		r.Push(exec.Result{}, nil)                            // wall
		r.Push(exec.Result{ExitCode: 1, Stderr: "nope"}, nil) // list-sessions fails
		mgr(t, r).NotifyAll(context.Background(), "T", "M")
		if n := len(r.Calls()); n != 2 {
			t.Errorf("ran %d, want 2 (wall + failed list)", n)
		}
	})
	t.Run("show-session failure and parse-reject are skipped", func(t *testing.T) {
		seamPresent(t)
		r := exectest.New(exec.Sudo)
		r.Push(exec.Result{}, nil)                                   // wall
		r.Push(exec.Result{Stdout: "c1 1 a s -\nc2 2 b s -"}, nil)   // list (2)
		r.Push(exec.Result{ExitCode: 1}, nil)                        // show c1 fails
		r.Push(exec.Result{Stdout: "Type=tty\nName=b\nUser=2"}, nil) // show c2 = tty (reject)
		mgr(t, r).NotifyAll(context.Background(), "T", "M")
		// wall + list + 2× show, no env (both sessions dropped).
		if n := len(r.Calls()); n != 4 {
			t.Errorf("ran %d, want 4 (no env for dropped sessions)", n)
		}
	})
}

func TestSendDesktopNotification_SocketAbsentAndFailure(t *testing.T) {
	t.Run("socket absent → skip env", func(t *testing.T) {
		ol, os_ := lookPath, statSocket
		t.Cleanup(func() { lookPath, statSocket = ol, os_ })
		lookPath = func(string) (string, error) { return "/usr/bin/notify-send", nil }
		statSocket = func(string) (os.FileInfo, error) { return nil, errors.New("no socket") }
		r := exectest.New(exec.Sudo)
		r.Push(exec.Result{}, nil)                                              // wall
		r.Push(exec.Result{Stdout: "c1 1000 alice s -"}, nil)                   // list
		r.Push(exec.Result{Stdout: "Type=wayland\nName=alice\nUser=1000"}, nil) // show
		mgr(t, r).NotifyAll(context.Background(), "T", "M")
		if n := len(r.Calls()); n != 3 {
			t.Errorf("ran %d, want 3 (no env when the dbus socket is missing)", n)
		}
	})
	t.Run("env failure is best-effort", func(t *testing.T) {
		seamPresent(t)
		r := exectest.New(exec.Sudo)
		r.Push(exec.Result{}, nil)                                              // wall
		r.Push(exec.Result{Stdout: "c1 1000 alice s -"}, nil)                   // list
		r.Push(exec.Result{Stdout: "Type=wayland\nName=alice\nUser=1000"}, nil) // show
		r.Push(exec.Result{ExitCode: 1, Stderr: "notify-send failed"}, nil)     // env fails
		mgr(t, r).NotifyAll(context.Background(), "T", "M")
		if n := len(r.Calls()); n != 4 {
			t.Errorf("ran %d, want 4 (env attempted despite failure)", n)
		}
	})
}
