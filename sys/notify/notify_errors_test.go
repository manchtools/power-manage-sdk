package notify

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

// seamNotifySendAbsent isolates the wall path: notify-send is "not installed",
// so the desktop branch is a graceful skip and only the wall result matters.
func seamNotifySendAbsent(t *testing.T) {
	t.Helper()
	ol, os_ := lookPath, statSocket
	t.Cleanup(func() { lookPath, statSocket = ol, os_ })
	lookPath = func(string) (string, error) { return "", errors.New("not found") }
	statSocket = func(string) (os.FileInfo, error) { return nil, errors.New("no socket") }
}

func TestNotifyAll_ReturnsErrorOnWallFailure(t *testing.T) {
	seamNotifySendAbsent(t)
	r := exectest.New(exec.Sudo)
	r.Push(exec.Result{ExitCode: 1, Stderr: "wall: permission denied"}, nil)
	if err := mgr(t, r).NotifyAll(context.Background(), "T", "m"); err == nil {
		t.Error("NotifyAll = nil when wall failed; the failure must be surfaced, not swallowed")
	}
}

func TestNotifyUsers_ReturnsErrorOnWallFailure(t *testing.T) {
	seamNotifySendAbsent(t)
	r := exectest.New(exec.Sudo)
	r.Push(exec.Result{}, errors.New("runner down")) // wall: runner error
	if err := mgr(t, r).NotifyUsers(context.Background(), []string{"alice"}, "T", "m"); err == nil {
		t.Error("NotifyUsers = nil when wall failed")
	}
}

// notify-send absent (a headless host) is a graceful skip, not a failure: a
// successful wall returns nil.
func TestNotifyAll_NilOnSuccessNoDesktopTool(t *testing.T) {
	seamNotifySendAbsent(t)
	r := exectest.New(exec.Sudo)
	r.Push(exec.Result{}, nil) // wall ok
	if err := mgr(t, r).NotifyAll(context.Background(), "T", "m"); err != nil {
		t.Errorf("NotifyAll = %v, want nil (wall ok, notify-send absent is a graceful skip)", err)
	}
}

// A notify-send delivery that runs and fails IS surfaced (aggregated).
func TestNotifyAll_AggregatesDesktopDeliveryFailure(t *testing.T) {
	seamPresent(t)
	r := exectest.New(exec.Sudo)
	r.Push(exec.Result{}, nil)                                              // wall ok
	r.Push(exec.Result{Stdout: "c1 1000 alice seat0 -"}, nil)               // list-sessions
	r.Push(exec.Result{Stdout: "Type=wayland\nName=alice\nUser=1000"}, nil) // show c1
	r.Push(exec.Result{ExitCode: 1, Stderr: "notify-send failed"}, nil)     // env notify-send alice → fail
	if err := mgr(t, r).NotifyAll(context.Background(), "T", "m"); err == nil {
		t.Error("NotifyAll = nil when a desktop notification delivery failed")
	}
}

// Full success (wall + every desktop delivery) returns nil.
func TestNotifyAll_NilOnFullSuccess(t *testing.T) {
	seamPresent(t)
	r := exectest.New(exec.Sudo)
	r.Push(exec.Result{}, nil)                                              // wall
	r.Push(exec.Result{Stdout: "c1 1000 alice seat0 -"}, nil)               // list-sessions
	r.Push(exec.Result{Stdout: "Type=wayland\nName=alice\nUser=1000"}, nil) // show c1
	r.Push(exec.Result{}, nil)                                              // env notify-send alice ok
	if err := mgr(t, r).NotifyAll(context.Background(), "T", "m"); err != nil {
		t.Errorf("NotifyAll = %v, want nil on full success", err)
	}
}

// Failing to enumerate sessions (loginctl) is surfaced — we couldn't determine
// who to notify on the desktop.
func TestNotifyAll_ErrorWhenSessionListFails(t *testing.T) {
	seamPresent(t)
	r := exectest.New(exec.Sudo)
	r.Push(exec.Result{}, nil)                                     // wall ok
	r.Push(exec.Result{ExitCode: 1, Stderr: "loginctl down"}, nil) // list-sessions fails
	if err := mgr(t, r).NotifyAll(context.Background(), "T", "m"); err == nil {
		t.Error("NotifyAll = nil when session enumeration failed")
	}
}

// A user with no D-Bus session socket is a graceful skip, not an error (nothing
// to deliver to).
func TestNotifyAll_MissingDBusSocketIsGracefulSkip(t *testing.T) {
	ol, os_ := lookPath, statSocket
	t.Cleanup(func() { lookPath, statSocket = ol, os_ })
	lookPath = func(string) (string, error) { return "/usr/bin/notify-send", nil }
	statSocket = func(string) (os.FileInfo, error) { return nil, errors.New("no socket") }
	r := exectest.New(exec.Sudo)
	r.Push(exec.Result{}, nil)                                              // wall ok
	r.Push(exec.Result{Stdout: "c1 1000 alice seat0 -"}, nil)               // list-sessions
	r.Push(exec.Result{Stdout: "Type=wayland\nName=alice\nUser=1000"}, nil) // show c1
	if err := mgr(t, r).NotifyAll(context.Background(), "T", "m"); err != nil {
		t.Errorf("NotifyAll = %v, want nil (missing D-Bus socket is a graceful skip)", err)
	}
	// No env/notify-send call was made (socket missing → skipped before delivery).
	for _, c := range r.Calls() {
		if c.Name == "env" {
			t.Error("notify-send ran despite a missing D-Bus socket")
		}
	}
}

// A Runner error (not just a non-zero exit) on session listing is surfaced.
func TestNotifyAll_ErrorWhenSessionListRunnerErrors(t *testing.T) {
	seamPresent(t)
	r := exectest.New(exec.Sudo)
	r.Push(exec.Result{}, nil)                       // wall ok
	r.Push(exec.Result{}, errors.New("runner down")) // list-sessions: runner error
	if err := mgr(t, r).NotifyAll(context.Background(), "T", "m"); err == nil {
		t.Error("NotifyAll = nil when the session-list runner errored")
	}
}

// A Runner error on a desktop delivery is surfaced (aggregated).
func TestNotifyAll_ErrorWhenDeliveryRunnerErrors(t *testing.T) {
	seamPresent(t)
	r := exectest.New(exec.Sudo)
	r.Push(exec.Result{}, nil)                                              // wall ok
	r.Push(exec.Result{Stdout: "c1 1000 alice seat0 -"}, nil)               // list-sessions
	r.Push(exec.Result{Stdout: "Type=wayland\nName=alice\nUser=1000"}, nil) // show c1
	r.Push(exec.Result{}, errors.New("runner down"))                        // env notify-send: runner error
	if err := mgr(t, r).NotifyAll(context.Background(), "T", "m"); err == nil {
		t.Error("NotifyAll = nil when a desktop delivery runner errored")
	}
}
