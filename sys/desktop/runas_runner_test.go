package desktop

import (
	"context"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

func TestRunAsRunner_WrapsCommandAsUser(t *testing.T) {
	base := exectest.New(pmexec.Direct)
	base.Push(pmexec.Result{}, nil)
	s := Session{Username: "alice", UID: 1000, Home: "/home/alice", RuntimeDir: "/run/user/1000"}
	ra, err := RunAsRunner(base, s)
	if err != nil {
		t.Fatalf("RunAsRunner: %v", err)
	}
	if _, err := ra.Run(context.Background(), pmexec.Command{Name: "flatpak", Args: []string{"install", "--user", "org.x.App"}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	c := base.Calls()[0]
	got := strings.Join(append([]string{c.Name}, c.Args...), " ")
	// The base Runner must receive a runuser-wrapped command that drops to alice,
	// applies her session env via `env`, forces the curated PATH last, then runs
	// the original command.
	want := runuserPath + " -u alice -- " + envPath +
		" HOME=/home/alice USER=alice LOGNAME=alice XDG_RUNTIME_DIR=/run/user/1000" +
		" DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus" +
		" PATH=" + UserPath(s) + " flatpak install --user org.x.App"
	if got != want {
		t.Errorf("wrapped command:\n got=%q\nwant=%q", got, want)
	}
	if c.Escalate {
		t.Error("runuser-from-root is a privilege DROP; the wrapped command must not also escalate")
	}
}

func TestRunAsRunner_Rejects(t *testing.T) {
	if _, err := RunAsRunner(nil, Session{Username: "alice"}); err == nil {
		t.Error("nil base Runner must be rejected")
	}
	if _, err := RunAsRunner(exectest.New(pmexec.Direct), Session{}); err == nil {
		t.Error("a session with no Username must be rejected (would silently run as the agent's UID)")
	}
}

// TestRunAsRunner_ScreensHijackEnv: a caller command carrying an LD_* hijack in
// its Env must be refused before it reaches the user-scoped command (the inner
// env bypasses the base Runner's own screening).
func TestRunAsRunner_ScreensHijackEnv(t *testing.T) {
	base := exectest.New(pmexec.Direct)
	s := Session{Username: "alice", UID: 1000, Home: "/home/alice", RuntimeDir: "/run/user/1000"}
	ra, _ := RunAsRunner(base, s)
	_, err := ra.Run(context.Background(), pmexec.Command{Name: "flatpak", Args: []string{"list"}, Env: []string{"LD_PRELOAD=/tmp/evil.so"}})
	if err == nil {
		t.Fatal("LD_PRELOAD in the command env must be rejected")
	}
	if len(base.Calls()) != 0 {
		t.Error("a rejected hijack env must run nothing")
	}
}
