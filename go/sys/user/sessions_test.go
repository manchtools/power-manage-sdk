package user

import (
	"context"
	"errors"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

func TestKillSessions(t *testing.T) {
	t.Run("loginctl succeeds → no pkill", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{ExitCode: 0}, nil) // loginctl terminate-user
		if err := mgr(t, f).KillSessions(context.Background(), "deploy"); err != nil {
			t.Fatal(err)
		}
		calls := f.Calls()
		if len(calls) != 1 || calls[0].Name != "loginctl" || !calls[0].Escalate {
			t.Errorf("expected one escalated loginctl call, got %+v", calls)
		}
	})

	t.Run("loginctl missing → falls back to pkill", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{}, errors.New("command not found: loginctl")) // loginctl run error
		f.Push(exec.Result{ExitCode: 0}, nil)                            // pkill
		if err := mgr(t, f).KillSessions(context.Background(), "deploy"); err != nil {
			t.Fatal(err)
		}
		calls := f.Calls()
		if len(calls) != 2 || calls[1].Name != "pkill" {
			t.Errorf("expected loginctl then pkill, got %+v", calls)
		}
	})

	t.Run("pkill exit 1 (no processes) is success", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{ExitCode: 1}, nil) // loginctl non-zero → fall through
		f.Push(exec.Result{ExitCode: 1}, nil) // pkill: no matching processes
		if err := mgr(t, f).KillSessions(context.Background(), "deploy"); err != nil {
			t.Errorf("pkill exit 1 should be success, got %v", err)
		}
	})

	t.Run("pkill hard failure surfaces", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{ExitCode: 1}, nil)                                         // loginctl
		f.Push(exec.Result{ExitCode: 2, Stderr: "pkill: invalid option -- 'u'"}, nil) // pkill real error
		err := mgr(t, f).KillSessions(context.Background(), "deploy")
		var ce *exec.CommandError
		if !errors.As(err, &ce) || ce.ExitCode != 2 {
			t.Errorf("err = %v, want *exec.CommandError exit 2", err)
		}
	})
}
