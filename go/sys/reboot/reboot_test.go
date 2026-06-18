package reboot

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
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

// withStat redirects the marker-file stat seam for one test.
func withStat(t *testing.T, fn func(string) (os.FileInfo, error)) {
	t.Helper()
	orig := statFunc
	statFunc = fn
	t.Cleanup(func() { statFunc = orig })
}

func TestNew_NilRunner(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, exec.ErrRunnerRequired) {
		t.Errorf("New(_, nil) error = %v, want ErrRunnerRequired", err)
	}
}

func TestIsRequired_MarkerPresent(t *testing.T) {
	withStat(t, func(string) (os.FileInfo, error) { return nil, nil }) // exists
	r := exectest.New(exec.Direct)
	need, err := mgr(t, r).IsRequired(context.Background())
	if err != nil || !need {
		t.Fatalf("IsRequired = (%v,%v), want (true,nil)", need, err)
	}
	if len(r.Calls()) != 0 {
		t.Error("marker present should short-circuit before running needs-restarting")
	}
}

func TestIsRequired_MarkerStatError(t *testing.T) {
	withStat(t, func(string) (os.FileInfo, error) {
		return nil, &fs.PathError{Op: "stat", Err: errors.New("permission denied")}
	})
	if _, err := mgr(t, exectest.New(exec.Direct)).IsRequired(context.Background()); err == nil {
		t.Error("a non-ENOENT stat error should surface, not be swallowed")
	}
}

func TestIsRequired_NeedsRestarting(t *testing.T) {
	withStat(t, func(string) (os.FileInfo, error) { return nil, os.ErrNotExist })
	cases := []struct {
		name    string
		res     exec.Result
		runErr  error
		want    bool
		wantErr bool
	}{
		{"reboot needed (exit 1)", exec.Result{ExitCode: 1}, nil, true, false},
		{"no reboot (exit 0)", exec.Result{ExitCode: 0}, nil, false, false},
		{"indeterminate (exit 2)", exec.Result{ExitCode: 2}, nil, false, false},
		// Tool absent (the exec layer wraps ErrBackendUnavailable for a missing
		// binary) → no detection available here, a graceful (false, nil).
		{
			"not installed (ErrBackendUnavailable)",
			exec.Result{},
			fmt.Errorf("%w: command not found: needs-restarting", exec.ErrBackendUnavailable),
			false, false,
		},
		// A genuine run failure (NOT a missing tool) must surface — we were asked
		// and couldn't answer for an unexpected reason; swallowing it as
		// "no reboot needed" hides the failure from the caller.
		{
			"genuine run error surfaces",
			exec.Result{},
			context.DeadlineExceeded,
			false, true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := exectest.New(exec.Direct)
			r.Push(c.res, c.runErr)
			need, err := mgr(t, r).IsRequired(context.Background())
			if (err != nil) != c.wantErr {
				t.Fatalf("IsRequired error = %v, wantErr = %v", err, c.wantErr)
			}
			if need != c.want {
				t.Fatalf("IsRequired need = %v, want %v", need, c.want)
			}
			cmd := r.Calls()[0]
			if cmd.Name != "needs-restarting" || cmd.Escalate || strings.Join(cmd.Args, " ") != "-r" {
				t.Errorf("command = %+v, want unprivileged `needs-restarting -r`", cmd)
			}
		})
	}
}

func TestSchedule(t *testing.T) {
	t.Run("zero options: default delay, no message, escalated", func(t *testing.T) {
		r := exectest.New(exec.Sudo)
		if err := mgr(t, r).Schedule(context.Background(), ScheduleOptions{}); err != nil {
			t.Fatal(err)
		}
		cmd := r.Calls()[0]
		if cmd.Name != "shutdown" || !cmd.Escalate {
			t.Fatalf("command = %+v, want escalated shutdown", cmd)
		}
		if strings.Join(cmd.Args, " ") != "-r +1" {
			t.Errorf("argv = %q, want `-r +1`", strings.Join(cmd.Args, " "))
		}
	})
	t.Run("default delay + message, escalated", func(t *testing.T) {
		r := exectest.New(exec.Sudo)
		if err := mgr(t, r).Schedule(context.Background(), ScheduleOptions{Message: "patching now"}); err != nil {
			t.Fatal(err)
		}
		cmd := r.Calls()[0]
		if cmd.Name != "shutdown" || !cmd.Escalate {
			t.Fatalf("command = %+v, want escalated shutdown", cmd)
		}
		if strings.Join(cmd.Args, " ") != "-r +1 patching now" {
			t.Errorf("argv = %q, want `-r +1 patching now`", strings.Join(cmd.Args, " "))
		}
	})
	t.Run("explicit delay, no message", func(t *testing.T) {
		r := exectest.New(exec.Sudo)
		if err := mgr(t, r).Schedule(context.Background(), ScheduleOptions{Delay: "+5"}); err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(r.Calls()[0].Args, " "); got != "-r +5" {
			t.Errorf("argv = %q, want `-r +5`", got)
		}
	})
	t.Run("explicit delay + message", func(t *testing.T) {
		r := exectest.New(exec.Sudo)
		if err := mgr(t, r).Schedule(context.Background(), ScheduleOptions{Delay: "+5", Message: "patching"}); err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(r.Calls()[0].Args, " "); got != "-r +5 patching" {
			t.Errorf("argv = %q, want `-r +5 patching`", got)
		}
	})
	t.Run("non-zero exit is an error", func(t *testing.T) {
		r := exectest.New(exec.Sudo)
		r.Push(exec.Result{ExitCode: 1, Stderr: "Failed to schedule"}, nil)
		if err := mgr(t, r).Schedule(context.Background(), ScheduleOptions{Delay: "+1"}); err == nil {
			t.Error("Schedule swallowed a non-zero exit")
		}
	})
	t.Run("exec failure is an error", func(t *testing.T) {
		r := exectest.New(exec.Sudo)
		r.Push(exec.Result{}, errors.New("sudo: a password is required"))
		if err := mgr(t, r).Schedule(context.Background(), ScheduleOptions{Delay: "+1"}); err == nil {
			t.Error("Schedule swallowed an exec failure")
		}
	})
}

func TestCancel(t *testing.T) {
	r := exectest.New(exec.Sudo)
	if err := mgr(t, r).Cancel(context.Background()); err != nil {
		t.Fatal(err)
	}
	cmd := r.Calls()[0]
	if cmd.Name != "shutdown" || !cmd.Escalate || strings.Join(cmd.Args, " ") != "-c" {
		t.Errorf("command = %+v, want escalated `shutdown -c`", cmd)
	}

	r2 := exectest.New(exec.Sudo)
	r2.Push(exec.Result{ExitCode: 1}, nil)
	if err := mgr(t, r2).Cancel(context.Background()); err == nil {
		t.Error("Cancel swallowed a non-zero exit")
	}
}
