package service

import (
	"context"
	"testing"
	"time"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

// query rejects a verb with no output whitelist (a defensive guard against an
// internal mis-call). Exercised directly since the public API only passes
// is-enabled/is-active.
func TestQuery_UnsupportedVerbRejected(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: "whatever\n"}, nil)
	s := &systemd{r: f}
	if _, err := s.query(context.Background(), "nginx.service", "is-failed"); err == nil {
		t.Error("query accepted an unwhitelisted verb")
	}
}

// A caller-supplied deadline is honored as-is (ensureCtx does not re-wrap it).
func TestEnsureCtx_HonorsCallerDeadline(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: "active\n"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := mgr(t, f).IsActive(ctx, "nginx.service"); err != nil {
		t.Fatalf("IsActive with a deadline ctx: %v", err)
	}
}

// Status surfaces a failure of EITHER underlying query.
func TestStatus_QueryErrors(t *testing.T) {
	t.Run("is-enabled fails", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{Stdout: "garbage-state\n", ExitCode: 4}, nil) // unrecognised → query error
		if _, err := mgr(t, f).Status(context.Background(), "nginx.service"); err == nil {
			t.Error("Status returned nil when is-enabled failed")
		}
	})
	t.Run("is-active fails", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{Stdout: "enabled\n"}, nil)                    // is-enabled ok
		f.Push(exec.Result{Stdout: "garbage-state\n", ExitCode: 4}, nil) // is-active unrecognised
		if _, err := mgr(t, f).Status(context.Background(), "nginx.service"); err == nil {
			t.Error("Status returned nil when is-active failed")
		}
	})
}

func TestIsMasked_QueryError(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: "not-found\n", ExitCode: 4}, nil)
	if _, err := mgr(t, f).IsMasked(context.Background(), "ghost.service"); err == nil {
		t.Error("IsMasked returned nil on an unrecognised query output")
	}
}
