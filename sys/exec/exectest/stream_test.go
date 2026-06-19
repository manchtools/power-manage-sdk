package exectest_test

import (
	"context"
	"errors"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

// Stream with a nil callback still records the Command and returns the scripted
// Result (no replay attempted).
func TestFakeRunner_StreamNilCallback(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{ExitCode: 0, Stdout: "line\n"}, nil)

	res, err := f.Stream(context.Background(), exec.Command{Name: "journalctl"}, nil)
	if err != nil {
		t.Fatalf("Stream(nil callback) err = %v", err)
	}
	if res.Stdout != "line\n" {
		t.Errorf("Stdout = %q, want the scripted result", res.Stdout)
	}
	if len(f.Calls()) != 1 || f.Calls()[0].Name != "journalctl" {
		t.Errorf("Stream did not record the Command: %+v", f.Calls())
	}
}

// Stream mirrors Run on an already-cancelled context: it returns ctx.Err(),
// does NOT consume the scripted result, and replays nothing.
func TestFakeRunner_StreamRespectsCancelledContext(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: "must-not-replay\n"}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	replayed := 0
	res, err := f.Stream(ctx, exec.Command{Name: "journalctl"},
		func(exec.StreamType, string, int64) { replayed++ })
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if replayed != 0 {
		t.Errorf("replayed %d lines on a cancelled Stream, want 0", replayed)
	}
	if res.Stdout != "" {
		t.Errorf("res = %+v, want zero value (scripted result not consumed)", res)
	}
	// The scripted result is preserved for the next (non-cancelled) call.
	if next, _ := f.Run(context.Background(), exec.Command{Name: "journalctl"}); next.Stdout != "must-not-replay\n" {
		t.Errorf("scripted result was wrongly consumed by the cancelled Stream: %q", next.Stdout)
	}
}
