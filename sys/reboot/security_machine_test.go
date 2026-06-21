package reboot

import (
	"context"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

type rebootScheduleAction int

const (
	rebootScheduleGraceful rebootScheduleAction = iota
	rebootScheduleImmediateNow
	rebootScheduleImmediateZero
	rebootScheduleNegativeDelay
	rebootScheduleControlDelay
	rebootScheduleControlMessage
)

type rebootScheduleStep struct {
	name       string
	action     rebootScheduleAction
	wantReject bool
}

// TestRebootScheduleSecurityMachine models shutdown scheduling as a small DoS
// boundary. A controlled grace period may reach shutdown; immediate, malformed,
// or terminal-control-bearing inputs must fail before the escalated reboot
// command is invoked.
func TestRebootScheduleSecurityMachine(t *testing.T) {
	steps := []rebootScheduleStep{
		{name: "graceful reboot window is accepted", action: rebootScheduleGraceful},
		{name: "now is rejected before shutdown", action: rebootScheduleImmediateNow, wantReject: true},
		{name: "+0 is rejected before shutdown", action: rebootScheduleImmediateZero, wantReject: true},
		{name: "negative delay is rejected before shutdown", action: rebootScheduleNegativeDelay, wantReject: true},
		{name: "control character in delay is rejected", action: rebootScheduleControlDelay, wantReject: true},
		{name: "control character in message is rejected", action: rebootScheduleControlMessage, wantReject: true},
	}

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			r := exectest.New(exec.Sudo)
			err := mgr(t, r).Schedule(context.Background(), rebootScheduleOptions(step.action))
			if step.wantReject {
				if err == nil {
					t.Errorf("%s reached accepted state; want validation rejection", step.name)
				}
				if calls := r.Calls(); len(calls) != 0 {
					t.Fatalf("%s reached escalated shutdown: %+v", step.name, calls)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s unexpected error: %v", step.name, err)
			}
			if calls := r.Calls(); len(calls) != 1 || calls[0].Name != "shutdown" || !calls[0].Escalate {
				t.Fatalf("accepted transition calls = %+v, want one escalated shutdown", calls)
			}
		})
	}
}

func rebootScheduleOptions(action rebootScheduleAction) ScheduleOptions {
	switch action {
	case rebootScheduleGraceful:
		return ScheduleOptions{Delay: "+15", Message: "maintenance reboot"}
	case rebootScheduleImmediateNow:
		return ScheduleOptions{Delay: "now", Message: "maintenance reboot"}
	case rebootScheduleImmediateZero:
		return ScheduleOptions{Delay: "+0", Message: "maintenance reboot"}
	case rebootScheduleNegativeDelay:
		return ScheduleOptions{Delay: "-1", Message: "maintenance reboot"}
	case rebootScheduleControlDelay:
		return ScheduleOptions{Delay: "+5\nnow", Message: "maintenance reboot"}
	case rebootScheduleControlMessage:
		return ScheduleOptions{Delay: "+15", Message: "maintenance\x1b[2Jreboot"}
	default:
		return ScheduleOptions{Delay: "+15", Message: "maintenance reboot"}
	}
}
