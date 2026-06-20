package notify

import (
	"context"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

type notificationAction int

const (
	notificationCleanBroadcast notificationAction = iota
	notificationControlTitle
	notificationControlMessage
	notificationOversizedMessage
	notificationInvalidUserFilter
)

type notificationStep struct {
	name       string
	action     notificationAction
	wantReject bool
}

// TestNotificationSecurityMachine models notification dispatch as terminal and
// desktop UI injection boundary. Clean messages may reach wall/notify-send;
// control characters, unbounded payloads, and invalid user filters must fail
// before any broadcast is attempted.
func TestNotificationSecurityMachine(t *testing.T) {
	steps := []notificationStep{
		{name: "clean broadcast is accepted", action: notificationCleanBroadcast},
		{name: "control title is rejected", action: notificationControlTitle, wantReject: true},
		{name: "control message is rejected", action: notificationControlMessage, wantReject: true},
		{name: "oversized message is rejected", action: notificationOversizedMessage, wantReject: true},
		{name: "invalid user filter is rejected", action: notificationInvalidUserFilter, wantReject: true},
	}

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			seamPresent(t)
			r := exectest.New(exec.Sudo)
			err := runNotificationStep(mgr(t, r), step.action)
			if step.wantReject {
				if err == nil {
					t.Errorf("%s reached accepted state; want validation rejection", step.name)
				}
				if calls := r.Calls(); len(calls) != 0 {
					t.Fatalf("%s reached notification side effects: %+v", step.name, calls)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s unexpected error: %v", step.name, err)
			}
			if calls := r.Calls(); len(calls) == 0 || calls[0].Name != "wall" {
				t.Fatalf("accepted notification calls = %+v, want wall broadcast path exercised", calls)
			}
		})
	}
}

func runNotificationStep(m Manager, action notificationAction) error {
	switch action {
	case notificationCleanBroadcast:
		return m.NotifyAll(context.Background(), "Maintenance", "Reboot in 15 minutes")
	case notificationControlTitle:
		return m.NotifyAll(context.Background(), "Maint\nenance", "Reboot in 15 minutes")
	case notificationControlMessage:
		return m.NotifyAll(context.Background(), "Maintenance", "Reboot \x1b[2Jsoon")
	case notificationOversizedMessage:
		return m.NotifyAll(context.Background(), "Maintenance", strings.Repeat("A", 4097))
	case notificationInvalidUserFilter:
		return m.NotifyUsers(context.Background(), []string{"alice\nroot"}, "Maintenance", "Reboot in 15 minutes")
	default:
		return m.NotifyAll(context.Background(), "Maintenance", "Reboot in 15 minutes")
	}
}
