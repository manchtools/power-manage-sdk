//go:build container

// Container-based real-execution test for the wall broadcast. The fake-runner
// unit tests assert the `wall` argv and stdin; this runs the REAL wall binary so
// an argv/stdin-handling change (or a wall that rejects our invocation) is caught.
// notify-send is intentionally not exercised (no D-Bus/graphical session in CI —
// the SDK skips it gracefully). Needs root-ish; self-skips when wall is absent.
package notify

import (
	"context"
	osexec "os/exec"
	"testing"
	"time"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

func TestNotifyAll_RealWall_Container(t *testing.T) {
	if _, err := osexec.LookPath("wall"); err != nil {
		t.Skip("wall not on PATH")
	}
	r, err := exec.NewRunner(exec.Direct)
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	m, err := New(r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// wall broadcasts to all terminals; with no logged-in terminals it still
	// succeeds (writes nowhere). A non-nil error means the real wall rejected our
	// argv/stdin — exactly the drift we want to catch. notify-send is skipped by
	// the SDK when no D-Bus session exists, so NotifyAll must return nil here.
	if err := m.NotifyAll(ctx, "PM Container Test", "hello from the container test"); err != nil {
		t.Fatalf("NotifyAll via real wall returned error: %v", err)
	}
}
