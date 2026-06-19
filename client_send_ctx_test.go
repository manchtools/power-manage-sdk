package sdk

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// WS16 finding #1: the Send* methods take a ctx but (*Client).send ignored
// it and held sendMu for the whole stream.Send. A single stalled send (peer
// not draining the HTTP/2 flow-control window) therefore wedged sendMu and
// blocked every other sender past its own deadline; the terminal-send 5s ctx
// was cosmetic. These tests pin that a Send must surface its ctx deadline as
// a ctx error — both when the call is itself the wedged writer and when it is
// merely queued behind one — without reintroducing on-wire corruption
// (TestConcurrentSend_PreservesEveryMessage must stay green).

// newStalledLoopback returns a loopback whose server accepts the stream but
// NEVER calls Receive, so the client's HTTP/2 send window fills and stays
// full: the next large write blocks at the transport layer indefinitely.
func newStalledLoopback(t *testing.T) *agentLoopback {
	t.Helper()
	l := newAgentLoopback(t)
	l.handler.onStream = func(ctx context.Context, _ *connect.BidiStream[pm.AgentMessage, pm.ServerMessage]) error {
		// Hold the stream open without ever draining the inbound side.
		<-ctx.Done()
		return nil
	}
	return l
}

// connectCancellable connects the client over a cancellable ctx and registers
// cleanup that cancels it (resetting the underlying HTTP/2 stream so any send
// wedged on a full flow-control window unblocks) before closing the client.
// This mirrors production: the agent's run ctx cancel on shutdown/reconnect is
// what tears down a stalled stream — Close alone cannot wake a flow-control
// wait.
func connectCancellable(t *testing.T, c *Client) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		done := make(chan struct{})
		go func() { _ = c.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			// Best-effort: the httptest server cleanup will finish teardown.
		}
	})
}

// bigTerminalOutput is intentionally far larger than the ~64 KiB HTTP/2
// flow-control window so a single Send to a non-draining peer blocks mid-write.
func bigTerminalOutput() *pm.TerminalOutput {
	return &pm.TerminalOutput{
		SessionId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Data:      make([]byte, 2<<20), // 2 MiB
	}
}

func TestSendTerminalOutput_HonorsContextDeadline_WhenPeerNotDraining(t *testing.T) {
	l := newStalledLoopback(t)
	c := l.newClient(WithAuth("device-x", "tok"))

	connectCancellable(t, c)

	// present-but-WRONG: an already-cancelled ctx must be refused up front,
	// before attempting the wedged send. Bounded so the buggy (ctx-ignoring)
	// path surfaces as a fast failure rather than a 10-minute hang.
	t.Run("already cancelled returns Canceled before sending", func(t *testing.T) {
		cctx, cancel := context.WithCancel(context.Background())
		cancel()
		done := make(chan error, 1)
		go func() { done <- c.SendTerminalOutput(cctx, bigTerminalOutput()) }()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("want context.Canceled, got %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("already-cancelled SendTerminalOutput blocked instead of refusing — finding #1 (ctx ignored)")
		}
	})

	// correct (the headline case): the call is itself the writer that wedges
	// on the full window; it must return its own deadline error within
	// roughly the timeout, not block forever.
	t.Run("deadline surfaces as DeadlineExceeded", func(t *testing.T) {
		done := make(chan error, 1)
		start := time.Now()
		go func() {
			sctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			done <- c.SendTerminalOutput(sctx, bigTerminalOutput())
		}()

		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("want context.DeadlineExceeded, got %v", err)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Errorf("send took %v, expected to abort near the 200ms deadline", elapsed)
			}
		case <-time.After(4 * time.Second):
			t.Fatal("SendTerminalOutput blocked far past its ctx deadline — finding #1 (ctx ignored / sendMu wedged)")
		}
	})
}

func TestSend_DoesNotSerializeAllTrafficBehindOneStalledSend(t *testing.T) {
	l := newStalledLoopback(t)
	c := l.newClient(WithAuth("device-x", "tok"))

	connectCancellable(t, c)

	// A long-lived blocker saturates the window and holds the send slot.
	blockerDone := make(chan struct{})
	go func() {
		defer close(blockerDone)
		// context.Background(): with the bug this blocks forever holding
		// sendMu; with the fix it holds the send slot until the stream is
		// torn down at Close, which is fine — the point is the victim below
		// must not inherit this wait.
		_ = c.SendTerminalOutput(context.Background(), bigTerminalOutput())
	}()

	// Give the blocker time to fill the window and claim the slot.
	time.Sleep(150 * time.Millisecond)

	// The victim is small but must still honor its own short deadline rather
	// than block behind the stalled blocker.
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		vctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		done <- c.SendHeartbeat(vctx, &pm.Heartbeat{})
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("want context.DeadlineExceeded for the queued victim, got %v", err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("victim send took %v, expected to abort near its 150ms deadline", elapsed)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("queued SendHeartbeat inherited the blocker's stall — finding #1 (one stalled send serializes all traffic)")
	}
}

func TestSendTerminalStateChange_HonorsContextDeadline(t *testing.T) {
	l := newStalledLoopback(t)
	c := l.newClient(WithAuth("device-x", "tok"))

	connectCancellable(t, c)

	// Saturate the window with a blocker so the state-change send is queued
	// behind a stall — the exact shape of the F053 EXITED path (terminal.go
	// passes a 5s ctx that was ignored).
	go func() { _ = c.SendTerminalOutput(context.Background(), bigTerminalOutput()) }()
	time.Sleep(150 * time.Millisecond)

	done := make(chan error, 1)
	go func() {
		sctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		done <- c.SendTerminalStateChange(sctx, &pm.TerminalStateChange{
			SessionId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
			State:     pm.TerminalSessionState_TERMINAL_SESSION_STATE_EXITED,
		})
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("want context.DeadlineExceeded, got %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("SendTerminalStateChange ignored its ctx deadline — finding #1 (F053 fix is cosmetic)")
	}
}

// TestSend_DrainingPeer_NoRegression proves the ctx plumbing does not break
// the normal path: against a draining server a Background-ctx send still
// succeeds (ABSENT deadline → nil).
func TestSend_DrainingPeer_NoRegression(t *testing.T) {
	l := newAgentLoopback(t) // default handler drains via Receive
	c := l.newClient(WithAuth("device-x", "tok"))

	connectCancellable(t, c)

	if err := c.SendHeartbeat(context.Background(), &pm.Heartbeat{}); err != nil {
		t.Fatalf("SendHeartbeat against a draining peer should succeed, got %v", err)
	}
}
