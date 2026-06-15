package sdk

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

const testULID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

// recordingTransport records CloseIdleConnections calls so the #8 seam can be
// verified without a real network.
type recordingTransport struct{ closeCalls int }

func (r *recordingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("recordingTransport: no real requests")
}
func (r *recordingTransport) CloseIdleConnections() { r.closeCalls++ }

// TestClient_CloseIdleConnections pins WS13 #8: CloseIdleConnections releases the
// transport's idle connections (so a reconnect loop doesn't leak transports) and
// is nil-safe.
func TestClient_CloseIdleConnections(t *testing.T) {
	rt := &recordingTransport{}
	c := NewClient("https://gw.example", WithHTTPClient(&http.Client{Transport: rt}))

	c.CloseIdleConnections()
	require.Equal(t, 1, rt.closeCalls, "CloseIdleConnections must release the underlying transport's idle connections")

	var nilClient *Client
	require.NotPanics(t, func() { nilClient.CloseIdleConnections() }, "must be nil-safe")
}

// offLoopHandler is a StreamingHandler whose action blocks until released, plus a
// TerminalHandler (via the embedded fake) so the off-loop test can prove a
// TerminalStop is handled while an action is still in-flight.
type offLoopHandler struct {
	*fakeTerminalHandler
	started chan struct{}
	release chan struct{}
}

func (h *offLoopHandler) OnActionWithStreaming(ctx context.Context, envelope, signature []byte, sendChunk func(*pm.OutputChunk) error) (*pm.ActionResult, error) {
	close(h.started)
	<-h.release
	return &pm.ActionResult{}, nil
}

// TestDispatch_ActionRunsOffLoop_DoesNotBlockTerminal pins WS13 #7: a
// long-running action is executed off the receive loop, so a TerminalStop
// dispatched while it is in-flight is still handled promptly (no head-of-line
// block). Against the old inline dispatch this would hang.
func TestDispatch_ActionRunsOffLoop_DoesNotBlockTerminal(t *testing.T) {
	c := newTestClient()

	// Stand up the per-Run action worker the way Run() does.
	actionCh := make(chan *pm.ActionDispatch, actionQueueDepth)
	c.mu.Lock()
	c.actionCh = actionCh
	c.mu.Unlock()
	h := &offLoopHandler{
		fakeTerminalHandler: &fakeTerminalHandler{},
		started:             make(chan struct{}),
		release:             make(chan struct{}),
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for d := range actionCh {
			c.runDispatchedAction(context.Background(), d, h)
		}
	}()
	// Cleanup closes h.release here (not at the end) so an early assertion
	// failure can't leave the worker blocked in OnActionWithStreaming and hang
	// wg.Wait(). Closed exactly once, on every exit path. Order matters: unblock
	// the action, then end the channel range, then wait.
	defer func() { close(h.release); close(actionCh); wg.Wait() }()

	// Dispatch a long-running action — returns immediately (enqueued off-loop).
	actionMsg := &pm.ServerMessage{Id: NewULID(), Payload: &pm.ServerMessage_Action{
		Action: &pm.ActionDispatch{Envelope: []byte{0x01}, Signature: []byte{0x01}},
	}}
	require.NoError(t, c.dispatchServerMessage(context.Background(), actionMsg, h))

	select {
	case <-h.started:
	case <-time.After(2 * time.Second):
		t.Fatal("action never started on the worker")
	}

	// While the action is blocked, a TerminalStop must still be handled.
	stopMsg := &pm.ServerMessage{Id: NewULID(), Payload: &pm.ServerMessage_TerminalStop{
		TerminalStop: &pm.TerminalStop{SessionId: testULID, Reason: "stop"},
	}}
	require.NoError(t, c.dispatchServerMessage(context.Background(), stopMsg, h))
	require.Len(t, h.stopCalls, 1, "TerminalStop must be handled while a long action is still in-flight (off-loop)")
	// h.release is closed by the deferred cleanup above (safe on any exit path).
}

// TestDispatch_DropsInvalidInbound pins WS13 #5: a command frame that violates
// the inbound `validate` gotags (out-of-range PTY dims, non-ULID session id) is
// dropped before the handler; a conformant frame reaches it.
func TestDispatch_DropsInvalidInbound(t *testing.T) {
	ctx := context.Background()
	start := func(sid, tty string, cols, rows uint32) *pm.ServerMessage {
		return &pm.ServerMessage{Id: NewULID(), Payload: &pm.ServerMessage_TerminalStart{
			TerminalStart: &pm.TerminalStart{SessionId: sid, TtyUser: tty, Cols: cols, Rows: rows},
		}}
	}

	t.Run("cols=0 dropped (gt=0)", func(t *testing.T) {
		c := newTestClient()
		h := &fakeTerminalHandler{}
		require.NoError(t, c.dispatchServerMessage(ctx, start(testULID, "pm-tty-x", 0, 24), h))
		require.Empty(t, h.startCalls, "a TerminalStart with cols=0 must be dropped by inbound validation")
	})

	t.Run("non-ULID session id dropped", func(t *testing.T) {
		c := newTestClient()
		h := &fakeTerminalHandler{}
		require.NoError(t, c.dispatchServerMessage(ctx, start("not-a-ulid", "pm-tty-x", 80, 24), h))
		require.Empty(t, h.startCalls, "a TerminalStart with a non-ULID session id must be dropped")
	})

	t.Run("conformant frame reaches the handler", func(t *testing.T) {
		c := newTestClient()
		h := &fakeTerminalHandler{}
		require.NoError(t, c.dispatchServerMessage(ctx, start(testULID, "pm-tty-x", 80, 24), h))
		require.Len(t, h.startCalls, 1, "a valid TerminalStart must reach the handler")
	})
}
