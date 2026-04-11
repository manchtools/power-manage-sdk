package sdk

import (
	"context"
	"errors"
	"testing"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// fakeTerminalHandler is a minimal StreamHandler+TerminalHandler that
// records every call so dispatch tests can assert against it.
type fakeTerminalHandler struct {
	startCalls  []*pm.TerminalStart
	inputCalls  []*pm.TerminalInput
	resizeCalls []*pm.TerminalResize
	stopCalls   []*pm.TerminalStop

	// Per-method error overrides for failure-path tests.
	startErr  error
	inputErr  error
	resizeErr error
	stopErr   error
}

// StreamHandler bits — we don't care about them in dispatch tests, so
// they're stubs that record nothing and return nil.
func (h *fakeTerminalHandler) OnWelcome(ctx context.Context, w *pm.Welcome) error {
	return nil
}
func (h *fakeTerminalHandler) OnAction(ctx context.Context, a *pm.Action) (*pm.ActionResult, error) {
	return nil, nil
}
func (h *fakeTerminalHandler) OnQuery(ctx context.Context, q *pm.OSQuery) (*pm.OSQueryResult, error) {
	return nil, nil
}
func (h *fakeTerminalHandler) OnError(ctx context.Context, e *pm.Error) error { return nil }

func (h *fakeTerminalHandler) OnTerminalStart(ctx context.Context, req *pm.TerminalStart) error {
	h.startCalls = append(h.startCalls, req)
	return h.startErr
}
func (h *fakeTerminalHandler) OnTerminalInput(ctx context.Context, req *pm.TerminalInput) error {
	h.inputCalls = append(h.inputCalls, req)
	return h.inputErr
}
func (h *fakeTerminalHandler) OnTerminalResize(ctx context.Context, req *pm.TerminalResize) error {
	h.resizeCalls = append(h.resizeCalls, req)
	return h.resizeErr
}
func (h *fakeTerminalHandler) OnTerminalStop(ctx context.Context, req *pm.TerminalStop) error {
	h.stopCalls = append(h.stopCalls, req)
	return h.stopErr
}

// fakeBareHandler implements StreamHandler but NOT TerminalHandler.
// Used to verify that dispatching a Terminal* message at a handler
// without terminal support is silently dropped (no error).
type fakeBareHandler struct{}

func (fakeBareHandler) OnWelcome(ctx context.Context, w *pm.Welcome) error { return nil }
func (fakeBareHandler) OnAction(ctx context.Context, a *pm.Action) (*pm.ActionResult, error) {
	return nil, nil
}
func (fakeBareHandler) OnQuery(ctx context.Context, q *pm.OSQuery) (*pm.OSQueryResult, error) {
	return nil, nil
}
func (fakeBareHandler) OnError(ctx context.Context, e *pm.Error) error { return nil }

// newTestClient builds a Client that can run dispatchServerMessage but
// is not actually connected to any server. The dispatch tests never
// touch the underlying stream, so the missing transport is fine.
func newTestClient() *Client {
	return NewClient("http://localhost:0")
}

func TestDispatch_TerminalStart_RoutesToHandler(t *testing.T) {
	c := newTestClient()
	h := &fakeTerminalHandler{}
	msg := &pm.ServerMessage{
		Id: NewULID(),
		Payload: &pm.ServerMessage_TerminalStart{
			TerminalStart: &pm.TerminalStart{
				SessionId: "01ABCDEF",
				TtyUser:   "pm-tty-test",
				Cols:      80,
				Rows:      24,
			},
		},
	}
	if err := c.dispatchServerMessage(context.Background(), msg, h); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if len(h.startCalls) != 1 {
		t.Fatalf("OnTerminalStart calls = %d, want 1", len(h.startCalls))
	}
	if h.startCalls[0].SessionId != "01ABCDEF" {
		t.Errorf("session_id = %q, want 01ABCDEF", h.startCalls[0].SessionId)
	}
	if h.startCalls[0].TtyUser != "pm-tty-test" {
		t.Errorf("tty_user = %q, want pm-tty-test", h.startCalls[0].TtyUser)
	}
}

func TestDispatch_TerminalInput_RoutesToHandler(t *testing.T) {
	c := newTestClient()
	h := &fakeTerminalHandler{}
	msg := &pm.ServerMessage{
		Id: NewULID(),
		Payload: &pm.ServerMessage_TerminalInput{
			TerminalInput: &pm.TerminalInput{
				SessionId: "01ABCDEF",
				Data:      []byte("ls -la\n"),
			},
		},
	}
	if err := c.dispatchServerMessage(context.Background(), msg, h); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if len(h.inputCalls) != 1 {
		t.Fatalf("OnTerminalInput calls = %d, want 1", len(h.inputCalls))
	}
	if string(h.inputCalls[0].Data) != "ls -la\n" {
		t.Errorf("data = %q, want %q", h.inputCalls[0].Data, "ls -la\n")
	}
}

func TestDispatch_TerminalResize_RoutesToHandler(t *testing.T) {
	c := newTestClient()
	h := &fakeTerminalHandler{}
	msg := &pm.ServerMessage{
		Id: NewULID(),
		Payload: &pm.ServerMessage_TerminalResize{
			TerminalResize: &pm.TerminalResize{
				SessionId: "01ABCDEF",
				Cols:      120,
				Rows:      40,
			},
		},
	}
	if err := c.dispatchServerMessage(context.Background(), msg, h); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if len(h.resizeCalls) != 1 {
		t.Fatalf("OnTerminalResize calls = %d, want 1", len(h.resizeCalls))
	}
	if h.resizeCalls[0].Cols != 120 || h.resizeCalls[0].Rows != 40 {
		t.Errorf("size = %dx%d, want 120x40", h.resizeCalls[0].Cols, h.resizeCalls[0].Rows)
	}
}

func TestDispatch_TerminalStop_RoutesToHandler(t *testing.T) {
	c := newTestClient()
	h := &fakeTerminalHandler{}
	msg := &pm.ServerMessage{
		Id: NewULID(),
		Payload: &pm.ServerMessage_TerminalStop{
			TerminalStop: &pm.TerminalStop{
				SessionId: "01ABCDEF",
				Reason:    "admin terminate",
			},
		},
	}
	if err := c.dispatchServerMessage(context.Background(), msg, h); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if len(h.stopCalls) != 1 {
		t.Fatalf("OnTerminalStop calls = %d, want 1", len(h.stopCalls))
	}
	if h.stopCalls[0].Reason != "admin terminate" {
		t.Errorf("reason = %q, want admin terminate", h.stopCalls[0].Reason)
	}
}

// Handler errors must propagate from dispatchServerMessage so the
// stream can be torn down. The error message must mention the message
// kind so operators can spot the failing path in logs.
func TestDispatch_TerminalStart_HandlerErrorPropagates(t *testing.T) {
	c := newTestClient()
	want := errors.New("pty alloc denied")
	h := &fakeTerminalHandler{startErr: want}
	msg := &pm.ServerMessage{
		Id: NewULID(),
		Payload: &pm.ServerMessage_TerminalStart{
			TerminalStart: &pm.TerminalStart{SessionId: "01ABCDEF", TtyUser: "pm-tty-x"},
		},
	}
	err := c.dispatchServerMessage(context.Background(), msg, h)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, want) {
		t.Errorf("expected errors.Is(err, want) = true, got err = %v", err)
	}
}

// A handler that does NOT implement TerminalHandler must silently
// drop terminal messages — no error, no panic. Critical for the
// transition window where the proto has shipped but agents haven't
// implemented terminal support yet.
func TestDispatch_Terminal_NoHandler_DropsSilently(t *testing.T) {
	c := newTestClient()
	bare := fakeBareHandler{}

	cases := []*pm.ServerMessage{
		{Id: NewULID(), Payload: &pm.ServerMessage_TerminalStart{TerminalStart: &pm.TerminalStart{SessionId: "01"}}},
		{Id: NewULID(), Payload: &pm.ServerMessage_TerminalInput{TerminalInput: &pm.TerminalInput{SessionId: "01"}}},
		{Id: NewULID(), Payload: &pm.ServerMessage_TerminalResize{TerminalResize: &pm.TerminalResize{SessionId: "01"}}},
		{Id: NewULID(), Payload: &pm.ServerMessage_TerminalStop{TerminalStop: &pm.TerminalStop{SessionId: "01"}}},
	}
	for _, msg := range cases {
		if err := c.dispatchServerMessage(context.Background(), msg, bare); err != nil {
			t.Errorf("dispatch %T: unexpected error: %v", msg.Payload, err)
		}
	}
}

// An unknown / unrecognized ServerMessage payload (e.g. a future
// variant from a newer server build) must NOT tear down the
// connection. Returning an error from dispatchServerMessage causes
// Run to terminate the stream, which is the wrong behaviour for an
// unknown frame — silently drop it instead.
//
// We synthesize "unknown" by passing a ServerMessage with a nil
// payload, which the type switch hits as the default case.
func TestDispatch_UnknownPayload_DropsSilently(t *testing.T) {
	c := newTestClient()
	h := &fakeTerminalHandler{}

	msg := &pm.ServerMessage{Id: NewULID()}
	if err := c.dispatchServerMessage(context.Background(), msg, h); err != nil {
		t.Errorf("dispatch unknown payload: unexpected error: %v", err)
	}
	// And no handler method should have been touched.
	if len(h.startCalls)+len(h.inputCalls)+len(h.resizeCalls)+len(h.stopCalls) != 0 {
		t.Errorf("unknown payload should not invoke any handler method")
	}
}

// TerminalHandler is a strict superset of StreamHandler — verify the
// interface assertion at compile time so a future change that breaks
// it shows up at build time, not at runtime.
var _ TerminalHandler = (*fakeTerminalHandler)(nil)
var _ StreamHandler = fakeBareHandler{}
