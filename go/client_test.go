package sdk

import (
	"context"
	"errors"
	"strings"
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

// makeTerminalMsg builds a ServerMessage carrying one of the four
// Terminal* payload variants. Used by both routing and error tests.
func makeTerminalMsg(name string) *pm.ServerMessage {
	msg := &pm.ServerMessage{Id: NewULID()}
	switch name {
	case "TerminalStart":
		msg.Payload = &pm.ServerMessage_TerminalStart{
			TerminalStart: &pm.TerminalStart{
				SessionId: "01ABCDEF",
				TtyUser:   "pm-tty-test",
				Cols:      80,
				Rows:      24,
			},
		}
	case "TerminalInput":
		msg.Payload = &pm.ServerMessage_TerminalInput{
			TerminalInput: &pm.TerminalInput{
				SessionId: "01ABCDEF",
				Data:      []byte("ls -la\n"),
			},
		}
	case "TerminalResize":
		msg.Payload = &pm.ServerMessage_TerminalResize{
			TerminalResize: &pm.TerminalResize{
				SessionId: "01ABCDEF",
				Cols:      120,
				Rows:      40,
			},
		}
	case "TerminalStop":
		msg.Payload = &pm.ServerMessage_TerminalStop{
			TerminalStop: &pm.TerminalStop{
				SessionId: "01ABCDEF",
				Reason:    "admin terminate",
			},
		}
	}
	return msg
}

// TestDispatch_Terminal_Routing is the table-driven covering test for
// the four Terminal* dispatch cases. Each row picks a payload, dispatches
// it through dispatchServerMessage, then runs case-specific assertions
// against the fake handler's recorded calls. Keeps the per-case error
// messages identical to the previous one-test-per-case shape so test
// failures stay readable.
func TestDispatch_Terminal_Routing(t *testing.T) {
	cases := []struct {
		name   string
		assert func(t *testing.T, h *fakeTerminalHandler)
	}{
		{
			name: "TerminalStart",
			assert: func(t *testing.T, h *fakeTerminalHandler) {
				t.Helper()
				if len(h.startCalls) != 1 {
					t.Fatalf("OnTerminalStart calls = %d, want 1", len(h.startCalls))
				}
				if h.startCalls[0].SessionId != "01ABCDEF" {
					t.Errorf("session_id = %q, want 01ABCDEF", h.startCalls[0].SessionId)
				}
				if h.startCalls[0].TtyUser != "pm-tty-test" {
					t.Errorf("tty_user = %q, want pm-tty-test", h.startCalls[0].TtyUser)
				}
			},
		},
		{
			name: "TerminalInput",
			assert: func(t *testing.T, h *fakeTerminalHandler) {
				t.Helper()
				if len(h.inputCalls) != 1 {
					t.Fatalf("OnTerminalInput calls = %d, want 1", len(h.inputCalls))
				}
				if string(h.inputCalls[0].Data) != "ls -la\n" {
					t.Errorf("data = %q, want %q", h.inputCalls[0].Data, "ls -la\n")
				}
			},
		},
		{
			name: "TerminalResize",
			assert: func(t *testing.T, h *fakeTerminalHandler) {
				t.Helper()
				if len(h.resizeCalls) != 1 {
					t.Fatalf("OnTerminalResize calls = %d, want 1", len(h.resizeCalls))
				}
				if h.resizeCalls[0].Cols != 120 || h.resizeCalls[0].Rows != 40 {
					t.Errorf("size = %dx%d, want 120x40", h.resizeCalls[0].Cols, h.resizeCalls[0].Rows)
				}
			},
		},
		{
			name: "TerminalStop",
			assert: func(t *testing.T, h *fakeTerminalHandler) {
				t.Helper()
				if len(h.stopCalls) != 1 {
					t.Fatalf("OnTerminalStop calls = %d, want 1", len(h.stopCalls))
				}
				if h.stopCalls[0].Reason != "admin terminate" {
					t.Errorf("reason = %q, want admin terminate", h.stopCalls[0].Reason)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient()
			h := &fakeTerminalHandler{}
			if err := c.dispatchServerMessage(context.Background(), makeTerminalMsg(tc.name), h); err != nil {
				t.Fatalf("dispatch: %v", err)
			}
			tc.assert(t, h)
		})
	}
}

// Handler errors must propagate from dispatchServerMessage so the
// stream can be torn down. The wrapper text must mention the message
// kind so operators can spot the failing path in logs — without that,
// every terminal failure looks identical in the error tail.
//
// Asserted for all four Terminal* methods so the wrapper contract is
// enforced uniformly, not just for Start.
func TestDispatch_Terminal_HandlerErrorPropagates(t *testing.T) {
	cases := []struct {
		name    string
		setErr  func(h *fakeTerminalHandler, want error)
		wantSub string // substring expected in err.Error()
	}{
		{
			name:    "TerminalStart",
			setErr:  func(h *fakeTerminalHandler, want error) { h.startErr = want },
			wantSub: "handle terminal start",
		},
		{
			name:    "TerminalInput",
			setErr:  func(h *fakeTerminalHandler, want error) { h.inputErr = want },
			wantSub: "handle terminal input",
		},
		{
			name:    "TerminalResize",
			setErr:  func(h *fakeTerminalHandler, want error) { h.resizeErr = want },
			wantSub: "handle terminal resize",
		},
		{
			name:    "TerminalStop",
			setErr:  func(h *fakeTerminalHandler, want error) { h.stopErr = want },
			wantSub: "handle terminal stop",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient()
			want := errors.New("handler refused")
			h := &fakeTerminalHandler{}
			tc.setErr(h, want)

			err := c.dispatchServerMessage(context.Background(), makeTerminalMsg(tc.name), h)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, want) {
				t.Errorf("expected errors.Is(err, want) = true, got err = %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("err.Error() = %q, want substring %q", err.Error(), tc.wantSub)
			}
		})
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
