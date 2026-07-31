package sdk

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// noopStreamHandler satisfies StreamHandler; these cases never reach a handler
// callback, they only exercise the pending-delivery routing.
type noopStreamHandler struct{}

func (noopStreamHandler) OnWelcome(context.Context, *pm.Welcome) error { return nil }
func (noopStreamHandler) OnAction(context.Context, []byte, []byte) (*pm.ActionResult, error) {
	return nil, nil
}
func (noopStreamHandler) OnQuery(context.Context, *pm.OSQuery) (*pm.OSQueryResult, error) {
	return nil, nil
}
func (noopStreamHandler) OnError(context.Context, *pm.Error) error { return nil }

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// Every Client method that sends a stream request and then BLOCKS on a pending
// channel depends on dispatchServerMessage routing the matching ServerMessage
// back through deliverPending. Miss that wiring and the call does not fail — it
// hangs until the caller's context expires, which for a secret-rotation batch
// means the agent has already changed the password locally and the report is
// lost.
//
// Spec 41 shipped exactly that bug: StoreLpsPasswords was added as a pending
// waiter while dispatchServerMessage still delivered only the two LUKS
// responses, so every LPS batch would have timed out. There was no equivalent
// test for StoreLuksKey either, which is why nothing caught it.
//
// This is table-driven over the response types so a newly added waiter is one
// line away from being covered, and it asserts delivery rather than absence of
// error — a dropped frame is silent by design.
func TestDispatchServerMessage_DeliversEveryPendingResponse(t *testing.T) {
	cases := []struct {
		name    string
		payload func() *pm.ServerMessage
	}{
		{
			name: "StoreLuksKey",
			payload: func() *pm.ServerMessage {
				return &pm.ServerMessage{Payload: &pm.ServerMessage_StoreLuksKey{
					StoreLuksKey: &pm.StoreLuksKeyResponse{Success: true},
				}}
			},
		},
		{
			name: "GetLuksKey",
			payload: func() *pm.ServerMessage {
				return &pm.ServerMessage{Payload: &pm.ServerMessage_GetLuksKey{
					GetLuksKey: &pm.GetLuksKeyResponse{Passphrase: "p"},
				}}
			},
		},
		{
			name: "StoreLpsPasswords",
			payload: func() *pm.ServerMessage {
				return &pm.ServerMessage{Payload: &pm.ServerMessage_StoreLpsPasswords{
					StoreLpsPasswords: &pm.StoreLpsPasswordsResponse{Success: true},
				}}
			},
		},
	}

	if len(cases) == 0 {
		t.Fatal("matches-zero: no pending-response types under test")
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{logger: quietLogger()}
			id := NewULID()
			ch := c.registerPending(id)
			defer c.unregisterPending(id)

			msg := tc.payload()
			msg.Id = id

			if err := c.dispatchServerMessage(context.Background(), msg, noopStreamHandler{}); err != nil {
				t.Fatalf("dispatchServerMessage: %v", err)
			}

			select {
			case got := <-ch:
				if got.Id != id {
					t.Errorf("delivered message id = %q, want %q", got.Id, id)
				}
			case <-time.After(time.Second):
				t.Fatalf("%s response was never delivered to the waiting caller — "+
					"dispatchServerMessage drops it, so the sender blocks until its context expires",
					tc.name)
			}
		})
	}
}

// A correlated ERROR must reach the caller that is blocked on it.
//
// The server answers a rejected StoreLpsPasswords / StoreLuksKey / GetLuksKey
// with a ServerMessage_Error carrying the request's message ID, and the waiting
// method already knows how to read one — it returns "server error: …". It never
// received any: the Error case in the dispatch loop went straight to
// handler.OnError, so the waiter blocked until its context expired while the
// answer sat one branch away.
//
// The cost is not latency. These are the irreversible operations: the agent has
// already changed the local passwords, or added a LUKS slot, and is waiting to
// learn whether control accepted them before committing or rolling back. A
// rejection it never sees stalls the rollback for the whole timeout.
func TestDispatchServerMessage_DeliversCorrelatedErrorToTheWaiter(t *testing.T) {
	c := &Client{logger: quietLogger()}
	id := NewULID()
	ch := c.registerPending(id)
	defer c.unregisterPending(id)

	msg := &pm.ServerMessage{
		Id: id,
		Payload: &pm.ServerMessage_Error{
			Error: &pm.Error{Code: "internal", Message: "failed to store LPS passwords"},
		},
	}

	handler := &recordingErrHandler{}
	if err := c.dispatchServerMessage(context.Background(), msg, handler); err != nil {
		t.Fatalf("dispatchServerMessage: %v", err)
	}

	select {
	case got := <-ch:
		if got.GetError().GetMessage() != "failed to store LPS passwords" {
			t.Errorf("waiter got %+v, want the server's rejection", got)
		}
	default:
		t.Fatal("the correlated error never reached the waiter — the caller blocks until its context expires " +
			"while the server has already answered, stalling the rollback of an irreversible change")
	}

	if handler.calls != 0 {
		t.Errorf("a correlated error also went to OnError (%d calls) — it belongs to its waiter, not the general handler", handler.calls)
	}
}

// An UNcorrelated error — no waiter for that id — must still reach OnError.
func TestDispatchServerMessage_UncorrelatedErrorStillReachesTheHandler(t *testing.T) {
	c := &Client{logger: quietLogger()}
	handler := &recordingErrHandler{}

	msg := &pm.ServerMessage{
		Id: NewULID(), // nothing is waiting on this
		Payload: &pm.ServerMessage_Error{
			Error: &pm.Error{Code: "internal", Message: "server-originated"},
		},
	}
	if err := c.dispatchServerMessage(context.Background(), msg, handler); err != nil {
		t.Fatalf("dispatchServerMessage: %v", err)
	}
	if handler.calls != 1 {
		t.Errorf("OnError calls = %d, want 1 — an error with no waiter must not be swallowed", handler.calls)
	}
}

type recordingErrHandler struct {
	noopStreamHandler
	calls int
}

func (h *recordingErrHandler) OnError(context.Context, *pm.Error) error {
	h.calls++
	return nil
}
