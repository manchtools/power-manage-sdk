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
