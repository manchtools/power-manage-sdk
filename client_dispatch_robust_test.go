package sdk

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
)

// WS15 #2 — stream-dispatch robustness.
//
// The SDK Client drives the agent's long-lived bidi stream. Run() treats a
// non-nil return from dispatchServerMessage as FATAL and tears the connection
// down. The design intent of WS15:
//
//   - A panic inside ANY handler method (including the spawned goroutine
//     fan-out legs) must be caught and turned into a NON-fatal, logged drop —
//     one bad handler invocation must not crash-loop the whole agent (fleet
//     DoS). It must NOT propagate as the returned error.
//   - A malformed manifest-delivery oneof (nil inner message) on the wire must
//     be dropped, never dereferenced. Intent: "every delivery on the wire
//     carries a delivery_id ULID and a manifest"; one that doesn't is
//     malformed and is refused, not crashed on.
//   - The inbound ServerMessage size must be bounded so the client refuses an
//     over-large frame (resource-exhausted) rather than allocating it.

// ---------------------------------------------------------------------------
// #2 — handler panic recovery
// ---------------------------------------------------------------------------

// panicStreamingHandler is a StreamingHandler whose
// OnManifestDeliveryWithStreaming signals it actually ran (via `ran`) and then
// panics. The signal proves the recover happens AFTER the handler body
// executed, not because the handler was skipped — a case that passes by never
// reaching the handler proves nothing.
type panicStreamingHandler struct {
	ran           chan struct{}
	panicDelivery bool
	panicInv      bool
	panicRevoke   bool
	mu            sync.Mutex
	closed        bool
}

func (h *panicStreamingHandler) signalRan() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.closed {
		close(h.ran)
		h.closed = true
	}
}

func (h *panicStreamingHandler) OnWelcome(ctx context.Context, w *pm.Welcome) error { return nil }
func (h *panicStreamingHandler) OnManifestDelivery(ctx context.Context, d *pm.ManifestDelivery) error {
	return nil
}
func (h *panicStreamingHandler) OnQuery(ctx context.Context, q *pm.OSQuery) (*pm.OSQueryResult, error) {
	return nil, nil
}
func (h *panicStreamingHandler) OnError(ctx context.Context, e *pm.Error) error { return nil }

func (h *panicStreamingHandler) OnManifestDeliveryWithStreaming(ctx context.Context, d *pm.ManifestDelivery, sendChunk func(*pm.OutputChunk) error) error {
	if h.panicDelivery {
		h.signalRan()
		panic("boom: handler exploded mid-dispatch")
	}
	return nil
}

func (h *panicStreamingHandler) CollectInventory(ctx context.Context) *pm.DeviceInventory { return nil }
func (h *panicStreamingHandler) OnRequestInventory(ctx context.Context, req *pm.RequestInventory) *pm.DeviceInventory {
	if h.panicInv {
		h.signalRan()
		panic("boom: inventory handler exploded")
	}
	return nil
}
func (h *panicStreamingHandler) OnRevokeLuksDeviceKey(ctx context.Context, req *pm.RevokeLuksDeviceKey) (bool, string) {
	if h.panicRevoke {
		h.signalRan()
		panic("boom: revoke handler exploded")
	}
	return false, ""
}

// validDeliveryMessage builds a well-formed manifest-delivery ServerMessage.
// It must actually survive validateInbound: a builder that quietly produced an
// invalid frame would make every "the handler ran" assertion below vacuous.
func validDeliveryMessage(t *testing.T) *pm.ServerMessage {
	t.Helper()
	return &pm.ServerMessage{
		Id: NewULID(),
		Payload: &pm.ServerMessage_ManifestDelivery{
			ManifestDelivery: newTestDelivery(),
		},
	}
}

// newTestDelivery is the minimal delivery that passes inbound validation.
func newTestDelivery() *pm.ManifestDelivery {
	return &pm.ManifestDelivery{
		DeliveryId: NewULID(),
		Manifest: &pm.Manifest{
			ManifestId: NewULID(),
			Provenance: &pm.ManifestProvenance{ActionId: NewULID()},
			Schedule:   &pm.ActionSchedule{IntervalHours: 8},
			Occurrences: []*pm.ManifestOccurrence{{
				OccurrenceId: NewULID(),
				Action: &pm.Action{
					Id:   &pm.ActionId{Value: NewULID()},
					Type: pm.ActionType_ACTION_TYPE_SHELL,
				},
			}},
		},
	}
}

func TestDispatch_HandlerPanic_Recovered_LoopSurvives(t *testing.T) {
	t.Run("correct: handler returns normally, no recovery", func(t *testing.T) {
		c := NewClient("https://gw.invalid", WithAuth("01HZZZZZZZZZZZZZZZZZZZZZZZZ", ""))
		h := &panicStreamingHandler{ran: make(chan struct{})}
		// No stream is connected, so the receipt send fails; that is logged,
		// not returned, so the happy path is still a clean nil.
		if err := c.dispatchServerMessage(context.Background(), validDeliveryMessage(t), h); err != nil {
			t.Fatalf("normal dispatch returned error: %v", err)
		}
	})

	t.Run("the bug: handler panic must be caught and turned non-fatal", func(t *testing.T) {
		c := NewClient("https://gw.invalid", WithAuth("01HZZZZZZZZZZZZZZZZZZZZZZZZ", ""))
		h := &panicStreamingHandler{ran: make(chan struct{}), panicDelivery: true}

		// The panic must be recovered and dispatch must return nil (NON-fatal —
		// Run must keep the loop alive).
		err := c.dispatchServerMessage(context.Background(), validDeliveryMessage(t), h)
		if err != nil {
			t.Fatalf("recovered handler panic must be non-fatal (nil), got: %v", err)
		}
		// Prove the handler actually ran (so we recovered AFTER the body, not
		// because the handler was skipped).
		select {
		case <-h.ran:
		default:
			t.Fatal("handler never ran — recovery proved nothing")
		}
	})

	t.Run("fan-out leg: inventory goroutine panic must not crash the process", func(t *testing.T) {
		c := NewClient("https://gw.invalid", WithAuth("01HZZZZZZZZZZZZZZZZZZZZZZZZ", ""))
		h := &panicStreamingHandler{ran: make(chan struct{}), panicInv: true}
		msg := &pm.ServerMessage{
			Id: NewULID(),
			Payload: &pm.ServerMessage_RequestInventory{
				RequestInventory: &pm.RequestInventory{QueryId: "01HQ0000000000000000000000"},
			},
		}
		if err := c.dispatchServerMessage(context.Background(), msg, h); err != nil {
			t.Fatalf("dispatch returned error: %v", err)
		}
		// The handler runs in a spawned goroutine; wait for it to enter and
		// panic. A missing recover crashes the whole test binary (RED).
		select {
		case <-h.ran:
		case <-time.After(2 * time.Second):
			t.Fatal("inventory handler never ran")
		}
		// Give the recovered goroutine a moment to unwind cleanly.
		time.Sleep(50 * time.Millisecond)
	})

	t.Run("fan-out leg: luks-revoke goroutine panic must not crash the process", func(t *testing.T) {
		c := NewClient("https://gw.invalid", WithAuth("01HZZZZZZZZZZZZZZZZZZZZZZZZ", ""))
		h := &panicStreamingHandler{ran: make(chan struct{}), panicRevoke: true}
		msg := &pm.ServerMessage{
			Id: NewULID(),
			Payload: &pm.ServerMessage_RevokeLuksDeviceKey{
				RevokeLuksDeviceKey: &pm.RevokeLuksDeviceKey{ActionId: "01HQ0000000000000000000000"},
			},
		}
		if err := c.dispatchServerMessage(context.Background(), msg, h); err != nil {
			t.Fatalf("dispatch returned error: %v", err)
		}
		select {
		case <-h.ran:
		case <-time.After(2 * time.Second):
			t.Fatal("revoke handler never ran")
		}
		time.Sleep(50 * time.Millisecond)
	})
}

// ---------------------------------------------------------------------------
// #2 — malformed Action oneof (nil inner) must be dropped, never dereferenced
// ---------------------------------------------------------------------------

func TestDispatch_ManifestDelivery_Malformed_NoPanic(t *testing.T) {
	// panicDelivery:true makes every "handler must NOT have been invoked"
	// assertion BINDING: if a guard regressed and the handler were reached,
	// signalRan() closes h.ran (before the recovered panic), so the select
	// fires t.Fatal. Without the flag the handler returns silently and the
	// assertion could never catch a leak.
	t.Run("correct: well-formed delivery dispatches without error", func(t *testing.T) {
		c := NewClient("https://gw.invalid", WithAuth("01HZZZZZZZZZZZZZZZZZZZZZZZZ", ""))
		h := &panicStreamingHandler{ran: make(chan struct{})}
		if err := c.dispatchServerMessage(context.Background(), validDeliveryMessage(t), h); err != nil {
			t.Fatalf("well-formed delivery errored: %v", err)
		}
	})

	t.Run("absent: nil inner delivery must be dropped, not dereferenced", func(t *testing.T) {
		c := NewClient("https://gw.invalid", WithAuth("01HZZZZZZZZZZZZZZZZZZZZZZZZ", ""))
		h := &panicStreamingHandler{ran: make(chan struct{}), panicDelivery: true}
		msg := &pm.ServerMessage{
			Id:      NewULID(),
			Payload: &pm.ServerMessage_ManifestDelivery{ManifestDelivery: nil},
		}
		if err := c.dispatchServerMessage(context.Background(), msg, h); err != nil {
			t.Fatalf("nil delivery must be dropped non-fatally, got: %v", err)
		}
		select {
		case <-h.ran:
			t.Fatal("handler was invoked on a malformed (nil) delivery")
		default:
		}
	})

	t.Run("present-but-wrong: delivery with no delivery_id is refused", func(t *testing.T) {
		// Every delivery on the wire carries a delivery_id ULID; one that does
		// not cannot be receipted, so executing it would run work whose outcome
		// control can never match to an assignment. Dropped at the boundary.
		c := NewClient("https://gw.invalid", WithAuth("01HZZZZZZZZZZZZZZZZZZZZZZZZ", ""))
		h := &panicStreamingHandler{ran: make(chan struct{}), panicDelivery: true}
		d := newTestDelivery()
		d.DeliveryId = ""
		msg := &pm.ServerMessage{
			Id:      NewULID(),
			Payload: &pm.ServerMessage_ManifestDelivery{ManifestDelivery: d},
		}
		if err := c.dispatchServerMessage(context.Background(), msg, h); err != nil {
			t.Fatalf("delivery without a delivery_id must be non-fatal, got: %v", err)
		}
		select {
		case <-h.ran:
			t.Fatal("handler was invoked on a delivery with no delivery_id")
		default:
		}
	})
}

// ---------------------------------------------------------------------------
// inbound message-size bound
// ---------------------------------------------------------------------------

// TestRun_InboundMessageSizeBounded proves the client refuses an over-large
// inbound ServerMessage (resource-exhausted) instead of allocating it, and
// that a message within the limit still round-trips. Asserting BOTH sides
// (limit+1 fails AND a normal message succeeds) means the test cannot pass
// against an unbounded client OR a client whose limit is absurdly small.
func TestRun_InboundMessageSizeBounded(t *testing.T) {
	if maxInboundMessageBytes <= 0 {
		t.Fatalf("maxInboundMessageBytes = %d, want a positive bound", maxInboundMessageBytes)
	}

	t.Run("within limit: normal message round-trips", func(t *testing.T) {
		l := newAgentLoopback(t)
		welcomeOnce := func(ctx context.Context, s *connect.BidiStream[pm.AgentMessage, pm.ServerMessage]) error {
			if _, err := s.Receive(); err != nil {
				return err
			}
			if err := s.Send(&pm.ServerMessage{
				Id:      NewULID(),
				Payload: &pm.ServerMessage_Welcome{Welcome: &pm.Welcome{ServerVersion: "test"}},
			}); err != nil {
				return err
			}
			for {
				if _, err := s.Receive(); err != nil {
					return nil
				}
			}
		}
		l.handler.onStream = welcomeOnce

		c := l.newClient(WithAuth("device", "tok"))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.Connect(ctx); err != nil {
			t.Fatalf("Connect: %v", err)
		}
		defer c.Close()
		if err := c.SendHello(ctx, "h", "v"); err != nil {
			t.Fatalf("SendHello: %v", err)
		}
		msg, err := c.Receive(ctx)
		if err != nil {
			t.Fatalf("Receive within limit failed: %v", err)
		}
		if msg.GetWelcome() == nil {
			t.Fatalf("expected Welcome, got %T", msg.Payload)
		}
	})

	t.Run("over limit: oversized inbound frame is refused (resource exhausted)", func(t *testing.T) {
		l := newAgentLoopback(t)
		oversize := func(ctx context.Context, s *connect.BidiStream[pm.AgentMessage, pm.ServerMessage]) error {
			if _, err := s.Receive(); err != nil {
				return err
			}
			// A LogQueryResult whose Logs field exceeds the inbound bound by a
			// comfortable margin. The wire frame is therefore > maxInboundMessageBytes.
			big := make([]byte, maxInboundMessageBytes+(1<<20))
			for i := range big {
				big[i] = 'a'
			}
			_ = s.Send(&pm.ServerMessage{
				Id: NewULID(),
				Payload: &pm.ServerMessage_Error{
					Error: &pm.Error{Code: "x", Message: string(big)},
				},
			})
			for {
				if _, err := s.Receive(); err != nil {
					return nil
				}
			}
		}
		l.handler.onStream = oversize

		c := l.newClient(WithAuth("device", "tok"))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.Connect(ctx); err != nil {
			t.Fatalf("Connect: %v", err)
		}
		defer c.Close()
		if err := c.SendHello(ctx, "h", "v"); err != nil {
			t.Fatalf("SendHello: %v", err)
		}
		_, err := c.Receive(ctx)
		if err == nil {
			t.Fatal("oversized inbound frame was accepted; expected a resource-exhausted error")
		}
		var connectErr *connect.Error
		if !errors.As(err, &connectErr) {
			t.Fatalf("want a *connect.Error for the oversized frame, got %T: %v", err, err)
		}
		if connectErr.Code() != connect.CodeResourceExhausted {
			t.Fatalf("oversized frame code = %v, want %v", connectErr.Code(), connect.CodeResourceExhausted)
		}
	})
}
