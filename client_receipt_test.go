package sdk

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
)

// Target design §7.2: control acknowledges a delivery only after the agent
// confirms durable receipt, never after a successful socket write. The SDK's
// half of that is the ordering it enforces — the DeliveryReceipt frame goes out
// if and only if the handler reported the delivery committed.
//
// Both directions are asserted end-to-end over the real bidi stream, because
// the failure that matters is silent: a receipt emitted for a delivery the
// device never persisted looks exactly like success until the device reboots
// and the work is gone.

// receiptHandler records the deliveries it is given and reports whether it
// "committed" them. recordErr simulates a failed durable write.
type receiptHandler struct {
	noopStreamHandler
	recordErr error
	seen      atomic.Int32
}

func (h *receiptHandler) OnManifestDelivery(_ context.Context, d *pm.ManifestDelivery) error {
	h.seen.Add(1)
	_ = d
	return h.recordErr
}

// deliverOnce pushes one ManifestDelivery after the agent's Hello, then keeps
// the stream open and records everything the agent sends back.
func deliverOnce(l *agentLoopback, d *pm.ManifestDelivery) {
	l.handler.onStream = func(_ context.Context, s *connect.BidiStream[pm.AgentMessage, pm.ServerMessage]) error {
		if _, err := s.Receive(); err != nil { // Hello
			return err
		}
		if err := s.Send(&pm.ServerMessage{
			Id:      NewULID(),
			Payload: &pm.ServerMessage_ManifestDelivery{ManifestDelivery: d},
		}); err != nil {
			return err
		}
		for {
			msg, err := s.Receive()
			if err != nil {
				return nil
			}
			l.handler.mu.Lock()
			l.handler.received = append(l.handler.received, msg)
			l.handler.mu.Unlock()
		}
	}
}

// runAgainstLoopback drives Run until fn reports done or the deadline expires.
func runAgainstLoopback(t *testing.T, l *agentLoopback, h StreamHandler, done func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := l.newClient(WithAuth("01HKDEVICE0000000000000000", "tok"))
	finished := make(chan error, 1)
	go func() { finished <- c.Run(ctx, "host", "v1", time.Hour, h) }()

	deadline := time.Now().Add(3 * time.Second)
	for !done() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-finished:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("Run returned: %v (after cancel)", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

// receiptsFor returns the delivery ids the agent receipted.
func receiptsFor(l *agentLoopback) []string {
	var out []string
	for _, m := range l.handler.snapshot() {
		if r := m.GetDeliveryReceipt(); r != nil {
			out = append(out, r.GetDeliveryId())
		}
	}
	return out
}

func TestDelivery_ReceiptSentOnlyAfterHandlerRecordsIt(t *testing.T) {
	t.Run("recorded: receipt carries the same delivery_id", func(t *testing.T) {
		l := newAgentLoopback(t)
		d := newTestDelivery()
		deliverOnce(l, d)

		h := &receiptHandler{}
		runAgainstLoopback(t, l, h, func() bool { return len(receiptsFor(l)) > 0 })

		got := receiptsFor(l)
		if len(got) != 1 {
			t.Fatalf("receipts = %v, want exactly one for %s", got, d.DeliveryId)
		}
		if got[0] != d.DeliveryId {
			t.Errorf("receipt names delivery %q, want %q — control would acknowledge the wrong delivery",
				got[0], d.DeliveryId)
		}
	})

	t.Run("not recorded: no receipt is sent at all", func(t *testing.T) {
		l := newAgentLoopback(t)
		d := newTestDelivery()
		deliverOnce(l, d)

		// The handler ran and refused to commit. A receipt here would tell
		// control the device holds work it does not, and control would stop
		// retrying.
		h := &receiptHandler{recordErr: errors.New("durable write failed")}
		runAgainstLoopback(t, l, h, func() bool { return h.seen.Load() > 0 })

		if h.seen.Load() == 0 {
			t.Fatal("handler never ran — the assertion below would prove nothing")
		}
		if got := receiptsFor(l); len(got) != 0 {
			t.Errorf("receipt(s) %v sent for a delivery the handler did not record — "+
				"control would acknowledge work the device never persisted", got)
		}
	})
}
