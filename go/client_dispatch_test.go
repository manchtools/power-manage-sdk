package sdk

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// WS6 #11: dispatchServerMessage spawned an UNBOUNDED goroutine for every
// RequestInventory and every RevokeLuksDeviceKey. A compromised or buggy
// gateway could flood the agent with these and exhaust memory/goroutines
// (each inventory collection forks osquery). The fix bounds in-flight
// handlers with a small semaphore and DROPS overflow rather than queuing
// it unboundedly.
//
// These tests pin: at most `cap` handlers run concurrently, and the
// EXCESS is dropped (not run later) — fire N >> cap and exactly `cap`
// ever enter the handler.

// blockingFanoutHandler implements StreamHandler + InventoryHandler +
// LuksHandler. The fan-out handlers block on `release` so the test can
// observe peak concurrency before letting them finish.
type blockingFanoutHandler struct {
	release  chan struct{}
	inFlight int32
	maxSeen  int32
	entered  int32
}

func (h *blockingFanoutHandler) enter() {
	cur := atomic.AddInt32(&h.inFlight, 1)
	atomic.AddInt32(&h.entered, 1)
	for {
		old := atomic.LoadInt32(&h.maxSeen)
		if cur <= old || atomic.CompareAndSwapInt32(&h.maxSeen, old, cur) {
			break
		}
	}
	<-h.release
	atomic.AddInt32(&h.inFlight, -1)
}

func (h *blockingFanoutHandler) OnWelcome(ctx context.Context, w *pm.Welcome) error { return nil }
func (h *blockingFanoutHandler) OnAction(ctx context.Context, envelope, signature []byte) (*pm.ActionResult, error) {
	return nil, nil
}
func (h *blockingFanoutHandler) OnQuery(ctx context.Context, q *pm.OSQuery) (*pm.OSQueryResult, error) {
	return nil, nil
}
func (h *blockingFanoutHandler) OnError(ctx context.Context, e *pm.Error) error { return nil }

func (h *blockingFanoutHandler) CollectInventory(ctx context.Context) *pm.DeviceInventory {
	return nil // agent-initiated path; unused by these dispatch tests
}

func (h *blockingFanoutHandler) OnRequestInventory(ctx context.Context, req *pm.RequestInventory) *pm.DeviceInventory {
	h.enter()
	return nil // nil → dispatch skips SendInventory (no stream in test)
}

func (h *blockingFanoutHandler) OnRevokeLuksDeviceKey(ctx context.Context, req *pm.RevokeLuksDeviceKey) (bool, string) {
	h.enter()
	return false, "blocked"
}

func waitForCond(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("condition not met within deadline")
}

func TestDispatchServerMessage_InventoryConcurrencyBounded(t *testing.T) {
	c := NewClient("https://gw.invalid", WithAuth("01HZZZZZZZZZZZZZZZZZZZZZZZZ", ""))
	h := &blockingFanoutHandler{release: make(chan struct{})}

	const fired = 50
	for i := 0; i < fired; i++ {
		msg := &pm.ServerMessage{
			Id: "m",
			Payload: &pm.ServerMessage_RequestInventory{
				RequestInventory: &pm.RequestInventory{QueryId: "01HQ0000000000000000000000"},
			},
		}
		if err := c.dispatchServerMessage(context.Background(), msg, h); err != nil {
			t.Fatalf("dispatch: %v", err)
		}
	}

	cap := inventoryDispatchConcurrency
	if cap < 1 {
		t.Fatalf("inventoryDispatchConcurrency = %d, want >= 1", cap)
	}
	// Wait until the bounded set of handlers has entered, then settle so
	// any (erroneously) unbounded extra goroutines would also enter and
	// inflate maxSeen/entered before we assert.
	waitForCond(t, func() bool { return atomic.LoadInt32(&h.entered) >= int32(cap) })
	time.Sleep(100 * time.Millisecond)

	if got := atomic.LoadInt32(&h.maxSeen); got != int32(cap) {
		t.Errorf("peak concurrent inventory handlers = %d, want %d", got, cap)
	}
	if got := atomic.LoadInt32(&h.entered); got != int32(cap) {
		t.Errorf("total inventory handlers entered = %d, want %d (excess of %d must be dropped)", got, cap, fired-cap)
	}

	close(h.release)
	waitForCond(t, func() bool { return atomic.LoadInt32(&h.inFlight) == 0 })
}

func TestDispatchServerMessage_LuksRevokeConcurrencyBounded(t *testing.T) {
	c := NewClient("https://gw.invalid", WithAuth("01HZZZZZZZZZZZZZZZZZZZZZZZZ", ""))
	h := &blockingFanoutHandler{release: make(chan struct{})}

	const fired = 50
	for i := 0; i < fired; i++ {
		msg := &pm.ServerMessage{
			Id: "m",
			Payload: &pm.ServerMessage_RevokeLuksDeviceKey{
				RevokeLuksDeviceKey: &pm.RevokeLuksDeviceKey{ActionId: "01HQ0000000000000000000000"},
			},
		}
		if err := c.dispatchServerMessage(context.Background(), msg, h); err != nil {
			t.Fatalf("dispatch: %v", err)
		}
	}

	cap := luksRevokeDispatchConcurrency
	if cap < 1 {
		t.Fatalf("luksRevokeDispatchConcurrency = %d, want >= 1", cap)
	}
	waitForCond(t, func() bool { return atomic.LoadInt32(&h.entered) >= int32(cap) })
	time.Sleep(100 * time.Millisecond)

	if got := atomic.LoadInt32(&h.maxSeen); got != int32(cap) {
		t.Errorf("peak concurrent luks-revoke handlers = %d, want %d", got, cap)
	}
	if got := atomic.LoadInt32(&h.entered); got != int32(cap) {
		t.Errorf("total luks-revoke handlers entered = %d, want %d (excess dropped)", got, cap)
	}

	close(h.release)
	waitForCond(t, func() bool { return atomic.LoadInt32(&h.inFlight) == 0 })
}
