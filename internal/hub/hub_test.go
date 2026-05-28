package hub

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/bastion/tracker/internal/models"
)

// helper: receive from a channel within a timeout, fail if nothing arrives.
func mustReceive(t *testing.T, ch <-chan []byte, timeout time.Duration) []byte {
	t.Helper()
	select {
	case msg := <-ch:
		return msg
	case <-time.After(timeout):
		t.Fatal("timed out waiting for message")
		return nil
	}
}

// helper: assert no message arrives within a duration.
func mustNotReceive(t *testing.T, ch <-chan []byte, window time.Duration) {
	t.Helper()
	select {
	case msg := <-ch:
		t.Fatalf("unexpected message received: %s", msg)
	case <-time.After(window):
	}
}

func newTestHub() *Hub {
	return New(64)
}

func wsMsg(msgType string, payload interface{}) models.WSMessage {
	var data json.RawMessage
	if payload != nil {
		b, _ := json.Marshal(payload)
		data = b
	}
	return models.WSMessage{Type: msgType, Payload: data}
}

// ─── New ─────────────────────────────────────────────────────────────────────

func TestNew_DefaultBufferSize(t *testing.T) {
	h := New(0) // 0 → uses default 256
	if h == nil {
		t.Fatal("expected non-nil Hub")
	}
	if h.bufferSize != 256 {
		t.Errorf("expected bufferSize=256, got %d", h.bufferSize)
	}
}

func TestNew_CustomBufferSize(t *testing.T) {
	h := New(128)
	if h.bufferSize != 128 {
		t.Errorf("expected bufferSize=128, got %d", h.bufferSize)
	}
}

func TestConnectionCount_StartsZero(t *testing.T) {
	h := newTestHub()
	if got := h.ConnectionCount(); got != 0 {
		t.Fatalf("expected 0 connections, got %d", got)
	}
}

// ─── Subscribe / Unsubscribe / Broadcast ─────────────────────────────────────

func TestBroadcast_NoSubscribers(t *testing.T) {
	h := newTestHub()
	// Should not panic or block with no subscribers.
	h.Broadcast(wsMsg("event", map[string]string{"test": "no-subs"}))
}

func TestSubscribe_ReceivesBroadcast(t *testing.T) {
	h := newTestHub()
	sub := h.Subscribe(8)

	h.Broadcast(wsMsg("event", map[string]string{"hello": "world"}))

	msg := mustReceive(t, sub.C(), 200*time.Millisecond)
	if len(msg) == 0 {
		t.Fatal("expected non-empty message")
	}
}

func TestSubscribe_MessageIsValidJSON(t *testing.T) {
	h := newTestHub()
	sub := h.Subscribe(8)

	h.Broadcast(wsMsg("event", map[string]string{"key": "val"}))

	msg := mustReceive(t, sub.C(), 200*time.Millisecond)
	var parsed map[string]interface{}
	if err := json.Unmarshal(msg, &parsed); err != nil {
		t.Fatalf("broadcast message is not valid JSON: %v", err)
	}
}

func TestSubscribe_MessageTypePreserved(t *testing.T) {
	h := newTestHub()
	sub := h.Subscribe(8)

	h.Broadcast(wsMsg("incident", nil))

	msg := mustReceive(t, sub.C(), 200*time.Millisecond)
	var parsed map[string]interface{}
	json.Unmarshal(msg, &parsed)
	if parsed["type"] != "incident" {
		t.Errorf("expected type=incident, got %v", parsed["type"])
	}
}

func TestMultipleSubscribers_AllReceive(t *testing.T) {
	h := newTestHub()
	sub1 := h.Subscribe(8)
	sub2 := h.Subscribe(8)
	sub3 := h.Subscribe(8)

	h.Broadcast(wsMsg("event", map[string]string{"x": "1"}))

	mustReceive(t, sub1.C(), 200*time.Millisecond)
	mustReceive(t, sub2.C(), 200*time.Millisecond)
	mustReceive(t, sub3.C(), 200*time.Millisecond)
}

func TestUnsubscribe_ChannelClosed(t *testing.T) {
	h := newTestHub()
	sub := h.Subscribe(8)
	h.Unsubscribe(sub)

	// Channel should be closed — reading from it returns immediately.
	select {
	case _, ok := <-sub.C():
		if ok {
			t.Fatal("expected channel to be closed (zero value, ok=false)")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("channel was not closed after Unsubscribe")
	}
}

func TestUnsubscribe_NoLongerReceivesBroadcast(t *testing.T) {
	h := newTestHub()
	sub1 := h.Subscribe(8)
	sub2 := h.Subscribe(8)

	h.Unsubscribe(sub1)

	// Give hub goroutine time to process unregister.
	time.Sleep(10 * time.Millisecond)

	h.Broadcast(wsMsg("event", nil))

	// sub2 should receive; sub1 should not (channel closed, reads zero value).
	mustReceive(t, sub2.C(), 200*time.Millisecond)
}

func TestSubscribe_DefaultBufferSize(t *testing.T) {
	h := New(32)
	sub := h.Subscribe(0) // 0 → use hub's bufferSize
	if cap(sub.ch) != 32 {
		t.Errorf("expected channel cap=32, got %d", cap(sub.ch))
	}
}

func TestSubscribe_CustomBufferSize(t *testing.T) {
	h := newTestHub()
	sub := h.Subscribe(16)
	if cap(sub.ch) != 16 {
		t.Errorf("expected channel cap=16, got %d", cap(sub.ch))
	}
}

func TestSubscription_C_ReturnsReadOnly(t *testing.T) {
	h := newTestHub()
	sub := h.Subscribe(4)
	// Compile-time: C() returns <-chan []byte, so it's read-only.
	_ = sub.C()
}

func TestBroadcast_MultipleTimes(t *testing.T) {
	h := newTestHub()
	sub := h.Subscribe(32)

	const n = 5
	for i := 0; i < n; i++ {
		h.Broadcast(wsMsg("event", map[string]int{"i": i}))
	}

	for i := 0; i < n; i++ {
		mustReceive(t, sub.C(), 200*time.Millisecond)
	}
}

// ─── allowsMessage (white-box) ────────────────────────────────────────────────

func makeEventMsg(module, severity, tenantID string) []byte {
	payload := map[string]interface{}{
		"module":    module,
		"severity":  severity,
		"tenant_id": tenantID,
	}
	pb, _ := json.Marshal(payload)
	msg := map[string]interface{}{
		"type":    "event",
		"payload": json.RawMessage(pb),
	}
	data, _ := json.Marshal(msg)
	return data
}

func TestAllowsMessage_NilFilterPassesAll(t *testing.T) {
	c := &client{}
	if !c.allowsMessage(makeEventMsg("sentinel", "info", "t1")) {
		t.Error("nil filter should pass all messages")
	}
}

func TestAllowsMessage_ModuleFilterMatch(t *testing.T) {
	c := &client{filter: &clientFilter{Module: "sentinel"}}
	if !c.allowsMessage(makeEventMsg("sentinel", "info", "t1")) {
		t.Error("module filter should pass matching module")
	}
}

func TestAllowsMessage_ModuleFilterNoMatch(t *testing.T) {
	c := &client{filter: &clientFilter{Module: "sentinel"}}
	if c.allowsMessage(makeEventMsg("vault", "info", "t1")) {
		t.Error("module filter should block non-matching module")
	}
}

func TestAllowsMessage_SeverityFilterMatch(t *testing.T) {
	c := &client{filter: &clientFilter{Severity: "critical"}}
	if !c.allowsMessage(makeEventMsg("any", "critical", "t1")) {
		t.Error("severity filter should pass matching severity")
	}
}

func TestAllowsMessage_SeverityFilterNoMatch(t *testing.T) {
	c := &client{filter: &clientFilter{Severity: "critical"}}
	if c.allowsMessage(makeEventMsg("any", "info", "t1")) {
		t.Error("severity filter should block non-matching severity")
	}
}

func TestAllowsMessage_TenantFilterMatch(t *testing.T) {
	c := &client{filter: &clientFilter{TenantID: "tenant-a"}}
	if !c.allowsMessage(makeEventMsg("any", "info", "tenant-a")) {
		t.Error("tenant filter should pass matching tenant")
	}
}

func TestAllowsMessage_TenantFilterNoMatch(t *testing.T) {
	c := &client{filter: &clientFilter{TenantID: "tenant-a"}}
	if c.allowsMessage(makeEventMsg("any", "info", "tenant-b")) {
		t.Error("tenant filter should block non-matching tenant")
	}
}

func TestAllowsMessage_NonEventTypePassesFilter(t *testing.T) {
	c := &client{filter: &clientFilter{Module: "sentinel"}}
	// A non-"event" message type should always pass through.
	msg := map[string]interface{}{
		"type": "checkpoint",
		"payload": map[string]string{"module": "vault"},
	}
	data, _ := json.Marshal(msg)
	if !c.allowsMessage(data) {
		t.Error("non-event messages should bypass module/severity/tenant filters")
	}
}

func TestAllowsMessage_InvalidJSONPassesThrough(t *testing.T) {
	c := &client{filter: &clientFilter{Module: "sentinel"}}
	if !c.allowsMessage([]byte("not-json")) {
		t.Error("invalid JSON should pass through (fail-open)")
	}
}

func TestAllowsMessage_MultiFieldFilter_AllMustMatch(t *testing.T) {
	c := &client{filter: &clientFilter{Module: "sentinel", Severity: "critical", TenantID: "t1"}}
	// All three match
	if !c.allowsMessage(makeEventMsg("sentinel", "critical", "t1")) {
		t.Error("should pass when all filter fields match")
	}
	// Only one mismatch → blocked
	if c.allowsMessage(makeEventMsg("vault", "critical", "t1")) {
		t.Error("should block when module doesn't match")
	}
}
