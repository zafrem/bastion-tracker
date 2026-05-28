package monitor

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bastion/tracker/internal/models"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func newMgr(mode Mode) *Manager {
	return New(Config{
		Mode:                  mode,
		SessionRetentionHours: 1,
		CheckpointTimeoutSec:  2, // short for tests
		AutoApproveOnTimeout:  false,
	})
}

func ev(traceID, module, eventType, status string) models.BastionEvent {
	return models.BastionEvent{
		EventID:   module + "-" + eventType,
		TraceID:   traceID,
		TenantID:  "tenant-a",
		UserID:    "user-1",
		Module:    module,
		EventType: eventType,
		Status:    status,
		Timestamp: time.Now(),
	}
}

// ─── Construction ─────────────────────────────────────────────────────────────

func TestNew_DefaultsMode(t *testing.T) {
	m := New(Config{})
	if got := m.GetMode(); got != ModeOff {
		t.Fatalf("expected ModeOff, got %q", got)
	}
}

func TestNew_ExplicitMode(t *testing.T) {
	m := newMgr(ModeObserve)
	if got := m.GetMode(); got != ModeObserve {
		t.Fatalf("expected ModeObserve, got %q", got)
	}
}

func TestNew_DefaultRetention(t *testing.T) {
	m := New(Config{}) // SessionRetentionHours = 0 → defaults to 24
	if m.cfg.SessionRetentionHours != 24 {
		t.Fatalf("expected 24, got %d", m.cfg.SessionRetentionHours)
	}
}

func TestNew_DefaultCheckpointTimeout(t *testing.T) {
	m := New(Config{}) // CheckpointTimeoutSec = 0 → defaults to 300
	if m.cfg.CheckpointTimeoutSec != 300 {
		t.Fatalf("expected 300, got %d", m.cfg.CheckpointTimeoutSec)
	}
}

// ─── Mode switching ───────────────────────────────────────────────────────────

func TestSetMode_ChangesMode(t *testing.T) {
	m := newMgr(ModeOff)
	m.SetMode(ModeObserve)
	if got := m.GetMode(); got != ModeObserve {
		t.Fatalf("expected ModeObserve, got %q", got)
	}
}

func TestSetMode_GateToOff_RejectsPendingCheckpoints(t *testing.T) {
	m := newMgr(ModeGate)

	cp := m.CreateCheckpoint("trace-1", "t1", "sentinel-in", nil)
	if cp == nil {
		t.Fatal("CreateCheckpoint returned nil in gate mode")
	}

	// WaitForDecision in background; switching mode should unblock it.
	var rejected atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ok, _ := m.WaitForDecision(cp.CheckpointID)
		if !ok {
			rejected.Store(true)
		}
	}()

	time.Sleep(20 * time.Millisecond) // give goroutine time to block
	m.SetMode(ModeOff)
	wg.Wait()

	if !rejected.Load() {
		t.Fatal("expected checkpoint to be rejected when switching gate → off")
	}
}

// ─── ObserveEvent ─────────────────────────────────────────────────────────────

func TestObserveEvent_IgnoredInOffMode(t *testing.T) {
	m := newMgr(ModeOff)
	m.ObserveEvent(ev("trace-1", "sentinel", "query_validated", "passed"))

	if sessions := m.ListSessions(); len(sessions) != 0 {
		t.Fatalf("expected no sessions in off mode, got %d", len(sessions))
	}
}

func TestObserveEvent_CreatesSession(t *testing.T) {
	m := newMgr(ModeObserve)
	m.ObserveEvent(ev("trace-1", "sentinel", "query_validated", "passed"))

	sessions := m.ListSessions()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].TraceID != "trace-1" {
		t.Fatalf("unexpected trace_id: %s", sessions[0].TraceID)
	}
}

func TestObserveEvent_AppendsStepsToSameSession(t *testing.T) {
	m := newMgr(ModeObserve)
	m.ObserveEvent(ev("trace-X", "sentinel", "query_validated", "passed"))
	m.ObserveEvent(ev("trace-X", "vault", "pii_tokenized", "passed"))
	m.ObserveEvent(ev("trace-X", "navigator", "search_completed", "passed"))

	sess, ok := m.byTrace["trace-X"]
	if !ok {
		t.Fatal("session not found by trace")
	}
	if len(sess.Steps) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(sess.Steps))
	}
}

func TestObserveEvent_DifferentTracesGetSeparateSessions(t *testing.T) {
	m := newMgr(ModeObserve)
	m.ObserveEvent(ev("trace-A", "sentinel", "query_validated", "passed"))
	m.ObserveEvent(ev("trace-B", "sentinel", "query_validated", "passed"))

	if len(m.ListSessions()) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(m.ListSessions()))
	}
}

func TestObserveEvent_BlockedStatusCompletesSession(t *testing.T) {
	m := newMgr(ModeObserve)
	m.ObserveEvent(ev("trace-block", "sentinel", "injection_detected", "blocked"))

	sess, _ := m.GetSession(m.ListSessions()[0].SessionID)
	if sess.Status != "completed" {
		t.Fatalf("expected completed, got %s", sess.Status)
	}
}

func TestObserveEvent_LLMModuleCompletesSession(t *testing.T) {
	m := newMgr(ModeObserve)
	m.ObserveEvent(ev("trace-llm", "llm", "response_generated", "passed"))

	sess, _ := m.GetSession(m.ListSessions()[0].SessionID)
	if sess.Status != "completed" {
		t.Fatalf("expected completed, got %s", sess.Status)
	}
}

func TestObserveEvent_StepFields(t *testing.T) {
	m := newMgr(ModeObserve)
	e := ev("trace-fields", "vault", "pii_tokenized", "passed")
	m.ObserveEvent(e)

	sess, _ := m.GetSession(m.ListSessions()[0].SessionID)
	step := sess.Steps[0]

	if step.Module != "vault" {
		t.Errorf("expected vault, got %s", step.Module)
	}
	if step.EventType != "pii_tokenized" {
		t.Errorf("expected pii_tokenized, got %s", step.EventType)
	}
	if step.Status != "passed" {
		t.Errorf("expected passed, got %s", step.Status)
	}
	if step.StepID == "" {
		t.Error("step_id should not be empty")
	}
}

func TestObserveEvent_BroadcastCalled(t *testing.T) {
	m := newMgr(ModeObserve)
	var count atomic.Int32
	m.SetBroadcast(func(any) { count.Add(1) })

	m.ObserveEvent(ev("trace-bc", "sentinel", "query_validated", "passed"))
	if count.Load() != 1 {
		t.Fatalf("expected 1 broadcast, got %d", count.Load())
	}
}

// ─── Session CRUD ─────────────────────────────────────────────────────────────

func TestGetSession_NotFound(t *testing.T) {
	m := newMgr(ModeObserve)
	_, ok := m.GetSession("nonexistent")
	if ok {
		t.Fatal("expected not found")
	}
}

func TestDeleteSession(t *testing.T) {
	m := newMgr(ModeObserve)
	m.ObserveEvent(ev("trace-del", "sentinel", "q", "passed"))

	sessID := m.ListSessions()[0].SessionID
	if !m.DeleteSession(sessID) {
		t.Fatal("DeleteSession returned false unexpectedly")
	}
	if _, ok := m.GetSession(sessID); ok {
		t.Fatal("session should be gone after delete")
	}
	// byTrace should also be cleaned up
	if _, ok := m.byTrace["trace-del"]; ok {
		t.Fatal("byTrace not cleaned up")
	}
}

func TestDeleteSession_NotFound(t *testing.T) {
	m := newMgr(ModeObserve)
	if m.DeleteSession("bad-id") {
		t.Fatal("expected false for missing session")
	}
}

func TestAnnotateStep(t *testing.T) {
	m := newMgr(ModeObserve)
	m.ObserveEvent(ev("trace-ann", "sentinel", "q", "passed"))

	sess := m.ListSessions()[0]
	stepID := sess.Steps[0].StepID

	if !m.AnnotateStep(sess.SessionID, stepID, "looks fine") {
		t.Fatal("AnnotateStep returned false")
	}

	updated, _ := m.GetSession(sess.SessionID)
	if updated.Steps[0].Annotation != "looks fine" {
		t.Fatalf("annotation not set, got %q", updated.Steps[0].Annotation)
	}
}

func TestAnnotateStep_BadSession(t *testing.T) {
	m := newMgr(ModeObserve)
	if m.AnnotateStep("no-such-session", "step-1", "note") {
		t.Fatal("expected false for missing session")
	}
}

func TestAnnotateStep_BadStep(t *testing.T) {
	m := newMgr(ModeObserve)
	m.ObserveEvent(ev("trace-ann2", "sentinel", "q", "passed"))
	sess := m.ListSessions()[0]

	if m.AnnotateStep(sess.SessionID, "bad-step-id", "note") {
		t.Fatal("expected false for missing step")
	}
}

// ─── Checkpoint lifecycle ─────────────────────────────────────────────────────

func TestCreateCheckpoint_NilWhenNotGateMode(t *testing.T) {
	for _, mode := range []Mode{ModeOff, ModeObserve} {
		m := newMgr(mode)
		cp := m.CreateCheckpoint("t", "ten", "stage", nil)
		if cp != nil {
			t.Fatalf("expected nil in mode %q, got checkpoint", mode)
		}
	}
}

func TestCreateCheckpoint_ReturnsCheckpointInGateMode(t *testing.T) {
	m := newMgr(ModeGate)
	cp := m.CreateCheckpoint("trace-gate", "t1", "navigator", map[string]any{"query": "test"})
	if cp == nil {
		t.Fatal("expected checkpoint, got nil")
	}
	if cp.CheckpointID == "" {
		t.Error("checkpoint_id empty")
	}
	if cp.Status != StatusPending {
		t.Errorf("expected pending, got %s", cp.Status)
	}
	if cp.Stage != "navigator" {
		t.Errorf("expected navigator, got %s", cp.Stage)
	}
}

func TestDecide_Approve(t *testing.T) {
	m := newMgr(ModeGate)
	cp := m.CreateCheckpoint("trace-approve", "t1", "vault", nil)

	var approved atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ok, _ := m.WaitForDecision(cp.CheckpointID)
		approved.Store(ok)
	}()

	time.Sleep(20 * time.Millisecond)
	updated, ok := m.Decide(cp.CheckpointID, "alice", "approve", "looks good")
	if !ok {
		t.Fatal("Decide returned false")
	}
	wg.Wait()

	if !approved.Load() {
		t.Fatal("WaitForDecision should have returned true on approve")
	}
	if updated.Status != StatusApproved {
		t.Errorf("expected approved, got %s", updated.Status)
	}
	if updated.DecidedBy != "alice" {
		t.Errorf("expected alice, got %s", updated.DecidedBy)
	}
	if updated.Notes != "looks good" {
		t.Errorf("unexpected notes: %s", updated.Notes)
	}
}

func TestDecide_Reject(t *testing.T) {
	m := newMgr(ModeGate)
	cp := m.CreateCheckpoint("trace-reject", "t1", "sentinel", nil)

	var approved atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ok, _ := m.WaitForDecision(cp.CheckpointID)
		approved.Store(ok)
	}()

	time.Sleep(20 * time.Millisecond)
	m.Decide(cp.CheckpointID, "bob", "reject", "suspicious")
	wg.Wait()

	if approved.Load() {
		t.Fatal("WaitForDecision should have returned false on reject")
	}
}

func TestDecide_AlreadyDecidedReturnsFalse(t *testing.T) {
	m := newMgr(ModeGate)
	cp := m.CreateCheckpoint("trace-dbl", "t1", "vault", nil)

	go m.WaitForDecision(cp.CheckpointID)
	time.Sleep(10 * time.Millisecond)
	m.Decide(cp.CheckpointID, "u", "approve", "")

	_, ok := m.Decide(cp.CheckpointID, "u", "approve", "again")
	if ok {
		t.Fatal("second Decide should return false (already decided)")
	}
}

func TestDecide_UnknownCheckpointReturnsFalse(t *testing.T) {
	m := newMgr(ModeGate)
	_, ok := m.Decide("nonexistent", "u", "approve", "")
	if ok {
		t.Fatal("expected false for unknown checkpoint")
	}
}

func TestWaitForDecision_UnknownCheckpoint(t *testing.T) {
	m := newMgr(ModeGate)
	ok, reason := m.WaitForDecision("no-such-id")
	if ok {
		t.Fatal("expected false for missing checkpoint")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestListCheckpoints(t *testing.T) {
	m := newMgr(ModeGate)
	cp1 := m.CreateCheckpoint("t-1", "ten", "s1", nil)
	cp2 := m.CreateCheckpoint("t-2", "ten", "s2", nil)

	all := m.ListCheckpoints(false)
	if len(all) != 2 {
		t.Fatalf("expected 2, got %d", len(all))
	}

	// Decide one
	go m.WaitForDecision(cp1.CheckpointID)
	time.Sleep(10 * time.Millisecond)
	m.Decide(cp1.CheckpointID, "u", "approve", "")

	pending := m.ListCheckpoints(true)
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}
	if pending[0].CheckpointID != cp2.CheckpointID {
		t.Errorf("wrong pending checkpoint: %s", pending[0].CheckpointID)
	}
}

func TestGetCheckpoint(t *testing.T) {
	m := newMgr(ModeGate)
	cp := m.CreateCheckpoint("trace-get", "t1", "vault", nil)

	got, ok := m.GetCheckpoint(cp.CheckpointID)
	if !ok {
		t.Fatal("GetCheckpoint returned not found")
	}
	if got.CheckpointID != cp.CheckpointID {
		t.Errorf("ID mismatch: %s vs %s", got.CheckpointID, cp.CheckpointID)
	}
}

// ─── Timeout ──────────────────────────────────────────────────────────────────

func TestTimeout_RejectOnTimeout(t *testing.T) {
	// AutoApproveOnTimeout = false → timeout causes rejection
	m := New(Config{
		Mode:                 ModeGate,
		CheckpointTimeoutSec: 1,
		AutoApproveOnTimeout: false,
	})

	cp := m.CreateCheckpoint("trace-timeout", "t1", "vault", nil)
	ok, reason := m.WaitForDecision(cp.CheckpointID)
	if ok {
		t.Fatal("expected rejection on timeout")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason on timeout")
	}
}

func TestTimeout_ApproveOnTimeout(t *testing.T) {
	// AutoApproveOnTimeout = true → timeout causes approval
	m := New(Config{
		Mode:                 ModeGate,
		CheckpointTimeoutSec: 1,
		AutoApproveOnTimeout: true,
	})

	cp := m.CreateCheckpoint("trace-autoapprove", "t1", "sentinel", nil)
	ok, _ := m.WaitForDecision(cp.CheckpointID)
	if !ok {
		t.Fatal("expected auto-approval on timeout")
	}
}

// ─── Broadcast ────────────────────────────────────────────────────────────────

func TestCheckpoint_BroadcastOnCreate(t *testing.T) {
	m := newMgr(ModeGate)
	var count atomic.Int32
	m.SetBroadcast(func(any) { count.Add(1) })

	cp := m.CreateCheckpoint("trace-bc", "t1", "vault", nil)
	if count.Load() < 1 {
		t.Fatal("expected broadcast on checkpoint creation")
	}

	// Approve and verify another broadcast
	go m.WaitForDecision(cp.CheckpointID)
	time.Sleep(10 * time.Millisecond)
	m.Decide(cp.CheckpointID, "u", "approve", "")
	time.Sleep(10 * time.Millisecond)
	if count.Load() < 2 {
		t.Fatal("expected broadcast on checkpoint decision")
	}
}

// ─── Concurrency ──────────────────────────────────────────────────────────────

func TestConcurrentObserve(t *testing.T) {
	m := newMgr(ModeObserve)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		traceID := "concurrent-trace"
		go func() {
			defer wg.Done()
			m.ObserveEvent(ev(traceID, "sentinel", "query_validated", "passed"))
		}()
	}
	wg.Wait()
	// All 50 events should land in the same session
	sess, ok := m.byTrace["concurrent-trace"]
	if !ok {
		t.Fatal("session not created")
	}
	if len(sess.Steps) != 50 {
		t.Fatalf("expected 50 steps, got %d", len(sess.Steps))
	}
}
