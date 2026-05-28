package rest

// Integration tests for the Tracker REST API.
// Auth is disabled in all tests (authCfg = nil) so every route is open.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bastion/tracker/internal/alerts"
	"github.com/bastion/tracker/internal/audit"
	"github.com/bastion/tracker/internal/demo"
	"github.com/bastion/tracker/internal/honeytoken"
	"github.com/bastion/tracker/internal/hub"
	"github.com/bastion/tracker/internal/incidents"
	"github.com/bastion/tracker/internal/models"
	"github.com/bastion/tracker/internal/monitor"
	"github.com/bastion/tracker/internal/processor"
	"github.com/bastion/tracker/internal/store"
	"github.com/bastion/tracker/internal/validator"
)

// ─── fixture ─────────────────────────────────────────────────────────────────

type testFixture struct {
	handler http.Handler
	store   *store.Store
	honey   *honeytoken.Manager
	inc     *incidents.Manager
	mon     *monitor.Manager
	proc    *processor.Processor
}

func newFixture(t *testing.T) *testFixture {
	t.Helper()
	s := store.New(1000)
	h := hub.New(64)
	al := alerts.New(nil, s, nil)
	inc := incidents.New(s)
	ht := honeytoken.New(s)
	proc := processor.New(s, h, al, inc, ht)

	// Wire validator so dead-letter endpoint works.
	val := validator.New()
	proc.SetValidator(val)

	demoEng := demo.NewEngine(proc)
	signer := audit.New("")
	mon := monitor.New(monitor.Config{Mode: monitor.ModeOff})

	// Wire monitor as a processor hook (same as main.go).
	proc.AddHook(func(ev models.BastionEvent) { mon.ObserveEvent(ev) })

	// Auth disabled (authCfg = nil).
	srv := New(s, h, proc, demoEng, al, inc, ht, nil, signer, mon, 0)
	return &testFixture{
		handler: srv.httpServer.Handler,
		store:   s,
		honey:   ht,
		inc:     inc,
		mon:     mon,
		proc:    proc,
	}
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

func (f *testFixture) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		req = httptest.NewRequest(method, path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	return w
}

func (f *testFixture) get(t *testing.T, path string) *httptest.ResponseRecorder {
	return f.do(t, http.MethodGet, path, nil)
}

func (f *testFixture) post(t *testing.T, path string, body any) *httptest.ResponseRecorder {
	return f.do(t, http.MethodPost, path, body)
}

func (f *testFixture) delete(t *testing.T, path string) *httptest.ResponseRecorder {
	return f.do(t, http.MethodDelete, path, nil)
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.NewDecoder(w.Body).Decode(dst); err != nil {
		t.Fatalf("decode response: %v\nbody: %s", err, w.Body.String())
	}
}

func mustStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("expected HTTP %d, got %d\nbody: %s", want, w.Code, w.Body.String())
	}
}

func sampleEvent(module, eventType string) models.BastionEvent {
	return models.BastionEvent{
		EventID:   fmt.Sprintf("%s-%s-%d", module, eventType, time.Now().UnixNano()),
		TraceID:   "trace-test",
		TenantID:  "tenant-a",
		UserID:    "user-1",
		Module:    module,
		EventType: eventType,
		Severity:  "info",
		Status:    "passed",
		Timestamp: time.Now(),
	}
}

// ─── Health ───────────────────────────────────────────────────────────────────

func TestHealth_OK(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/health")
	mustStatus(t, w, http.StatusOK)
	var resp map[string]any
	decodeBody(t, w, &resp)
	if resp["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", resp["status"])
	}
}

func TestHealth_Live(t *testing.T) {
	f := newFixture(t)
	mustStatus(t, f.get(t, "/v1/health/live"), http.StatusOK)
}

func TestHealth_Ready(t *testing.T) {
	f := newFixture(t)
	mustStatus(t, f.get(t, "/v1/health/ready"), http.StatusOK)
}

// ─── Event submission ─────────────────────────────────────────────────────────

func TestSubmitEvent_Accepted(t *testing.T) {
	f := newFixture(t)
	ev := sampleEvent("sentinel", "query_validated")
	w := f.post(t, "/v1/events", ev)
	mustStatus(t, w, http.StatusAccepted)
}

func TestSubmitEvent_AlwaysReturns202(t *testing.T) {
	// SubmitEvent returns 202 regardless of validation; invalid events go to
	// dead-letter asynchronously. This documents the fire-and-forget design.
	f := newFixture(t)
	ev := sampleEvent("sentinel", "")
	ev.EventType = ""
	w := f.post(t, "/v1/events", ev)
	mustStatus(t, w, http.StatusAccepted)
}

func TestSubmitBatch_Accepted(t *testing.T) {
	f := newFixture(t)
	batch := models.BatchEventRequest{
		Events: []models.BastionEvent{
			sampleEvent("sentinel", "query_validated"),
			sampleEvent("vault", "pii_tokenized"),
		},
	}
	w := f.post(t, "/v1/events/batch", batch)
	mustStatus(t, w, http.StatusAccepted)
}

// ─── Event listing ────────────────────────────────────────────────────────────

func TestListEvents_EmptyInitially(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/events")
	mustStatus(t, w, http.StatusOK)
}

func TestListEvents_ReturnsSubmittedEvents(t *testing.T) {
	f := newFixture(t)
	f.post(t, "/v1/events", sampleEvent("sentinel", "query_validated"))
	f.post(t, "/v1/events", sampleEvent("vault", "pii_tokenized"))
	w := f.get(t, "/v1/events")
	mustStatus(t, w, http.StatusOK)

	var resp map[string]any
	decodeBody(t, w, &resp)
	events, _ := resp["events"].([]any)
	if len(events) < 2 {
		t.Fatalf("expected ≥2 events, got %v", resp)
	}
}

func TestSearchEvents_ReturnsResults(t *testing.T) {
	f := newFixture(t)
	f.post(t, "/v1/events", sampleEvent("sentinel", "injection_detected"))
	w := f.get(t, "/v1/events/search?q=injection")
	mustStatus(t, w, http.StatusOK)
}

func TestGetEvent_NotFound(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/events/nonexistent-id")
	mustStatus(t, w, http.StatusNotFound)
}

func TestGetEvent_Found(t *testing.T) {
	f := newFixture(t)
	ev := sampleEvent("sentinel", "query_validated")
	f.post(t, "/v1/events", ev)
	w := f.get(t, "/v1/events/"+ev.EventID)
	mustStatus(t, w, http.StatusOK)
}

// ─── Traces ───────────────────────────────────────────────────────────────────

func TestListTraces_Empty(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/traces")
	mustStatus(t, w, http.StatusOK)
}

func TestGetTrace_NotFound(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/traces/no-such-trace")
	mustStatus(t, w, http.StatusNotFound)
}

func TestGetTrace_Found(t *testing.T) {
	f := newFixture(t)
	ev := sampleEvent("sentinel", "query_validated")
	ev.TraceID = "trace-abc"
	f.post(t, "/v1/events", ev)
	w := f.get(t, "/v1/traces/trace-abc")
	mustStatus(t, w, http.StatusOK)
}

func TestGetTraceTimeline_NotFound(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/traces/missing-trace/timeline")
	mustStatus(t, w, http.StatusNotFound)
}

// ─── Honey-tokens ─────────────────────────────────────────────────────────────

func TestListHoneyTokens_Empty(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/honey-tokens")
	mustStatus(t, w, http.StatusOK)
}

func TestCreateHoneyToken_Success(t *testing.T) {
	f := newFixture(t)
	body := map[string]any{
		"name":        "Fake CEO email",
		"description": "Decoy for intrusion detection",
		"location":    "customer_db",
		"type":        "email",
	}
	w := f.post(t, "/v1/honey-tokens", body)
	mustStatus(t, w, http.StatusCreated)
	var resp map[string]any
	decodeBody(t, w, &resp)
	if resp["token_id"] == "" || resp["token_id"] == nil {
		t.Fatalf("expected token_id in response, got %v", resp)
	}
}

func TestCreateHoneyToken_AllowsEmptyName(t *testing.T) {
	// The handler does not validate the name field — empty name is accepted.
	f := newFixture(t)
	w := f.post(t, "/v1/honey-tokens", map[string]any{"type": "email"})
	mustStatus(t, w, http.StatusCreated)
}

func TestDeleteHoneyToken_NotFound(t *testing.T) {
	f := newFixture(t)
	w := f.delete(t, "/v1/honey-tokens/HT-0000")
	mustStatus(t, w, http.StatusNotFound)
}

func TestDeleteHoneyToken_Success(t *testing.T) {
	f := newFixture(t)
	body := map[string]any{
		"name":        "Fake API Key",
		"description": "Decoy",
		"location":    "hr_db",
		"type":        "credential",
	}
	wc := f.post(t, "/v1/honey-tokens", body)
	mustStatus(t, wc, http.StatusCreated)
	var created map[string]any
	decodeBody(t, wc, &created)
	tokenID := created["token_id"].(string)

	wd := f.delete(t, "/v1/honey-tokens/"+tokenID)
	mustStatus(t, wd, http.StatusNoContent)
}

func TestHoneyTokenTriggers_Empty(t *testing.T) {
	f := newFixture(t)
	wc := f.post(t, "/v1/honey-tokens", map[string]any{
		"name": "decoy", "description": "d", "location": "l", "type": "email",
	})
	var created map[string]any
	decodeBody(t, wc, &created)
	tokenID := created["token_id"].(string)

	wt := f.get(t, "/v1/honey-tokens/"+tokenID+"/triggers")
	mustStatus(t, wt, http.StatusOK)
}

func TestAllHoneyTokenTriggers(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/honey-tokens/triggers")
	mustStatus(t, w, http.StatusOK)
}

// ─── Incidents ────────────────────────────────────────────────────────────────

func TestListIncidents_Empty(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/security/incidents")
	mustStatus(t, w, http.StatusOK)
}

func TestResolveIncident_NotFound(t *testing.T) {
	f := newFixture(t)
	w := f.post(t, "/v1/security/incidents/INC-9999/resolve", map[string]any{"notes": "done"})
	mustStatus(t, w, http.StatusNotFound)
}

func TestListIncidents_AfterHoneyTokenEvent(t *testing.T) {
	f := newFixture(t)
	ev := sampleEvent("vault", "honey_token_accessed")
	ev.Data = map[string]any{"honey_token_id": "HT-TEST"}
	f.post(t, "/v1/events", ev)

	w := f.get(t, "/v1/security/incidents")
	mustStatus(t, w, http.StatusOK)
	// Response is a JSON array (not wrapped).
	var incList []map[string]any
	decodeBody(t, w, &incList)
	if len(incList) == 0 {
		t.Fatal("expected at least 1 incident after honey-token event")
	}
	if incList[0]["incident_id"] == nil {
		t.Fatalf("expected incident_id in response, got %v", incList[0])
	}
}

func TestResolveIncident_Success(t *testing.T) {
	f := newFixture(t)
	ev := sampleEvent("vault", "honey_token_accessed")
	ev.Data = map[string]any{"honey_token_id": "HT-TEST"}
	f.post(t, "/v1/events", ev)

	// Incidents returned as a JSON array.
	w := f.get(t, "/v1/security/incidents")
	var incList []map[string]any
	decodeBody(t, w, &incList)
	if len(incList) == 0 {
		t.Skip("no incident auto-created")
	}
	id := incList[0]["incident_id"].(string)

	wr := f.post(t, "/v1/security/incidents/"+id+"/resolve", map[string]any{"notes": "all clear"})
	mustStatus(t, wr, http.StatusOK)
	var resolved map[string]any
	decodeBody(t, wr, &resolved)
	if resolved["status"] != "resolved" {
		t.Fatalf("expected resolved, got %v", resolved["status"])
	}
}

// ─── Alerts ───────────────────────────────────────────────────────────────────

func TestListAlerts_Empty(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/alerts")
	mustStatus(t, w, http.StatusOK)
}

// ─── Security events ─────────────────────────────────────────────────────────

func TestGetSecurityEvents(t *testing.T) {
	f := newFixture(t)
	ev := sampleEvent("sentinel", "injection_detected")
	ev.Status = "blocked"
	f.post(t, "/v1/events", ev)

	w := f.get(t, "/v1/security/events")
	mustStatus(t, w, http.StatusOK)
}

// ─── Runbooks ─────────────────────────────────────────────────────────────────

func TestListRunBooks(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/runbooks")
	mustStatus(t, w, http.StatusOK)
	// Response is a JSON array.
	var books []map[string]any
	decodeBody(t, w, &books)
	if len(books) == 0 {
		t.Fatal("expected at least one default runbook")
	}
}

func TestGetRunBook_NotFound(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/runbooks/no-such-id")
	mustStatus(t, w, http.StatusNotFound)
}

func TestGetRunBook_Found(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/runbooks")
	var books []map[string]any
	decodeBody(t, w, &books)
	if len(books) == 0 {
		t.Skip("no runbooks available")
	}
	id := books[0]["id"].(string)

	wg := f.get(t, "/v1/runbooks/"+id)
	mustStatus(t, wg, http.StatusOK)
	var rb map[string]any
	decodeBody(t, wg, &rb)
	if rb["id"] != id {
		t.Fatalf("expected runbook id=%s, got %v", id, rb["id"])
	}
}

// ─── Monitor — mode ───────────────────────────────────────────────────────────

func TestMonitorGetMode_Default(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/monitor/mode")
	mustStatus(t, w, http.StatusOK)
	var resp map[string]any
	decodeBody(t, w, &resp)
	if resp["mode"] != "off" {
		t.Fatalf("expected off, got %v", resp["mode"])
	}
}

func TestMonitorSetMode_Observe(t *testing.T) {
	f := newFixture(t)
	w := f.post(t, "/v1/monitor/mode", map[string]any{"mode": "observe"})
	mustStatus(t, w, http.StatusOK)
	var resp map[string]any
	decodeBody(t, w, &resp)
	if resp["mode"] != "observe" {
		t.Fatalf("expected observe, got %v", resp["mode"])
	}
	if f.mon.GetMode() != monitor.ModeObserve {
		t.Fatal("manager mode not updated to observe")
	}
}

func TestMonitorSetMode_Gate(t *testing.T) {
	f := newFixture(t)
	w := f.post(t, "/v1/monitor/mode", map[string]any{"mode": "gate"})
	mustStatus(t, w, http.StatusOK)
	if f.mon.GetMode() != monitor.ModeGate {
		t.Fatal("expected gate mode")
	}
}

func TestMonitorSetMode_InvalidMode(t *testing.T) {
	f := newFixture(t)
	w := f.post(t, "/v1/monitor/mode", map[string]any{"mode": "invalid"})
	mustStatus(t, w, http.StatusBadRequest)
}

func TestMonitorSetMode_BackToOff(t *testing.T) {
	f := newFixture(t)
	f.post(t, "/v1/monitor/mode", map[string]any{"mode": "observe"})
	w := f.post(t, "/v1/monitor/mode", map[string]any{"mode": "off"})
	mustStatus(t, w, http.StatusOK)
	if f.mon.GetMode() != monitor.ModeOff {
		t.Fatal("expected off mode")
	}
}

// ─── Monitor — sessions ───────────────────────────────────────────────────────

func TestMonitorListSessions_Empty(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/monitor/sessions")
	mustStatus(t, w, http.StatusOK)
	var resp map[string]any
	decodeBody(t, w, &resp)
	if resp["sessions"] == nil && resp["total"] == nil {
		t.Fatalf("expected sessions/total in response, got %v", resp)
	}
}

func TestMonitorListSessions_PopulatedAfterEvents(t *testing.T) {
	f := newFixture(t)
	// Switch to observe; the monitor hook is wired to proc in newFixture.
	f.post(t, "/v1/monitor/mode", map[string]any{"mode": "observe"})

	ev := sampleEvent("sentinel", "query_validated")
	ev.TraceID = "trace-monitor-observe"
	f.post(t, "/v1/events", ev)

	w := f.get(t, "/v1/monitor/sessions")
	mustStatus(t, w, http.StatusOK)
	var resp map[string]any
	decodeBody(t, w, &resp)
	sessions, _ := resp["sessions"].([]any)
	if len(sessions) == 0 {
		t.Fatal("expected ≥1 session in observe mode after event submission")
	}
}

func TestMonitorGetSession_NotFound(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/monitor/sessions/nonexistent-session")
	mustStatus(t, w, http.StatusNotFound)
}

func TestMonitorDeleteSession_NotFound(t *testing.T) {
	f := newFixture(t)
	w := f.delete(t, "/v1/monitor/sessions/bad-id")
	mustStatus(t, w, http.StatusNotFound)
}

func TestMonitorGetAndDeleteSession(t *testing.T) {
	f := newFixture(t)
	f.post(t, "/v1/monitor/mode", map[string]any{"mode": "observe"})

	ev := sampleEvent("vault", "pii_tokenized")
	ev.TraceID = "trace-get-del"
	f.post(t, "/v1/events", ev)

	// List sessions.
	w := f.get(t, "/v1/monitor/sessions")
	var list map[string]any
	decodeBody(t, w, &list)
	sessions, _ := list["sessions"].([]any)
	if len(sessions) == 0 {
		t.Skip("no session created")
	}
	first := sessions[0].(map[string]any)
	sessID := first["session_id"].(string)

	// Get by ID.
	wg := f.get(t, "/v1/monitor/sessions/"+sessID)
	mustStatus(t, wg, http.StatusOK)
	var got map[string]any
	decodeBody(t, wg, &got)
	if got["session_id"] != sessID {
		t.Fatalf("wrong session: %v", got["session_id"])
	}

	// Delete.
	wd := f.delete(t, "/v1/monitor/sessions/"+sessID)
	mustStatus(t, wd, http.StatusNoContent)

	// Gone.
	mustStatus(t, f.get(t, "/v1/monitor/sessions/"+sessID), http.StatusNotFound)
}

// ─── Monitor — checkpoints ────────────────────────────────────────────────────

func TestMonitorListCheckpoints_Empty(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/monitor/checkpoints")
	mustStatus(t, w, http.StatusOK)
}

func TestMonitorCreateCheckpoint_RequiresGateMode(t *testing.T) {
	f := newFixture(t)
	// mode is off → CreateCheckpoint returns nil → 409 Conflict
	w := f.post(t, "/v1/monitor/checkpoints", map[string]any{
		"trace_id": "t1", "tenant_id": "ten1", "stage": "vault",
	})
	mustStatus(t, w, http.StatusConflict)
}

func TestMonitorCreateCheckpoint_Success(t *testing.T) {
	f := newFixture(t)
	f.post(t, "/v1/monitor/mode", map[string]any{"mode": "gate"})

	w := f.post(t, "/v1/monitor/checkpoints", map[string]any{
		"trace_id": "t1", "tenant_id": "ten1", "stage": "navigator",
	})
	mustStatus(t, w, http.StatusCreated)
	var resp map[string]any
	decodeBody(t, w, &resp)
	if resp["checkpoint_id"] == nil || resp["checkpoint_id"] == "" {
		t.Fatalf("expected checkpoint_id, got %v", resp)
	}
}

func TestMonitorGetCheckpoint_NotFound(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/monitor/checkpoints/bad-id")
	mustStatus(t, w, http.StatusNotFound)
}

func TestMonitorDecideCheckpoint_NotFound(t *testing.T) {
	f := newFixture(t)
	w := f.post(t, "/v1/monitor/checkpoints/bad-id/decide", map[string]any{"decision": "approve"})
	mustStatus(t, w, http.StatusNotFound)
}

func TestMonitorDecideCheckpoint_Approve(t *testing.T) {
	f := newFixture(t)
	f.post(t, "/v1/monitor/mode", map[string]any{"mode": "gate"})

	wc := f.post(t, "/v1/monitor/checkpoints", map[string]any{
		"trace_id": "t2", "tenant_id": "ten1", "stage": "vault",
	})
	var cp map[string]any
	decodeBody(t, wc, &cp)
	cpID := cp["checkpoint_id"].(string)

	wd := f.post(t, "/v1/monitor/checkpoints/"+cpID+"/decide", map[string]any{
		"decision": "approve",
		"notes":    "looks good",
	})
	mustStatus(t, wd, http.StatusOK)
	var decided map[string]any
	decodeBody(t, wd, &decided)
	if decided["status"] != "approved" {
		t.Fatalf("expected approved, got %v", decided["status"])
	}
}

func TestMonitorDecideCheckpoint_Reject(t *testing.T) {
	f := newFixture(t)
	f.post(t, "/v1/monitor/mode", map[string]any{"mode": "gate"})

	wc := f.post(t, "/v1/monitor/checkpoints", map[string]any{
		"trace_id": "t3", "tenant_id": "ten1", "stage": "sentinel",
	})
	var cp map[string]any
	decodeBody(t, wc, &cp)
	cpID := cp["checkpoint_id"].(string)

	wd := f.post(t, "/v1/monitor/checkpoints/"+cpID+"/decide", map[string]any{
		"decision": "reject",
		"notes":    "suspicious",
	})
	mustStatus(t, wd, http.StatusOK)
	var decided map[string]any
	decodeBody(t, wd, &decided)
	if decided["status"] != "rejected" {
		t.Fatalf("expected rejected, got %v", decided["status"])
	}
}

func TestMonitorGetCheckpoint_Found(t *testing.T) {
	f := newFixture(t)
	f.post(t, "/v1/monitor/mode", map[string]any{"mode": "gate"})
	wc := f.post(t, "/v1/monitor/checkpoints", map[string]any{
		"trace_id": "t4", "tenant_id": "ten1", "stage": "anchor",
	})
	var cp map[string]any
	decodeBody(t, wc, &cp)
	cpID := cp["checkpoint_id"].(string)

	wg := f.get(t, "/v1/monitor/checkpoints/"+cpID)
	mustStatus(t, wg, http.StatusOK)
	var got map[string]any
	decodeBody(t, wg, &got)
	if got["checkpoint_id"] != cpID {
		t.Fatalf("wrong checkpoint: %v", got["checkpoint_id"])
	}
}

// ─── Validator / Dead-letter ──────────────────────────────────────────────────

func TestListDeadLetters_Empty(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/dead-letter")
	mustStatus(t, w, http.StatusOK)
}

func TestListDeadLetters_AfterBadEvent(t *testing.T) {
	f := newFixture(t)
	// Submit a valid event first to confirm the pipeline works, then an invalid one.
	bad := sampleEvent("", "")
	bad.EventType = ""
	bad.Module = ""
	f.post(t, "/v1/events", bad)

	w := f.get(t, "/v1/dead-letter")
	mustStatus(t, w, http.StatusOK)
	// Response is a JSON array.
	var entries []map[string]any
	decodeBody(t, w, &entries)
	if len(entries) == 0 {
		t.Fatal("expected ≥1 dead-letter entry after invalid event")
	}
	if entries[0]["reason"] == nil {
		t.Fatalf("expected reason in dead-letter entry, got %v", entries[0])
	}
}

// ─── Lineage ─────────────────────────────────────────────────────────────────

func TestLineageByTrace_Alias(t *testing.T) {
	f := newFixture(t)
	ev := sampleEvent("sentinel", "query_validated")
	ev.TraceID = "lineage-trace"
	f.post(t, "/v1/events", ev)
	w := f.get(t, "/v1/lineage/lineage-trace")
	mustStatus(t, w, http.StatusOK)
}

func TestLineageByUser_Empty(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/lineage/user/no-such-user")
	mustStatus(t, w, http.StatusOK)
}

func TestLineageAudit(t *testing.T) {
	f := newFixture(t)
	w := f.get(t, "/v1/lineage/audit")
	mustStatus(t, w, http.StatusOK)
}

// ─── Topology ─────────────────────────────────────────────────────────────────

func TestTopology(t *testing.T) {
	f := newFixture(t)
	mustStatus(t, f.get(t, "/v1/topology"), http.StatusOK)
}

func TestTopologyHealth(t *testing.T) {
	f := newFixture(t)
	mustStatus(t, f.get(t, "/v1/topology/health"), http.StatusOK)
}

func TestPipelineStats(t *testing.T) {
	f := newFixture(t)
	mustStatus(t, f.get(t, "/v1/pipelines/stats"), http.StatusOK)
}
