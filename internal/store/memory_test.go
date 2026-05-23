package store

import (
	"testing"
	"time"

	"github.com/bastion/tracker/internal/models"
)

func ev(module, eventType, severity, status string) models.BastionEvent {
	return models.BastionEvent{
		EventID:   module + "-" + eventType,
		Module:    module,
		EventType: eventType,
		Severity:  severity,
		Status:    status,
		Timestamp: time.Now(),
		TenantID:  "tenant-test",
		TraceID:   "trace-" + module,
		SpanID:    "span-" + module,
	}
}

// ─── Events ring buffer ───────────────────────────────────────────────────────

func TestAddEvent_StoresAndRetrieves(t *testing.T) {
	s := New(100)
	s.AddEvent(ev("sentinel", "validation_passed", "info", "passed"))
	results := s.RecentEvents(models.QueryRequest{}, 10)
	if len(results) != 1 {
		t.Fatalf("expected 1 event, got %d", len(results))
	}
	if results[0].Module != "sentinel" {
		t.Errorf("unexpected module: %s", results[0].Module)
	}
}

func TestAddEvent_RingBufferWraps(t *testing.T) {
	s := New(5)
	for i := 0; i < 10; i++ {
		e := ev("mod", "evt", "info", "passed")
		e.EventID = string(rune('a' + i))
		s.AddEvent(e)
	}
	results := s.RecentEvents(models.QueryRequest{}, 10)
	if len(results) != 5 {
		t.Errorf("expected 5 events (ring buffer size), got %d", len(results))
	}
}

func TestRecentEvents_FilterByModule(t *testing.T) {
	s := New(100)
	s.AddEvent(ev("sentinel", "x", "info", "passed"))
	s.AddEvent(ev("vault", "y", "info", "passed"))
	results := s.RecentEvents(models.QueryRequest{Module: "sentinel"}, 10)
	if len(results) != 1 || results[0].Module != "sentinel" {
		t.Errorf("expected 1 sentinel event, got %d", len(results))
	}
}

func TestRecentEvents_FilterBySeverity(t *testing.T) {
	s := New(100)
	s.AddEvent(ev("sentinel", "x", "info", "passed"))
	s.AddEvent(ev("vault", "y", "critical", "error"))
	results := s.RecentEvents(models.QueryRequest{Severity: "critical"}, 10)
	if len(results) != 1 || results[0].Severity != "critical" {
		t.Errorf("expected 1 critical event, got %d", len(results))
	}
}

func TestSearchEvents_FindsByKeyword(t *testing.T) {
	s := New(100)
	e := ev("sentinel", "prompt_injection_detected", "critical", "blocked")
	s.AddEvent(e)
	results := s.SearchEvents("prompt", 10)
	if len(results) != 1 {
		t.Errorf("expected 1 match, got %d", len(results))
	}
}

func TestSearchEvents_NoMatch(t *testing.T) {
	s := New(100)
	s.AddEvent(ev("sentinel", "validation_passed", "info", "passed"))
	results := s.SearchEvents("honey_token", 10)
	if len(results) != 0 {
		t.Errorf("expected 0 matches, got %d", len(results))
	}
}

// ─── Traces ───────────────────────────────────────────────────────────────────

func TestUpsertTrace_CreatesTrace(t *testing.T) {
	s := New(100)
	e := ev("sentinel", "validation_passed", "info", "passed")
	e.TraceID = "trace-001"
	e.SpanID = "span-001"
	s.UpsertTrace(e)
	tr, ok := s.GetTrace("trace-001")
	if !ok {
		t.Fatal("expected trace to exist")
	}
	if len(tr.Spans) != 1 {
		t.Errorf("expected 1 span, got %d", len(tr.Spans))
	}
}

func TestUpsertTrace_AppendsMutlipleSpans(t *testing.T) {
	s := New(100)
	modules := []string{"sentinel", "vault", "navigator"}
	for _, m := range modules {
		e := ev(m, "ok", "info", "passed")
		e.TraceID = "trace-multi"
		e.SpanID = "span-" + m
		s.UpsertTrace(e)
	}
	tr, ok := s.GetTrace("trace-multi")
	if !ok {
		t.Fatal("trace missing")
	}
	if len(tr.Spans) != 3 {
		t.Errorf("expected 3 spans, got %d", len(tr.Spans))
	}
}

func TestGetTrace_MissingReturnsNotOK(t *testing.T) {
	s := New(100)
	_, ok := s.GetTrace("does-not-exist")
	if ok {
		t.Error("expected not ok for missing trace")
	}
}

// ─── Incidents ────────────────────────────────────────────────────────────────

func TestAddListIncident(t *testing.T) {
	s := New(100)
	inc := &models.Incident{IncidentID: "INC-001", Title: "Test", Status: models.IncidentOpen, Severity: "critical"}
	s.AddIncident(inc)
	list := s.ListIncidents("")
	if len(list) != 1 || list[0].IncidentID != "INC-001" {
		t.Errorf("incident not found in list")
	}
}

func TestListIncidents_StatusFilter(t *testing.T) {
	s := New(100)
	s.AddIncident(&models.Incident{IncidentID: "I1", Status: models.IncidentOpen})
	s.AddIncident(&models.Incident{IncidentID: "I2", Status: models.IncidentResolved})
	open := s.ListIncidents("open")
	if len(open) != 1 || open[0].IncidentID != "I1" {
		t.Errorf("expected 1 open incident, got %d", len(open))
	}
}

// ─── Honey-tokens ─────────────────────────────────────────────────────────────

func TestAddDeleteToken(t *testing.T) {
	s := New(100)
	tok := &models.HoneyToken{TokenID: "HT-001", Name: "Test", Enabled: true}
	s.AddToken(tok)
	if _, ok := s.GetToken("HT-001"); !ok {
		t.Error("expected token to exist")
	}
	if !s.DeleteToken("HT-001") {
		t.Error("expected delete to return true")
	}
	if _, ok := s.GetToken("HT-001"); ok {
		t.Error("expected token to be deleted")
	}
}

func TestRecordTrigger_IncrementsCount(t *testing.T) {
	s := New(100)
	tok := &models.HoneyToken{TokenID: "HT-002", Name: "T"}
	s.AddToken(tok)
	s.RecordTrigger(models.HoneyTokenTrigger{TriggerID: "t1", TokenID: "HT-002", TriggeredAt: time.Now()})
	s.RecordTrigger(models.HoneyTokenTrigger{TriggerID: "t2", TokenID: "HT-002", TriggeredAt: time.Now()})
	got, _ := s.GetToken("HT-002")
	if got.TriggerCount != 2 {
		t.Errorf("expected trigger count 2, got %d", got.TriggerCount)
	}
	triggers := s.TokenTriggers("HT-002")
	if len(triggers) != 2 {
		t.Errorf("expected 2 triggers, got %d", len(triggers))
	}
}

// ─── Alerts ───────────────────────────────────────────────────────────────────

func TestAcknowledgeAlert(t *testing.T) {
	s := New(100)
	al := &models.Alert{AlertID: "ALT-001", Status: models.AlertFiring, RuleName: "test", FiredAt: time.Now()}
	s.AddAlert(al)
	if !s.AcknowledgeAlert("ALT-001") {
		t.Error("expected acknowledge to return true")
	}
	list := s.ListAlerts("acknowledged")
	if len(list) != 1 {
		t.Errorf("expected 1 acknowledged alert, got %d", len(list))
	}
}

func TestAcknowledgeAlert_MissingReturnsFalse(t *testing.T) {
	s := New(100)
	if s.AcknowledgeAlert("no-such-id") {
		t.Error("expected false for missing alert")
	}
}

// ─── Topology ─────────────────────────────────────────────────────────────────

func TestTopology_ReturnsAllKnownModules(t *testing.T) {
	s := New(100)
	// Add an event so the store is not empty.
	e := ev("sentinel", "validation_passed", "info", "passed")
	s.AddEvent(e)
	topo := s.Topology()
	if len(topo.Modules) == 0 {
		t.Error("expected topology to contain at least one module")
	}
}
