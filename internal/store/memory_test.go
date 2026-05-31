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

// ─── DashboardSummary ─────────────────────────────────────────────────────────

func TestDashboardSummary_EmptyStore(t *testing.T) {
	s := New(100)
	sum := s.DashboardSummary()
	if sum.EventCount1h != 0 || sum.EventCount24h != 0 {
		t.Error("empty store should return zero counts")
	}
}

func TestDashboardSummary_CountsEvents1hAnd24h(t *testing.T) {
	s := New(1000)
	// Add 5 recent events.
	for i := 0; i < 5; i++ {
		s.AddEvent(ev("sentinel", "validation_passed", "info", "passed"))
	}
	sum := s.DashboardSummary()
	if sum.EventCount1h != 5 {
		t.Errorf("expected 5 events in 1h, got %d", sum.EventCount1h)
	}
	if sum.EventCount24h != 5 {
		t.Errorf("expected 5 events in 24h, got %d", sum.EventCount24h)
	}
}

func TestDashboardSummary_BlockedRequestCount(t *testing.T) {
	s := New(100)
	s.AddEvent(ev("sentinel", "validation_blocked", "warning", "blocked"))
	s.AddEvent(ev("sentinel", "validation_passed", "info", "passed"))
	sum := s.DashboardSummary()
	if sum.BlockedRequests1h != 1 {
		t.Errorf("expected 1 blocked, got %d", sum.BlockedRequests1h)
	}
}

func TestDashboardSummary_TopModules(t *testing.T) {
	s := New(100)
	// 3 sentinel, 1 vault.
	for i := 0; i < 3; i++ {
		s.AddEvent(ev("sentinel", "e", "info", "passed"))
	}
	s.AddEvent(ev("vault", "e", "info", "passed"))
	sum := s.DashboardSummary()
	if len(sum.TopModules) == 0 {
		t.Fatal("expected top modules")
	}
	if sum.TopModules[0].Module != "sentinel" {
		t.Errorf("expected sentinel first, got %s", sum.TopModules[0].Module)
	}
	if sum.TopModules[0].Count != 3 {
		t.Errorf("expected count 3, got %d", sum.TopModules[0].Count)
	}
}

func TestDashboardSummary_ActiveIncidents(t *testing.T) {
	s := New(100)
	s.AddIncident(&models.Incident{
		IncidentID: "INC-1", Status: models.IncidentOpen, TenantID: "t1",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	s.AddIncident(&models.Incident{
		IncidentID: "INC-2", Status: models.IncidentResolved, TenantID: "t1",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	sum := s.DashboardSummary()
	if sum.ActiveIncidents != 1 {
		t.Errorf("expected 1 active incident, got %d", sum.ActiveIncidents)
	}
}

func TestDashboardSummary_FiringAlerts(t *testing.T) {
	s := New(100)
	now := time.Now()
	s.AddAlert(&models.Alert{AlertID: "a1", Status: models.AlertFiring, FiredAt: now})
	s.AddAlert(&models.Alert{AlertID: "a2", Status: models.AlertResolved, FiredAt: now})
	sum := s.DashboardSummary()
	if sum.FiringAlerts != 1 {
		t.Errorf("expected 1 firing alert, got %d", sum.FiringAlerts)
	}
}

func TestDashboardSummary_HoneyTokenTriggers(t *testing.T) {
	s := New(100)
	s.AddEvent(models.BastionEvent{
		EventID: "h1", Module: "navigator", EventType: "honey_token_retrieved",
		Severity: "critical", Status: "detected", Timestamp: time.Now(),
	})
	s.AddEvent(ev("sentinel", "validation_passed", "info", "passed"))
	sum := s.DashboardSummary()
	if sum.HoneyTokenTriggers != 1 {
		t.Errorf("expected 1 honey-token trigger, got %d", sum.HoneyTokenTriggers)
	}
}

// ─── EventsPage (cursor-based pagination) ─────────────────────────────────────

func TestEventsPage_NoEvents(t *testing.T) {
	s := New(100)
	page := s.EventsPage(models.QueryRequest{}, "", 10)
	if len(page.Events) != 0 {
		t.Errorf("empty store, expected 0 events, got %d", len(page.Events))
	}
	if page.NextCursor != "" {
		t.Error("empty result should have no cursor")
	}
}

func TestEventsPage_LimitRespected(t *testing.T) {
	s := New(200)
	for i := 0; i < 20; i++ {
		s.AddEvent(ev("sentinel", "e", "info", "passed"))
	}
	page := s.EventsPage(models.QueryRequest{}, "", 5)
	if len(page.Events) != 5 {
		t.Errorf("expected 5 events, got %d", len(page.Events))
	}
}

func TestEventsPage_NextCursorSetWhenFull(t *testing.T) {
	s := New(200)
	for i := 0; i < 10; i++ {
		s.AddEvent(models.BastionEvent{
			EventID: "ev-" + string(rune('a'+i)), Module: "sentinel",
			EventType: "e", Severity: "info", Status: "passed", Timestamp: time.Now(),
		})
	}
	page := s.EventsPage(models.QueryRequest{}, "", 5)
	if page.NextCursor == "" {
		t.Error("full page should set NextCursor")
	}
}

func TestEventsPage_CursorPagination(t *testing.T) {
	s := New(200)
	ids := make([]string, 10)
	for i := 0; i < 10; i++ {
		id := "evid-" + string(rune('A'+i))
		ids[i] = id
		s.AddEvent(models.BastionEvent{
			EventID: id, Module: "sentinel", EventType: "e",
			Severity: "info", Status: "passed", Timestamp: time.Now(),
		})
	}
	// Page 1: most recent 5.
	p1 := s.EventsPage(models.QueryRequest{}, "", 5)
	if len(p1.Events) != 5 {
		t.Fatalf("page1: expected 5, got %d", len(p1.Events))
	}
	// Page 2: next 5 after cursor.
	if p1.NextCursor == "" {
		t.Fatal("page1 should have next cursor")
	}
	p2 := s.EventsPage(models.QueryRequest{}, p1.NextCursor, 5)
	// Check no event appears in both pages.
	seen := make(map[string]bool)
	for _, e := range p1.Events {
		seen[e.EventID] = true
	}
	for _, e := range p2.Events {
		if seen[e.EventID] {
			t.Errorf("event %s appears in both pages (cursor not working)", e.EventID)
		}
	}
}

func TestEventsPage_LimitCappedAt200(t *testing.T) {
	s := New(1000)
	for i := 0; i < 500; i++ {
		s.AddEvent(ev("sentinel", "e", "info", "passed"))
	}
	page := s.EventsPage(models.QueryRequest{}, "", 999)
	if len(page.Events) > 200 {
		t.Errorf("limit should be capped at 200, got %d", len(page.Events))
	}
}

// ─── Login audit ──────────────────────────────────────────────────────────────

func TestRecordLogin_StoresEntry(t *testing.T) {
	s := New(100)
	s.RecordLogin(models.LoginAuditEvent{
		Timestamp: time.Now(), Username: "alice", Role: "admin",
		SourceIP: "10.0.0.1", Success: true,
	})
	entries := s.RecentLogins(10)
	if len(entries) != 1 {
		t.Fatalf("expected 1 login entry, got %d", len(entries))
	}
	if entries[0].Username != "alice" {
		t.Errorf("wrong username: %s", entries[0].Username)
	}
}

func TestRecordLogin_MultipleEntries_NewestLast(t *testing.T) {
	s := New(100)
	for _, name := range []string{"alice", "bob", "carol"} {
		s.RecordLogin(models.LoginAuditEvent{
			Timestamp: time.Now(), Username: name, Success: true,
		})
	}
	entries := s.RecentLogins(10)
	if len(entries) != 3 {
		t.Fatalf("expected 3, got %d", len(entries))
	}
	if entries[len(entries)-1].Username != "carol" {
		t.Errorf("newest should be carol, got %s", entries[len(entries)-1].Username)
	}
}

func TestRecordLogin_CapAt10000(t *testing.T) {
	s := New(100)
	for i := 0; i < 10001; i++ {
		s.RecordLogin(models.LoginAuditEvent{Timestamp: time.Now(), Username: "u"})
	}
	entries := s.RecentLogins(20000)
	if len(entries) > 10000 {
		t.Errorf("login audit should cap at 10000, got %d", len(entries))
	}
}

func TestRecordLogin_FailedAttemptRecorded(t *testing.T) {
	s := New(100)
	s.RecordLogin(models.LoginAuditEvent{
		Timestamp: time.Now(), Username: "hacker",
		Success: false, Reason: "invalid credentials",
	})
	entries := s.RecentLogins(5)
	if len(entries) == 0 || entries[0].Success {
		t.Error("failed login should be recorded with Success=false")
	}
}

// ─── PipelineHealth ───────────────────────────────────────────────────────────

func TestPipelineHealth_ReturnsModules(t *testing.T) {
	s := New(100)
	s.AddEvent(ev("sentinel", "e", "info", "passed"))
	health := s.PipelineHealth()
	if len(health.Modules) == 0 {
		t.Error("expected at least one module in pipeline health")
	}
}

// ─── TenantActivity ───────────────────────────────────────────────────────────

func TestTenantActivity_FiltersByTenant(t *testing.T) {
	s := New(100)
	// 3 events for acme-corp, 2 for rival-corp.
	for i := 0; i < 3; i++ {
		e := ev("navigator", "search_completed", "info", "passed")
		e.TenantID = "acme-corp"
		s.AddEvent(e)
	}
	for i := 0; i < 2; i++ {
		e := ev("navigator", "search_completed", "info", "passed")
		e.TenantID = "rival-corp"
		s.AddEvent(e)
	}
	act := s.TenantActivity("acme-corp")
	if act.EventCount1h != 3 {
		t.Errorf("expected 3 events for acme-corp, got %d", act.EventCount1h)
	}
	if act.TenantID != "acme-corp" {
		t.Errorf("wrong tenant in response")
	}
}
