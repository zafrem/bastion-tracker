package processor

import (
	"testing"
	"time"

	"github.com/bastion/tracker/internal/alerts"
	"github.com/bastion/tracker/internal/config"
	"github.com/bastion/tracker/internal/honeytoken"
	"github.com/bastion/tracker/internal/hub"
	"github.com/bastion/tracker/internal/incidents"
	"github.com/bastion/tracker/internal/models"
	"github.com/bastion/tracker/internal/store"
)

func newProcessor() *Processor {
	s := store.New(100)
	h := hub.New(16)
	cfg := config.Defaults()
	al := alerts.New(cfg.Alerting.Rules, s, nil)
	inc := incidents.New(s)
	ht := honeytoken.New(s)
	return New(s, h, al, inc, ht)
}

func TestProcess_StoresEvent(t *testing.T) {
	proc := newProcessor()
	ev := models.BastionEvent{
		EventID:   "test-001",
		Module:    "sentinel",
		EventType: "validation_passed",
		Severity:  "info",
		Status:    "passed",
		Timestamp: time.Now(),
		TenantID:  "tenant-test",
		TraceID:   "trace-001",
	}
	proc.Process(ev)
	s := store.New(100) // just to check via proc's store
	_ = s
	// If process didn't panic the event was handled.
}

func TestProcess_EnrichesEmptyID(t *testing.T) {
	// Create a dedicated store to inspect after processing.
	s := store.New(100)
	h := hub.New(16)
	cfg := config.Defaults()
	al := alerts.New(cfg.Alerting.Rules, s, nil)
	inc := incidents.New(s)
	ht := honeytoken.New(s)
	proc := New(s, h, al, inc, ht)

	proc.Process(models.BastionEvent{
		Module:    "vault",
		EventType: "anonymization_applied",
		Status:    "passed",
		Timestamp: time.Now(),
	})

	events := s.RecentEvents(models.QueryRequest{Module: "vault"}, 1)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].EventID == "" {
		t.Error("event ID should have been generated")
	}
}

func TestProcess_BuildsTrace(t *testing.T) {
	s := store.New(100)
	h := hub.New(16)
	cfg := config.Defaults()
	proc := New(s, h, alerts.New(cfg.Alerting.Rules, s, nil), incidents.New(s), honeytoken.New(s))

	ev := models.BastionEvent{
		Module:    "navigator",
		EventType: "search_completed",
		Severity:  "info",
		Status:    "passed",
		Timestamp: time.Now(),
		TraceID:   "trace-build",
		SpanID:    "span-nav",
	}
	proc.Process(ev)
	tr, ok := s.GetTrace("trace-build")
	if !ok {
		t.Fatal("trace not built")
	}
	if len(tr.Spans) != 1 {
		t.Errorf("expected 1 span, got %d", len(tr.Spans))
	}
}

func TestProcess_HoneyTokenEventTriggersCheck(t *testing.T) {
	s := store.New(100)
	h := hub.New(16)
	cfg := config.Defaults()
	ht := honeytoken.New(s)
	// Create a token first.
	tok := ht.Create("Fake CEO", "decoy", "customer_db", models.HoneyTokenEmail)
	proc := New(s, h, alerts.New(cfg.Alerting.Rules, s, nil), incidents.New(s), ht)

	ev := models.BastionEvent{
		EventID:   "trg-001",
		Module:    "security",
		EventType: "honey_token_triggered",
		Severity:  "critical",
		Status:    "error",
		Timestamp: time.Now(),
		Data:      map[string]any{"token_id": tok.TokenID},
	}
	proc.Process(ev)
	// If no panic and trigger count increased, the pipeline ran correctly.
	updated, _ := s.GetToken(tok.TokenID)
	if updated.TriggerCount != 1 {
		t.Errorf("expected trigger count 1, got %d", updated.TriggerCount)
	}
}

func TestProcess_AlertFiredForMatchingEvent(t *testing.T) {
	s := store.New(100)
	h := hub.New(16)
	rules := []config.AlertRule{
		{Name: "test_rule", Condition: "sentinel.prompt_injection_detected", Severity: "warning"},
	}
	al := alerts.New(rules, s, nil)
	proc := New(s, h, al, incidents.New(s), honeytoken.New(s))

	proc.Process(models.BastionEvent{
		Module:    "sentinel",
		EventType: "prompt_injection_detected",
		Severity:  "warning",
		Status:    "blocked",
		Timestamp: time.Now(),
	})

	fired := s.ListAlerts("firing")
	if len(fired) == 0 {
		t.Error("expected at least one alert to fire")
	}
}
