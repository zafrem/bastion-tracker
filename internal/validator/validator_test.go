package validator

import (
	"testing"
	"time"

	"github.com/bastion/tracker/internal/models"
)

func valid() *models.BastionEvent {
	return &models.BastionEvent{
		EventID:   "ev-1",
		EventType: "query_validated",
		Module:    "sentinel",
		Severity:  "info",
		Status:    "passed",
		Timestamp: time.Now(),
	}
}

// ─── Validate ─────────────────────────────────────────────────────────────────

func TestValidate_ValidEvent(t *testing.T) {
	v := New()
	if err := v.Validate(valid()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_MissingEventType(t *testing.T) {
	v := New()
	ev := valid()
	ev.EventType = ""
	if err := v.Validate(ev); err == nil {
		t.Fatal("expected error for missing event_type")
	}
}

func TestValidate_WhitespaceEventType(t *testing.T) {
	v := New()
	ev := valid()
	ev.EventType = "   "
	if err := v.Validate(ev); err == nil {
		t.Fatal("expected error for whitespace-only event_type")
	}
}

func TestValidate_MissingModule(t *testing.T) {
	v := New()
	ev := valid()
	ev.Module = ""
	if err := v.Validate(ev); err == nil {
		t.Fatal("expected error for missing module")
	}
}

func TestValidate_EmptySeverityAllowed(t *testing.T) {
	// Empty severity is valid (processor defaults it to "info").
	v := New()
	ev := valid()
	ev.Severity = ""
	if err := v.Validate(ev); err != nil {
		t.Fatalf("empty severity should be allowed: %v", err)
	}
}

func TestValidate_ValidSeverities(t *testing.T) {
	v := New()
	for _, sev := range []string{"info", "warning", "error", "critical"} {
		ev := valid()
		ev.Severity = sev
		if err := v.Validate(ev); err != nil {
			t.Errorf("severity %q should be valid: %v", sev, err)
		}
	}
}

func TestValidate_InvalidSeverity(t *testing.T) {
	v := New()
	ev := valid()
	ev.Severity = "debug"
	if err := v.Validate(ev); err == nil {
		t.Fatal("expected error for invalid severity 'debug'")
	}
}

func TestValidate_EmptyStatusAllowed(t *testing.T) {
	v := New()
	ev := valid()
	ev.Status = ""
	if err := v.Validate(ev); err != nil {
		t.Fatalf("empty status should be allowed: %v", err)
	}
}

func TestValidate_ValidStatuses(t *testing.T) {
	v := New()
	for _, st := range []string{"passed", "blocked", "error", "pending", "in_progress"} {
		ev := valid()
		ev.Status = st
		if err := v.Validate(ev); err != nil {
			t.Errorf("status %q should be valid: %v", st, err)
		}
	}
}

func TestValidate_InvalidStatus(t *testing.T) {
	v := New()
	ev := valid()
	ev.Status = "unknown_status"
	if err := v.Validate(ev); err == nil {
		t.Fatal("expected error for invalid status")
	}
}

// ─── Reject / Dead-letter ─────────────────────────────────────────────────────

func TestReject_AddsToDeadLetters(t *testing.T) {
	v := New()
	ev := *valid()
	v.Reject(ev, "test reason")

	dl := v.DeadLetters()
	if len(dl) != 1 {
		t.Fatalf("expected 1 dead-letter, got %d", len(dl))
	}
}

func TestReject_ReasonStored(t *testing.T) {
	v := New()
	v.Reject(*valid(), "bad event: missing field")

	dl := v.DeadLetters()
	if dl[0].Reason != "bad event: missing field" {
		t.Errorf("unexpected reason: %s", dl[0].Reason)
	}
}

func TestReject_RawJSONStored(t *testing.T) {
	v := New()
	v.Reject(*valid(), "reason")
	dl := v.DeadLetters()
	if len(dl[0].Raw) == 0 {
		t.Fatal("expected non-empty raw JSON")
	}
}

func TestDeadLetters_NewestFirst(t *testing.T) {
	v := New()
	ev1 := *valid()
	ev1.EventID = "first"
	ev2 := *valid()
	ev2.EventID = "second"
	v.Reject(ev1, "r1")
	v.Reject(ev2, "r2")

	dl := v.DeadLetters()
	if len(dl) != 2 {
		t.Fatalf("expected 2, got %d", len(dl))
	}
	// Newest first: ev2 should be at index 0.
	if dl[0].Reason != "r2" {
		t.Errorf("expected r2 at index 0, got %q", dl[0].Reason)
	}
}

func TestDeadLetters_CapsAtMaxSize(t *testing.T) {
	v := New()
	for i := 0; i < maxDeadLetters+50; i++ {
		ev := *valid()
		v.Reject(ev, "overflow")
	}
	dl := v.DeadLetters()
	if len(dl) > maxDeadLetters {
		t.Fatalf("expected ≤%d dead-letters, got %d", maxDeadLetters, len(dl))
	}
}

func TestDeadLetters_Empty(t *testing.T) {
	v := New()
	if dl := v.DeadLetters(); len(dl) != 0 {
		t.Fatalf("expected empty, got %d", len(dl))
	}
}
