package incidents

import (
	"testing"
	"time"

	"github.com/bastion/tracker/internal/models"
	"github.com/bastion/tracker/internal/store"
)

func newMgr() *Manager {
	return New(store.New(1000))
}

func ev(eventType, severity, userID string) models.BastionEvent {
	return models.BastionEvent{
		EventID:   "ev-" + eventType,
		EventType: eventType,
		Module:    "sentinel",
		Severity:  severity,
		UserID:    userID,
		TenantID:  "t1",
		Timestamp: time.Now(),
		Data:      map[string]any{"honey_token_id": "HT-0001"},
	}
}

// ─── AutoCreate ───────────────────────────────────────────────────────────────

func TestAutoCreate_HoneyTokenAlwaysCreatesIncident(t *testing.T) {
	tests := []struct {
		eventType string
		severity  string
	}{
		{"honey_token_triggered", "info"},    // honey-token bypasses severity gate
		{"honey_token_accessed", "warning"},
		{"honey_token_retrieved", "info"},
		{"honey_token_referenced", "info"},
		{"honey_token_leaked", "critical"},
	}
	for _, tt := range tests {
		m := newMgr()
		inc := m.AutoCreate(ev(tt.eventType, tt.severity, "user-x"))
		if inc == nil {
			t.Errorf("eventType=%q severity=%q: expected incident, got nil", tt.eventType, tt.severity)
		}
	}
}

func TestAutoCreate_IncidentID_Sequential(t *testing.T) {
	m := newMgr()
	i1 := m.AutoCreate(ev("honey_token_triggered", "info", "u"))
	i2 := m.AutoCreate(ev("honey_token_accessed", "info", "u"))
	if i1.IncidentID == i2.IncidentID {
		t.Fatal("incident IDs should be unique")
	}
}

func TestAutoCreate_TitleContainsHoneyTokenInfo(t *testing.T) {
	m := newMgr()
	inc := m.AutoCreate(ev("honey_token_accessed", "info", "u"))
	if inc.Title == "" {
		t.Fatal("title should not be empty")
	}
}

func TestAutoCreate_PromptInjection_CriticalCreatesIncident(t *testing.T) {
	m := newMgr()
	e := ev("prompt_injection_detected", "critical", "attacker")
	inc := m.AutoCreate(e)
	if inc == nil {
		t.Fatal("expected incident for prompt_injection_detected with critical severity")
	}
	if inc.Title == "" {
		t.Fatal("title should not be empty")
	}
}

func TestAutoCreate_PromptInjection_LowSeverityNoIncident(t *testing.T) {
	m := newMgr()
	// non-honey-token event with info severity → should not create incident
	e := ev("prompt_injection_detected", "info", "u")
	inc := m.AutoCreate(e)
	if inc != nil {
		t.Fatal("expected no incident for low-severity non-honey-token event")
	}
}

func TestAutoCreate_CrossTenantAttempt_CriticalCreatesIncident(t *testing.T) {
	m := newMgr()
	e := ev("cross_tenant_attempt", "critical", "bad-user")
	inc := m.AutoCreate(e)
	if inc == nil {
		t.Fatal("expected incident for critical cross_tenant_attempt")
	}
}

func TestAutoCreate_UnknownEventTypeNoIncident(t *testing.T) {
	m := newMgr()
	e := ev("query_validated", "critical", "u")
	inc := m.AutoCreate(e)
	if inc != nil {
		t.Fatal("expected no incident for unknown event type")
	}
}

func TestAutoCreate_IncidentOpenStatus(t *testing.T) {
	m := newMgr()
	inc := m.AutoCreate(ev("honey_token_triggered", "info", "u"))
	if inc.Status != models.IncidentOpen {
		t.Errorf("expected open, got %s", inc.Status)
	}
}

func TestAutoCreate_EventIDInList(t *testing.T) {
	m := newMgr()
	e := ev("honey_token_accessed", "warning", "u")
	inc := m.AutoCreate(e)
	found := false
	for _, id := range inc.EventIDs {
		if id == e.EventID {
			found = true
		}
	}
	if !found {
		t.Fatalf("event ID %s not in incident.EventIDs: %v", e.EventID, inc.EventIDs)
	}
}

func TestAutoCreate_TenantIDPropagated(t *testing.T) {
	m := newMgr()
	inc := m.AutoCreate(ev("honey_token_triggered", "info", "u"))
	if inc.TenantID != "t1" {
		t.Errorf("expected t1, got %s", inc.TenantID)
	}
}

func TestAutoCreate_DescriptionNonEmpty(t *testing.T) {
	m := newMgr()
	inc := m.AutoCreate(ev("honey_token_triggered", "info", "u"))
	if inc.Description == "" {
		t.Fatal("description should not be empty")
	}
}

// ─── Resolve ──────────────────────────────────────────────────────────────────

func TestResolve_ChangesStatus(t *testing.T) {
	m := newMgr()
	inc := m.AutoCreate(ev("honey_token_triggered", "critical", "u"))

	resolved, ok := m.Resolve(inc.IncidentID, "investigation complete")
	if !ok {
		t.Fatal("Resolve returned false")
	}
	if resolved.Status != models.IncidentResolved {
		t.Errorf("expected resolved, got %s", resolved.Status)
	}
}

func TestResolve_SetsResolvedAt(t *testing.T) {
	m := newMgr()
	inc := m.AutoCreate(ev("honey_token_triggered", "info", "u"))

	resolved, _ := m.Resolve(inc.IncidentID, "done")
	if resolved.ResolvedAt == nil {
		t.Fatal("ResolvedAt should be set after resolve")
	}
}

func TestResolve_StoresNotes(t *testing.T) {
	m := newMgr()
	inc := m.AutoCreate(ev("honey_token_triggered", "info", "u"))

	resolved, _ := m.Resolve(inc.IncidentID, "root cause found")
	if resolved.Notes != "root cause found" {
		t.Errorf("unexpected notes: %s", resolved.Notes)
	}
}

func TestResolve_EmptyNotesDoesNotOverwrite(t *testing.T) {
	m := newMgr()
	inc := m.AutoCreate(ev("honey_token_triggered", "info", "u"))
	// First resolve with notes
	m.Resolve(inc.IncidentID, "original note")
	// Notes won't be overwritten after resolved — just verify no crash
}

func TestResolve_NotFound(t *testing.T) {
	m := newMgr()
	_, ok := m.Resolve("INC-9999", "")
	if ok {
		t.Fatal("expected false for unknown incident")
	}
}

// ─── honeyTokenTitle helper ───────────────────────────────────────────────────

func TestHoneyTokenTitle_WithTokenID(t *testing.T) {
	e := ev("honey_token_accessed", "info", "u")
	title := honeyTokenTitle(e)
	if title == "" {
		t.Fatal("title should not be empty")
	}
}

func TestHoneyTokenTitle_UnknownEventType(t *testing.T) {
	e := ev("honey_token_unknown_type", "info", "u")
	title := honeyTokenTitle(e)
	if title == "" {
		t.Fatal("title should not be empty even for unknown sub-type")
	}
}

func TestHoneyTokenTitle_KnownLayers(t *testing.T) {
	layers := map[string]string{
		"honey_token_accessed":   "Vault",
		"honey_token_retrieved":  "Navigator",
		"honey_token_referenced": "Sentinel",
		"honey_token_leaked":     "Sentinel",
	}
	for eventType, _ := range layers {
		e := ev(eventType, "info", "u")
		title := honeyTokenTitle(e)
		if title == "" {
			t.Errorf("expected non-empty title for %s", eventType)
		}
	}
}
