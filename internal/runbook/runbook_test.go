package runbook

import (
	"testing"
)

// ─── New / seed ───────────────────────────────────────────────────────────────

func TestNew_SeedsRunbooks(t *testing.T) {
	m := New()
	if got := m.List(); len(got) == 0 {
		t.Fatal("expected at least one seeded runbook")
	}
}

func TestNew_SeedsSixRunbooks(t *testing.T) {
	m := New()
	if got := m.List(); len(got) != 6 {
		t.Fatalf("expected 6 runbooks, got %d", len(got))
	}
}

// ─── List ─────────────────────────────────────────────────────────────────────

func TestList_ReturnsAll(t *testing.T) {
	m := New()
	books := m.List()
	if len(books) == 0 {
		t.Fatal("expected non-empty list")
	}
}

func TestList_AllHaveIDs(t *testing.T) {
	m := New()
	for _, rb := range m.List() {
		if rb.ID == "" {
			t.Errorf("runbook missing ID: %+v", rb)
		}
	}
}

func TestList_AllHaveNames(t *testing.T) {
	m := New()
	for _, rb := range m.List() {
		if rb.Name == "" {
			t.Errorf("runbook %q missing Name", rb.ID)
		}
	}
}

func TestList_AllHaveSteps(t *testing.T) {
	m := New()
	for _, rb := range m.List() {
		if len(rb.Steps) == 0 {
			t.Errorf("runbook %q has no steps", rb.ID)
		}
	}
}

func TestList_AllHaveTriggers(t *testing.T) {
	m := New()
	for _, rb := range m.List() {
		if len(rb.Triggers) == 0 {
			t.Errorf("runbook %q has no triggers", rb.ID)
		}
	}
}

func TestList_StepsHaveOrders(t *testing.T) {
	m := New()
	for _, rb := range m.List() {
		for _, step := range rb.Steps {
			if step.Order <= 0 {
				t.Errorf("runbook %q step %q has invalid order %d", rb.ID, step.Title, step.Order)
			}
		}
	}
}

// ─── Get ──────────────────────────────────────────────────────────────────────

func TestGet_PromptInjectionFound(t *testing.T) {
	m := New()
	rb, ok := m.Get("rb-prompt-injection")
	if !ok {
		t.Fatal("expected to find rb-prompt-injection")
	}
	if rb.ID != "rb-prompt-injection" {
		t.Errorf("unexpected ID: %s", rb.ID)
	}
}

func TestGet_HoneyTokenFound(t *testing.T) {
	m := New()
	_, ok := m.Get("rb-honey-token")
	if !ok {
		t.Fatal("expected to find rb-honey-token")
	}
}

func TestGet_CrossTenantFound(t *testing.T) {
	m := New()
	_, ok := m.Get("rb-cross-tenant")
	if !ok {
		t.Fatal("expected to find rb-cross-tenant")
	}
}

func TestGet_NotFound(t *testing.T) {
	m := New()
	_, ok := m.Get("rb-does-not-exist")
	if ok {
		t.Fatal("expected not found for unknown ID")
	}
}

func TestGet_ReturnedFieldsPopulated(t *testing.T) {
	m := New()
	rb, ok := m.Get("rb-prompt-injection")
	if !ok {
		t.Fatal("expected to find rb-prompt-injection")
	}
	if rb.Category == "" {
		t.Error("expected non-empty Category")
	}
	if rb.Severity == "" {
		t.Error("expected non-empty Severity")
	}
	if rb.EstimatedMinutes == 0 {
		t.Error("expected non-zero EstimatedMinutes")
	}
}

// ─── ForAlert ─────────────────────────────────────────────────────────────────

func TestForAlert_MatchesByTriggerName(t *testing.T) {
	m := New()
	books := m.ForAlert("prompt_injection_detected")
	if len(books) == 0 {
		t.Fatal("expected at least one runbook for prompt_injection_detected")
	}
}

func TestForAlert_HoneyTokenTriggered(t *testing.T) {
	m := New()
	books := m.ForAlert("honey_token_triggered")
	if len(books) == 0 {
		t.Fatal("expected runbooks for honey_token_triggered")
	}
}

func TestForAlert_CrossTenantAttempt(t *testing.T) {
	m := New()
	books := m.ForAlert("cross_tenant_attempt")
	if len(books) == 0 {
		t.Fatal("expected runbooks for cross_tenant_attempt")
	}
}

func TestForAlert_WildcardMatchesAll(t *testing.T) {
	m := New()
	// "any_critical_event" and "*" triggers should match any rule name with wildcard
	// The rb-high-error-rate runbook has Triggers: {"any_critical_event", "*"}
	books := m.ForAlert("anything_goes")
	// At least rb-high-error-rate should match due to "*"
	if len(books) == 0 {
		t.Fatal("expected wildcard runbook to match any alert name")
	}
}

func TestForAlert_AnyRuleNameMatchesWildcard(t *testing.T) {
	m := New()
	books := m.ForAlert("my_custom_alert")
	found := false
	for _, rb := range books {
		if rb.ID == "rb-high-error-rate" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected rb-high-error-rate (wildcard *) to match custom alert names")
	}
}

func TestForAlert_ModuleDegradedOnlyMatchesSpecificRunbook(t *testing.T) {
	m := New()
	books := m.ForAlert("module_degraded")
	// rb-module-degraded should be in results (exact trigger match).
	found := false
	for _, rb := range books {
		if rb.ID == "rb-module-degraded" {
			found = true
		}
	}
	if !found {
		t.Error("expected rb-module-degraded in ForAlert(\"module_degraded\")")
	}
}

func TestForAlert_SpecificTriggerDoesNotMatchUnrelatedRunbook(t *testing.T) {
	m := New()
	// "prompt_injection_detected" should not match rb-cross-tenant or rb-module-degraded.
	books := m.ForAlert("prompt_injection_detected")
	for _, rb := range books {
		if rb.ID == "rb-cross-tenant" || rb.ID == "rb-module-degraded" {
			t.Errorf("runbook %q should not match prompt_injection_detected", rb.ID)
		}
	}
}

func TestForAlert_ReturnsCorrectRunbook(t *testing.T) {
	m := New()
	books := m.ForAlert("bypass_anomaly_detected")
	if len(books) == 0 {
		t.Fatal("expected runbooks for bypass_anomaly_detected")
	}
	found := false
	for _, rb := range books {
		if rb.ID == "rb-bypass-anomaly" {
			found = true
		}
	}
	if !found {
		t.Error("expected rb-bypass-anomaly in results")
	}
}
