package alerts

import (
	"testing"
	"time"

	"github.com/bastion/tracker/internal/config"
	"github.com/bastion/tracker/internal/models"
	"github.com/bastion/tracker/internal/store"
)

func newMgr(rules []config.AlertRule) *Manager {
	return New(rules, store.New(1000), nil)
}

func ev(module, eventType, severity string) models.BastionEvent {
	return models.BastionEvent{
		EventID:   "ev-" + eventType,
		Module:    module,
		EventType: eventType,
		Severity:  severity,
		Status:    "passed",
		TenantID:  "t1",
		Timestamp: time.Now(),
	}
}

func rule(name, condition, severity string) config.AlertRule {
	return config.AlertRule{Name: name, Condition: condition, Severity: severity}
}

// ─── Evaluate — matching ──────────────────────────────────────────────────────

func TestEvaluate_NoRulesReturnsEmpty(t *testing.T) {
	m := newMgr(nil)
	alerts := m.Evaluate(ev("sentinel", "query_validated", "info"))
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts with no rules, got %d", len(alerts))
	}
}

func TestEvaluate_ExactModuleDotEventType(t *testing.T) {
	m := newMgr([]config.AlertRule{rule("r1", "sentinel.prompt_injection_detected", "warning")})
	alerts := m.Evaluate(ev("sentinel", "prompt_injection_detected", "warning"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
}

func TestEvaluate_ExactNoMatchModule(t *testing.T) {
	m := newMgr([]config.AlertRule{rule("r1", "sentinel.prompt_injection_detected", "warning")})
	alerts := m.Evaluate(ev("vault", "prompt_injection_detected", "warning"))
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts for wrong module, got %d", len(alerts))
	}
}

func TestEvaluate_ExactNoMatchEventType(t *testing.T) {
	m := newMgr([]config.AlertRule{rule("r1", "sentinel.prompt_injection_detected", "warning")})
	alerts := m.Evaluate(ev("sentinel", "query_validated", "warning"))
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts for wrong event type, got %d", len(alerts))
	}
}

func TestEvaluate_WildcardModule(t *testing.T) {
	m := newMgr([]config.AlertRule{rule("r1", "*.cross_tenant_attempt", "warning")})
	// Should match any module with this event type
	alerts := m.Evaluate(ev("vault", "cross_tenant_attempt", "warning"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for wildcard module, got %d", len(alerts))
	}
}

func TestEvaluate_WildcardEventType(t *testing.T) {
	m := newMgr([]config.AlertRule{rule("r1", "navigator.*", "info")})
	alerts := m.Evaluate(ev("navigator", "anything", "info"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for wildcard event type, got %d", len(alerts))
	}
}

func TestEvaluate_SeverityCondition(t *testing.T) {
	m := newMgr([]config.AlertRule{rule("r1", "severity:critical", "critical")})
	alerts := m.Evaluate(ev("sentinel", "any_event", "critical"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for severity:critical, got %d", len(alerts))
	}
}

func TestEvaluate_SeverityConditionNoMatch(t *testing.T) {
	m := newMgr([]config.AlertRule{rule("r1", "severity:critical", "critical")})
	alerts := m.Evaluate(ev("sentinel", "any_event", "info"))
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts — severity info does not match severity:critical, got %d", len(alerts))
	}
}

func TestEvaluate_StatusCondition(t *testing.T) {
	m := newMgr([]config.AlertRule{rule("r1", "status:blocked", "warning")})
	e := ev("sentinel", "any_event", "info")
	e.Status = "blocked"
	alerts := m.Evaluate(e)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for status:blocked, got %d", len(alerts))
	}
}

func TestEvaluate_BareEventType(t *testing.T) {
	m := newMgr([]config.AlertRule{rule("r1", "honey_token_triggered", "critical")})
	alerts := m.Evaluate(ev("vault", "honey_token_triggered", "critical"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for bare event_type, got %d", len(alerts))
	}
}

func TestEvaluate_MultipleRulesAllFire(t *testing.T) {
	m := newMgr([]config.AlertRule{
		rule("r1", "sentinel.prompt_injection_detected", "warning"),
		rule("r2", "severity:warning", "warning"),
	})
	alerts := m.Evaluate(ev("sentinel", "prompt_injection_detected", "warning"))
	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts (both rules match), got %d", len(alerts))
	}
}

func TestEvaluate_MultipleRulesOnlyOneFires(t *testing.T) {
	m := newMgr([]config.AlertRule{
		rule("r1", "sentinel.prompt_injection_detected", "warning"),
		rule("r2", "vault.cross_tenant_attempt", "critical"),
	})
	alerts := m.Evaluate(ev("sentinel", "prompt_injection_detected", "warning"))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].RuleName != "r1" {
		t.Errorf("expected r1, got %s", alerts[0].RuleName)
	}
}

// ─── Evaluate — alert fields ──────────────────────────────────────────────────

func TestEvaluate_AlertIDNonEmpty(t *testing.T) {
	m := newMgr([]config.AlertRule{rule("r1", "sentinel.*", "info")})
	alerts := m.Evaluate(ev("sentinel", "any", "info"))
	if alerts[0].AlertID == "" {
		t.Fatal("expected non-empty AlertID")
	}
}

func TestEvaluate_AlertIDsAreSequential(t *testing.T) {
	m := newMgr([]config.AlertRule{
		rule("r1", "sentinel.*", "info"),
		rule("r2", "sentinel.*", "info"),
	})
	alerts := m.Evaluate(ev("sentinel", "any", "info"))
	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts, got %d", len(alerts))
	}
	if alerts[0].AlertID == alerts[1].AlertID {
		t.Error("alert IDs should be unique")
	}
}

func TestEvaluate_AlertRuleName(t *testing.T) {
	m := newMgr([]config.AlertRule{rule("my-rule", "sentinel.*", "warning")})
	alerts := m.Evaluate(ev("sentinel", "any", "warning"))
	if alerts[0].RuleName != "my-rule" {
		t.Errorf("expected RuleName=my-rule, got %s", alerts[0].RuleName)
	}
}

func TestEvaluate_AlertSeverityCopiedFromRule(t *testing.T) {
	m := newMgr([]config.AlertRule{rule("r1", "sentinel.*", "critical")})
	alerts := m.Evaluate(ev("sentinel", "any", "info"))
	if alerts[0].Severity != "critical" {
		t.Errorf("alert severity should come from rule, got %s", alerts[0].Severity)
	}
}

func TestEvaluate_AlertStatusFiring(t *testing.T) {
	m := newMgr([]config.AlertRule{rule("r1", "sentinel.*", "info")})
	alerts := m.Evaluate(ev("sentinel", "any", "info"))
	if alerts[0].Status != models.AlertFiring {
		t.Errorf("new alert status should be Firing, got %s", alerts[0].Status)
	}
}

func TestEvaluate_AlertModulePropagated(t *testing.T) {
	m := newMgr([]config.AlertRule{rule("r1", "navigator.*", "info")})
	alerts := m.Evaluate(ev("navigator", "search", "info"))
	if alerts[0].Module != "navigator" {
		t.Errorf("expected module=navigator, got %s", alerts[0].Module)
	}
}

func TestEvaluate_AlertTenantPropagated(t *testing.T) {
	m := newMgr([]config.AlertRule{rule("r1", "sentinel.*", "info")})
	e := ev("sentinel", "any", "info")
	e.TenantID = "tenant-xyz"
	alerts := m.Evaluate(e)
	if alerts[0].TenantID != "tenant-xyz" {
		t.Errorf("expected TenantID=tenant-xyz, got %s", alerts[0].TenantID)
	}
}

func TestEvaluate_AlertMessageNonEmpty(t *testing.T) {
	m := newMgr([]config.AlertRule{rule("r1", "sentinel.*", "info")})
	alerts := m.Evaluate(ev("sentinel", "any", "info"))
	if alerts[0].Message == "" {
		t.Error("alert message should not be empty")
	}
}

func TestEvaluate_AlertStoredInStore(t *testing.T) {
	s := store.New(1000)
	m := New([]config.AlertRule{rule("r1", "sentinel.*", "warning")}, s, nil)
	m.Evaluate(ev("sentinel", "any", "warning"))

	stored := s.ListAlerts("")
	if len(stored) != 1 {
		t.Fatalf("expected 1 stored alert, got %d", len(stored))
	}
}

// ─── matches ──────────────────────────────────────────────────────────────────

func TestMatches_SeverityInfo(t *testing.T) {
	e := ev("sentinel", "query_validated", "info")
	if !matches("severity:info", e) {
		t.Error("severity:info should match info event")
	}
}

func TestMatches_SeverityMismatch(t *testing.T) {
	e := ev("sentinel", "query_validated", "info")
	if matches("severity:critical", e) {
		t.Error("severity:critical should not match info event")
	}
}

func TestMatches_StatusBlocked(t *testing.T) {
	e := ev("sentinel", "query_validated", "info")
	e.Status = "blocked"
	if !matches("status:blocked", e) {
		t.Error("status:blocked should match blocked event")
	}
}

func TestMatches_BothWildcard(t *testing.T) {
	e := ev("anything", "anything", "info")
	if !matches("*.*", e) {
		t.Error("*.* should match everything")
	}
}

func TestMatches_BareEventTypeMatch(t *testing.T) {
	e := ev("vault", "honey_token_triggered", "critical")
	if !matches("honey_token_triggered", e) {
		t.Error("bare event_type should match regardless of module")
	}
}

func TestMatches_BareEventTypeMismatch(t *testing.T) {
	e := ev("vault", "query_validated", "info")
	if matches("honey_token_triggered", e) {
		t.Error("bare event_type should not match different event type")
	}
}
