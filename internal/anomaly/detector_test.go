package anomaly

import (
	"testing"
	"time"

	"github.com/bastion/tracker/internal/config"
	"github.com/bastion/tracker/internal/models"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

type collectingSink struct {
	events []models.AnomalyEvent
}

func (c *collectingSink) OnAnomaly(ev models.AnomalyEvent) {
	c.events = append(c.events, ev)
}

func defaultCfg() config.AnomalyConfig {
	return config.AnomalyConfig{
		Enabled:             true,
		SigmaThreshold:      3.0,
		WindowHours:         1,
		HighFreqUserLimit:   5,
		RepeatedBlockWindow: "5m",
		RepeatedBlockCount:  3,
	}
}

func ev(module, eventType, status, tenantID, userID, traceID string) models.BastionEvent {
	return models.BastionEvent{
		EventID:   newID(),
		Module:    module,
		EventType: eventType,
		Status:    status,
		TenantID:  tenantID,
		UserID:    userID,
		TraceID:   traceID,
		Timestamp: time.Now(),
	}
}

// ─── Disabled detector ────────────────────────────────────────────────────────

func TestDetector_Disabled_NoFire(t *testing.T) {
	sink := &collectingSink{}
	cfg := defaultCfg()
	cfg.Enabled = false
	d := New(cfg, sink)

	for i := 0; i < 100; i++ {
		d.Inspect(ev("sentinel", "input_validated", "blocked", "t1", "u1", "tr1"))
	}
	if len(sink.events) > 0 {
		t.Fatalf("disabled detector fired %d events", len(sink.events))
	}
}

// ─── High-frequency user ──────────────────────────────────────────────────────

func TestDetector_HighFreqUser_FiresAtLimit(t *testing.T) {
	sink := &collectingSink{}
	cfg := defaultCfg()
	cfg.HighFreqUserLimit = 5
	d := New(cfg, sink)

	for i := 0; i < 5; i++ {
		d.Inspect(ev("navigator", "search_completed", "passed", "acme", "joe", ""))
	}

	hf := anomalyByPattern(sink.events, "high_freq_user")
	if len(hf) == 0 {
		t.Fatal("expected high_freq_user anomaly, got none")
	}
}

func TestDetector_HighFreqUser_DoesNotFireBeforeLimit(t *testing.T) {
	sink := &collectingSink{}
	cfg := defaultCfg()
	cfg.HighFreqUserLimit = 5
	d := New(cfg, sink)

	for i := 0; i < 4; i++ {
		d.Inspect(ev("navigator", "search_completed", "passed", "acme", "joe", ""))
	}

	if len(anomalyByPattern(sink.events, "high_freq_user")) != 0 {
		t.Fatal("should not fire before limit")
	}
}

func TestDetector_HighFreqUser_DifferentUsersIsolated(t *testing.T) {
	sink := &collectingSink{}
	cfg := defaultCfg()
	cfg.HighFreqUserLimit = 3
	d := New(cfg, sink)

	// Two different users each get 2 requests — neither should fire alone.
	for _, uid := range []string{"alice", "bob"} {
		for i := 0; i < 2; i++ {
			d.Inspect(ev("navigator", "search_completed", "passed", "acme", uid, ""))
		}
	}
	if len(anomalyByPattern(sink.events, "high_freq_user")) != 0 {
		t.Fatal("different users should not aggregate")
	}
}

func TestDetector_HighFreqUser_NoUserID_NoFire(t *testing.T) {
	sink := &collectingSink{}
	d := New(defaultCfg(), sink)
	for i := 0; i < 100; i++ {
		d.Inspect(ev("sentinel", "input_validated", "passed", "acme", "", ""))
	}
	if len(anomalyByPattern(sink.events, "high_freq_user")) != 0 {
		t.Fatal("empty user_id should not trigger high-freq rule")
	}
}

// ─── Repeated block ───────────────────────────────────────────────────────────

func TestDetector_RepeatedBlock_FiresAtThreshold(t *testing.T) {
	sink := &collectingSink{}
	cfg := defaultCfg()
	cfg.RepeatedBlockCount = 3
	cfg.RepeatedBlockWindow = "5m"
	d := New(cfg, sink)

	for i := 0; i < 3; i++ {
		d.Inspect(ev("sentinel", "input_validated", "blocked", "acme", "attacker", ""))
	}

	if len(anomalyByPattern(sink.events, "repeated_block")) == 0 {
		t.Fatal("expected repeated_block anomaly")
	}
}

func TestDetector_RepeatedBlock_MustBeBlocked(t *testing.T) {
	sink := &collectingSink{}
	cfg := defaultCfg()
	cfg.RepeatedBlockCount = 2
	d := New(cfg, sink)

	// Status "passed" should not count toward the block window.
	for i := 0; i < 10; i++ {
		d.Inspect(ev("sentinel", "input_validated", "passed", "acme", "user1", ""))
	}
	if len(anomalyByPattern(sink.events, "repeated_block")) != 0 {
		t.Fatal("passed events must not trigger repeated_block")
	}
}

func TestDetector_RepeatedBlock_SeverityIsCritical(t *testing.T) {
	sink := &collectingSink{}
	cfg := defaultCfg()
	cfg.RepeatedBlockCount = 2
	d := New(cfg, sink)

	for i := 0; i < 2; i++ {
		d.Inspect(ev("sentinel", "input_validated", "blocked", "acme", "bad_actor", ""))
	}

	hits := anomalyByPattern(sink.events, "repeated_block")
	if len(hits) == 0 {
		t.Fatal("no anomaly")
	}
	if hits[0].Severity != "critical" {
		t.Fatalf("expected critical, got %s", hits[0].Severity)
	}
}

// ─── Cross-tenant signal ──────────────────────────────────────────────────────

func TestDetector_CrossTenant_AlwaysFires(t *testing.T) {
	sink := &collectingSink{}
	d := New(defaultCfg(), sink)

	d.Inspect(ev("vault", "cross_tenant_attempt", "error", "acme", "u1", "tr1"))

	hits := anomalyByPattern(sink.events, "cross_tenant_signal")
	if len(hits) == 0 {
		t.Fatal("expected cross_tenant_signal anomaly")
	}
	if hits[0].Severity != "critical" {
		t.Fatalf("expected critical, got %s", hits[0].Severity)
	}
}

func TestDetector_CrossTenant_OtherEventsDontFire(t *testing.T) {
	sink := &collectingSink{}
	d := New(defaultCfg(), sink)

	d.Inspect(ev("vault", "pii_tokenized", "passed", "acme", "u1", "tr1"))

	if len(anomalyByPattern(sink.events, "cross_tenant_signal")) != 0 {
		t.Fatal("should not fire on non-cross-tenant events")
	}
}

// ─── Honey-token multi-layer ──────────────────────────────────────────────────

func TestDetector_HoneyMultiLayer_FiresOn2Modules(t *testing.T) {
	sink := &collectingSink{}
	d := New(defaultCfg(), sink)

	// Same trace_id, two different modules.
	d.Inspect(models.BastionEvent{
		EventID: newID(), Module: "sentinel", EventType: "honey_token_referenced",
		TenantID: "t1", UserID: "u1", TraceID: "trace-001", Timestamp: time.Now(),
	})
	d.Inspect(models.BastionEvent{
		EventID: newID(), Module: "navigator", EventType: "honey_token_retrieved",
		TenantID: "t1", UserID: "u1", TraceID: "trace-001", Timestamp: time.Now(),
	})

	hits := anomalyByPattern(sink.events, "honey_multi_layer")
	if len(hits) == 0 {
		t.Fatal("expected honey_multi_layer anomaly on 2 modules")
	}
	if hits[0].Severity != "critical" {
		t.Fatalf("expected critical, got %s", hits[0].Severity)
	}
}

func TestDetector_HoneyMultiLayer_SingleModuleNoFire(t *testing.T) {
	sink := &collectingSink{}
	d := New(defaultCfg(), sink)

	// Same module twice on same trace.
	for i := 0; i < 3; i++ {
		d.Inspect(models.BastionEvent{
			EventID: newID(), Module: "navigator", EventType: "honey_token_retrieved",
			TenantID: "t1", TraceID: "trace-002", Timestamp: time.Now(),
		})
	}
	if len(anomalyByPattern(sink.events, "honey_multi_layer")) != 0 {
		t.Fatal("same module repeated should not trigger multi-layer rule")
	}
}

func TestDetector_HoneyMultiLayer_DifferentTraces_NoFire(t *testing.T) {
	sink := &collectingSink{}
	d := New(defaultCfg(), sink)

	// Different traces — each trace only has one module.
	d.Inspect(models.BastionEvent{
		EventID: newID(), Module: "sentinel", EventType: "honey_token_referenced",
		TenantID: "t1", TraceID: "traceA", Timestamp: time.Now(),
	})
	d.Inspect(models.BastionEvent{
		EventID: newID(), Module: "navigator", EventType: "honey_token_retrieved",
		TenantID: "t1", TraceID: "traceB", Timestamp: time.Now(),
	})
	if len(anomalyByPattern(sink.events, "honey_multi_layer")) != 0 {
		t.Fatal("different traces must not aggregate for multi-layer detection")
	}
}

// ─── Off-hours access ─────────────────────────────────────────────────────────

func TestDetector_OffHours_FiresOutsideWindow(t *testing.T) {
	sink := &collectingSink{}
	cfg := defaultCfg()
	cfg.ActiveHoursStart = 9
	cfg.ActiveHoursEnd = 18
	d := New(cfg, sink)

	// Craft a timestamp at 3am.
	at := time.Date(2026, 6, 1, 3, 0, 0, 0, time.UTC)
	e := ev("navigator", "search_completed", "passed", "acme", "u1", "")
	e.Timestamp = at
	d.Inspect(e)

	if len(anomalyByPattern(sink.events, "off_hours_access")) == 0 {
		t.Fatal("expected off_hours_access at 3am")
	}
}

func TestDetector_OffHours_NoFireInsideWindow(t *testing.T) {
	sink := &collectingSink{}
	cfg := defaultCfg()
	cfg.ActiveHoursStart = 9
	cfg.ActiveHoursEnd = 18
	d := New(cfg, sink)

	at := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC) // 2pm
	e := ev("navigator", "search_completed", "passed", "acme", "u1", "")
	e.Timestamp = at
	d.Inspect(e)

	if len(anomalyByPattern(sink.events, "off_hours_access")) != 0 {
		t.Fatal("should not fire at 2pm within active window")
	}
}

func TestDetector_OffHours_Disabled_NoFire(t *testing.T) {
	sink := &collectingSink{}
	cfg := defaultCfg()
	cfg.ActiveHoursStart = 0 // both zero = disabled
	cfg.ActiveHoursEnd = 0
	d := New(cfg, sink)

	at := time.Date(2026, 6, 1, 2, 0, 0, 0, time.UTC)
	e := ev("navigator", "search_completed", "passed", "acme", "u1", "")
	e.Timestamp = at
	d.Inspect(e)

	if len(anomalyByPattern(sink.events, "off_hours_access")) != 0 {
		t.Fatal("off-hours check should be disabled when both hours are 0")
	}
}

// ─── Recent / Baselines ───────────────────────────────────────────────────────

func TestDetector_Recent_ReturnsLast24h(t *testing.T) {
	sink := &collectingSink{}
	d := New(defaultCfg(), sink)

	d.Inspect(ev("vault", "cross_tenant_attempt", "error", "t1", "u1", "tr1"))
	d.Inspect(ev("vault", "cross_tenant_attempt", "error", "t2", "u2", "tr2"))

	recent := d.Recent()
	if len(recent) < 2 {
		t.Fatalf("expected >= 2 recent events, got %d", len(recent))
	}
}

func TestDetector_Baselines_ReturnsList(t *testing.T) {
	sink := &collectingSink{}
	d := New(defaultCfg(), sink)
	bl := d.Baselines()
	// May be empty initially — just check it doesn't panic.
	_ = bl
}

func TestDetector_DetectedEventsStored(t *testing.T) {
	sink := &collectingSink{}
	cfg := defaultCfg()
	cfg.RepeatedBlockCount = 2
	d := New(cfg, sink)

	for i := 0; i < 2; i++ {
		d.Inspect(ev("sentinel", "input_validated", "blocked", "acme", "x", ""))
	}

	if len(sink.events) == 0 {
		t.Fatal("sink received no anomaly events")
	}
	if len(d.Recent()) == 0 {
		t.Fatal("detector.Recent() should include stored events")
	}
}

// ─── helper ───────────────────────────────────────────────────────────────────

func anomalyByPattern(events []models.AnomalyEvent, pattern string) []models.AnomalyEvent {
	var out []models.AnomalyEvent
	for _, e := range events {
		if e.Pattern == pattern {
			out = append(out, e)
		}
	}
	return out
}
