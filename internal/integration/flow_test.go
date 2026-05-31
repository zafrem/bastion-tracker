// Package integration_test drives a realistic multi-module event sequence
// through the REAL Tracker components (store + processor + anomaly detector +
// honey-token manager + incidents + audit signer) and asserts that the full
// observability and management flow behaves end-to-end.
//
// Unlike the per-package unit tests, this wires the components together exactly
// as cmd/tracker-cli does, so it catches integration regressions between the
// event pipeline, lineage reconstruction, anomaly detection, and the dashboard.
package integration_test

import (
	"testing"
	"time"

	"github.com/bastion/tracker/internal/alerts"
	"github.com/bastion/tracker/internal/anomaly"
	"github.com/bastion/tracker/internal/audit"
	"github.com/bastion/tracker/internal/config"
	"github.com/bastion/tracker/internal/honeytoken"
	"github.com/bastion/tracker/internal/hub"
	"github.com/bastion/tracker/internal/incidents"
	"github.com/bastion/tracker/internal/models"
	"github.com/bastion/tracker/internal/processor"
	"github.com/bastion/tracker/internal/store"
)

// rig bundles the wired-together Tracker stack for a test.
type rig struct {
	store   *store.Store
	proc    *processor.Processor
	signer  *audit.Signer
	anomaly *anomaly.Detector
	hub     *hub.Hub
	anomalies []models.AnomalyEvent
}

// collectingSink captures anomalies AND re-feeds them into the processor,
// mirroring the anomalySink wiring in cmd/tracker-cli/main.go.
type collectingSink struct {
	rig  *rig
	proc *processor.Processor
}

func (c *collectingSink) OnAnomaly(ev models.AnomalyEvent) {
	c.rig.anomalies = append(c.rig.anomalies, ev)
	// Re-enter the pipeline as a synthetic security event (triggers incidents).
	c.proc.Process(models.BastionEvent{
		Module: "tracker", EventType: "anomaly_detected",
		Severity: ev.Severity, Status: "error",
		TenantID: ev.TenantID, UserID: ev.UserID, TraceID: ev.TraceID,
		Timestamp: time.Now(),
		Data: map[string]any{
			"anomaly_id": ev.AnomalyID, "pattern": ev.Pattern,
		},
	})
}

func newRig(t *testing.T) *rig {
	t.Helper()
	s := store.New(10000)
	h := hub.New(64)
	cfg := config.Defaults()
	al := alerts.New(cfg.Alerting.Rules, s, nil)
	inc := incidents.New(s)
	ht := honeytoken.New(s)
	ht.SeedDefaults() // HT-0001..HT-0003

	proc := processor.New(s, h, al, inc, ht)

	signer := audit.New("integration-test-key")
	proc.SetSigner(signer)

	r := &rig{store: s, proc: proc, signer: signer, hub: h}

	anomalyCfg := cfg.Anomaly
	anomalyCfg.Enabled = true
	det := anomaly.New(anomalyCfg, &collectingSink{rig: r, proc: proc})
	proc.AddHook(func(ev models.BastionEvent) { det.Inspect(ev) })
	r.anomaly = det

	return r
}

// ─── Helpers to build pipeline events ─────────────────────────────────────────

func evt(module, eventType, status, traceID, tenant, user string) models.BastionEvent {
	return models.BastionEvent{
		EventID:   "",
		Module:    module,
		EventType: eventType,
		Severity:  "info",
		Status:    status,
		Timestamp: time.Now(),
		TraceID:   traceID,
		TenantID:  tenant,
		UserID:    user,
		SpanID:    module + "-span",
	}
}

// ─── Flow 1: Normal pipeline trace → lineage reconstruction ───────────────────

func TestFlow_NormalPipeline_LineageReconstructed(t *testing.T) {
	r := newRig(t)
	trace := "trace-normal-001"

	// Simulate a full pipeline: Sentinel → Vault → Navigator (2 chunks) → Anchor.
	r.proc.Process(evt("sentinel", "input_validated", "passed", trace, "acme", "alice"))
	r.proc.Process(evt("vault", "pii_tokenized", "passed", trace, "acme", "alice"))

	// Navigator emits chunk_retrieved events that build chunk lineage.
	chunk1 := evt("navigator", "chunk_retrieved", "passed", trace, "acme", "alice")
	chunk1.Data = map[string]any{
		"chunk_id": "doc1_0000", "document_id": "doc1",
		"score": 0.91, "rank": float64(0), "collection": "customer_docs",
	}
	r.proc.Process(chunk1)

	chunk2 := evt("navigator", "chunk_retrieved", "passed", trace, "acme", "alice")
	chunk2.Data = map[string]any{
		"chunk_id": "doc1_0001", "document_id": "doc1",
		"score": 0.87, "rank": float64(1), "collection": "customer_docs",
	}
	r.proc.Process(chunk2)

	// Anchor closes the trace (status → completed via UpsertTrace state machine).
	r.proc.Process(evt("anchor", "embedding_secured", "passed", trace, "acme", "alice"))

	// ── Assert: trace reconstructed with all spans ───────────────────────────
	tr, ok := r.store.GetTrace(trace)
	if !ok {
		t.Fatal("trace was not reconstructed")
	}
	if len(tr.Spans) != 5 {
		t.Errorf("expected 5 spans, got %d", len(tr.Spans))
	}
	if tr.TenantID != "acme" || tr.UserID != "alice" {
		t.Errorf("trace identity wrong: tenant=%q user=%q", tr.TenantID, tr.UserID)
	}

	// ── Assert: chunk lineage captured and rank-sorted ───────────────────────
	chunks, found := r.store.GetLineageSources(trace)
	if !found {
		t.Fatal("chunk lineage not found")
	}
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunk lineage entries, got %d", len(chunks))
	}
	if chunks[0].Rank != 0 || chunks[1].Rank != 1 {
		t.Errorf("chunk lineage not rank-sorted: %d, %d", chunks[0].Rank, chunks[1].Rank)
	}
	if chunks[0].ChunkID != "doc1_0000" || chunks[0].DocumentID != "doc1" {
		t.Errorf("chunk lineage data wrong: %+v", chunks[0])
	}
}

// ─── Flow 2: Honey-token multi-layer intrusion → anomaly + incident ───────────

func TestFlow_HoneyTokenMultiLayer_TriggersAnomalyAndIncident(t *testing.T) {
	r := newRig(t)
	trace := "trace-attack-001"

	// Same trace touches a honey-token at TWO pipeline layers — confirmed intrusion.
	ref := evt("sentinel", "honey_token_referenced", "passed", trace, "acme", "mallory")
	ref.Severity = "critical"
	ref.Data = map[string]any{"honey_token_id": "HT-0003", "source_ip": "10.0.0.66"}
	r.proc.Process(ref)

	ret := evt("navigator", "honey_token_retrieved", "passed", trace, "acme", "mallory")
	ret.Severity = "critical"
	ret.Data = map[string]any{"honey_token_id": "HT-0003"}
	r.proc.Process(ret)

	// ── Assert: honey-token trigger recorded on HT-0003 ──────────────────────
	tok, ok := r.store.GetToken("HT-0003")
	if !ok {
		t.Fatal("HT-0003 not found")
	}
	if tok.TriggerCount < 2 {
		t.Errorf("expected >= 2 triggers on HT-0003, got %d", tok.TriggerCount)
	}

	// ── Assert: honey_multi_layer anomaly fired ──────────────────────────────
	if !hasAnomalyPattern(r.anomalies, "honey_multi_layer") {
		t.Errorf("expected honey_multi_layer anomaly; got patterns %v", anomalyPatterns(r.anomalies))
	}

	// ── Assert: an incident was auto-created (honey_token_* always creates) ───
	incs := r.store.ListIncidents("")
	if len(incs) == 0 {
		t.Fatal("expected at least one incident from honey-token detection")
	}
	foundHoney := false
	for _, inc := range incs {
		if inc.TenantID == "acme" {
			foundHoney = true
		}
	}
	if !foundHoney {
		t.Error("expected an incident scoped to tenant acme")
	}
}

// ─── Flow 3: Repeated blocks → critical anomaly ───────────────────────────────

func TestFlow_RepeatedBlock_TriggersCriticalAnomaly(t *testing.T) {
	r := newRig(t)

	// Same user blocked 3 times within the window → repeated_block (critical).
	for i := 0; i < 3; i++ {
		r.proc.Process(evt("sentinel", "input_validated", "blocked", "", "acme", "attacker"))
	}

	hits := filterAnomalies(r.anomalies, "repeated_block")
	if len(hits) == 0 {
		t.Fatalf("expected repeated_block anomaly; got %v", anomalyPatterns(r.anomalies))
	}
	if hits[0].Severity != "critical" {
		t.Errorf("repeated_block should be critical, got %q", hits[0].Severity)
	}
}

// ─── Flow 4: Cross-tenant attempt → critical anomaly ──────────────────────────

func TestFlow_CrossTenant_TriggersAnomaly(t *testing.T) {
	r := newRig(t)
	ev := evt("vault", "cross_tenant_attempt", "error", "trace-xt", "acme", "spy")
	ev.Severity = "critical"
	r.proc.Process(ev)

	if !hasAnomalyPattern(r.anomalies, "cross_tenant_signal") {
		t.Errorf("expected cross_tenant_signal anomaly; got %v", anomalyPatterns(r.anomalies))
	}
}

// ─── Flow 5: Dashboard summary reflects ingested events ───────────────────────

func TestFlow_DashboardSummary_ReflectsActivity(t *testing.T) {
	r := newRig(t)

	// 3 normal sentinel events + 1 blocked.
	for i := 0; i < 3; i++ {
		r.proc.Process(evt("sentinel", "input_validated", "passed", "", "acme", "alice"))
	}
	r.proc.Process(evt("sentinel", "input_validated", "blocked", "", "acme", "bob"))

	sum := r.store.DashboardSummary()
	if sum.EventCount1h < 4 {
		t.Errorf("expected >= 4 events in 1h window, got %d", sum.EventCount1h)
	}
	if sum.BlockedRequests1h < 1 {
		t.Errorf("expected >= 1 blocked request, got %d", sum.BlockedRequests1h)
	}
	if len(sum.TopModules) == 0 || sum.TopModules[0].Module != "sentinel" {
		t.Errorf("expected sentinel as top module, got %+v", sum.TopModules)
	}
}

// ─── Flow 6: Audit signature integrity across the pipeline ────────────────────

func TestFlow_AuditSignatures_VerifyAcrossPipeline(t *testing.T) {
	r := newRig(t)
	trace := "trace-audit-001"

	for _, m := range []string{"sentinel", "vault", "navigator", "anchor"} {
		r.proc.Process(evt(m, "step_done", "passed", trace, "acme", "alice"))
	}

	// Every stored event for this trace must carry a valid HMAC signature.
	evs := r.store.RecentEvents(models.QueryRequest{TraceID: trace}, 100)
	if len(evs) == 0 {
		t.Fatal("no events stored for trace")
	}
	for _, e := range evs {
		if e.Signature == "" {
			t.Errorf("event %s (%s) is unsigned", e.EventID, e.Module)
			continue
		}
		if !r.signer.Verify(e) {
			t.Errorf("event %s (%s) failed signature verification", e.EventID, e.Module)
		}
	}
}

// ─── Flow 7: Tenant activity isolation ────────────────────────────────────────

func TestFlow_TenantActivity_Isolated(t *testing.T) {
	r := newRig(t)

	for i := 0; i < 3; i++ {
		r.proc.Process(evt("navigator", "search_completed", "passed", "", "acme", "alice"))
	}
	for i := 0; i < 2; i++ {
		r.proc.Process(evt("navigator", "search_completed", "passed", "", "rival", "bob"))
	}

	acme := r.store.TenantActivity("acme")
	if acme.EventCount1h != 3 {
		t.Errorf("acme: expected 3 events, got %d", acme.EventCount1h)
	}
	rival := r.store.TenantActivity("rival")
	if rival.EventCount1h != 2 {
		t.Errorf("rival: expected 2 events, got %d", rival.EventCount1h)
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func hasAnomalyPattern(events []models.AnomalyEvent, pattern string) bool {
	for _, e := range events {
		if e.Pattern == pattern {
			return true
		}
	}
	return false
}

func filterAnomalies(events []models.AnomalyEvent, pattern string) []models.AnomalyEvent {
	var out []models.AnomalyEvent
	for _, e := range events {
		if e.Pattern == pattern {
			out = append(out, e)
		}
	}
	return out
}

func anomalyPatterns(events []models.AnomalyEvent) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Pattern)
	}
	return out
}
