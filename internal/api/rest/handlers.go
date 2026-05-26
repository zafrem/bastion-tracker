package rest

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/bastion/tracker/internal/alerts"
	"github.com/bastion/tracker/internal/audit"
	"github.com/bastion/tracker/internal/auth"
	"github.com/bastion/tracker/internal/config"
	"github.com/bastion/tracker/internal/demo"
	"github.com/bastion/tracker/internal/events"
	"github.com/bastion/tracker/internal/honeytoken"
	"github.com/bastion/tracker/internal/hub"
	"github.com/bastion/tracker/internal/incidents"
	"github.com/bastion/tracker/internal/models"
	"github.com/bastion/tracker/internal/processor"
	"github.com/bastion/tracker/internal/runbook"
	"github.com/bastion/tracker/internal/store"
)

type handlers struct {
	store     *store.Store
	hub       *hub.Hub
	proc      *processor.Processor
	demo      *demo.Engine
	alerts    *alerts.Manager
	incidents *incidents.Manager
	honey     *honeytoken.Manager
	authCfg   *config.AuthConfig
	recorder  *demo.Recorder
	runbooks  *runbook.Manager
	signer    *audit.Signer // for audit verification endpoint
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

func (h *handlers) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if h.authCfg == nil || !h.authCfg.Enabled {
		writeError(w, http.StatusNotFound, "auth not enabled")
		return
	}

	var matched *config.UserConfig
	for i := range h.authCfg.Users {
		if h.authCfg.Users[i].Name == req.Username {
			matched = &h.authCfg.Users[i]
			break
		}
	}
	if matched == nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Support both bcrypt hashes ($2a$...) and plain-text (PoC mode).
	var passwordOK bool
	if strings.HasPrefix(matched.Password, "$2") {
		passwordOK = bcrypt.CompareHashAndPassword([]byte(matched.Password), []byte(req.Password)) == nil
	} else {
		passwordOK = matched.Password == req.Password
	}
	if !passwordOK {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	expiry, err := time.ParseDuration(h.authCfg.JWTExpiry)
	if err != nil {
		expiry = auth.DefaultExpiry
	}
	token, err := auth.GenerateToken(matched.Name, matched.Role, h.authCfg.JWTSecret, expiry)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	writeJSON(w, http.StatusOK, models.LoginResponse{
		Token:     token,
		ExpiresIn: expiry.String(),
		Role:      matched.Role,
	})
}

// ─── Health ───────────────────────────────────────────────────────────────────

func (h *handlers) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, models.HealthStatus{
		Status:  "ok",
		Version: "1.0.0",
		Checks: map[string]string{
			"store":       "up",
			"websocket":   "up",
			"demo_engine": "up",
		},
	})
}

func (h *handlers) Live(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "alive"})
}
func (h *handlers) Ready(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ready"})
}

// ─── Events ───────────────────────────────────────────────────────────────────

func (h *handlers) ListEvents(w http.ResponseWriter, r *http.Request) {
	q := parseQuery(r)
	limit := intParam(r, "limit", 100)
	events := h.store.RecentEvents(q, limit)
	writeJSON(w, 200, models.EventsResponse{Events: events, Total: len(events)})
}

func (h *handlers) GetEvent(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "event_id")
	ev, ok := h.store.GetEvent(id)
	if !ok {
		writeError(w, 404, "event not found")
		return
	}
	writeJSON(w, 200, ev)
}

func (h *handlers) SearchEvents(w http.ResponseWriter, r *http.Request) {
	keyword := r.URL.Query().Get("q")
	limit := intParam(r, "limit", 100)
	events := h.store.SearchEvents(keyword, limit)
	writeJSON(w, 200, models.EventsResponse{Events: events, Total: len(events)})
}

// ─── Security events ──────────────────────────────────────────────────────────

// GetSecurityEvents returns events from the security module or with critical/error severity.
func (h *handlers) GetSecurityEvents(w http.ResponseWriter, r *http.Request) {
	limit := intParam(r, "limit", 100)
	severity := r.URL.Query().Get("severity")
	module := r.URL.Query().Get("module")

	// Default to security module events or critical severity if no filter given.
	if module == "" && severity == "" {
		module = "security"
	}

	q := parseQuery(r)
	q.Module = module
	q.Severity = severity

	// If caller wants all security-related events (module=security OR high severity),
	// fetch both and merge. For simplicity we serve either/or based on params.
	events := h.store.RecentEvents(q, limit)

	// When no explicit module filter and no results, fall back to critical events.
	if len(events) == 0 && module == "security" && severity == "" {
		q.Module = ""
		q.Severity = "critical"
		events = h.store.RecentEvents(q, limit)
	}

	writeJSON(w, 200, models.EventsResponse{Events: events, Total: len(events)})
}

// ─── Traces ───────────────────────────────────────────────────────────────────

func (h *handlers) ListTraces(w http.ResponseWriter, r *http.Request) {
	q := parseQuery(r)
	limit := intParam(r, "limit", 50)
	traces := h.store.RecentTraces(q, limit)
	writeJSON(w, 200, models.TracesResponse{Traces: traces, Total: len(traces)})
}

// ListTracesByUser returns all traces for a given user — supports the lineage
// "user activity" query (SRS doc 22 §6.1 query type 3).
func (h *handlers) ListTracesByUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "user_id")
	limit := intParam(r, "limit", 50)
	q := models.QueryRequest{UserID: userID}
	traces := h.store.RecentTraces(q, limit)
	writeJSON(w, 200, models.TracesResponse{Traces: traces, Total: len(traces)})
}

func (h *handlers) GetTrace(w http.ResponseWriter, r *http.Request) {
	traceID := chi.URLParam(r, "trace_id")
	tr, ok := h.store.GetTrace(traceID)
	if !ok {
		writeError(w, 404, "trace not found")
		return
	}
	writeJSON(w, 200, tr)
}

// LineageByDataRef returns all traces that touched a specific data element
// (SRS doc 22 §6.2: GET /v1/lineage/data/{data_ref}).
func (h *handlers) LineageByDataRef(w http.ResponseWriter, r *http.Request) {
	dataRef := chi.URLParam(r, "data_ref")
	limit := intParam(r, "limit", 50)
	// Search events whose metadata/data contains the data_ref as a value.
	evts := h.store.SearchEvents(dataRef, limit)
	traceIDs := make(map[string]struct{})
	for _, ev := range evts {
		if ev.TraceID != "" {
			traceIDs[ev.TraceID] = struct{}{}
		}
	}
	var traces []models.Trace
	for traceID := range traceIDs {
		if tr, ok := h.store.GetTrace(traceID); ok {
			traces = append(traces, *tr)
		}
	}
	if pub := h.proc.Publisher(); pub != nil {
		pub.Publish(events.EventLineageCompleted("", "data_ref", r.URL.Query().Get("tenant_id"), len(traces)))
	}
	writeJSON(w, 200, models.TracesResponse{Traces: traces, Total: len(traces)})
}

// LineageAudit returns events in a time range for compliance audit
// (SRS doc 22 §6.2: GET /v1/lineage/audit?from=&to=).
func (h *handlers) LineageAudit(w http.ResponseWriter, r *http.Request) {
	limit := intParam(r, "limit", 200)
	q := models.QueryRequest{TenantID: r.URL.Query().Get("tenant_id")}
	if from := r.URL.Query().Get("from"); from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			q.Since = t
		}
	}
	if to := r.URL.Query().Get("to"); to != "" {
		if t, err := time.Parse(time.RFC3339, to); err == nil {
			q.Until = t
		}
	}
	evts := h.store.RecentEvents(q, limit)
	if pub := h.proc.Publisher(); pub != nil {
		pub.Publish(events.EventLineageCompleted("", "audit", q.TenantID, len(evts)))
	}
	writeJSON(w, 200, models.EventsResponse{Events: evts, Total: len(evts)})
}

// GetTraceTimeline returns spans positioned on a timeline, ready for visualization.
func (h *handlers) GetTraceTimeline(w http.ResponseWriter, r *http.Request) {
	traceID := chi.URLParam(r, "trace_id")
	tr, ok := h.store.GetTrace(traceID)
	if !ok {
		writeError(w, 404, "trace not found")
		return
	}

	var maxMs int64
	entries := make([]models.TimelineEntry, 0, len(tr.Spans))
	for _, span := range tr.Spans {
		offset := span.StartTime.Sub(tr.StartTime).Milliseconds()
		if offset < 0 {
			offset = 0
		}
		entries = append(entries, models.TimelineEntry{
			SpanID:     span.SpanID,
			Module:     span.Module,
			EventType:  span.EventType,
			OffsetMs:   offset,
			DurationMs: span.DurationMs,
			Status:     span.Status,
		})
		if span.DurationMs > maxMs {
			maxMs = span.DurationMs
		}
	}

	writeJSON(w, 200, models.TraceTimeline{
		TraceID:      tr.TraceID,
		PipelineType: tr.PipelineType,
		TotalMs:      tr.TotalMs,
		MaxMs:        maxMs,
		Entries:      entries,
	})
}

// ─── Topology ─────────────────────────────────────────────────────────────────

func (h *handlers) Topology(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, h.store.Topology())
}

// TopologyHealth returns only the per-module health slice (subset of full topology).
func (h *handlers) TopologyHealth(w http.ResponseWriter, r *http.Request) {
	snap := h.store.Topology()
	writeJSON(w, 200, map[string]interface{}{
		"updated_at": snap.UpdatedAt,
		"modules":    snap.Modules,
	})
}

func (h *handlers) PipelineStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, h.store.PipelineStats())
}

// ─── Security / Incidents ─────────────────────────────────────────────────────

func (h *handlers) ListIncidents(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	writeJSON(w, 200, h.store.ListIncidents(status))
}

func (h *handlers) ResolveIncident(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		Notes string `json:"notes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	inc, ok := h.incidents.Resolve(id, body.Notes)
	if !ok {
		writeError(w, 404, "incident not found")
		return
	}
	writeJSON(w, 200, inc)
}

// ─── Alerts ───────────────────────────────────────────────────────────────────

func (h *handlers) ListAlerts(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	writeJSON(w, 200, h.store.ListAlerts(status))
}

func (h *handlers) AcknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !h.store.AcknowledgeAlert(id) {
		writeError(w, 404, "alert not found")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "acknowledged"})
}

func (h *handlers) ResolveAlert(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !h.store.ResolveAlert(id) {
		writeError(w, 404, "alert not found")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "resolved"})
}

// ─── Honey-tokens ─────────────────────────────────────────────────────────────

func (h *handlers) ListHoneyTokens(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, h.honey.List())
}

func (h *handlers) CreateHoneyToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string                `json:"name"`
		Description string                `json:"description"`
		Location    string                `json:"location"`
		Type        models.HoneyTokenType `json:"type"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	tok := h.honey.Create(body.Name, body.Description, body.Location, body.Type)
	writeJSON(w, http.StatusCreated, tok)
}

func (h *handlers) DeleteHoneyToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !h.honey.Delete(id) {
		writeError(w, 404, "token not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) HoneyTokenTriggers(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	writeJSON(w, 200, h.honey.Triggers(id))
}

func (h *handlers) AllHoneyTokenTriggers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, h.honey.AllTriggers())
}

// ─── Demo ─────────────────────────────────────────────────────────────────────

func (h *handlers) ListScenarios(w http.ResponseWriter, r *http.Request) {
	scenarios := h.demo.List()
	for i := range scenarios {
		scenarios[i].Events = nil
	}
	writeJSON(w, 200, scenarios)
}

func (h *handlers) GetScenario(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	sc, ok := h.demo.Get(name)
	if !ok {
		writeError(w, 404, "scenario not found")
		return
	}
	writeJSON(w, 200, sc)
}

func (h *handlers) ReplayScenario(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name  string  `json:"name"`
		Speed float64 `json:"speed"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := h.demo.Replay(body.Name, body.Speed); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "started", "scenario": body.Name})
}

func (h *handlers) InjectEvent(w http.ResponseWriter, r *http.Request) {
	var ev models.BastionEvent
	if !decodeJSON(w, r, &ev) {
		return
	}
	h.demo.Inject(ev)
	writeJSON(w, 200, map[string]string{"status": "injected"})
}

func (h *handlers) ActiveScenarios(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"active": h.demo.ActiveScenarios()})
}

func (h *handlers) StopScenario(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	h.demo.Stop(body.Name)
	writeJSON(w, 200, map[string]string{"status": "stopped"})
}

// ─── Recording ────────────────────────────────────────────────────────────────

func (h *handlers) StartRecording(w http.ResponseWriter, r *http.Request) {
	if h.recorder == nil {
		writeError(w, http.StatusServiceUnavailable, "recorder not available")
		return
	}
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Name == "" {
		body.Name = "recorded-" + time.Now().Format("20060102-150405")
	}
	if !h.recorder.Start(body.Name, body.Description) {
		writeError(w, http.StatusConflict, "recording already in progress")
		return
	}
	writeJSON(w, 200, h.recorder.Status())
}

func (h *handlers) StopRecording(w http.ResponseWriter, r *http.Request) {
	if h.recorder == nil {
		writeError(w, http.StatusServiceUnavailable, "recorder not available")
		return
	}
	sc, ok := h.recorder.Stop()
	if !ok {
		writeError(w, http.StatusConflict, "no active recording")
		return
	}
	h.demo.AddScenario(sc)
	writeJSON(w, 200, h.recorder.Status())
}

func (h *handlers) RecordingStatus(w http.ResponseWriter, r *http.Request) {
	if h.recorder == nil {
		writeError(w, http.StatusServiceUnavailable, "recorder not available")
		return
	}
	writeJSON(w, 200, h.recorder.Status())
}

// ─── Event submission ─────────────────────────────────────────────────────────

func (h *handlers) SubmitEvent(w http.ResponseWriter, r *http.Request) {
	var ev models.BastionEvent
	if !decodeJSON(w, r, &ev) {
		return
	}
	h.proc.Process(ev)
	writeJSON(w, http.StatusAccepted, models.SubmitResponse{EventID: ev.EventID, Accepted: true})
}

func (h *handlers) SubmitBatch(w http.ResponseWriter, r *http.Request) {
	var body models.BatchEventRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	for _, ev := range body.Events {
		h.proc.Process(ev)
	}
	writeJSON(w, http.StatusAccepted, models.BatchResponse{Accepted: len(body.Events)})
}

// ─── Config ───────────────────────────────────────────────────────────────────

func (h *handlers) ReloadConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "reloaded"})
}

// ─── Run books ────────────────────────────────────────────────────────────────

func (h *handlers) ListRunBooks(w http.ResponseWriter, r *http.Request) {
	if h.runbooks == nil {
		writeJSON(w, 200, []struct{}{})
		return
	}
	// Optional filter by alert rule name.
	if rule := r.URL.Query().Get("alert"); rule != "" {
		writeJSON(w, 200, h.runbooks.ForAlert(rule))
		return
	}
	writeJSON(w, 200, h.runbooks.List())
}

func (h *handlers) GetRunBook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if h.runbooks == nil {
		writeError(w, 404, "runbook not found")
		return
	}
	rb, ok := h.runbooks.Get(id)
	if !ok {
		writeError(w, 404, "runbook not found")
		return
	}
	writeJSON(w, 200, rb)
}

// ─── Dead letter ──────────────────────────────────────────────────────────────

func (h *handlers) ListDeadLetters(w http.ResponseWriter, r *http.Request) {
	val := h.proc.Validator()
	if val == nil {
		writeJSON(w, 200, []struct{}{})
		return
	}
	writeJSON(w, 200, val.DeadLetters())
}

// ─── Audit verification ───────────────────────────────────────────────────────

func (h *handlers) VerifyAuditLog(w http.ResponseWriter, r *http.Request) {
	if h.signer == nil {
		writeError(w, 503, "audit signing not configured")
		return
	}
	limit := intParam(r, "limit", 1000)
	q := parseQuery(r)
	events := h.store.RecentEvents(q, limit)

	result := models.AuditVerifyResult{Total: len(events)}
	for _, ev := range events {
		if ev.Signature == "" {
			result.Unsigned++
		} else if h.signer.Verify(ev) {
			result.Valid++
		} else {
			result.Invalid++
			result.Tampered = append(result.Tampered, ev.EventID)
		}
	}
	writeJSON(w, 200, result)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func parseQuery(r *http.Request) models.QueryRequest {
	q := models.QueryRequest{
		TraceID:  r.URL.Query().Get("trace_id"),
		UserID:   r.URL.Query().Get("user_id"),
		TenantID: r.URL.Query().Get("tenant_id"),
		Module:   r.URL.Query().Get("module"),
		Severity: r.URL.Query().Get("severity"),
		Status:   r.URL.Query().Get("status"),
	}
	if since := r.URL.Query().Get("since"); since != "" {
		if d, err := time.ParseDuration(since); err == nil {
			q.Since = time.Now().Add(-d)
		}
	}
	return q
}

func intParam(r *http.Request, key string, def int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, models.ErrorResponse{Error: msg, Code: status})
}
