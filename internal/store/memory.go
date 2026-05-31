// Package store provides an in-memory ring-buffer store for events and traces.
package store

import (
	"strings"
	"sync"
	"time"

	"github.com/bastion/tracker/internal/models"
)

// Store holds recent events and traces in memory (PoC — no external DB required).
type Store struct {
	mu        sync.RWMutex
	events    []models.BastionEvent // ring buffer
	maxEvents int
	head      int // next write position
	count     int // total written

	traces    map[string]*models.Trace
	incidents map[string]*models.Incident
	alerts    map[string]*models.Alert
	tokens    map[string]*models.HoneyToken
	triggers  map[string][]models.HoneyTokenTrigger // token_id → triggers

	// MR-05-003: chunk lineage — trace_id → ordered list of retrieved chunks
	lineage map[string][]models.ChunkLineageEntry

	// Login audit trail — last 10 000 entries (ring-style via slice cap)
	loginAudit []models.LoginAuditEvent
}

// New creates a Store with the given ring-buffer capacity.
func New(maxEvents int) *Store {
	if maxEvents <= 0 {
		maxEvents = 10000
	}
	return &Store{
		events:     make([]models.BastionEvent, maxEvents),
		maxEvents:  maxEvents,
		traces:     make(map[string]*models.Trace),
		incidents:  make(map[string]*models.Incident),
		alerts:     make(map[string]*models.Alert),
		tokens:     make(map[string]*models.HoneyToken),
		triggers:   make(map[string][]models.HoneyTokenTrigger),
		lineage:    make(map[string][]models.ChunkLineageEntry),
		loginAudit: make([]models.LoginAuditEvent, 0, 256),
	}
}

// ─── Events ───────────────────────────────────────────────────────────────────

// AddEvent writes an event into the ring buffer.
func (s *Store) AddEvent(ev models.BastionEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events[s.head] = ev
	s.head = (s.head + 1) % s.maxEvents
	s.count++
}

// GetEvent returns a single event by its ID, or (nil, false) if not found.
func (s *Store) GetEvent(id string) (*models.BastionEvent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	size := s.maxEvents
	if s.count < size {
		size = s.count
	}
	for i := 0; i < size; i++ {
		idx := ((s.head - 1 - i) + s.maxEvents) % s.maxEvents
		ev := s.events[idx]
		if ev.EventID == id {
			cp := ev
			return &cp, true
		}
	}
	return nil, false
}

// RecentEvents returns the last n events that match the optional query fields.
func (s *Store) RecentEvents(q models.QueryRequest, limit int) []models.BastionEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}

	results := make([]models.BastionEvent, 0, limit)
	size := s.maxEvents
	if s.count < size {
		size = s.count
	}

	for i := 0; i < size && len(results) < limit; i++ {
		idx := ((s.head - 1 - i) + s.maxEvents) % s.maxEvents
		ev := s.events[idx]
		if ev.EventID == "" {
			continue
		}
		if !matchEvent(ev, q) {
			continue
		}
		results = append(results, ev)
	}
	return results
}

func matchEvent(ev models.BastionEvent, q models.QueryRequest) bool {
	if q.Module != "" && ev.Module != q.Module {
		return false
	}
	if q.TenantID != "" && ev.TenantID != q.TenantID {
		return false
	}
	if q.UserID != "" && ev.UserID != q.UserID {
		return false
	}
	if q.Severity != "" && ev.Severity != q.Severity {
		return false
	}
	if q.Status != "" && ev.Status != q.Status {
		return false
	}
	if q.TraceID != "" && ev.TraceID != q.TraceID {
		return false
	}
	if !q.Since.IsZero() && ev.Timestamp.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && ev.Timestamp.After(q.Until) {
		return false
	}
	return true
}

// ─── Traces ───────────────────────────────────────────────────────────────────

// UpsertTrace adds or updates a trace from an incoming event.
func (s *Store) UpsertTrace(ev models.BastionEvent) {
	if ev.TraceID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tr, ok := s.traces[ev.TraceID]
	if !ok {
		tr = &models.Trace{
			TraceID:        ev.TraceID,
			RequestID:      ev.RequestID,
			TenantID:       ev.TenantID,
			UserID:         ev.UserID,
			PipelineType:   ev.PipelineType,
			ModulesUsed:    ev.ModulesUsed,
			ModulesSkipped: ev.ModulesSkipped,
			StartTime:      ev.Timestamp,
			Status:         "in_progress",
		}
		s.traces[ev.TraceID] = tr
	}

	if tr.PipelineType == "" {
		tr.PipelineType = ev.PipelineType
		tr.ModulesUsed = ev.ModulesUsed
		tr.ModulesSkipped = ev.ModulesSkipped
	}

	span := models.Span{
		SpanID:     ev.SpanID,
		Module:     ev.Module,
		EventType:  ev.EventType,
		StartTime:  ev.Timestamp,
		DurationMs: ev.DurationMs,
		Status:     ev.Status,
		Data:       ev.Data,
	}
	tr.Spans = append(tr.Spans, span)

	if ev.Status == "blocked" || ev.Status == "error" {
		tr.Status = ev.Status
	} else if ev.Module == "llm" || ev.Module == "anchor" {
		tr.Status = "completed"
	}

	if tr.Status == "completed" || tr.Status == "blocked" || tr.Status == "error" {
		now := ev.Timestamp
		tr.EndTime = &now
		tr.TotalMs = now.Sub(tr.StartTime).Milliseconds()
	}
}

// GetTrace returns a trace by ID.
func (s *Store) GetTrace(traceID string) (*models.Trace, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tr, ok := s.traces[traceID]
	if !ok {
		return nil, false
	}
	cp := *tr
	return &cp, true
}

// RecentTraces returns the last n traces matching the query, newest first.
func (s *Store) RecentTraces(q models.QueryRequest, limit int) []models.Trace {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = 50
	}
	out := make([]models.Trace, 0, len(s.traces))
	for _, tr := range s.traces {
		if matchTrace(tr, q) {
			out = append(out, *tr)
		}
	}
	// Sort newest first (bubble sort — PoC dataset is small).
	for i := 0; i < len(out)-1; i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].StartTime.After(out[i].StartTime) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func matchTrace(tr *models.Trace, q models.QueryRequest) bool {
	if q.TraceID != "" && tr.TraceID != q.TraceID {
		return false
	}
	if q.UserID != "" && tr.UserID != q.UserID {
		return false
	}
	if q.TenantID != "" && tr.TenantID != q.TenantID {
		return false
	}
	if q.Status != "" && tr.Status != q.Status {
		return false
	}
	if !q.Since.IsZero() && tr.StartTime.Before(q.Since) {
		return false
	}
	return true
}

// ─── Topology ─────────────────────────────────────────────────────────────────

// Topology computes module health from recent events.
func (s *Store) Topology() models.TopologySnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	modules := []string{"sentinel", "vault", "navigator", "anchor"}
	type stat struct {
		count    int
		errors   int
		totalMs  int64
		lastSeen *time.Time
	}
	stats := make(map[string]stat)

	size := s.maxEvents
	if s.count < size {
		size = s.count
	}
	cutoff := time.Now().Add(-5 * time.Minute)
	for i := 0; i < size; i++ {
		idx := ((s.head - 1 - i) + s.maxEvents) % s.maxEvents
		ev := s.events[idx]
		if ev.EventID == "" || ev.Timestamp.Before(cutoff) {
			continue
		}
		st := stats[ev.Module]
		st.count++
		if ev.Status == "error" {
			st.errors++
		}
		st.totalMs += ev.DurationMs
		t := ev.Timestamp
		if st.lastSeen == nil || t.After(*st.lastSeen) {
			st.lastSeen = &t
		}
		stats[ev.Module] = st
	}

	health := make([]models.ModuleHealth, 0, len(modules))
	for _, mod := range modules {
		st := stats[mod]
		mh := models.ModuleHealth{
			Module:      mod,
			Status:      "unknown",
			LastEventAt: st.lastSeen,
		}
		if st.count > 0 {
			mh.LatencyMs = float64(st.totalMs) / float64(st.count)
			mh.ErrorRate = float64(st.errors) / float64(st.count)
			mh.Throughput = float64(st.count) / 300 // per second over 5m window
			switch {
			case mh.ErrorRate > 0.3:
				mh.Status = "down"
			case mh.ErrorRate > 0.1 || mh.LatencyMs > 500:
				mh.Status = "degraded"
			default:
				mh.Status = "healthy"
			}
		}
		health = append(health, mh)
	}
	return models.TopologySnapshot{UpdatedAt: time.Now(), Modules: health}
}

// ─── Pipeline stats ───────────────────────────────────────────────────────────

// PipelineStats returns counts per pipeline type over the last hour.
func (s *Store) PipelineStats() models.PipelineStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	since := time.Now().Add(-1 * time.Hour)
	breakdown := make(map[string]int64)
	var total int64

	size := s.maxEvents
	if s.count < size {
		size = s.count
	}
	for i := 0; i < size; i++ {
		idx := ((s.head - 1 - i) + s.maxEvents) % s.maxEvents
		ev := s.events[idx]
		if ev.EventID == "" || ev.Timestamp.Before(since) {
			continue
		}
		if ev.PipelineType != "" && ev.Module == "sentinel" {
			breakdown[ev.PipelineType]++
			total++
		}
	}
	return models.PipelineStats{
		PeriodStart:   since,
		PeriodEnd:     time.Now(),
		TotalRequests: total,
		Breakdown:     breakdown,
	}
}

// ─── Incidents ────────────────────────────────────────────────────────────────

func (s *Store) AddIncident(inc *models.Incident) {
	s.mu.Lock()
	s.incidents[inc.IncidentID] = inc
	s.mu.Unlock()
}

func (s *Store) GetIncident(id string) (*models.Incident, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inc, ok := s.incidents[id]
	if !ok {
		return nil, false
	}
	cp := *inc
	return &cp, true
}

func (s *Store) UpdateIncident(inc *models.Incident) {
	s.mu.Lock()
	s.incidents[inc.IncidentID] = inc
	s.mu.Unlock()
}

func (s *Store) ListIncidents(statusFilter string) []models.Incident {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.Incident, 0)
	for _, inc := range s.incidents {
		if statusFilter != "" && string(inc.Status) != statusFilter {
			continue
		}
		out = append(out, *inc)
	}
	return out
}

// ─── Alerts ───────────────────────────────────────────────────────────────────

func (s *Store) AddAlert(al *models.Alert) {
	s.mu.Lock()
	s.alerts[al.AlertID] = al
	s.mu.Unlock()
}

func (s *Store) ListAlerts(statusFilter string) []models.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.Alert, 0)
	for _, al := range s.alerts {
		if statusFilter != "" && string(al.Status) != statusFilter {
			continue
		}
		out = append(out, *al)
	}
	return out
}

func (s *Store) AcknowledgeAlert(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	al, ok := s.alerts[id]
	if !ok {
		return false
	}
	now := time.Now()
	al.Status = models.AlertAcknowledged
	al.AckedAt = &now
	return true
}

func (s *Store) ResolveAlert(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	al, ok := s.alerts[id]
	if !ok {
		return false
	}
	now := time.Now()
	al.Status = models.AlertResolved
	al.ResolvedAt = &now
	return true
}

func (s *Store) EscalateAlert(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	al, ok := s.alerts[id]
	if !ok || al.Status != models.AlertFiring {
		return false
	}
	now := time.Now()
	al.EscalatedAt = &now
	al.Severity = "critical"
	return true
}

func (s *Store) GetAlert(id string) (*models.Alert, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	al, ok := s.alerts[id]
	if !ok {
		return nil, false
	}
	cp := *al
	return &cp, true
}

// ─── Honey-tokens ─────────────────────────────────────────────────────────────

func (s *Store) AddToken(tok *models.HoneyToken) {
	s.mu.Lock()
	s.tokens[tok.TokenID] = tok
	s.mu.Unlock()
}

func (s *Store) GetToken(id string) (*models.HoneyToken, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[id]
	if !ok {
		return nil, false
	}
	cp := *t
	return &cp, true
}

func (s *Store) ListTokens() []models.HoneyToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.HoneyToken, 0, len(s.tokens))
	for _, t := range s.tokens {
		out = append(out, *t)
	}
	return out
}

func (s *Store) DeleteToken(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.tokens[id]
	if ok {
		delete(s.tokens, id)
	}
	return ok
}

func (s *Store) RecordTrigger(tr models.HoneyTokenTrigger) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, ok := s.tokens[tr.TokenID]
	if !ok {
		return
	}
	now := tr.TriggeredAt
	tok.TriggerCount++
	tok.LastTriggered = &now
	s.triggers[tr.TokenID] = append(s.triggers[tr.TokenID], tr)
}

func (s *Store) TokenTriggers(tokenID string) []models.HoneyTokenTrigger {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]models.HoneyTokenTrigger{}, s.triggers[tokenID]...)
}

func (s *Store) AllTriggers() []models.HoneyTokenTrigger {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var all []models.HoneyTokenTrigger
	for _, trigs := range s.triggers {
		all = append(all, trigs...)
	}
	return all
}

// ─── Chunk lineage (MR-05-003) ────────────────────────────────────────────────

// AddChunkLineage records a single retrieved chunk for a trace.
func (s *Store) AddChunkLineage(traceID string, entry models.ChunkLineageEntry) {
	if traceID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lineage[traceID] = append(s.lineage[traceID], entry)
}

// GetLineageSources returns the chunk lineage for a trace, sorted by rank.
func (s *Store) GetLineageSources(traceID string) ([]models.ChunkLineageEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries, ok := s.lineage[traceID]
	if !ok || len(entries) == 0 {
		return nil, false
	}
	// Return a copy sorted by rank.
	cp := make([]models.ChunkLineageEntry, len(entries))
	copy(cp, entries)
	for i := 0; i < len(cp)-1; i++ {
		for j := i + 1; j < len(cp); j++ {
			if cp[j].Rank < cp[i].Rank {
				cp[i], cp[j] = cp[j], cp[i]
			}
		}
	}
	return cp, true
}

// ─── Search ───────────────────────────────────────────────────────────────────

// ─── Dashboard helpers ────────────────────────────────────────────────────────

// DashboardSummary computes the real-time summary for the management dashboard.
func (s *Store) DashboardSummary() models.DashboardSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	cutoff1h := now.Add(-1 * time.Hour)
	cutoff24h := now.Add(-24 * time.Hour)

	size := s.maxEvents
	if s.count < size {
		size = s.count
	}

	var count1h, count24h, blocked1h int64
	moduleCounts := make(map[string]int64)
	honeyTriggers := 0

	for i := 0; i < size; i++ {
		idx := ((s.head - 1 - i) + s.maxEvents) % s.maxEvents
		ev := s.events[idx]
		if ev.EventID == "" {
			continue
		}
		if ev.Timestamp.Before(cutoff24h) {
			break // ring buffer is newest-first; once we pass 24h we're done
		}
		count24h++
		moduleCounts[ev.Module]++
		if ev.Timestamp.After(cutoff1h) {
			count1h++
			if ev.Status == "blocked" {
				blocked1h++
			}
		}
		if len(ev.EventType) >= 12 && ev.EventType[:12] == "honey_token_" {
			honeyTriggers++
		}
	}

	// Top-5 modules sorted by count.
	type kv struct {
		k string
		v int64
	}
	sorted := make([]kv, 0, len(moduleCounts))
	for k, v := range moduleCounts {
		sorted = append(sorted, kv{k, v})
	}
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].v > sorted[i].v {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	top := make([]models.ModuleVolume, 0, 5)
	for _, item := range sorted {
		if len(top) == 5 {
			break
		}
		top = append(top, models.ModuleVolume{Module: item.k, Count: item.v})
	}

	// Count active incidents and firing alerts.
	activeInc := 0
	for _, inc := range s.incidents {
		if inc.Status != models.IncidentResolved {
			activeInc++
		}
	}
	firingAlerts := 0
	for _, al := range s.alerts {
		if al.Status == models.AlertFiring {
			firingAlerts++
		}
	}

	return models.DashboardSummary{
		EventCount1h:       count1h,
		EventCount24h:      count24h,
		ActiveIncidents:    activeInc,
		FiringAlerts:       firingAlerts,
		HoneyTokenTriggers: honeyTriggers,
		BlockedRequests1h:  blocked1h,
		TopModules:         top,
		UpdatedAt:          now,
	}
}

// PipelineHealth returns per-module health enriched with events/min throughput.
func (s *Store) PipelineHealth() models.PipelineHealthResponse {
	snap := s.Topology() // existing method
	entries := make([]models.PipelineHealthEntry, 0, len(snap.Modules))
	for _, m := range snap.Modules {
		entries = append(entries, models.PipelineHealthEntry{
			Module:       m.Module,
			Status:       m.Status,
			AvgLatencyMs: m.LatencyMs,
			ErrorRate:    m.ErrorRate,
			EventsPerMin: m.Throughput * 60,
			LastEventAt:  m.LastEventAt,
		})
	}
	return models.PipelineHealthResponse{Modules: entries, UpdatedAt: snap.UpdatedAt}
}

// TenantActivity returns activity counts for a specific tenant.
func (s *Store) TenantActivity(tenantID string) models.TenantActivity {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	cutoff1h := now.Add(-1 * time.Hour)
	size := s.maxEvents
	if s.count < size {
		size = s.count
	}

	var count1h, blocked1h int64
	catBreakdown := make(map[string]int64)
	honeyCount := 0

	for i := 0; i < size; i++ {
		idx := ((s.head - 1 - i) + s.maxEvents) % s.maxEvents
		ev := s.events[idx]
		if ev.EventID == "" || ev.TenantID != tenantID {
			continue
		}
		if ev.Timestamp.Before(cutoff1h) {
			continue
		}
		count1h++
		if ev.Status == "blocked" {
			blocked1h++
		}
		if cat, ok := ev.Labels["category"]; ok && cat != "" {
			catBreakdown[cat]++
		}
		if len(ev.EventType) >= 12 && ev.EventType[:12] == "honey_token_" {
			honeyCount++
		}
	}

	incCount := 0
	for _, inc := range s.incidents {
		if inc.TenantID == tenantID {
			incCount++
		}
	}

	return models.TenantActivity{
		TenantID:           tenantID,
		EventCount1h:       count1h,
		IncidentCount:      incCount,
		BlockedCount1h:     blocked1h,
		HoneyTokenTriggers: honeyCount,
		CategoryBreakdown:  catBreakdown,
		UpdatedAt:          now,
	}
}

// EventsPage returns a cursor-paginated page of events.
// cursor is the event_id of the last event on the previous page (empty = start from most recent).
// limit is capped at 200.
func (s *Store) EventsPage(q models.QueryRequest, cursor string, limit int) models.EventsPage {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	size := s.maxEvents
	if s.count < size {
		size = s.count
	}

	// Find the cursor position in the ring.
	startIdx := 0
	if cursor != "" {
		for i := 0; i < size; i++ {
			idx := ((s.head - 1 - i) + s.maxEvents) % s.maxEvents
			if s.events[idx].EventID == cursor {
				startIdx = i + 1 // begin after the cursor
				break
			}
		}
	}

	results := make([]models.BastionEvent, 0, limit)
	for i := startIdx; i < size && len(results) < limit; i++ {
		idx := ((s.head - 1 - i) + s.maxEvents) % s.maxEvents
		ev := s.events[idx]
		if ev.EventID == "" {
			continue
		}
		if !matchEvent(ev, q) {
			continue
		}
		results = append(results, ev)
	}

	nextCursor := ""
	if len(results) == limit {
		nextCursor = results[len(results)-1].EventID
	}
	return models.EventsPage{
		Events:     results,
		Total:      len(results),
		NextCursor: nextCursor,
	}
}

// ─── Login audit ──────────────────────────────────────────────────────────────

// RecordLogin appends a login audit event; trims to last 10 000.
func (s *Store) RecordLogin(ev models.LoginAuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.loginAudit) >= 10000 {
		s.loginAudit = s.loginAudit[1:]
	}
	s.loginAudit = append(s.loginAudit, ev)
}

// RecentLogins returns the last n login audit events.
func (s *Store) RecentLogins(limit int) []models.LoginAuditEvent {
	if limit <= 0 {
		limit = 100
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.loginAudit) <= limit {
		out := make([]models.LoginAuditEvent, len(s.loginAudit))
		copy(out, s.loginAudit)
		return out
	}
	start := len(s.loginAudit) - limit
	out := make([]models.LoginAuditEvent, limit)
	copy(out, s.loginAudit[start:])
	return out
}

// ─── Search (keyword) ─────────────────────────────────────────────────────────

func (s *Store) SearchEvents(keyword string, limit int) []models.BastionEvent {
	if limit <= 0 {
		limit = 100
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	results := make([]models.BastionEvent, 0, limit)
	size := s.maxEvents
	if s.count < size {
		size = s.count
	}
	kw := strings.ToLower(keyword)
	for i := 0; i < size && len(results) < limit; i++ {
		idx := ((s.head - 1 - i) + s.maxEvents) % s.maxEvents
		ev := s.events[idx]
		if ev.EventID == "" {
			continue
		}
		if kw == "" || strings.Contains(strings.ToLower(ev.EventType), kw) ||
			strings.Contains(strings.ToLower(ev.Module), kw) ||
			strings.Contains(strings.ToLower(ev.TenantID), kw) {
			results = append(results, ev)
		}
	}
	return results
}
