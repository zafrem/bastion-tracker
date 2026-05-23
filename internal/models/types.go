// Package models defines the shared domain types for Bastion-Tracker.
package models

import "time"

// ─── Event schema ─────────────────────────────────────────────────────────────

// BastionEvent is the canonical event emitted by every Bastion module.
type BastionEvent struct {
	EventID        string            `json:"event_id"`
	TraceID        string            `json:"trace_id"`
	SpanID         string            `json:"span_id"`
	ParentSpanID   string            `json:"parent_span_id"`
	Module         string            `json:"module"`          // sentinel, vault, navigator, anchor
	EventType      string            `json:"event_type"`
	Severity       string            `json:"severity"`        // info, warning, error, critical
	Timestamp      time.Time         `json:"timestamp"`
	TenantID       string            `json:"tenant_id"`
	UserID         string            `json:"user_id"`
	RequestID      string            `json:"request_id"`
	Labels         map[string]string `json:"labels,omitempty"`
	Data           map[string]any    `json:"data,omitempty"`
	PipelineType   string            `json:"pipeline_type"`   // full, lite, minimal, custom
	ModulesUsed    []string          `json:"modules_used,omitempty"`
	ModulesSkipped []string          `json:"modules_skipped,omitempty"`
	DurationMs     int64             `json:"duration_ms"`
	Status         string            `json:"status"`          // passed, blocked, error
	ActionTaken    string            `json:"action_taken,omitempty"`
	Signature      string            `json:"signature,omitempty"` // HMAC-SHA256 audit integrity seal
}

// ─── Traces ───────────────────────────────────────────────────────────────────

// Trace assembles all events belonging to a single end-to-end request.
type Trace struct {
	TraceID        string     `json:"trace_id"`
	RequestID      string     `json:"request_id"`
	TenantID       string     `json:"tenant_id"`
	UserID         string     `json:"user_id"`
	PipelineType   string     `json:"pipeline_type"`
	ModulesUsed    []string   `json:"modules_used,omitempty"`
	ModulesSkipped []string   `json:"modules_skipped,omitempty"`
	StartTime      time.Time  `json:"start_time"`
	EndTime        *time.Time `json:"end_time,omitempty"`
	TotalMs        int64      `json:"total_ms"`
	Status         string     `json:"status"` // in_progress, passed, blocked, error
	Spans          []Span     `json:"spans"`
}

// Span is a single module's contribution to a trace.
type Span struct {
	SpanID     string         `json:"span_id"`
	Module     string         `json:"module"`
	EventType  string         `json:"event_type"`
	StartTime  time.Time      `json:"start_time"`
	DurationMs int64          `json:"duration_ms"`
	Status     string         `json:"status"`
	Data       map[string]any `json:"data,omitempty"`
}

// TraceTimeline is a visualization-friendly representation of a trace's spans.
type TraceTimeline struct {
	TraceID      string          `json:"trace_id"`
	PipelineType string          `json:"pipeline_type"`
	TotalMs      int64           `json:"total_ms"`
	MaxMs        int64           `json:"max_ms"` // longest single span
	Entries      []TimelineEntry `json:"entries"`
}

// TimelineEntry is one span positioned on the timeline.
type TimelineEntry struct {
	SpanID     string `json:"span_id"`
	Module     string `json:"module"`
	EventType  string `json:"event_type"`
	OffsetMs   int64  `json:"offset_ms"`   // ms after trace start
	DurationMs int64  `json:"duration_ms"`
	Status     string `json:"status"`
}

// ─── Incidents ────────────────────────────────────────────────────────────────

type IncidentStatus string

const (
	IncidentOpen          IncidentStatus = "open"
	IncidentInvestigating IncidentStatus = "investigating"
	IncidentResolved      IncidentStatus = "resolved"
)

// Incident groups related security events into an actionable unit.
type Incident struct {
	IncidentID  string         `json:"incident_id"`
	Title       string         `json:"title"`
	Severity    string         `json:"severity"`
	Status      IncidentStatus `json:"status"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	ResolvedAt  *time.Time     `json:"resolved_at,omitempty"`
	TenantID    string         `json:"tenant_id"`
	Description string         `json:"description"`
	EventIDs    []string       `json:"event_ids"`
	Notes       string         `json:"notes,omitempty"`
}

// ─── Honey-tokens ─────────────────────────────────────────────────────────────

type HoneyTokenType string

const (
	HoneyTokenEmail      HoneyTokenType = "email"
	HoneyTokenCredential HoneyTokenType = "credential"
	HoneyTokenIdentity   HoneyTokenType = "identity"
	HoneyTokenDocument   HoneyTokenType = "document"
)

// HoneyToken is a decoy data record used to detect intrusion.
type HoneyToken struct {
	TokenID       string         `json:"token_id"`
	Name          string         `json:"name"`
	Type          HoneyTokenType `json:"type"`
	Location      string         `json:"location"`
	Description   string         `json:"description"`
	CreatedAt     time.Time      `json:"created_at"`
	Enabled       bool           `json:"enabled"`
	TriggerCount  int            `json:"trigger_count"`
	LastTriggered *time.Time     `json:"last_triggered,omitempty"`
	IncidentID    string         `json:"incident_id,omitempty"`
}

// HoneyTokenTrigger records a single trigger event.
type HoneyTokenTrigger struct {
	TriggerID   string    `json:"trigger_id"`
	TokenID     string    `json:"token_id"`
	TriggeredAt time.Time `json:"triggered_at"`
	SourceIP    string    `json:"source_ip,omitempty"`
	UserID      string    `json:"user_id,omitempty"`
	TenantID    string    `json:"tenant_id,omitempty"`
	EventID     string    `json:"event_id"`
}

// ─── Alerts ───────────────────────────────────────────────────────────────────

type AlertStatus string

const (
	AlertFiring       AlertStatus = "firing"
	AlertAcknowledged AlertStatus = "acknowledged"
	AlertResolved     AlertStatus = "resolved"
)

// Alert is a threshold-crossing notification.
type Alert struct {
	AlertID     string      `json:"alert_id"`
	RuleName    string      `json:"rule_name"`
	Severity    string      `json:"severity"`
	Status      AlertStatus `json:"status"`
	Message     string      `json:"message"`
	Module      string      `json:"module,omitempty"`
	TenantID    string      `json:"tenant_id,omitempty"`
	FiredAt     time.Time   `json:"fired_at"`
	AckedAt     *time.Time  `json:"acked_at,omitempty"`
	ResolvedAt  *time.Time  `json:"resolved_at,omitempty"`
	EscalatedAt *time.Time  `json:"escalated_at,omitempty"`
}

// ─── Demo ─────────────────────────────────────────────────────────────────────

// Annotation is a timestamped note displayed during scenario replay.
type Annotation struct {
	OffsetMs int64  `json:"offset_ms"`
	Text     string `json:"text"`
	Style    string `json:"style,omitempty"` // info, warning, critical
}

// DemoScenario describes a pre-recorded event sequence for PoC demos.
type DemoScenario struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	DurationSec float64      `json:"duration_sec"`
	Events      []DemoEvent  `json:"events"`
	Annotations []Annotation `json:"annotations,omitempty"`
}

// DemoEvent is a timestamped event within a scenario.
type DemoEvent struct {
	OffsetMs int64        `json:"offset_ms"` // ms after scenario start
	Event    BastionEvent `json:"event"`
}

// ─── Recording ────────────────────────────────────────────────────────────────

type RecordingState string

const (
	RecordingIdle    RecordingState = "idle"
	RecordingActive  RecordingState = "active"
	RecordingStopped RecordingState = "stopped"
)

// RecordingStatus reports the current state of the live event recorder.
type RecordingStatus struct {
	State      RecordingState `json:"state"`
	StartedAt  *time.Time     `json:"started_at,omitempty"`
	StoppedAt  *time.Time     `json:"stopped_at,omitempty"`
	EventCount int            `json:"event_count"`
	Scenario   *DemoScenario  `json:"scenario,omitempty"`
}

// ─── WebSocket messages ───────────────────────────────────────────────────────

// WSMessage is the envelope sent to WebSocket clients.
type WSMessage struct {
	Type    string `json:"type"` // event, trace_update, alert, incident, topology
	Payload any    `json:"payload"`
}

// ─── Topology ─────────────────────────────────────────────────────────────────

// ModuleHealth reports the operational status of a single module.
type ModuleHealth struct {
	Module      string     `json:"module"`
	Status      string     `json:"status"` // healthy, degraded, down, unknown
	LatencyMs   float64    `json:"latency_ms"`
	ErrorRate   float64    `json:"error_rate"`
	Throughput  float64    `json:"throughput"` // req/s
	LastEventAt *time.Time `json:"last_event_at,omitempty"`
}

// TopologySnapshot is the current health of all modules.
type TopologySnapshot struct {
	UpdatedAt time.Time      `json:"updated_at"`
	Modules   []ModuleHealth `json:"modules"`
}

// ─── Pipeline stats ───────────────────────────────────────────────────────────

// PipelineStats tracks usage ratios by pipeline type.
type PipelineStats struct {
	PeriodStart   time.Time        `json:"period_start"`
	PeriodEnd     time.Time        `json:"period_end"`
	TotalRequests int64            `json:"total_requests"`
	Breakdown     map[string]int64 `json:"breakdown"` // pipeline_type → count
}

// ─── REST responses ───────────────────────────────────────────────────────────

type EventsResponse struct {
	Events []BastionEvent `json:"events"`
	Total  int            `json:"total"`
}

type TracesResponse struct {
	Traces []Trace `json:"traces"`
	Total  int     `json:"total"`
}

type HealthStatus struct {
	Status  string            `json:"status"`
	Checks  map[string]string `json:"checks"`
	Version string            `json:"version"`
}

type ErrorResponse struct {
	Error string `json:"error"`
	Code  int    `json:"code"`
}

// AuditVerifyResult summarises the HMAC verification pass over stored events.
type AuditVerifyResult struct {
	Total    int      `json:"total"`
	Valid    int      `json:"valid"`
	Invalid  int      `json:"invalid"`   // signature present but wrong
	Unsigned int      `json:"unsigned"`  // no signature field
	Tampered []string `json:"tampered"`  // event_ids with bad signatures
}

// LoginRequest is the body for POST /v1/auth/login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse carries the issued JWT.
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresIn string `json:"expires_in"`
	Role      string `json:"role"`
}

// ─── gRPC stubs ───────────────────────────────────────────────────────────────

type SubmitResponse struct {
	EventID  string `json:"event_id"`
	Accepted bool   `json:"accepted"`
}

type BatchEventRequest struct {
	Events []BastionEvent `json:"events"`
}

type BatchResponse struct {
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
}

type QueryRequest struct {
	TraceID  string    `json:"trace_id,omitempty"`
	UserID   string    `json:"user_id,omitempty"`
	TenantID string    `json:"tenant_id,omitempty"`
	Module   string    `json:"module,omitempty"`
	Severity string    `json:"severity,omitempty"`
	Status   string    `json:"status,omitempty"`
	Since    time.Time `json:"since,omitempty"`
	Limit    int       `json:"limit,omitempty"`
}

type TraceRequest struct {
	TraceID string `json:"trace_id"`
}

type TraceResponse struct {
	Trace Trace `json:"trace"`
}

type HealthRequest struct{}

// StreamEventsRequest is the filter sent by a gRPC StreamEvents client.
type StreamEventsRequest struct {
	Module   string `json:"module,omitempty"`
	Severity string `json:"severity,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
}
