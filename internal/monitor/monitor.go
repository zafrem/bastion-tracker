// Package monitor implements the Tracker pipeline monitoring mode.
//
// Two sub-modes are supported and switchable at runtime via the REST API:
//
//   - observe  (non-blocking): every inbound event is captured into a MonitorSession,
//     presenting a step-by-step view of each real request for operators.
//     No pipeline modules need to change; data arrives via the existing Processor hook.
//
//   - gate     (blocking): a pipeline module calls CreateCheckpoint before proceeding;
//     execution blocks on WaitForDecision until an operator approves or rejects
//     the step via the REST API.  Auto-approve-on-timeout protects liveness.
//
// Mode "off" disables all monitoring overhead (default).
package monitor

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/bastion/tracker/internal/models"
)

// ─── Mode ────────────────────────────────────────────────────────────────────

// Mode controls pipeline observation behaviour.
type Mode string

const (
	ModeOff     Mode = "off"     // no monitoring (default)
	ModeObserve Mode = "observe" // capture & replay, non-blocking
	ModeGate    Mode = "gate"    // human approval required at each stage
)

// ─── Session ─────────────────────────────────────────────────────────────────

// Session captures a real request's step-by-step journey through the pipeline.
type Session struct {
	SessionID string    `json:"session_id"`
	TraceID   string    `json:"trace_id"`
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	Mode      Mode      `json:"mode"`
	StartedAt time.Time `json:"started_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// Status: "active" while pipeline is running, "completed" when terminal event arrives.
	Status string `json:"status"`
	Steps  []Step `json:"steps"`
}

// Step is one module's span within a monitored session.
type Step struct {
	StepID     string         `json:"step_id"`
	StepIndex  int            `json:"step_index"`
	Module     string         `json:"module"`
	EventType  string         `json:"event_type"`
	Timestamp  time.Time      `json:"timestamp"`
	DurationMs int64          `json:"duration_ms"`
	// Status mirrors the event status: "passed", "blocked", "sanitized", "error".
	Status     string         `json:"status"`
	Data       map[string]any `json:"data,omitempty"`
	// Annotation is a human-added note attached via REST (observe mode).
	Annotation string `json:"annotation,omitempty"`
}

// ─── Checkpoint ──────────────────────────────────────────────────────────────

// CheckpointStatus is the lifecycle state of a gate-mode checkpoint.
type CheckpointStatus string

const (
	StatusPending   CheckpointStatus = "pending"
	StatusApproved  CheckpointStatus = "approved"
	StatusRejected  CheckpointStatus = "rejected"
	StatusTimedOut  CheckpointStatus = "timed_out"
)

// Checkpoint is a pending gate-mode decision awaiting human approval.
// A pipeline module creates one by calling POST /v1/monitor/checkpoints and then
// calls WaitForDecision, which blocks until an operator decides.
type Checkpoint struct {
	CheckpointID string           `json:"checkpoint_id"`
	TraceID      string           `json:"trace_id"`
	TenantID     string           `json:"tenant_id"`
	// Stage identifies which pipeline step is paused (e.g. "sentinel-in", "vault", "navigator").
	Stage       string           `json:"stage"`
	RequestData map[string]any   `json:"request_data,omitempty"`
	Status      CheckpointStatus `json:"status"`
	CreatedAt   time.Time        `json:"created_at"`
	TimeoutAt   time.Time        `json:"timeout_at"`
	DecidedAt   *time.Time       `json:"decided_at,omitempty"`
	DecidedBy   string           `json:"decided_by,omitempty"`
	Notes       string           `json:"notes,omitempty"`
}

// ─── Config ───────────────────────────────────────────────────────────────────

// Config holds monitoring mode settings (loaded from Tracker config.yaml).
type Config struct {
	// Mode is the initial monitoring mode.  Can be overridden at runtime.
	Mode Mode `yaml:"mode"`
	// SessionRetentionHours is how long completed sessions are kept in memory (default 24).
	SessionRetentionHours int `yaml:"session_retention_hours"`
	// CheckpointTimeoutSec is how long a gate checkpoint waits before timing out (default 300).
	CheckpointTimeoutSec int `yaml:"checkpoint_timeout_sec"`
	// AutoApproveOnTimeout: when true, a timed-out checkpoint is treated as approved.
	// When false (default), timeout causes rejection — fail-safe.
	AutoApproveOnTimeout bool `yaml:"auto_approve_on_timeout"`
}

// ─── Manager ─────────────────────────────────────────────────────────────────

// Manager controls monitoring mode and manages sessions and checkpoints.
// It is safe for concurrent use.
type Manager struct {
	mu      sync.RWMutex
	mode    Mode
	cfg     Config

	// sessions indexed by session_id and trace_id.
	sessions map[string]*Session
	byTrace  map[string]*Session

	// checkpoints indexed by checkpoint_id.
	checkpoints map[string]*Checkpoint
	// pendingCh carries the decision for each pending checkpoint.
	pendingCh map[string]chan CheckpointStatus

	// broadcastFn is optional; wired to hub.Broadcast for WebSocket push.
	broadcastFn func(any)
}

// New creates a Manager with the given configuration.
func New(cfg Config) *Manager {
	if cfg.SessionRetentionHours == 0 {
		cfg.SessionRetentionHours = 24
	}
	if cfg.CheckpointTimeoutSec == 0 {
		cfg.CheckpointTimeoutSec = 300 // 5 minutes
	}
	initialMode := cfg.Mode
	if initialMode == "" {
		initialMode = ModeOff
	}
	return &Manager{
		mode:        initialMode,
		cfg:         cfg,
		sessions:    make(map[string]*Session),
		byTrace:     make(map[string]*Session),
		checkpoints: make(map[string]*Checkpoint),
		pendingCh:   make(map[string]chan CheckpointStatus),
	}
}

// SetBroadcast attaches a WebSocket broadcast function (called with WSMessage-shaped any).
func (m *Manager) SetBroadcast(fn func(any)) {
	m.mu.Lock()
	m.broadcastFn = fn
	m.mu.Unlock()
}

// ─── Mode control ─────────────────────────────────────────────────────────────

// GetMode returns the current monitoring mode.
func (m *Manager) GetMode() Mode {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.mode
}

// SetMode changes the monitoring mode at runtime.
// Switching from gate to off or observe rejects all pending checkpoints.
func (m *Manager) SetMode(mode Mode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev := m.mode
	m.mode = mode
	if prev == ModeGate && mode != ModeGate {
		// Release all pending checkpoints as rejected so callers don't block forever.
		for id, ch := range m.pendingCh {
			ch <- StatusRejected
			delete(m.pendingCh, id)
		}
	}
}

// ─── Observe mode: session management ─────────────────────────────────────────

// ObserveEvent is the Processor hook.  Called for every processed event.
// In observe/gate mode it builds or extends a Session for the request's trace.
func (m *Manager) ObserveEvent(ev models.BastionEvent) {
	m.mu.RLock()
	mode := m.mode
	m.mu.RUnlock()
	if mode == ModeOff {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.byTrace[ev.TraceID]
	if !ok {
		sess = &Session{
			SessionID: newID(),
			TraceID:   ev.TraceID,
			TenantID:  ev.TenantID,
			UserID:    ev.UserID,
			Mode:      mode,
			StartedAt: ev.Timestamp,
			UpdatedAt: ev.Timestamp,
			Status:    "active",
		}
		m.sessions[sess.SessionID] = sess
		m.byTrace[ev.TraceID] = sess
	}

	step := Step{
		StepID:     newID(),
		StepIndex:  len(sess.Steps),
		Module:     ev.Module,
		EventType:  ev.EventType,
		Timestamp:  ev.Timestamp,
		DurationMs: ev.DurationMs,
		Status:     ev.Status,
		Data:       ev.Data,
	}
	sess.Steps = append(sess.Steps, step)
	sess.UpdatedAt = ev.Timestamp

	// Terminal states: LLM response produced OR request was blocked at any layer.
	if ev.Module == "llm" || ev.Status == "blocked" {
		sess.Status = "completed"
	}

	if m.broadcastFn != nil {
		m.broadcastFn(models.WSMessage{
			Type:    "monitor_step",
			Payload: map[string]any{"session_id": sess.SessionID, "step": step},
		})
	}
}

// ListSessions returns all active and recently completed sessions.
func (m *Manager) ListSessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	return out
}

// GetSession retrieves a session by its session_id.
func (m *Manager) GetSession(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

// DeleteSession removes a session from memory.
func (m *Manager) DeleteSession(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return false
	}
	delete(m.sessions, id)
	delete(m.byTrace, s.TraceID)
	return true
}

// AnnotateStep appends a human note to a session step (observe mode).
func (m *Manager) AnnotateStep(sessionID, stepID, note string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return false
	}
	for i := range s.Steps {
		if s.Steps[i].StepID == stepID {
			s.Steps[i].Annotation = note
			return true
		}
	}
	return false
}

// ─── Gate mode: checkpoint management ────────────────────────────────────────

// CreateCheckpoint registers a new pending checkpoint and returns it.
// The calling pipeline module should call WaitForDecision immediately after.
// Returns nil if the current mode is not gate.
func (m *Manager) CreateCheckpoint(traceID, tenantID, stage string, data map[string]any) *Checkpoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mode != ModeGate {
		return nil
	}
	cp := &Checkpoint{
		CheckpointID: newID(),
		TraceID:      traceID,
		TenantID:     tenantID,
		Stage:        stage,
		RequestData:  data,
		Status:       StatusPending,
		CreatedAt:    time.Now().UTC(),
		TimeoutAt:    time.Now().UTC().Add(time.Duration(m.cfg.CheckpointTimeoutSec) * time.Second),
	}
	m.checkpoints[cp.CheckpointID] = cp
	ch := make(chan CheckpointStatus, 1)
	m.pendingCh[cp.CheckpointID] = ch

	if m.broadcastFn != nil {
		m.broadcastFn(models.WSMessage{Type: "monitor_checkpoint", Payload: cp})
	}

	// Start a background goroutine to enforce the timeout.
	go m.enforceTimeout(cp.CheckpointID)
	return cp
}

// WaitForDecision blocks the calling goroutine until the checkpoint is decided
// or the configured timeout elapses.  Returns (true, "") on approval, or
// (false, reason) on rejection / timeout.
func (m *Manager) WaitForDecision(checkpointID string) (bool, string) {
	m.mu.RLock()
	ch, ok := m.pendingCh[checkpointID]
	m.mu.RUnlock()
	if !ok {
		return false, "checkpoint not found"
	}
	switch <-ch {
	case StatusApproved:
		return true, ""
	case StatusTimedOut:
		if m.cfg.AutoApproveOnTimeout {
			return true, "auto-approved on timeout"
		}
		return false, "timed out waiting for operator decision"
	default:
		return false, "rejected by operator"
	}
}

// Decide records an operator decision (approve/reject) on a pending checkpoint.
// decidedBy is the operator's username from the JWT claim (may be empty when auth is off).
func (m *Manager) Decide(checkpointID, decidedBy, decision, notes string) (*Checkpoint, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp, ok := m.checkpoints[checkpointID]
	if !ok || cp.Status != StatusPending {
		return nil, false
	}
	now := time.Now().UTC()
	cp.DecidedAt = &now
	cp.DecidedBy = decidedBy
	cp.Notes = notes

	var status CheckpointStatus
	if decision == "approve" {
		status = StatusApproved
	} else {
		status = StatusRejected
	}
	cp.Status = status

	if ch, ok := m.pendingCh[cp.CheckpointID]; ok {
		ch <- status
		delete(m.pendingCh, cp.CheckpointID)
	}

	if m.broadcastFn != nil {
		m.broadcastFn(models.WSMessage{Type: "monitor_checkpoint_decided", Payload: cp})
	}
	return cp, true
}

// ListCheckpoints returns checkpoints, optionally filtered to pending only.
func (m *Manager) ListCheckpoints(pendingOnly bool) []*Checkpoint {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Checkpoint, 0, len(m.checkpoints))
	for _, cp := range m.checkpoints {
		if pendingOnly && cp.Status != StatusPending {
			continue
		}
		out = append(out, cp)
	}
	return out
}

// GetCheckpoint returns a checkpoint by checkpoint_id.
func (m *Manager) GetCheckpoint(id string) (*Checkpoint, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cp, ok := m.checkpoints[id]
	return cp, ok
}

// enforceTimeout auto-decides a checkpoint when it exceeds the configured timeout.
func (m *Manager) enforceTimeout(checkpointID string) {
	m.mu.RLock()
	cp, ok := m.checkpoints[checkpointID]
	if !ok {
		m.mu.RUnlock()
		return
	}
	wait := time.Until(cp.TimeoutAt)
	m.mu.RUnlock()

	if wait > 0 {
		time.Sleep(wait)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	cp2, ok := m.checkpoints[checkpointID]
	if !ok || cp2.Status != StatusPending {
		return // already decided
	}
	now := time.Now().UTC()
	cp2.DecidedAt = &now
	cp2.Status = StatusTimedOut
	if ch, ok := m.pendingCh[checkpointID]; ok {
		ch <- StatusTimedOut
		delete(m.pendingCh, checkpointID)
	}
	if m.broadcastFn != nil {
		m.broadcastFn(models.WSMessage{Type: "monitor_checkpoint_decided", Payload: cp2})
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
