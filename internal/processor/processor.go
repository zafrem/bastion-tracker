// Package processor routes inbound events through the tracker pipeline:
// enrich → store → build traces → detect honey-tokens → evaluate alerts → broadcast.
package processor

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/bastion/tracker/internal/alerts"
	"github.com/bastion/tracker/internal/audit"
	"github.com/bastion/tracker/internal/bypass"
	"github.com/bastion/tracker/internal/events"
	"github.com/bastion/tracker/internal/hub"
	"github.com/bastion/tracker/internal/incidents"
	"github.com/bastion/tracker/internal/honeytoken"
	"github.com/bastion/tracker/internal/metrics"
	"github.com/bastion/tracker/internal/models"
	"github.com/bastion/tracker/internal/store"
	"github.com/bastion/tracker/internal/validator"
)

// EventHook is called after each event is stored, before broadcasting.
type EventHook func(ev models.BastionEvent)

// Processor is the central event-processing pipeline.
type Processor struct {
	store     *store.Store
	hub       *hub.Hub
	alerts    *alerts.Manager
	incidents *incidents.Manager
	honey     *honeytoken.Manager
	bypass    *bypass.Monitor      // optional
	signer    *audit.Signer        // optional; signs events before storage
	validator *validator.Validator // optional; rejects malformed events
	pub       *events.Publisher    // optional; publishes tracker-originated events to NATS

	hooksMu sync.RWMutex
	hooks   []EventHook
}

// New wires up the processor with all required subsystems.
func New(
	s *store.Store,
	h *hub.Hub,
	al *alerts.Manager,
	inc *incidents.Manager,
	ht *honeytoken.Manager,
) *Processor {
	return &Processor{
		store:     s,
		hub:       h,
		alerts:    al,
		incidents: inc,
		honey:     ht,
	}
}

// SetBypassMonitor attaches the bypass anomaly monitor.
func (p *Processor) SetBypassMonitor(m *bypass.Monitor) { p.bypass = m }

// SetPublisher attaches the NATS event publisher for tracker-originated events.
func (p *Processor) SetPublisher(pub *events.Publisher) { p.pub = pub }

// Publisher returns the attached NATS publisher (may be nil).
func (p *Processor) Publisher() *events.Publisher { return p.pub }

// SetSigner attaches the audit event signer.
func (p *Processor) SetSigner(s *audit.Signer) { p.signer = s }

// SetValidator attaches the event schema validator.
func (p *Processor) SetValidator(v *validator.Validator) { p.validator = v }

// Validator returns the attached validator (may be nil).
func (p *Processor) Validator() *validator.Validator { return p.validator }

// AddHook registers a function that is called for every processed event.
func (p *Processor) AddHook(fn EventHook) {
	p.hooksMu.Lock()
	p.hooks = append(p.hooks, fn)
	p.hooksMu.Unlock()
}

// Process handles a single inbound event.
func (p *Processor) Process(ev models.BastionEvent) {
	start := time.Now()

	// Enrich with defaults before validation so severity default is applied first.
	if ev.EventID == "" {
		ev.EventID = newID()
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	if ev.Severity == "" {
		ev.Severity = "info"
	}

	// Schema validation — reject malformed events to dead letter.
	if p.validator != nil {
		if err := p.validator.Validate(&ev); err != nil {
			p.validator.Reject(ev, err.Error())
			log.Printf("[processor] event rejected: %s", err)
			return
		}
	}

	// Metrics.
	metrics.EventsReceived.WithLabelValues(ev.Module, ev.EventType).Inc()

	// Sign event for audit integrity before storing.
	if p.signer != nil {
		p.signer.Sign(&ev)
	}

	// Store.
	p.store.AddEvent(ev)
	p.store.UpsertTrace(ev)

	// MR-05-003: extract chunk lineage from navigator.chunk_retrieved events.
	if ev.EventType == "chunk_retrieved" && ev.TraceID != "" {
		entry := models.ChunkLineageEntry{
			TenantID: ev.TenantID,
		}
		if v, ok := ev.Data["chunk_id"].(string); ok {
			entry.ChunkID = v
		}
		if v, ok := ev.Data["document_id"].(string); ok {
			entry.DocumentID = v
		}
		if v, ok := ev.Data["score"].(float64); ok {
			entry.Score = v
		}
		if v, ok := ev.Data["rank"].(float64); ok {
			entry.Rank = int(v)
		}
		if v, ok := ev.Data["collection"].(string); ok {
			entry.Collection = v
		}
		p.store.AddChunkLineage(ev.TraceID, entry)
	}

	// Pipeline stats.
	if ev.PipelineType != "" {
		metrics.PipelineRequests.WithLabelValues(ev.PipelineType, ev.Status).Inc()
	}

	// Bypass anomaly detection.
	if p.bypass != nil {
		p.bypass.Check(ev)
	}

	// Honey-token detection.
	if tokenID := p.honey.CheckEvent(ev); tokenID != "" {
		log.Printf("[processor] honey-token triggered: %s (event=%s)", tokenID, ev.EventID)
		if p.pub != nil {
			trigID := fmt.Sprintf("%s-trg-%s", tokenID, ev.EventID)
			p.pub.Publish(events.EventHoneyTokenAlert(tokenID, trigID, ev.TenantID, ev.TraceID))
		}
	}

	// Incident auto-creation for security events.
	if inc := p.incidents.AutoCreate(ev); inc != nil {
		p.hub.Broadcast(models.WSMessage{Type: "incident", Payload: inc})
		if p.pub != nil {
			p.pub.Publish(events.EventIncidentCreated(inc.IncidentID, inc.Title, inc.Severity, inc.TenantID, ev.TraceID))
		}
	}

	// Alert evaluation.
	fired := p.alerts.Evaluate(ev)
	for _, al := range fired {
		p.hub.Broadcast(models.WSMessage{Type: "alert", Payload: al})
	}

	// Broadcast the event itself to all WebSocket clients.
	p.hub.Broadcast(models.WSMessage{Type: "event", Payload: ev})

	// Notify registered hooks (e.g. live recorder).
	p.hooksMu.RLock()
	hooks := p.hooks
	p.hooksMu.RUnlock()
	for _, fn := range hooks {
		fn(ev)
	}

	metrics.EventsProcessed.WithLabelValues(ev.Module).Inc()
	metrics.ProcessingDuration.WithLabelValues(ev.Module).Observe(time.Since(start).Seconds())
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
