// Package events publishes Tracker-originated events to NATS (Foundation schema doc 02).
// Subject: bastion.events.tracker.{event_type}
// Silently no-ops if NATS is unavailable so the processing pipeline is never blocked.
package events

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	trackerModule  = "tracker"
	trackerVersion = "1.0.0"
	schemaVer      = "1.0"
	subjectPfx     = "bastion.events.tracker"
)

// TrackerEvent is a Foundation-standard event (doc 02) emitted by Tracker.
type TrackerEvent struct {
	EventID       string                 `json:"event_id"`
	EventType     string                 `json:"event_type"`
	SchemaVersion string                 `json:"schema_version"`
	TraceID       string                 `json:"trace_id,omitempty"`
	Module        string                 `json:"module"`
	ModuleVersion string                 `json:"module_version"`
	Timestamp     int64                  `json:"timestamp"`
	TenantID      string                 `json:"tenant_id,omitempty"`
	Severity      string                 `json:"severity"`
	Category      string                 `json:"category"`
	Status        string                 `json:"status,omitempty"`
	ActionTaken   string                 `json:"action_taken,omitempty"`
	Data          map[string]interface{} `json:"data,omitempty"`
}

// Publisher publishes Tracker events to NATS.
type Publisher struct {
	nc *nats.Conn
}

// New connects to NATS. Returns a silent no-op publisher on error.
func New(natsURL string) *Publisher {
	if natsURL == "" {
		return &Publisher{}
	}
	nc, err := nats.Connect(natsURL,
		nats.MaxReconnects(5),
		nats.ReconnectWait(2e9),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			log.Printf("[tracker-events] nats error: %v", err)
		}),
	)
	if err != nil {
		log.Printf("[tracker-events] nats unavailable (%v), events disabled", err)
		return &Publisher{}
	}
	return &Publisher{nc: nc}
}

// Publish fires the event asynchronously; never blocks the caller.
func (p *Publisher) Publish(ev TrackerEvent) {
	if p == nil || p.nc == nil {
		return
	}
	go func() {
		data, err := json.Marshal(ev)
		if err != nil {
			return
		}
		subject := fmt.Sprintf("%s.%s", subjectPfx, ev.EventType)
		_ = p.nc.Publish(subject, data)
	}()
}

// Close drains the NATS connection.
func (p *Publisher) Close() {
	if p != nil && p.nc != nil {
		p.nc.Drain() //nolint:errcheck
	}
}

func newEvent(eventType, severity, category string, data map[string]interface{}) TrackerEvent {
	return TrackerEvent{
		EventID:       newID(),
		EventType:     eventType,
		SchemaVersion: schemaVer,
		Module:        trackerModule,
		ModuleVersion: trackerVersion,
		Timestamp:     time.Now().UnixNano(),
		Severity:      severity,
		Category:      category,
		Data:          data,
	}
}

// EventIncidentCreated is emitted when Tracker auto-creates a security incident (SRS doc 14).
func EventIncidentCreated(incidentID, title, severity, tenantID, traceID string) TrackerEvent {
	ev := newEvent("incident_created", severity, "security", map[string]interface{}{
		"incident_id": incidentID,
		"title":       title,
	})
	ev.TenantID = tenantID
	ev.TraceID = traceID
	ev.Status = "created"
	ev.ActionTaken = "incident_created"
	return ev
}

// EventHoneyTokenAlert is emitted when Tracker detects a honey-token trigger (SRS doc 14).
func EventHoneyTokenAlert(tokenID, triggerID, tenantID, traceID string) TrackerEvent {
	ev := newEvent("honey_token_alert", "critical", "security", map[string]interface{}{
		"honey_token_id": tokenID,
		"trigger_id":     triggerID,
	})
	ev.TenantID = tenantID
	ev.TraceID = traceID
	ev.Status = "alerted"
	ev.ActionTaken = "alert_raised"
	return ev
}

// EventLineageCompleted is emitted when a lineage query returns results (SRS doc 14).
func EventLineageCompleted(traceID, queryType, tenantID string, resultCount int) TrackerEvent {
	ev := newEvent("lineage_completed", "info", "operational", map[string]interface{}{
		"query_type":   queryType,
		"result_count": resultCount,
	})
	ev.TenantID = tenantID
	ev.TraceID = traceID
	ev.Status = "completed"
	return ev
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
