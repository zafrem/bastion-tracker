// Package bypass detects suspicious pipeline bypass anomalies.
package bypass

import (
	"sync"
	"time"

	"github.com/bastion/tracker/internal/models"
)

// EventSink receives synthesised anomaly events.
type EventSink interface {
	Process(ev models.BastionEvent)
}

type pipelineEntry struct {
	pipelineType string
	at           time.Time
}

// Monitor tracks per-tenant pipeline history and detects bypass anomalies.
type Monitor struct {
	mu              sync.Mutex
	history         map[string][]pipelineEntry
	sensitiveLabels map[string]struct{}
	sink            EventSink
}

// New creates a Monitor. sensitiveLabels are label keys that indicate sensitive data.
func New(sensitiveLabels []string, sink EventSink) *Monitor {
	m := &Monitor{
		history:         make(map[string][]pipelineEntry),
		sensitiveLabels: make(map[string]struct{}),
		sink:            sink,
	}
	for _, l := range sensitiveLabels {
		m.sensitiveLabels[l] = struct{}{}
	}
	return m
}

// Check inspects an event for bypass anomalies and emits security events if found.
func (m *Monitor) Check(ev models.BastionEvent) {
	if ev.TenantID == "" || ev.PipelineType == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Prune history entries older than 1 hour.
	cutoff := time.Now().Add(-time.Hour)
	hist := m.history[ev.TenantID]
	pruned := hist[:0]
	for _, e := range hist {
		if e.at.After(cutoff) {
			pruned = append(pruned, e)
		}
	}
	m.history[ev.TenantID] = append(pruned, pipelineEntry{pipelineType: ev.PipelineType, at: ev.Timestamp})

	// Anomaly 1: event carries a sensitive label but vault was skipped.
	if len(m.sensitiveLabels) > 0 && len(ev.ModulesSkipped) > 0 {
		for k := range ev.Labels {
			if _, sensitive := m.sensitiveLabels[k]; sensitive {
				for _, mod := range ev.ModulesSkipped {
					if mod == "vault" {
						m.emit(ev, "sensitive_label_vault_skipped",
							"event carries sensitive label '"+k+"' but vault module was skipped")
						return
					}
				}
			}
		}
	}

	// Anomaly 2: tenant used full pipeline ≥90% of recent history, then suddenly lite/minimal.
	if ev.PipelineType == "lite" || ev.PipelineType == "minimal" {
		hist = m.history[ev.TenantID]
		prior := hist[:len(hist)-1] // exclude the entry we just added
		if len(prior) >= 10 {
			full := 0
			for _, e := range prior {
				if e.pipelineType == "full" {
					full++
				}
			}
			if float64(full)/float64(len(prior)) >= 0.9 {
				m.emit(ev, "pipeline_downgrade_anomaly",
					"tenant switched from full pipeline (≥90% history) to "+ev.PipelineType)
			}
		}
	}
}

func (m *Monitor) emit(trigger models.BastionEvent, anomalyType, reason string) {
	if m.sink == nil {
		return
	}
	anomaly := models.BastionEvent{
		Module:    "security",
		EventType: "bypass_anomaly_detected",
		Severity:  "warning",
		Status:    "error",
		Timestamp: time.Now(),
		TenantID:  trigger.TenantID,
		UserID:    trigger.UserID,
		TraceID:   trigger.TraceID,
		Data: map[string]any{
			"anomaly_type":     anomalyType,
			"reason":           reason,
			"trigger_event_id": trigger.EventID,
			"pipeline_type":    trigger.PipelineType,
		},
	}
	go m.sink.Process(anomaly)
}
