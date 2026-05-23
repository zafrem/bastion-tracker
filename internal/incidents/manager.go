// Package incidents manages the lifecycle of security incidents.
package incidents

import (
	"fmt"
	"time"

	"github.com/bastion/tracker/internal/metrics"
	"github.com/bastion/tracker/internal/models"
	"github.com/bastion/tracker/internal/store"
)

// Manager creates and updates incidents.
type Manager struct {
	store *store.Store
	seq   int
}

// New creates a Manager backed by the given store.
func New(s *store.Store) *Manager {
	return &Manager{store: s}
}

// AutoCreate inspects an event and creates an incident if it warrants one.
func (m *Manager) AutoCreate(ev models.BastionEvent) *models.Incident {
	var title, desc string
	switch ev.EventType {
	case "honey_token_triggered":
		title = fmt.Sprintf("Honey-token triggered: %v", ev.Data["token_id"])
		desc = "A honey-token was accessed — potential intrusion detected."
	case "prompt_injection_detected":
		title = "Prompt injection attempt detected"
		desc = fmt.Sprintf("Sentinel blocked a prompt injection from user %s.", ev.UserID)
	case "cross_tenant_attempt":
		title = "Cross-tenant access attempt"
		desc = fmt.Sprintf("User %s attempted to access another tenant's data.", ev.UserID)
	default:
		return nil
	}

	if ev.Severity != "critical" && ev.Severity != "error" {
		if ev.EventType != "honey_token_triggered" {
			return nil
		}
	}

	m.seq++
	inc := &models.Incident{
		IncidentID:  fmt.Sprintf("INC-%04d", m.seq),
		Title:       title,
		Severity:    ev.Severity,
		Status:      models.IncidentOpen,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		TenantID:    ev.TenantID,
		Description: desc,
		EventIDs:    []string{ev.EventID},
	}

	m.store.AddIncident(inc)
	metrics.IncidentsCreated.WithLabelValues(inc.Severity).Inc()
	return inc
}

// Resolve closes an open incident.
func (m *Manager) Resolve(incidentID, notes string) (*models.Incident, bool) {
	inc, ok := m.store.GetIncident(incidentID)
	if !ok {
		return nil, false
	}
	now := time.Now()
	inc.Status = models.IncidentResolved
	inc.ResolvedAt = &now
	inc.UpdatedAt = now
	if notes != "" {
		inc.Notes = notes
	}
	m.store.UpdateIncident(inc)
	return inc, true
}
