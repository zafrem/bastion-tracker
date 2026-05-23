// Package alerts evaluates alert rules against incoming events and dispatches notifications.
package alerts

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/bastion/tracker/internal/config"
	"github.com/bastion/tracker/internal/metrics"
	"github.com/bastion/tracker/internal/models"
	"github.com/bastion/tracker/internal/notify"
	"github.com/bastion/tracker/internal/store"
)

// Manager evaluates configurable alert rules and dispatches notifications.
type Manager struct {
	rules     []config.AlertRule
	store     *store.Store
	notifiers map[string]notify.Notifier // channel name → notifier
	seq       int
}

// New creates an alert Manager with per-channel notifiers.
// The notifiers map keys should match rule Channel names ("slack", "email", "webhook").
func New(rules []config.AlertRule, s *store.Store, notifiers map[string]notify.Notifier) *Manager {
	if notifiers == nil {
		notifiers = map[string]notify.Notifier{}
	}
	return &Manager{rules: rules, store: s, notifiers: notifiers}
}

// Evaluate checks an event against all rules and fires matching alerts.
func (m *Manager) Evaluate(ev models.BastionEvent) []*models.Alert {
	var fired []*models.Alert
	for _, rule := range m.rules {
		if !matches(rule.Condition, ev) {
			continue
		}
		m.seq++
		now := time.Now()
		al := &models.Alert{
			AlertID:  fmt.Sprintf("ALT-%04d", m.seq),
			RuleName: rule.Name,
			Severity: rule.Severity,
			Status:   models.AlertFiring,
			Message:  fmt.Sprintf("Rule %q matched %s.%s (tenant=%s)", rule.Name, ev.Module, ev.EventType, ev.TenantID),
			Module:   ev.Module,
			TenantID: ev.TenantID,
			FiredAt:  now,
		}
		m.store.AddAlert(al)
		metrics.AlertsFired.WithLabelValues(rule.Name, rule.Severity).Inc()
		metrics.ActiveAlerts.Inc()
		fired = append(fired, al)

		// Dispatch to configured channels asynchronously.
		if len(rule.Channels) > 0 {
			go m.dispatch(rule, al)
		}
	}
	return fired
}

func (m *Manager) dispatch(rule config.AlertRule, al *models.Alert) {
	for _, ch := range rule.Channels {
		n, ok := m.notifiers[ch]
		if !ok {
			log.Printf("[alerts] unknown notification channel %q for rule %s", ch, rule.Name)
			continue
		}
		if err := n.Notify(al.RuleName, al.Message, al.Severity); err != nil {
			log.Printf("[alerts] notify %s failed for rule %s: %v", ch, rule.Name, err)
		}
	}
}

// StartBackgroundTasks runs a ticker that auto-resolves and escalates alerts per rule config.
// Call once from main; blocks until ctx is cancelled.
func (m *Manager) StartBackgroundTasks(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.runLifecycleTick()
		}
	}
}

func (m *Manager) runLifecycleTick() {
	now := time.Now()
	firing := m.store.ListAlerts(string(models.AlertFiring))
	for _, al := range firing {
		rule := m.ruleByName(al.RuleName)
		if rule == nil {
			continue
		}
		// Auto-resolve.
		if rule.AutoResolveAfter != "" {
			d, err := time.ParseDuration(rule.AutoResolveAfter)
			if err == nil && now.Sub(al.FiredAt) >= d {
				if m.store.ResolveAlert(al.AlertID) {
					log.Printf("[alerts] auto-resolved %s (rule=%s)", al.AlertID, rule.Name)
					metrics.ActiveAlerts.Dec()
				}
				continue
			}
		}
		// Escalate if not yet escalated.
		if rule.EscalateAfter != "" && al.EscalatedAt == nil {
			d, err := time.ParseDuration(rule.EscalateAfter)
			if err == nil && now.Sub(al.FiredAt) >= d {
				if m.store.EscalateAlert(al.AlertID) {
					log.Printf("[alerts] escalated %s (rule=%s)", al.AlertID, rule.Name)
					if len(rule.Channels) > 0 {
						go m.dispatch(*rule, &al)
					}
				}
			}
		}
	}
}

func (m *Manager) ruleByName(name string) *config.AlertRule {
	for i := range m.rules {
		if m.rules[i].Name == name {
			return &m.rules[i]
		}
	}
	return nil
}

// matches checks whether an event satisfies a rule condition string.
//
// Supported condition formats:
//
//	module.event_type   — exact match on both fields
//	*.event_type        — any module, specific event_type
//	module.*            — any event_type from a specific module
//	severity:<level>    — any event at this severity
//	status:<status>     — any event with this status
//	bare_event_type     — match event_type regardless of module (no dot)
func matches(cond string, ev models.BastionEvent) bool {
	// severity:<level>
	if rest, ok := strings.CutPrefix(cond, "severity:"); ok {
		return ev.Severity == rest
	}
	// status:<status>
	if rest, ok := strings.CutPrefix(cond, "status:"); ok {
		return ev.Status == rest
	}
	// module.event_type  /  *.event_type  /  module.*
	if dot := strings.Index(cond, "."); dot >= 0 {
		module, evType := cond[:dot], cond[dot+1:]
		moduleMatch := module == "*" || module == ev.Module
		evTypeMatch := evType == "*" || evType == ev.EventType
		return moduleMatch && evTypeMatch
	}
	// bare event_type
	return cond == ev.EventType
}
