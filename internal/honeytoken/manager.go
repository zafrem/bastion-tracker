// Package honeytoken manages honey-token creation, storage, and trigger detection.
package honeytoken

import (
	"fmt"
	"time"

	"github.com/bastion/tracker/internal/metrics"
	"github.com/bastion/tracker/internal/models"
	"github.com/bastion/tracker/internal/store"
)

// Manager provides CRUD operations and trigger detection for honey-tokens.
type Manager struct {
	store *store.Store
	seq   int
}

// New creates a Manager.
func New(s *store.Store) *Manager {
	return &Manager{store: s}
}

// Create registers a new honey-token and returns it.
func (m *Manager) Create(name, description, location string, typ models.HoneyTokenType) *models.HoneyToken {
	m.seq++
	tok := &models.HoneyToken{
		TokenID:     fmt.Sprintf("HT-%04d", m.seq),
		Name:        name,
		Type:        typ,
		Location:    location,
		Description: description,
		CreatedAt:   time.Now(),
		Enabled:     true,
	}
	m.store.AddToken(tok)
	return tok
}

// List returns all honey-tokens.
func (m *Manager) List() []models.HoneyToken { return m.store.ListTokens() }

// Get returns a token by ID.
func (m *Manager) Get(id string) (*models.HoneyToken, bool) { return m.store.GetToken(id) }

// Delete removes a token and returns false if it didn't exist.
func (m *Manager) Delete(id string) bool { return m.store.DeleteToken(id) }

// Triggers returns the trigger history for a token.
func (m *Manager) Triggers(tokenID string) []models.HoneyTokenTrigger {
	return m.store.TokenTriggers(tokenID)
}

// CheckEvent examines an event for honey-token triggers and records them.
// Returns the token ID if a trigger was detected.
func (m *Manager) CheckEvent(ev models.BastionEvent) string {
	if ev.EventType != "honey_token_triggered" {
		return ""
	}
	tokenIDRaw, ok := ev.Data["token_id"]
	if !ok {
		return ""
	}
	tokenID, _ := tokenIDRaw.(string)
	if tokenID == "" {
		return ""
	}

	trig := models.HoneyTokenTrigger{
		TriggerID:   fmt.Sprintf("%s-trg-%d", tokenID, time.Now().UnixNano()),
		TokenID:     tokenID,
		TriggeredAt: ev.Timestamp,
		UserID:      ev.UserID,
		TenantID:    ev.TenantID,
		EventID:     ev.EventID,
	}
	if ip, ok := ev.Data["source_ip"].(string); ok {
		trig.SourceIP = ip
	}

	m.store.RecordTrigger(trig)
	metrics.HoneyTokenTriggers.Inc()
	return tokenID
}

// SeedDefaults creates the three default demo honey-tokens from the SRS.
func (m *Manager) SeedDefaults() {
	m.Create("Fake CEO Email", "Decoy CEO email address for intrusion detection",
		"customer_database", models.HoneyTokenEmail)
	m.Create("Fake API Key", "Decoy API key placed in HR database",
		"hr_database", models.HoneyTokenCredential)
	m.Create("Fake Customer Record", "Hong Gildong with fake SSN in customer DB",
		"customer_database", models.HoneyTokenIdentity)
}
