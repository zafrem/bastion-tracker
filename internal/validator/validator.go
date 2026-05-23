// Package validator checks BastionEvents for schema compliance and maintains
// a dead-letter buffer for rejected events.
package validator

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/bastion/tracker/internal/metrics"
	"github.com/bastion/tracker/internal/models"
)

var validSeverities = map[string]bool{
	"":         true, // processor will default to "info"
	"info":     true,
	"warning":  true,
	"error":    true,
	"critical": true,
}

var validStatuses = map[string]bool{
	"":            true,
	"passed":      true,
	"blocked":     true,
	"error":       true,
	"pending":     true,
	"in_progress": true,
}

const maxDeadLetters = 200

// DeadLetterEntry is a rejected event with the reason for rejection.
type DeadLetterEntry struct {
	ReceivedAt time.Time       `json:"received_at"`
	Reason     string          `json:"reason"`
	Raw        json.RawMessage `json:"raw"`
}

// Validator checks BastionEvents for schema compliance.
type Validator struct {
	mu          sync.RWMutex
	deadLetters []DeadLetterEntry
}

// New returns a ready-to-use Validator.
func New() *Validator {
	return &Validator{}
}

// Validate returns a non-nil error if the event is malformed.
// It does NOT mutate the event.
func (v *Validator) Validate(ev *models.BastionEvent) error {
	if strings.TrimSpace(ev.EventType) == "" {
		return fmt.Errorf("event_type is required")
	}
	if strings.TrimSpace(ev.Module) == "" {
		return fmt.Errorf("module is required")
	}
	if !validSeverities[ev.Severity] {
		return fmt.Errorf("invalid severity %q: must be info, warning, error, or critical", ev.Severity)
	}
	if !validStatuses[ev.Status] {
		return fmt.Errorf("invalid status %q: must be passed, blocked, error, or pending", ev.Status)
	}
	return nil
}

// Reject marshals ev to JSON and stores it in the dead-letter buffer with reason.
func (v *Validator) Reject(ev models.BastionEvent, reason string) {
	metrics.EventsRejected.Inc()
	log.Printf("[validator] rejected event: %s", reason)

	raw, _ := json.Marshal(ev)
	entry := DeadLetterEntry{
		ReceivedAt: time.Now(),
		Reason:     reason,
		Raw:        raw,
	}
	v.mu.Lock()
	v.deadLetters = append(v.deadLetters, entry)
	if len(v.deadLetters) > maxDeadLetters {
		// drop oldest
		v.deadLetters = v.deadLetters[len(v.deadLetters)-maxDeadLetters:]
	}
	v.mu.Unlock()
}

// DeadLetters returns a snapshot of the buffer, newest first.
func (v *Validator) DeadLetters() []DeadLetterEntry {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]DeadLetterEntry, len(v.deadLetters))
	for i, e := range v.deadLetters {
		out[len(v.deadLetters)-1-i] = e
	}
	return out
}
