// Package audit provides HMAC-SHA256 signing and verification for BastionEvent records.
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/bastion/tracker/internal/models"
)

// defaultKey is used in standalone/demo mode when no secret is configured.
const defaultKey = "bastion-tracker-demo-audit-key-v1"

// Signer signs and verifies BastionEvent records using HMAC-SHA256.
// The signature covers the immutable identity fields of the event so that
// any post-storage mutation is detectable.
type Signer struct {
	key []byte
}

// New returns a Signer. If secret is empty the built-in demo key is used,
// so standalone mode works without any configuration.
func New(secret string) *Signer {
	if secret == "" {
		secret = defaultKey
	}
	return &Signer{key: []byte(secret)}
}

// Sign computes the HMAC, stores it in ev.Signature, and returns the hex string.
func (s *Signer) Sign(ev *models.BastionEvent) string {
	sig := s.compute(ev)
	ev.Signature = sig
	return sig
}

// Verify returns true when ev.Signature matches a freshly computed MAC.
// Returns false for unsigned events (empty Signature).
func (s *Signer) Verify(ev models.BastionEvent) bool {
	if ev.Signature == "" {
		return false
	}
	expected := s.compute(&ev)
	return hmac.Equal([]byte(ev.Signature), []byte(expected))
}

// canonical returns the deterministic string that is signed.
// Covers the fields that must never change after storage.
func (s *Signer) compute(ev *models.BastionEvent) string {
	canon := fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s",
		ev.EventID,
		ev.Timestamp.UnixNano(),
		ev.Module,
		ev.EventType,
		ev.TenantID,
		ev.Severity,
		ev.Status,
	)
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(canon))
	return hex.EncodeToString(mac.Sum(nil))
}
