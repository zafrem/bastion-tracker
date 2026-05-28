package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/bastion/tracker/internal/models"
)

func baseEvent() *models.BastionEvent {
	return &models.BastionEvent{
		EventID:   "ev-1",
		Module:    "sentinel",
		EventType: "query_validated",
		TenantID:  "tenant-a",
		Severity:  "info",
		Status:    "passed",
		Timestamp: time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC),
	}
}

// ─── New ─────────────────────────────────────────────────────────────────────

func TestNew_WithSecret(t *testing.T) {
	s := New("my-secret")
	if s == nil {
		t.Fatal("expected non-nil Signer")
	}
}

func TestNew_EmptySecretUsesDefaultKey(t *testing.T) {
	s1 := New("")
	s2 := New(defaultKey)
	ev := baseEvent()
	sig1 := s1.Sign(ev)
	ev2 := baseEvent()
	sig2 := s2.Sign(ev2)
	if sig1 != sig2 {
		t.Error("empty-secret signer should behave identically to one using the default key")
	}
}

// ─── Sign ─────────────────────────────────────────────────────────────────────

func TestSign_SetsSignatureOnEvent(t *testing.T) {
	s := New("key")
	ev := baseEvent()
	s.Sign(ev)
	if ev.Signature == "" {
		t.Fatal("Sign should set ev.Signature")
	}
}

func TestSign_ReturnsHexString(t *testing.T) {
	s := New("key")
	sig := s.Sign(baseEvent())
	for _, c := range sig {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("signature %q is not lowercase hex", sig)
		}
	}
}

func TestSign_SHA256Length(t *testing.T) {
	s := New("key")
	sig := s.Sign(baseEvent())
	// SHA-256 hex = 64 characters
	if len(sig) != 64 {
		t.Fatalf("expected 64-char hex signature, got %d", len(sig))
	}
}

func TestSign_Deterministic(t *testing.T) {
	s := New("key")
	ev1 := baseEvent()
	ev2 := baseEvent()
	sig1 := s.Sign(ev1)
	// Re-create to reset Signature field
	ev2.Signature = ""
	sig2 := s.Sign(ev2)
	if sig1 != sig2 {
		t.Errorf("Sign should be deterministic: %s != %s", sig1, sig2)
	}
}

func TestSign_DifferentKeysProduceDifferentSigs(t *testing.T) {
	s1 := New("key-a")
	s2 := New("key-b")
	ev := baseEvent()
	sig1 := s1.Sign(ev)
	ev.Signature = ""
	sig2 := s2.Sign(ev)
	if sig1 == sig2 {
		t.Error("different keys should produce different signatures")
	}
}

func TestSign_DifferentEventsProduceDifferentSigs(t *testing.T) {
	s := New("key")
	ev1 := baseEvent()
	ev2 := baseEvent()
	ev2.EventID = "ev-2"
	sig1 := s.Sign(ev1)
	ev2.Signature = ""
	sig2 := s.Sign(ev2)
	if sig1 == sig2 {
		t.Error("different event IDs should produce different signatures")
	}
}

// ─── Verify ───────────────────────────────────────────────────────────────────

func TestVerify_ValidSignature(t *testing.T) {
	s := New("key")
	ev := baseEvent()
	s.Sign(ev)
	if !s.Verify(*ev) {
		t.Fatal("Verify should return true for a freshly signed event")
	}
}

func TestVerify_EmptySignature(t *testing.T) {
	s := New("key")
	ev := baseEvent()
	// Do not sign — Signature is empty
	if s.Verify(*ev) {
		t.Fatal("Verify should return false for unsigned event (empty Signature)")
	}
}

func TestVerify_TamperedEventID(t *testing.T) {
	s := New("key")
	ev := baseEvent()
	s.Sign(ev)
	ev.EventID = "ev-tampered"
	if s.Verify(*ev) {
		t.Fatal("Verify should return false after EventID was tampered")
	}
}

func TestVerify_TamperedModule(t *testing.T) {
	s := New("key")
	ev := baseEvent()
	s.Sign(ev)
	ev.Module = "vault"
	if s.Verify(*ev) {
		t.Fatal("Verify should return false after Module was tampered")
	}
}

func TestVerify_TamperedEventType(t *testing.T) {
	s := New("key")
	ev := baseEvent()
	s.Sign(ev)
	ev.EventType = "injection_detected"
	if s.Verify(*ev) {
		t.Fatal("Verify should return false after EventType was tampered")
	}
}

func TestVerify_TamperedSeverity(t *testing.T) {
	s := New("key")
	ev := baseEvent()
	s.Sign(ev)
	ev.Severity = "critical"
	if s.Verify(*ev) {
		t.Fatal("Verify should return false after Severity was tampered")
	}
}

func TestVerify_TamperedStatus(t *testing.T) {
	s := New("key")
	ev := baseEvent()
	s.Sign(ev)
	ev.Status = "blocked"
	if s.Verify(*ev) {
		t.Fatal("Verify should return false after Status was tampered")
	}
}

func TestVerify_TamperedTimestamp(t *testing.T) {
	s := New("key")
	ev := baseEvent()
	s.Sign(ev)
	ev.Timestamp = ev.Timestamp.Add(time.Second)
	if s.Verify(*ev) {
		t.Fatal("Verify should return false after Timestamp was tampered")
	}
}

func TestVerify_WrongKeySigner(t *testing.T) {
	signer := New("key-correct")
	verifier := New("key-wrong")
	ev := baseEvent()
	signer.Sign(ev)
	if verifier.Verify(*ev) {
		t.Fatal("Verify should return false when using a different key")
	}
}

func TestVerify_SignatureNotPartOfCanon(t *testing.T) {
	// The Signature field itself is not part of the canonical string,
	// so modifying it directly makes verification fail while not affecting canon.
	s := New("key")
	ev := baseEvent()
	s.Sign(ev)
	ev.Signature = "0000000000000000000000000000000000000000000000000000000000000000"
	if s.Verify(*ev) {
		t.Fatal("Verify should return false when Signature field is replaced with wrong value")
	}
}
