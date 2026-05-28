package honeytoken

import (
	"testing"
	"time"

	"github.com/bastion/tracker/internal/models"
	"github.com/bastion/tracker/internal/store"
)

func newMgr() *Manager {
	return New(store.New(1000))
}

func htEv(eventType, tokenID string) models.BastionEvent {
	data := map[string]any{}
	if tokenID != "" {
		data["honey_token_id"] = tokenID
	}
	return models.BastionEvent{
		EventID:   "ev-" + eventType,
		EventType: eventType,
		Module:    "vault",
		TenantID:  "t1",
		UserID:    "attacker",
		Timestamp: time.Now(),
		Data:      data,
	}
}

// ─── CRUD ─────────────────────────────────────────────────────────────────────

func TestCreate_AssignsID(t *testing.T) {
	m := newMgr()
	tok := m.Create("Fake CEO", "desc", "customer_db", models.HoneyTokenEmail)
	if tok.TokenID == "" {
		t.Fatal("expected non-empty TokenID")
	}
}

func TestCreate_IDsAreSequential(t *testing.T) {
	m := newMgr()
	t1 := m.Create("A", "d", "loc", models.HoneyTokenEmail)
	t2 := m.Create("B", "d", "loc", models.HoneyTokenCredential)
	if t1.TokenID == t2.TokenID {
		t.Fatal("IDs should be unique")
	}
}

func TestCreate_EnabledByDefault(t *testing.T) {
	m := newMgr()
	tok := m.Create("tok", "d", "loc", models.HoneyTokenDocument)
	if !tok.Enabled {
		t.Fatal("token should be enabled by default")
	}
}

func TestCreate_FieldsSet(t *testing.T) {
	m := newMgr()
	tok := m.Create("mytoken", "my desc", "hr_db", models.HoneyTokenIdentity)
	if tok.Name != "mytoken" {
		t.Errorf("unexpected name: %s", tok.Name)
	}
	if tok.Description != "my desc" {
		t.Errorf("unexpected description: %s", tok.Description)
	}
	if tok.Location != "hr_db" {
		t.Errorf("unexpected location: %s", tok.Location)
	}
	if tok.Type != models.HoneyTokenIdentity {
		t.Errorf("unexpected type: %s", tok.Type)
	}
}

func TestList_Empty(t *testing.T) {
	m := newMgr()
	if got := m.List(); len(got) != 0 {
		t.Fatalf("expected empty list, got %d", len(got))
	}
}

func TestList_ReturnAll(t *testing.T) {
	m := newMgr()
	m.Create("A", "", "loc", models.HoneyTokenEmail)
	m.Create("B", "", "loc", models.HoneyTokenCredential)
	m.Create("C", "", "loc", models.HoneyTokenDocument)
	if got := m.List(); len(got) != 3 {
		t.Fatalf("expected 3, got %d", len(got))
	}
}

func TestGet_Found(t *testing.T) {
	m := newMgr()
	tok := m.Create("findme", "d", "loc", models.HoneyTokenEmail)
	got, ok := m.Get(tok.TokenID)
	if !ok {
		t.Fatal("expected to find token")
	}
	if got.Name != "findme" {
		t.Errorf("unexpected name: %s", got.Name)
	}
}

func TestGet_NotFound(t *testing.T) {
	m := newMgr()
	_, ok := m.Get("HT-9999")
	if ok {
		t.Fatal("expected not found")
	}
}

func TestDelete_RemovesToken(t *testing.T) {
	m := newMgr()
	tok := m.Create("del", "d", "loc", models.HoneyTokenCredential)
	if !m.Delete(tok.TokenID) {
		t.Fatal("Delete returned false")
	}
	if _, ok := m.Get(tok.TokenID); ok {
		t.Fatal("token should be gone")
	}
}

func TestDelete_NotFound(t *testing.T) {
	m := newMgr()
	if m.Delete("nonexistent") {
		t.Fatal("expected false for unknown token")
	}
}

// ─── Trigger detection ────────────────────────────────────────────────────────

func TestCheckEvent_ReturnsTriggerIDForKnownEvent(t *testing.T) {
	tests := []string{
		"honey_token_triggered",
		"honey_token_accessed",
		"honey_token_retrieved",
		"honey_token_referenced",
		"honey_token_leaked",
	}
	for _, et := range tests {
		m := newMgr()
		ev := htEv(et, "HT-0001")
		got := m.CheckEvent(ev)
		if got == "" {
			t.Errorf("event type %q: expected token ID, got empty", et)
		}
	}
}

func TestCheckEvent_IgnoresNonHoneyTokenEvents(t *testing.T) {
	m := newMgr()
	nonHoney := models.BastionEvent{
		EventID:   "ev-1",
		EventType: "query_validated",
		Module:    "sentinel",
		Timestamp: time.Now(),
	}
	got := m.CheckEvent(nonHoney)
	if got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestCheckEvent_RecordsTrigger(t *testing.T) {
	m := newMgr()
	// Token must be registered so RecordTrigger persists it.
	tok := m.Create("decoy-record", "d", "loc", models.HoneyTokenEmail)
	e := htEv("honey_token_accessed", tok.TokenID)
	m.CheckEvent(e)

	triggers := m.AllTriggers()
	if len(triggers) != 1 {
		t.Fatalf("expected 1 trigger, got %d", len(triggers))
	}
	if triggers[0].TokenID != tok.TokenID {
		t.Errorf("unexpected token ID: %s", triggers[0].TokenID)
	}
}

func TestCheckEvent_FallbackToLegacyTokenID(t *testing.T) {
	m := newMgr()
	ev := models.BastionEvent{
		EventID:   "ev-legacy",
		EventType: "honey_token_triggered",
		Module:    "vault",
		Timestamp: time.Now(),
		Data:      map[string]any{"token_id": "LEGACY-001"},
	}
	got := m.CheckEvent(ev)
	if got != "LEGACY-001" {
		t.Errorf("expected LEGACY-001, got %q", got)
	}
}

func TestCheckEvent_UnknownTokenIDBecomesUnknown(t *testing.T) {
	m := newMgr()
	ev := htEv("honey_token_triggered", "") // no token ID in data
	got := m.CheckEvent(ev)
	if got != "unknown" {
		t.Errorf("expected 'unknown', got %q", got)
	}
}

func TestCheckEvent_RecordsSourceIP(t *testing.T) {
	m := newMgr()
	// Token must exist in store for RecordTrigger to persist the trigger.
	tok := m.Create("decoy", "d", "loc", models.HoneyTokenEmail)
	e := models.BastionEvent{
		EventID:   "ev-ip",
		EventType: "honey_token_accessed",
		Module:    "vault",
		Timestamp: time.Now(),
		Data:      map[string]any{"honey_token_id": tok.TokenID, "source_ip": "10.0.0.1"},
	}
	m.CheckEvent(e)
	triggers := m.AllTriggers()
	if len(triggers) != 1 || triggers[0].SourceIP != "10.0.0.1" {
		t.Fatalf("expected source_ip=10.0.0.1, got %+v", triggers)
	}
}

func TestTriggers_ByTokenID(t *testing.T) {
	m := newMgr()
	// Tokens must be registered before triggers can be recorded.
	tokA := m.Create("decoy-A", "d", "loc", models.HoneyTokenEmail)
	tokB := m.Create("decoy-B", "d", "loc", models.HoneyTokenCredential)
	m.CheckEvent(htEv("honey_token_accessed", tokA.TokenID))
	m.CheckEvent(htEv("honey_token_retrieved", tokA.TokenID))
	m.CheckEvent(htEv("honey_token_accessed", tokB.TokenID))

	aTrigs := m.Triggers(tokA.TokenID)
	if len(aTrigs) != 2 {
		t.Fatalf("expected 2 triggers for %s, got %d", tokA.TokenID, len(aTrigs))
	}
}

func TestAllTriggers(t *testing.T) {
	m := newMgr()
	t1 := m.Create("d1", "d", "loc", models.HoneyTokenEmail)
	t2 := m.Create("d2", "d", "loc", models.HoneyTokenCredential)
	t3 := m.Create("d3", "d", "loc", models.HoneyTokenIdentity)
	m.CheckEvent(htEv("honey_token_accessed", t1.TokenID))
	m.CheckEvent(htEv("honey_token_leaked", t2.TokenID))
	m.CheckEvent(htEv("honey_token_referenced", t3.TokenID))

	all := m.AllTriggers()
	if len(all) != 3 {
		t.Fatalf("expected 3 total triggers, got %d", len(all))
	}
}

// ─── SeedDefaults ─────────────────────────────────────────────────────────────

func TestSeedDefaults_CreatesThreeTokens(t *testing.T) {
	m := newMgr()
	m.SeedDefaults()
	if got := m.List(); len(got) != 3 {
		t.Fatalf("expected 3 tokens after SeedDefaults, got %d", len(got))
	}
}

func TestSeedDefaults_TokenTypesCorrect(t *testing.T) {
	m := newMgr()
	m.SeedDefaults()
	types := map[models.HoneyTokenType]bool{}
	for _, tok := range m.List() {
		types[tok.Type] = true
	}
	for _, expected := range []models.HoneyTokenType{
		models.HoneyTokenEmail,
		models.HoneyTokenCredential,
		models.HoneyTokenIdentity,
	} {
		if !types[expected] {
			t.Errorf("missing token type: %s", expected)
		}
	}
}
