# Tracker — Honey-Token Injection

**Module:** Tracker (`internal/honeytoken/`, `internal/store/`, `internal/processor/`, `internal/incidents/`, `internal/events/`)
**Version:** 3.0
**Last updated:** 2026-05-30

---

## Overview

Honey-tokens are decoy data records deliberately placed in the pipeline. They look like real sensitive records (email addresses, API keys, customer identities) but are never used in normal operations. Any event that references a honey-token is by definition an intrusion indicator — a legitimate process would never encounter one.

This makes honey-token detection high-signal and nearly zero false-positive: unlike rule-based anomaly detection, a honey-token trigger requires no threshold tuning. If it fires, something anomalous happened.

The Tracker owns the honey-token lifecycle. Detection events are emitted by the modules where the token was encountered (Sentinel, Vault, Navigator) and forwarded to Tracker for correlation and incident creation.

---

## `HoneyToken` — the data model

```go
// internal/models/types.go

type HoneyToken struct {
    TokenID       string         `json:"token_id"`        // "HT-0001", "HT-0002", ...
    Name          string         `json:"name"`            // human label
    Type          HoneyTokenType `json:"type"`            // email|credential|identity|document
    Location      string         `json:"location"`        // where the decoy was injected
    Description   string         `json:"description"`
    CreatedAt     time.Time      `json:"created_at"`
    Enabled       bool           `json:"enabled"`         // false = inactive; events still received
    TriggerCount  int            `json:"trigger_count"`   // incremented on each trigger
    LastTriggered *time.Time     `json:"last_triggered,omitempty"` // nil until first trigger
    IncidentID    string         `json:"incident_id,omitempty"`    // set after incident auto-created
}

type HoneyTokenType string

const (
    HoneyTokenEmail      HoneyTokenType = "email"       // fake email address
    HoneyTokenCredential HoneyTokenType = "credential"  // fake API key or password
    HoneyTokenIdentity   HoneyTokenType = "identity"    // fake person record
    HoneyTokenDocument   HoneyTokenType = "document"    // fake document or report
)
```

### `HoneyTokenTrigger` — one activation record

```go
type HoneyTokenTrigger struct {
    TriggerID   string    `json:"trigger_id"`    // "{token_id}-trg-{UnixNano}"
    TokenID     string    `json:"token_id"`
    TriggeredAt time.Time `json:"triggered_at"`
    SourceIP    string    `json:"source_ip,omitempty"` // when available in event Data
    UserID      string    `json:"user_id,omitempty"`
    TenantID    string    `json:"tenant_id,omitempty"`
    EventID     string    `json:"event_id"`            // links back to the triggering BastionEvent
}
```

---

## `Manager` — lifecycle operations

```go
// internal/honeytoken/manager.go

type Manager struct {
    store *store.Store
    seq   int  // monotonic counter for token IDs
}

// Create registers a new honey-token with a sequential ID.
// All tokens start enabled=true so they are immediately active.
func (m *Manager) Create(name, description, location string, typ models.HoneyTokenType) *models.HoneyToken {
    m.seq++
    tok := &models.HoneyToken{
        TokenID:     fmt.Sprintf("HT-%04d", m.seq),  // e.g. "HT-0001"
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
```

### Default seed tokens

Three demo tokens are pre-created on startup:

```go
// internal/honeytoken/manager.go

func (m *Manager) SeedDefaults() {
    // HT-0001: Fake CEO email in customer database
    // Trigger indicates: attacker exfiltrated customer email list and found this entry
    m.Create(
        "Fake CEO Email",
        "Decoy CEO email address for intrusion detection",
        "customer_database",
        models.HoneyTokenEmail,
    )
    // HT-0002: Fake API key in HR database
    // Trigger indicates: attacker accessed HR records looking for credentials
    m.Create(
        "Fake API Key",
        "Decoy API key placed in HR database",
        "hr_database",
        models.HoneyTokenCredential,
    )
    // HT-0003: Fake customer identity with fake SSN
    // Trigger indicates: specific customer record queried — high precision indicator
    m.Create(
        "Fake Customer Record",
        "Hong Gildong with fake SSN in customer DB",
        "customer_database",
        models.HoneyTokenIdentity,
    )
}
```

---

## Detection — `CheckEvent()`

Detection runs inside `Processor.Process()` on every inbound event. It is a pure pattern-match — no ML, no thresholds:

```go
// internal/honeytoken/manager.go

// detectionEventTypes contains all event types that signal an active honey-token encounter.
// Each type maps to a different pipeline layer where the token was detected.
var detectionEventTypes = map[string]bool{
    "honey_token_triggered":  true, // generic / legacy — any layer
    "honey_token_accessed":   true, // Vault: token was accessed at the data layer
    "honey_token_retrieved":  true, // Navigator: token appeared in search results
    "honey_token_referenced": true, // Sentinel: token appeared in a user query (input)
    "honey_token_leaked":     true, // Sentinel: token appeared in LLM response (output)
}

func (m *Manager) CheckEvent(ev models.BastionEvent) string {
    // Fast path: reject non-honey-token events without touching the store.
    // The string prefix check ("honey_token_") catches custom subtypes not in the map.
    if !detectionEventTypes[ev.EventType] && !strings.HasPrefix(ev.EventType, "honey_token_") {
        return ""
    }

    // Extract the honey-token ID from the event's Data map.
    // Modules publish "honey_token_id"; legacy events may use "token_id".
    tokenID, _ := ev.Data["honey_token_id"].(string)
    if tokenID == "" {
        tokenID, _ = ev.Data["token_id"].(string)
    }
    if tokenID == "" {
        tokenID = "unknown"  // still record the trigger; token creation may have failed
    }

    trig := models.HoneyTokenTrigger{
        // TriggerID uses UnixNano for uniqueness within the same token.
        TriggerID:   fmt.Sprintf("%s-trg-%d", tokenID, time.Now().UnixNano()),
        TokenID:     tokenID,
        TriggeredAt: ev.Timestamp,
        UserID:      ev.UserID,
        TenantID:    ev.TenantID,
        EventID:     ev.EventID,  // links trigger to original event for audit
    }
    if ip, ok := ev.Data["source_ip"].(string); ok {
        trig.SourceIP = ip
    }

    m.store.RecordTrigger(trig)
    metrics.HoneyTokenTriggers.Inc()
    return tokenID
}
```

### `Store.RecordTrigger()` — updating the token and recording the history

```go
// internal/store/memory.go

func (s *Store) RecordTrigger(tr models.HoneyTokenTrigger) {
    s.mu.Lock()
    defer s.mu.Unlock()
    tok, ok := s.tokens[tr.TokenID]
    if !ok {
        return  // token doesn't exist — trigger is still stored under the unknown ID
    }
    now := tr.TriggeredAt
    tok.TriggerCount++             // incremented for every trigger
    tok.LastTriggered = &now       // tracks most recent activation time
    s.triggers[tr.TokenID] = append(s.triggers[tr.TokenID], tr)  // append to history
}
```

---

## Detection layers — where tokens are encountered

Each module emits a different event type depending on where in the pipeline the honey-token was seen:

| Event type | Module | What it means |
|---|---|---|
| `honey_token_referenced` | Sentinel-IN | User query contains a honey-token value — attacker is probing the system |
| `honey_token_accessed` | Vault | Honey-token record was decrypted/tokenized — attacker accessed the data layer |
| `honey_token_retrieved` | Navigator | Honey-token appeared in Qdrant search results — attacker searched for it |
| `honey_token_leaked` | Sentinel-OUT | Honey-token appeared in LLM response — data exfiltration attempt at output |
| `honey_token_triggered` | Any | Generic trigger for tokens not covered by the above types |

The layer label is extracted in `incidents.Manager.honeyTokenTitle()` for human-readable incident titles:

```go
// internal/incidents/manager.go

func honeyTokenTitle(ev models.BastionEvent) string {
    tokenID, _ := ev.Data["honey_token_id"].(string)
    if tokenID == "" {
        tokenID, _ = ev.Data["token_id"].(string)
    }

    layer := map[string]string{
        "honey_token_triggered":  "triggered",
        "honey_token_accessed":   "data-layer access (Vault)",
        "honey_token_retrieved":  "search-layer retrieval (Navigator)",
        "honey_token_referenced": "input-layer reference (Sentinel)",
        "honey_token_leaked":     "output-layer leak (Sentinel)",
    }
    lbl := layer[ev.EventType]
    if lbl == "" {
        lbl = ev.EventType  // custom subtype — use the type string directly
    }

    if tokenID != "" {
        return fmt.Sprintf("Honey-token %s: %s", lbl, tokenID)
    }
    return fmt.Sprintf("Honey-token %s", lbl)
}
```

---

## Incident auto-creation

Every honey-token trigger automatically creates a security incident, regardless of severity:

```go
// internal/incidents/manager.go

func (m *Manager) AutoCreate(ev models.BastionEvent) *models.Incident {
    var title, desc string

    switch {
    case strings.HasPrefix(ev.EventType, "honey_token_"):
        title = honeyTokenTitle(ev)
        desc = fmt.Sprintf(
            "Honey-token detection at %s layer — potential intrusion (module: %s).",
            ev.EventType, ev.Module,
        )
    case ev.EventType == "prompt_injection_detected":
        // ... other auto-create cases
    default:
        return nil
    }

    // For honey-token events, severity check is skipped — they always create incidents.
    // Other event types require critical or error severity.
    if ev.Severity != "critical" && ev.Severity != "error" {
        if !strings.HasPrefix(ev.EventType, "honey_token_") {
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
        EventIDs:    []string{ev.EventID},  // link to triggering event for audit
    }

    m.store.AddIncident(inc)
    metrics.IncidentsCreated.WithLabelValues(inc.Severity).Inc()
    return inc
}
```

---

## NATS alert emission

After the honey-token trigger is recorded and the incident is created, a critical NATS event is published:

```go
// internal/events/publisher.go

// EventHoneyTokenAlert is emitted on every honey-token trigger.
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
```

Called from `processor.Process()`:

```go
// internal/processor/processor.go

if tokenID := p.honey.CheckEvent(ev); tokenID != "" {
    log.Printf("[processor] honey-token triggered: %s (event=%s)", tokenID, ev.EventID)
    if p.pub != nil {
        trigID := fmt.Sprintf("%s-trg-%s", tokenID, ev.EventID)
        p.pub.Publish(events.EventHoneyTokenAlert(tokenID, trigID, ev.TenantID, ev.TraceID))
    }
}
```

The trigger then flows through the remaining pipeline steps:

```go
// After honey-token check:

// Auto-create incident → WebSocket broadcast to all connected dashboard clients
if inc := p.incidents.AutoCreate(ev); inc != nil {
    p.hub.Broadcast(models.WSMessage{Type: "incident", Payload: inc})
    if p.pub != nil {
        p.pub.Publish(events.EventIncidentCreated(...))
    }
}

// Alert rules may also fire (e.g. "alert on any honey_token_ event")
fired := p.alerts.Evaluate(ev)
for _, al := range fired {
    p.hub.Broadcast(models.WSMessage{Type: "alert", Payload: al})
}

// The original event itself is broadcast to all WebSocket clients
p.hub.Broadcast(models.WSMessage{Type: "event", Payload: ev})
```

---

## REST API — honey-token endpoints

```
GET    /v1/honey-tokens                  → List all tokens
POST   /v1/honey-tokens                  → Create a token
DELETE /v1/honey-tokens/{id}             → Delete a token
GET    /v1/honey-tokens/{id}/triggers    → Trigger history for one token
GET    /v1/honey-tokens/triggers         → All triggers across all tokens
```

### Create

```go
// internal/api/rest/handlers.go

func (h *handlers) CreateHoneyToken(w http.ResponseWriter, r *http.Request) {
    var body struct {
        Name        string                `json:"name"`
        Description string                `json:"description"`
        Location    string                `json:"location"`
        Type        models.HoneyTokenType `json:"type"`
    }
    if !decodeJSON(w, r, &body) { return }
    tok := h.honey.Create(body.Name, body.Description, body.Location, body.Type)
    writeJSON(w, http.StatusCreated, tok)
}
```

Request:
```json
{
  "name":        "Fake HR Director",
  "description": "Decoy identity in HR payroll table",
  "location":    "hr_payroll",
  "type":        "identity"
}
```

Response (`201 Created`):
```json
{
  "token_id":    "HT-0004",
  "name":        "Fake HR Director",
  "type":        "identity",
  "location":    "hr_payroll",
  "description": "Decoy identity in HR payroll table",
  "created_at":  "2026-05-30T12:00:00Z",
  "enabled":     true,
  "trigger_count": 0,
  "last_triggered": null
}
```

### Trigger history

```go
func (h *handlers) HoneyTokenTriggers(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    writeJSON(w, 200, h.honey.Triggers(id))
}
```

Response:
```json
[
  {
    "trigger_id":   "HT-0001-trg-1748598000000000000",
    "token_id":     "HT-0001",
    "triggered_at": "2026-05-30T12:15:00Z",
    "source_ip":    "10.0.0.42",
    "user_id":      "j.kim",
    "tenant_id":    "acme-corp",
    "event_id":     "8f3a2b1c"
  }
]
```

---

## End-to-end trace — Navigator retrieval trigger

**Scenario:** An attacker (or compromised user) runs a search that retrieves the fake customer record `"Hong Gildong"`.

```
1. User submits query: "Hong Gildong"

2. Navigator performs vector search on customer_docs collection.
   The fake customer record (honey-token HT-0003) appears in results.

3. Navigator emits:
   BastionEvent{
     EventType  = "honey_token_retrieved",
     Module     = "navigator",
     Severity   = "critical",
     TraceID    = "trace-xyz-789",
     TenantID   = "acme-corp",
     UserID     = "j.kim",
     Data = {
       "honey_token_id": "HT-0003",
       "document_id":    "fake_customer_hong_gildong",
       "collection":     "customer_docs",
     }
   }

4. Tracker receives event via NATS → processor.Process():

   Step 4: signer.Sign(ev)  → ev.Signature = "a3f8c..."
   Step 5: store.AddEvent(ev), store.UpsertTrace(ev)
   Step 8: honey.CheckEvent(ev):
     detectionEventTypes["honey_token_retrieved"] = true  ✓
     tokenID = ev.Data["honey_token_id"] = "HT-0003"
     trig = HoneyTokenTrigger{
       TriggerID:   "HT-0003-trg-1748598015123456789",
       TokenID:     "HT-0003",
       TriggeredAt: ev.Timestamp,
       UserID:      "j.kim",
       TenantID:    "acme-corp",
       EventID:     ev.EventID,
     }
     store.RecordTrigger(trig):
       tokens["HT-0003"].TriggerCount = 1
       tokens["HT-0003"].LastTriggered = &now
       triggers["HT-0003"] = [trig]
     → returns "HT-0003"

   Processor logs: "[processor] honey-token triggered: HT-0003 (event=...)"
   pub.Publish(EventHoneyTokenAlert("HT-0003", "HT-0003-trg-...", "acme-corp", "trace-xyz-789"))
   → bastion.events.tracker.honey_token_alert (critical, async)

   Step 9: incidents.AutoCreate(ev):
     title = "Honey-token search-layer retrieval (Navigator): HT-0003"
     desc  = "Honey-token detection at honey_token_retrieved layer — potential intrusion (module: navigator)."
     INC-0001 created → status: open, severity: critical
     hub.Broadcast({Type:"incident", Payload:INC-0001})
     → all WebSocket dashboard clients receive the incident immediately

   Step 11: hub.Broadcast({Type:"event", Payload:ev})
     → event appears in live dashboard stream

5. SOC operator queries:
   GET /v1/honey-tokens/HT-0003/triggers
   → [{"trigger_id":"HT-0003-trg-...", "user_id":"j.kim", "source_ip":"10.0.0.42"}]

   GET /v1/lineage/trace-xyz-789
   → Trace{Spans:[...all pipeline spans including honey_token_retrieved...]}

   POST /v1/security/incidents/INC-0001/resolve
   {"notes": "User j.kim account suspended; investigation complete."}
   → Incident{Status:"resolved", ResolvedAt:"2026-05-30T13:00:00Z"}
```

---

## Summary — trigger detection sequence

```
Module emits BastionEvent{EventType="honey_token_*"}
    │
    ▼
NATS → Tracker processor.Process()
    │
    ├── Step 4: Sign event (HMAC-SHA256)
    ├── Step 5: Store + UpsertTrace
    ├── Step 8: honeytoken.CheckEvent()
    │     ├── Match event type against detectionEventTypes
    │     ├── Extract token_id from Data
    │     ├── store.RecordTrigger() → TriggerCount++, LastTriggered
    │     └── return tokenID
    ├── pub.Publish(EventHoneyTokenAlert)  → NATS: bastion.events.tracker.honey_token_alert
    ├── Step 9: incidents.AutoCreate() → INC-XXXX (status: open)
    │     └── hub.Broadcast({type:"incident"})  → WebSocket clients
    └── Step 11: hub.Broadcast({type:"event"})  → WebSocket clients
```

---

## Related documents

- `tracker/docs/lineage-tracking.md` — trace and chunk lineage data tracking
- `docs/14_module_tracker_srs_v3.md` — full Tracker SRS
- `docs/20_cross_honey_token_srs.md` — cross-module honey-token specification
- `docs/32_injection_defense_architecture.md` — injection defense specification (D-13 honey-token detection)
