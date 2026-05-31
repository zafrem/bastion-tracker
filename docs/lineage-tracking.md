# Tracker — Lineage Tracking

**Module:** Tracker (`internal/models/`, `internal/store/`, `internal/processor/`, `internal/api/rest/`, `internal/audit/`)
**Version:** 3.0
**Last updated:** 2026-05-30

---

## Overview

Lineage tracking in the Tracker module answers the question: *for a given request, what happened, in what order, and which source documents contributed to the final LLM response?*

It operates at two levels:

| Level | Unit | Key type | Where |
|---|---|---|---|
| **Pipeline span lineage** | `Trace` + `Span` | `trace_id` | Every event from any module |
| **Chunk source lineage** | `ChunkLineageEntry` | `trace_id` + `chunk_id` | `chunk_retrieved` events from Navigator |

Both are built automatically from inbound `BastionEvent` records — no module needs to write to the lineage store directly.

---

## The `BastionEvent` — canonical schema

Every event flowing through the system uses this struct:

```go
// internal/models/types.go

type BastionEvent struct {
    EventID        string            `json:"event_id"`
    SchemaVersion  string            `json:"schema_version,omitempty"`
    TraceID        string            `json:"trace_id"`        // links spans into traces
    SpanID         string            `json:"span_id"`         // this event's position in the trace
    ParentSpanID   string            `json:"parent_span_id"`  // for nested calls
    Module         string            `json:"module"`          // sentinel|vault|navigator|anchor
    ModuleVersion  string            `json:"module_version,omitempty"`
    EventType      string            `json:"event_type"`      // e.g. "chunk_retrieved"
    Severity       string            `json:"severity"`        // info|warning|error|critical
    Category       string            `json:"category,omitempty"` // operational|security|performance|audit
    Timestamp      time.Time         `json:"-"`               // decoded by UnmarshalJSON
    TenantID       string            `json:"tenant_id"`
    UserID         string            `json:"user_id"`
    RequestID      string            `json:"request_id"`
    Labels         map[string]string `json:"labels,omitempty"`
    Data           map[string]any    `json:"data,omitempty"`  // event-specific payload
    PipelineType   string            `json:"pipeline_type"`
    ModulesUsed    []string          `json:"modules_used,omitempty"`
    ModulesSkipped []string          `json:"modules_skipped,omitempty"`
    DurationMs     int64             `json:"duration_ms"`
    Status         string            `json:"status"`          // passed|blocked|error
    ActionTaken    string            `json:"action_taken,omitempty"`
    Signature      string            `json:"signature,omitempty"` // HMAC-SHA256 audit seal
}
```

### Dual-format timestamp handling

Module publishers emit `timestamp` as `int64` UnixNano. Legacy REST callers may send RFC3339 strings. `UnmarshalJSON` handles both:

```go
// internal/models/types.go

func (e *BastionEvent) UnmarshalJSON(data []byte) error {
    // Use an alias to avoid infinite recursion when calling json.Unmarshal.
    type Alias BastionEvent
    aux := &struct {
        Timestamp interface{} `json:"timestamp"` // accepts float64 (JSON number) or string
        *Alias
    }{Alias: (*Alias)(e)}

    if err := json.Unmarshal(data, aux); err != nil {
        return err
    }

    switch v := aux.Timestamp.(type) {
    case float64:
        // JSON numbers decode as float64; cast to int64 for UnixNano.
        e.Timestamp = time.Unix(0, int64(v))
    case string:
        // Try RFC3339Nano first (nanosecond precision), then plain RFC3339.
        if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
            e.Timestamp = t
        } else if t, err := time.Parse(time.RFC3339, v); err == nil {
            e.Timestamp = t
        }
    }
    return nil
}

// MarshalJSON always emits timestamp as int64 UnixNano for module publisher compatibility.
func (e BastionEvent) MarshalJSON() ([]byte, error) {
    type Alias BastionEvent
    return json.Marshal(&struct {
        Timestamp int64 `json:"timestamp"`
        Alias
    }{
        Timestamp: e.Timestamp.UnixNano(),
        Alias:     (Alias)(e),
    })
}
```

---

## Event storage — ring buffer

The store holds recent events in a fixed-capacity ring buffer. When full, the oldest entry is silently overwritten — this is a design choice for the in-memory PoC: memory is bounded without a compaction pass.

```go
// internal/store/memory.go

type Store struct {
    mu        sync.RWMutex
    events    []models.BastionEvent  // fixed-size slice
    maxEvents int
    head      int  // next write position (wraps at maxEvents)
    count     int  // total events written (never decremented)
    // ...other maps
}

// AddEvent writes to the current head and advances it.
func (s *Store) AddEvent(ev models.BastionEvent) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.events[s.head] = ev
    s.head = (s.head + 1) % s.maxEvents  // wrap around
    s.count++
}
```

### `GetEvent()` — reverse traversal

The most recent events are nearest to `head - 1`. Older events are found by walking backwards:

```go
func (s *Store) GetEvent(id string) (*models.BastionEvent, bool) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    size := s.maxEvents
    if s.count < size {
        size = s.count  // buffer not yet full
    }

    for i := 0; i < size; i++ {
        // Walk backwards from head: most recent = head-1, oldest = head-size.
        // The modular arithmetic handles the wraparound correctly.
        idx := ((s.head - 1 - i) + s.maxEvents) % s.maxEvents
        ev := s.events[idx]
        if ev.EventID == id {
            cp := ev
            return &cp, true  // return a copy; never the live pointer
        }
    }
    return nil, false
}
```

`RecentEvents()` uses the same backwards-walk pattern and stops when the limit is reached, making it O(limit) rather than O(maxEvents).

---

## Trace assembly — `UpsertTrace()`

Every event with a non-empty `TraceID` is folded into a `Trace`. The trace is created on the first event for a given `trace_id` and updated on every subsequent one:

```go
// internal/store/memory.go

func (s *Store) UpsertTrace(ev models.BastionEvent) {
    if ev.TraceID == "" {
        return  // events without a trace_id are stored but not traced
    }
    s.mu.Lock()
    defer s.mu.Unlock()

    tr, ok := s.traces[ev.TraceID]
    if !ok {
        // First event for this trace: create the trace record.
        tr = &models.Trace{
            TraceID:        ev.TraceID,
            RequestID:      ev.RequestID,
            TenantID:       ev.TenantID,
            UserID:         ev.UserID,
            PipelineType:   ev.PipelineType,
            ModulesUsed:    ev.ModulesUsed,
            ModulesSkipped: ev.ModulesSkipped,
            StartTime:      ev.Timestamp,
            Status:         "in_progress",
        }
        s.traces[ev.TraceID] = tr
    }

    // Append the event as a new span in the trace.
    tr.Spans = append(tr.Spans, models.Span{
        SpanID:     ev.SpanID,
        Module:     ev.Module,
        EventType:  ev.EventType,
        StartTime:  ev.Timestamp,
        DurationMs: ev.DurationMs,
        Status:     ev.Status,
        Data:       ev.Data,
    })

    // Status state machine:
    // - blocked or error from any module finalizes the trace.
    // - "completed" is set when the last module in the pipeline (llm or anchor) reports.
    if ev.Status == "blocked" || ev.Status == "error" {
        tr.Status = ev.Status
    } else if ev.Module == "llm" || ev.Module == "anchor" {
        tr.Status = "completed"
    }

    // Record the end time and total duration when finalized.
    if tr.Status == "completed" || tr.Status == "blocked" || tr.Status == "error" {
        now := ev.Timestamp
        tr.EndTime = &now
        tr.TotalMs = now.Sub(tr.StartTime).Milliseconds()
    }
}
```

### `Span` — one module's contribution

```go
type Span struct {
    SpanID     string         `json:"span_id"`
    Module     string         `json:"module"`     // which module emitted this event
    EventType  string         `json:"event_type"`
    StartTime  time.Time      `json:"start_time"`
    DurationMs int64          `json:"duration_ms"`
    Status     string         `json:"status"`
    Data       map[string]any `json:"data,omitempty"` // event-specific payload preserved verbatim
}
```

---

## Chunk source lineage — MR-05-003

When Navigator retrieves a chunk from Qdrant, it emits a `chunk_retrieved` event. The processor extracts the chunk fields and stores them in the `lineage` map:

```go
// internal/processor/processor.go

// Inside Process():
if ev.EventType == "chunk_retrieved" && ev.TraceID != "" {
    entry := models.ChunkLineageEntry{
        TenantID: ev.TenantID,
    }
    // Type-assert each field from the untyped Data map.
    // JSON numbers always decode as float64 in Go; cast as needed.
    if v, ok := ev.Data["chunk_id"].(string);    ok { entry.ChunkID    = v }
    if v, ok := ev.Data["document_id"].(string); ok { entry.DocumentID = v }
    if v, ok := ev.Data["score"].(float64);      ok { entry.Score      = v }
    if v, ok := ev.Data["rank"].(float64);       ok { entry.Rank       = int(v) }
    if v, ok := ev.Data["collection"].(string);  ok { entry.Collection = v }

    p.store.AddChunkLineage(ev.TraceID, entry)
}
```

### `AddChunkLineage()` — appending to the lineage map

```go
// internal/store/memory.go

// lineage map: trace_id → ordered append of ChunkLineageEntry
// Entries are appended in arrival order (which matches Navigator's rank order
// because chunk_retrieved events are emitted sequentially by rank).
func (s *Store) AddChunkLineage(traceID string, entry models.ChunkLineageEntry) {
    if traceID == "" {
        return
    }
    s.mu.Lock()
    defer s.mu.Unlock()
    s.lineage[traceID] = append(s.lineage[traceID], entry)
}
```

### `GetLineageSources()` — sorted by rank

```go
func (s *Store) GetLineageSources(traceID string) ([]models.ChunkLineageEntry, bool) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    entries, ok := s.lineage[traceID]
    if !ok || len(entries) == 0 {
        return nil, false
    }
    // Return a defensive copy; sort by rank ascending.
    // Rank 0 = most relevant; rank N = least relevant.
    cp := make([]models.ChunkLineageEntry, len(entries))
    copy(cp, entries)
    for i := 0; i < len(cp)-1; i++ {
        for j := i + 1; j < len(cp); j++ {
            if cp[j].Rank < cp[i].Rank {
                cp[i], cp[j] = cp[j], cp[i]
            }
        }
    }
    return cp, true
}
```

The `ChunkLineageEntry` struct:

```go
// internal/models/types.go

type ChunkLineageEntry struct {
    ChunkID    string  `json:"chunk_id"`     // "{document_id}_{index:04d}"
    DocumentID string  `json:"document_id"`  // parent document
    Score      float64 `json:"score"`        // cosine similarity or rerank score
    Rank       int     `json:"rank"`         // 0 = top result
    Collection string  `json:"collection"`   // Qdrant collection name
    TenantID   string  `json:"tenant_id"`
}
```

---

## Audit integrity — `Signer`

Every event is signed before storage so that post-storage tampering is detectable:

```go
// internal/audit/signer.go

type Signer struct {
    key []byte  // HMAC-SHA256 key; set from config or demo default
}

// Sign computes the HMAC and stores it in ev.Signature.
func (s *Signer) Sign(ev *models.BastionEvent) string {
    sig := s.compute(ev)
    ev.Signature = sig
    return sig
}

// compute builds the canonical string that is signed.
// Only immutable identity fields are included — mutable fields like Labels
// and Data are excluded so the signature survives legitimate metadata enrichment.
func (s *Signer) compute(ev *models.BastionEvent) string {
    canon := fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s",
        ev.EventID,
        ev.Timestamp.UnixNano(),   // nanosecond precision; monotonic
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

// Verify checks the signature without side effects.
// Returns false for unsigned events (empty Signature) to distinguish
// "unsigned" from "tampered" during audit verification.
func (s *Signer) Verify(ev models.BastionEvent) bool {
    if ev.Signature == "" {
        return false
    }
    expected := s.compute(&ev)
    // hmac.Equal is constant-time; prevents timing attacks on signature comparison.
    return hmac.Equal([]byte(ev.Signature), []byte(expected))
}
```

The `GET /v1/audit/verify` endpoint walks all stored events and counts `valid`, `invalid` (signature present but wrong), and `unsigned`:

```go
// AuditVerifyResult summarises the pass:
type AuditVerifyResult struct {
    Total    int      `json:"total"`
    Valid    int      `json:"valid"`
    Invalid  int      `json:"invalid"`   // signature present but wrong — tampered
    Unsigned int      `json:"unsigned"`  // no signature — pre-dates signing
    Tampered []string `json:"tampered"`  // event_ids with bad signatures
}
```

---

## `Processor.Process()` — the full event pipeline

```go
// internal/processor/processor.go

func (p *Processor) Process(ev models.BastionEvent) {
    start := time.Now()

    // ── Step 1: Enrich ────────────────────────────────────────────────────────
    if ev.EventID == ""   { ev.EventID = newID() }     // assign ID if missing
    if ev.Timestamp.IsZero() { ev.Timestamp = time.Now() }
    if ev.Severity == ""  { ev.Severity = "info" }     // default severity

    // ── Step 2: Validate ──────────────────────────────────────────────────────
    if p.validator != nil {
        if err := p.validator.Validate(&ev); err != nil {
            p.validator.Reject(ev, err.Error())  // send to dead-letter queue
            return
        }
    }

    // ── Step 3: Metrics ───────────────────────────────────────────────────────
    metrics.EventsReceived.WithLabelValues(ev.Module, ev.EventType).Inc()

    // ── Step 4: Sign ──────────────────────────────────────────────────────────
    if p.signer != nil { p.signer.Sign(&ev) }

    // ── Step 5: Store ─────────────────────────────────────────────────────────
    p.store.AddEvent(ev)
    p.store.UpsertTrace(ev)

    // ── Step 6: Chunk lineage extraction (MR-05-003) ──────────────────────────
    if ev.EventType == "chunk_retrieved" && ev.TraceID != "" {
        // ... extract and store ChunkLineageEntry
    }

    // ── Step 7: Bypass anomaly detection ─────────────────────────────────────
    if p.bypass != nil { p.bypass.Check(ev) }

    // ── Step 8: Honey-token detection ────────────────────────────────────────
    if tokenID := p.honey.CheckEvent(ev); tokenID != "" {
        // Publish critical NATS alert and log.
    }

    // ── Step 9: Incident auto-creation ────────────────────────────────────────
    if inc := p.incidents.AutoCreate(ev); inc != nil {
        p.hub.Broadcast(models.WSMessage{Type: "incident", Payload: inc})
    }

    // ── Step 10: Alert evaluation ─────────────────────────────────────────────
    fired := p.alerts.Evaluate(ev)
    for _, al := range fired {
        p.hub.Broadcast(models.WSMessage{Type: "alert", Payload: al})
    }

    // ── Step 11: WebSocket broadcast ──────────────────────────────────────────
    p.hub.Broadcast(models.WSMessage{Type: "event", Payload: ev})

    // ── Step 12: Registered hooks (e.g. demo recorder) ────────────────────────
    for _, fn := range p.hooks { fn(ev) }

    metrics.EventsProcessed.WithLabelValues(ev.Module).Inc()
    metrics.ProcessingDuration.WithLabelValues(ev.Module).Observe(time.Since(start).Seconds())
}
```

---

## REST API — lineage endpoints

All lineage endpoints are mounted under `/v1/lineage/`:

```
GET /v1/lineage/{trace_id}            → GetTrace  (span list for a trace)
GET /v1/lineage/{trace_id}/sources    → GetLineageSources  (chunk source lineage)
GET /v1/lineage/user/{user_id}        → ListTracesByUser
GET /v1/lineage/data/{data_ref}       → LineageByDataRef  (event text search)
GET /v1/lineage/audit                 → LineageAudit  (time-range event query)
```

### `GET /v1/lineage/{trace_id}/sources` — chunk sources

```go
// internal/api/rest/handlers.go

func (h *handlers) GetLineageSources(w http.ResponseWriter, r *http.Request) {
    traceID := chi.URLParam(r, "trace_id")
    chunks, ok := h.store.GetLineageSources(traceID)
    writeJSON(w, 200, models.LineageSourcesResponse{
        TraceID: traceID,
        Found:   ok,                // false when no chunk_retrieved events for this trace
        Chunks:  chunks,            // sorted by rank ascending
    })
}
```

Response:
```json
{
  "trace_id": "abc-123",
  "found":    true,
  "chunks": [
    {
      "chunk_id":    "mfg_report_q1_0000",
      "document_id": "mfg_report_q1",
      "score":       0.91,
      "rank":        0,
      "collection":  "manufacturing_docs",
      "tenant_id":   "acme-corp"
    },
    {
      "chunk_id":    "mfg_report_q1_0001",
      "document_id": "mfg_report_q1",
      "score":       0.87,
      "rank":        1,
      "collection":  "manufacturing_docs",
      "tenant_id":   "acme-corp"
    }
  ]
}
```

### `GET /v1/lineage/data/{data_ref}` — data element lineage

Searches all stored event text for `data_ref`, then returns the traces that contained matching events:

```go
func (h *handlers) LineageByDataRef(w http.ResponseWriter, r *http.Request) {
    dataRef := chi.URLParam(r, "data_ref")
    limit := intParam(r, "limit", 50)

    // Full-text search across event_type, module, tenant_id fields.
    evts := h.store.SearchEvents(dataRef, limit)

    // Collect unique trace_ids from matching events.
    traceIDs := make(map[string]struct{})
    for _, ev := range evts {
        if ev.TraceID != "" {
            traceIDs[ev.TraceID] = struct{}{}
        }
    }

    // Fetch the full trace for each matched trace_id.
    var traces []models.Trace
    for traceID := range traceIDs {
        if tr, ok := h.store.GetTrace(traceID); ok {
            traces = append(traces, *tr)
        }
    }
    writeJSON(w, 200, models.TracesResponse{Traces: traces, Total: len(traces)})
}
```

### `GET /v1/traces/{trace_id}/timeline` — visualization

Positions each span on a ms timeline relative to trace start:

```go
func (h *handlers) GetTraceTimeline(w http.ResponseWriter, r *http.Request) {
    tr, ok := h.store.GetTrace(chi.URLParam(r, "trace_id"))
    if !ok { writeError(w, 404, "trace not found"); return }

    var maxMs int64
    entries := make([]models.TimelineEntry, 0, len(tr.Spans))
    for _, span := range tr.Spans {
        // OffsetMs = milliseconds after trace start; clamped to >= 0 for
        // events that arrive slightly out of order due to clock skew.
        offset := span.StartTime.Sub(tr.StartTime).Milliseconds()
        if offset < 0 { offset = 0 }
        entries = append(entries, models.TimelineEntry{
            SpanID:     span.SpanID,
            Module:     span.Module,
            EventType:  span.EventType,
            OffsetMs:   offset,
            DurationMs: span.DurationMs,
            Status:     span.Status,
        })
        if span.DurationMs > maxMs { maxMs = span.DurationMs }
    }

    writeJSON(w, 200, models.TraceTimeline{
        TraceID:      tr.TraceID,
        PipelineType: tr.PipelineType,
        TotalMs:      tr.TotalMs,
        MaxMs:        maxMs,       // longest single span; useful for scaling the UI bar chart
        Entries:      entries,
    })
}
```

---

## NATS publisher — async, fail-silent

```go
// internal/events/publisher.go

func (p *Publisher) Publish(ev TrackerEvent) {
    if p == nil || p.nc == nil {
        return  // silent no-op when NATS is unavailable
    }
    // Fire-and-forget in a goroutine so the processing pipeline is never blocked
    // by NATS latency or backpressure.
    go func() {
        data, err := json.Marshal(ev)
        if err != nil { return }
        subject := fmt.Sprintf("%s.%s", subjectPfx, ev.EventType)
        // bastion-rag.events.tracker.incident_created
        // bastion-rag.events.tracker.honey_token_alert
        // etc.
        _ = p.nc.Publish(subject, data)
    }()
}
```

---

## End-to-end lineage trace

**Scenario:** A manufacturing search request is processed end-to-end.

```
trace_id = "trace-abc-001"

1. Sentinel-IN emits:
   BastionEvent{
     EventType="input_validated", Module="sentinel",
     TraceID="trace-abc-001", SpanID="span-s-001",
     Status="passed", DurationMs=4
   }
   → processor.Process() → store.AddEvent → store.UpsertTrace
     Trace{TraceID="trace-abc-001", Status="in_progress", Spans=[span-s-001]}

2. Vault emits:
   BastionEvent{EventType="pii_tokenized", Module="vault", TraceID="trace-abc-001", ...}
   → Trace.Spans = [span-s-001, span-v-001]

3. Navigator emits (×2 chunks):
   BastionEvent{EventType="chunk_retrieved", Module="navigator",
     TraceID="trace-abc-001", SpanID="span-n-001",
     Data={"chunk_id":"mfg_report_q1_0000","document_id":"mfg_report_q1",
           "score":0.91,"rank":0,"collection":"manufacturing_docs"}
   }
   → processor detects EventType=="chunk_retrieved"
   → store.AddChunkLineage("trace-abc-001", ChunkLineageEntry{...rank=0})

   BastionEvent{EventType="chunk_retrieved", ..., Data={..., "rank":1}}
   → store.AddChunkLineage("trace-abc-001", ChunkLineageEntry{...rank=1})

4. Anchor emits:
   BastionEvent{EventType="embedding_secured", Module="anchor", ...}
   → Status="completed" → Trace.EndTime set, TotalMs computed

GET /v1/lineage/trace-abc-001
→ Trace{
    TraceID: "trace-abc-001",
    Status:  "completed",
    TotalMs: 312,
    Spans: [
      {Module:"sentinel", EventType:"input_validated",  DurationMs:4},
      {Module:"vault",    EventType:"pii_tokenized",    DurationMs:8},
      {Module:"navigator",EventType:"chunk_retrieved",  DurationMs:145},
      {Module:"navigator",EventType:"chunk_retrieved",  DurationMs:0},
      {Module:"anchor",   EventType:"embedding_secured",DurationMs:2},
    ]
  }

GET /v1/lineage/trace-abc-001/sources
→ LineageSourcesResponse{
    TraceID: "trace-abc-001",
    Found:   true,
    Chunks: [
      {ChunkID:"mfg_report_q1_0000", Score:0.91, Rank:0},
      {ChunkID:"mfg_report_q1_0001", Score:0.87, Rank:1},
    ]
  }
```

---

## Related documents

- `tracker/docs/honey-token-injection.md` — honey-token lifecycle and trigger detection
- `docs/14_module_tracker_srs_v3.md` — full Tracker SRS
- `docs/22_cross_data_lineage_srs.md` — cross-module data lineage specification
- `docs/02_foundation_event_schema_standard.md` — Foundation event schema (BastionEvent definition)
