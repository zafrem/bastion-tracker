# Tracker — Management Features

**Module:** Tracker (`internal/auth/`, `internal/anomaly/`, `internal/store/`, `internal/hub/`, `internal/api/rest/`)
**Version:** 3.1
**Last updated:** 2026-05-31

---

## Overview

The management layer turns the Tracker observer backend into an operator-facing control plane. It adds four capability groups on top of the existing event ingestion pipeline:

| Group | Purpose | Key files |
|---|---|---|
| **Admin authentication** | JWT login, session refresh, login audit trail | `internal/auth/auth.go` |
| **Dashboard** | Live summary, pipeline health, per-tenant activity | `internal/store/memory.go` |
| **Log browser** | Cursor pagination, time-range filter, JSONL export | `internal/store/memory.go`, handlers |
| **Anomaly detection** | Statistical baseline + 6 pattern rules | `internal/anomaly/detector.go` |

None of these touch the data path — Tracker remains a pure observer (the Foundation litmus test still passes).

---

## 1. Admin Authentication

### Role hierarchy

```go
// internal/auth/auth.go

// RoleLevel maps a role string to a numeric level for hierarchical comparison.
// admin (3) > operator (2) > viewer (1) > unknown (0)
func RoleLevel(role string) int {
    switch role {
    case "admin":
        return 3
    case "operator":
        return 2
    case "viewer":
        return 1
    default:
        return 0
    }
}
```

Routes are gated by minimum role. `operatorOrOpen`/`adminOrOpen` middleware apply the check only when `auth.enabled` is true, so standalone/PoC mode stays frictionless.

### Session refresh

A stateless JWT cannot be revoked, but it can be re-issued with a fresh expiry while it is still valid. `RefreshToken` validates the incoming token, then mints a new one preserving user ID and role:

```go
// internal/auth/auth.go

// RefreshToken validates an existing token and issues a fresh one with a new
// expiry. The user ID and role are preserved; the old token is not revoked
// (stateless JWT — revocation requires a denylist, out of scope for PoC).
func RefreshToken(tokenStr, secret string, newExpiry time.Duration) (string, *Claims, error) {
    claims, err := ValidateToken(tokenStr, secret)
    if err != nil {
        return "", nil, err  // expired or tampered tokens cannot be refreshed
    }
    if newExpiry <= 0 {
        newExpiry = DefaultExpiry
    }
    newToken, err := GenerateToken(claims.UserID, claims.Role, secret, newExpiry)
    if err != nil {
        return "", nil, err
    }
    return newToken, claims, nil
}
```

The handler wires this to `POST /v1/auth/refresh` and records every attempt:

```go
// internal/api/rest/handlers.go

func (h *handlers) RefreshToken(w http.ResponseWriter, r *http.Request) {
    var req models.RefreshRequest
    if !decodeJSON(w, r, &req) {
        return
    }
    if h.authCfg == nil || !h.authCfg.Enabled {
        writeError(w, http.StatusNotFound, "auth not enabled")
        return
    }
    refreshExpiry, err := time.ParseDuration(h.authCfg.RefreshExpiry)
    if err != nil || refreshExpiry <= 0 {
        refreshExpiry, _ = time.ParseDuration(h.authCfg.JWTExpiry)  // fall back to access TTL
    }
    token, claims, err := auth.RefreshToken(req.Token, h.authCfg.JWTSecret, refreshExpiry)
    if err != nil {
        h.store.RecordLogin(models.LoginAuditEvent{
            Timestamp: time.Now(), Username: "unknown",
            SourceIP: r.RemoteAddr, Success: false, Reason: "refresh: " + err.Error(),
        })
        writeError(w, http.StatusUnauthorized, "invalid or expired token")
        return
    }
    writeJSON(w, http.StatusOK, models.LoginResponse{
        Token: token, ExpiresIn: refreshExpiry.String(), Role: claims.Role,
    })
}
```

### Login audit trail

Every login and refresh attempt — success or failure — is appended to a bounded ring buffer:

```go
// internal/store/memory.go

// RecordLogin appends a login audit event; trims to last 10 000.
func (s *Store) RecordLogin(ev models.LoginAuditEvent) {
    s.mu.Lock()
    defer s.mu.Unlock()
    if len(s.loginAudit) >= 10000 {
        s.loginAudit = s.loginAudit[1:]  // drop oldest
    }
    s.loginAudit = append(s.loginAudit, ev)
}
```

The `Login` handler records both outcomes so a brute-force attempt is visible in the trail:

```go
// internal/api/rest/handlers.go — inside Login()

if !passwordOK {
    h.loginAuditRecord(req.Username, "", r.RemoteAddr, false, "invalid credentials")
    writeError(w, http.StatusUnauthorized, "invalid credentials")
    return
}
// ... on success:
h.loginAuditRecord(matched.Name, matched.Role, r.RemoteAddr, true, "")
```

Queryable at `GET /v1/auth/login-audit` (admin only).

### Configuration

```yaml
auth:
  enabled: true            # gates all management endpoints
  jwt_secret: "..."        # HS256 signing key
  jwt_expiry: "8h"         # access token TTL
  refresh_expiry: "168h"   # refresh window (7 days)
  require_bcrypt: true     # reject plaintext passwords at startup
  users:
    - { name: admin, password: "$2a$...", role: admin }
```

---

## 2. Dashboard

### `DashboardSummary` — computed live from the ring buffer

A single pass over the event ring buffer produces all summary counters. The loop walks newest-first and **breaks** as soon as it crosses the 24h boundary, making it O(events-in-window) rather than O(buffer-size):

```go
// internal/store/memory.go

func (s *Store) DashboardSummary() models.DashboardSummary {
    s.mu.RLock()
    defer s.mu.RUnlock()

    now := time.Now()
    cutoff1h := now.Add(-1 * time.Hour)
    cutoff24h := now.Add(-24 * time.Hour)

    var count1h, count24h, blocked1h int64
    moduleCounts := make(map[string]int64)
    honeyTriggers := 0

    for i := 0; i < size; i++ {
        idx := ((s.head - 1 - i) + s.maxEvents) % s.maxEvents
        ev := s.events[idx]
        if ev.EventID == "" {
            continue
        }
        if ev.Timestamp.Before(cutoff24h) {
            break  // ring buffer is newest-first; nothing older matters
        }
        count24h++
        moduleCounts[ev.Module]++
        if ev.Timestamp.After(cutoff1h) {
            count1h++
            if ev.Status == "blocked" {
                blocked1h++
            }
        }
        if len(ev.EventType) >= 12 && ev.EventType[:12] == "honey_token_" {
            honeyTriggers++
        }
    }
    // ... top-5 modules (sort), active incidents, firing alerts ...
}
```

The active-incident and firing-alert counts come from the same lock-held snapshot of the `incidents` and `alerts` maps, so the whole summary is internally consistent.

### Endpoints

| Endpoint | Role | Returns |
|---|---|---|
| `GET /v1/dashboard/summary` | viewer | `DashboardSummary` |
| `GET /v1/dashboard/pipeline-health` | viewer | per-module latency, error rate, events/min |
| `GET /v1/dashboard/recent-activity` | viewer | last 20 events of severity ≥ warning |
| `GET /v1/dashboard/tenant/{tenant_id}` | operator | per-tenant breakdown |

`PipelineHealth()` reuses the existing `Topology()` computation and enriches it with throughput:

```go
// internal/store/memory.go

func (s *Store) PipelineHealth() models.PipelineHealthResponse {
    snap := s.Topology()  // existing per-module health
    entries := make([]models.PipelineHealthEntry, 0, len(snap.Modules))
    for _, m := range snap.Modules {
        entries = append(entries, models.PipelineHealthEntry{
            Module:       m.Module,
            Status:       m.Status,
            AvgLatencyMs: m.LatencyMs,
            ErrorRate:    m.ErrorRate,
            EventsPerMin: m.Throughput * 60,  // Topology reports per-second
            LastEventAt:  m.LastEventAt,
        })
    }
    return models.PipelineHealthResponse{Modules: entries, UpdatedAt: snap.UpdatedAt}
}
```

### WebSocket push

The hub pushes a fresh summary to every connected client every 30 seconds, eliminating client-side polling:

```go
// internal/hub/hub.go

// StartDashboardPush begins broadcasting dashboard summary updates every interval
// to all connected WebSocket clients.
func (h *Hub) StartDashboardPush(ctx interface{ Done() <-chan struct{} }, interval time.Duration, summaryFn func() models.WSMessage) {
    if interval <= 0 {
        interval = 30 * time.Second
    }
    go func() {
        ticker := time.NewTicker(interval)
        defer ticker.Stop()
        for {
            select {
            case <-ticker.C:
                h.Broadcast(summaryFn())
            case <-ctx.Done():
                return
            }
        }
    }()
}
```

Wired in `rest.New()`:

```go
h.StartDashboardPush(srv, 30*time.Second, func() models.WSMessage {
    return models.WSMessage{Type: "dashboard_summary", Payload: s.DashboardSummary()}
})
```

---

## 3. Enhanced Log Browser

### Cursor-based pagination

`EventsPage` finds the cursor's position in the ring buffer, then collects the next page after it. The cursor is the `event_id` of the last event on the previous page:

```go
// internal/store/memory.go

func (s *Store) EventsPage(q models.QueryRequest, cursor string, limit int) models.EventsPage {
    if limit <= 0 || limit > 200 {
        limit = 50  // hard cap protects against unbounded scans
    }
    // ...
    // Find the cursor position in the ring.
    startIdx := 0
    if cursor != "" {
        for i := 0; i < size; i++ {
            idx := ((s.head - 1 - i) + s.maxEvents) % s.maxEvents
            if s.events[idx].EventID == cursor {
                startIdx = i + 1  // begin AFTER the cursor
                break
            }
        }
    }

    results := make([]models.BastionEvent, 0, limit)
    for i := startIdx; i < size && len(results) < limit; i++ {
        idx := ((s.head - 1 - i) + s.maxEvents) % s.maxEvents
        ev := s.events[idx]
        if ev.EventID == "" || !matchEvent(ev, q) {
            continue
        }
        results = append(results, ev)
    }

    nextCursor := ""
    if len(results) == limit {
        nextCursor = results[len(results)-1].EventID  // empty = last page
    }
    return models.EventsPage{Events: results, Total: len(results), NextCursor: nextCursor}
}
```

`matchEvent(ev, q)` applies module/severity/tenant/time-range filters, so pagination and filtering compose.

### JSONL export

`GET /v1/events/export` streams NDJSON (one JSON object per line) so an operator can pull a time-bounded slice for offline analysis. Admin only:

```go
// internal/api/rest/handlers.go

func (h *handlers) ExportEvents(w http.ResponseWriter, r *http.Request) {
    q := parseQuery(r)
    limit := intParam(r, "limit", 10000)
    if limit > 10000 {
        limit = 10000
    }
    evts := h.store.RecentEvents(q, limit)
    w.Header().Set("Content-Type", "application/x-ndjson")
    w.Header().Set("Content-Disposition",
        fmt.Sprintf(`attachment; filename="events-%s.jsonl"`, time.Now().Format("20060102-150405")))
    w.WriteHeader(http.StatusOK)
    enc := json.NewEncoder(w)
    for _, ev := range evts {
        _ = enc.Encode(ev)  // streamed — no full buffer in memory
    }
}
```

---

## 4. Anomaly Detection

`anomaly.Detector` runs as a processor hook — every inbound event passes through `Inspect()`. It combines one statistical method and five pattern rules.

### Detector wiring

```go
// cmd/tracker-cli/main.go — inside buildComponents()

var anomalyDet *anomaly.Detector
if cfg.Anomaly.Enabled {
    anomalyDet = anomaly.New(cfg.Anomaly, &anomalySink{proc: proc, hub: h})
    proc.AddHook(func(ev models.BastionEvent) { anomalyDet.Inspect(ev) })
}
```

The `anomalySink` closes the loop: a detected anomaly is both broadcast to the dashboard and fed back into the processor as a synthetic event, which triggers incident auto-creation:

```go
// cmd/tracker-cli/main.go

func (a *anomalySink) OnAnomaly(ev models.AnomalyEvent) {
    a.hub.Broadcast(models.WSMessage{Type: "anomaly", Payload: ev})
    bastionEv := models.BastionEvent{
        Module: "tracker", EventType: "anomaly_detected",
        Severity: ev.Severity, Status: "error",
        TenantID: ev.TenantID, UserID: ev.UserID, TraceID: ev.TraceID,
        Data: map[string]any{
            "anomaly_id": ev.AnomalyID, "pattern": ev.Pattern, "description": ev.Description,
        },
    }
    go a.proc.Process(bastionEv)  // re-enters pipeline → incident auto-creation
}
```

### Statistical baseline (3σ spike)

Per `module × event_type`, the detector keeps 1-minute buckets over a rolling window, computes mean and sample standard deviation, and flags the current minute when it exceeds the configured sigma threshold:

```go
// internal/anomaly/detector.go

func (bt *baselineTracker) record(module, eventType string, at time.Time) bool {
    // ... prune buckets older than the window, add current ...

    if len(bt.windows[k]) < 10 {
        return false  // too few samples to establish a baseline
    }

    // Bucket counts by minute, then compute mean + stddev.
    mean, stddev := meanStddev(counts)
    // ... store baseline ...

    currentRate := float64(minuteMap[currentMin])
    if stddev > 0 && (currentRate-mean)/stddev > bt.sigma {
        return true  // anomaly: current minute is > Nσ above the mean
    }
    return false
}
```

`meanStddev` uses the unbiased (n−1) variance estimator.

### Pattern rules

All six fire inside `Inspect()`:

| Pattern | Logic | Severity |
|---|---|---|
| `statistical_spike` | baseline > Nσ (above) | warning |
| `high_freq_user` | `userWindow.add()` reaches `HighFreqUserLimit` within 1 minute | warning |
| `repeated_block` | `blockWindow.add()` reaches `RepeatedBlockCount` within window (only `status=blocked`) | critical |
| `cross_tenant_signal` | any `cross_tenant_attempt` event | critical |
| `honey_multi_layer` | same `trace_id` triggers honey-tokens in ≥ 2 distinct modules | critical |
| `off_hours_access` | event hour outside `[active_hours_start, active_hours_end)` when configured | warning |

The sliding-window counter is shared between the high-frequency and repeated-block rules:

```go
// internal/anomaly/detector.go

func (pw *patternWindow) add(key string, at time.Time, window time.Duration) int {
    pw.mu.Lock()
    defer pw.mu.Unlock()
    cutoff := at.Add(-window)
    pruned := pw.entries[key][:0]
    for _, t := range pw.entries[key] {
        if t.After(cutoff) {
            pruned = append(pruned, t)
        }
    }
    pruned = append(pruned, at)
    pw.entries[key] = pruned
    return len(pruned)  // count within window
}
```

The honey-token multi-layer tracker accumulates the **set** of modules per trace (10-minute expiry) and fires when the set reaches size 2 — this is the highest-confidence intrusion signal because a single trace touching a decoy in two pipeline layers cannot be coincidence:

```go
// internal/anomaly/detector.go

func (h *honeyLayerTracker) record(traceID, module string, at time.Time) (int, []string) {
    // ... expire entries older than 10 minutes ...
    if h.modules[traceID] == nil {
        h.modules[traceID] = make(map[string]struct{})
    }
    h.modules[traceID][module] = struct{}{}  // set semantics — duplicates ignored
    h.times[traceID] = at

    mods := make([]string, 0, len(h.modules[traceID]))
    for m := range h.modules[traceID] {
        mods = append(mods, m)
    }
    return len(mods), mods
}
```

### Endpoints

| Endpoint | Returns |
|---|---|
| `GET /v1/anomaly/baselines` | active `AnomalyBaseline` snapshots (module, event_type, mean, stddev, sigma) |
| `GET /v1/anomaly/events` | `AnomalyEvent` list detected in the last 24h |

### Configuration

```yaml
anomaly:
  enabled: true
  sigma_threshold: 3.0       # statistical spike threshold
  window_hours: 1            # rolling baseline window
  high_freq_user_limit: 30   # requests/minute per user
  repeated_block_window: "5m"
  repeated_block_count: 3
  active_hours_start: 0      # 0/0 disables off-hours check
  active_hours_end: 0
```

---

## Testing

| Test file | Coverage |
|---|---|
| `internal/anomaly/detector_test.go` | 19 tests — all 6 pattern rules, disabled guard, isolation, severity, Recent/Baselines |
| `internal/store/memory_test.go` | DashboardSummary (6), EventsPage cursor pagination (5), RecordLogin (4), PipelineHealth, TenantActivity |
| `internal/auth/auth_test.go` | 9 tests — token round-trip, refresh, expiry rejection, role ordering |
| `internal/api/rest/rest_test.go` | dashboard, log browser, export, anomaly, auth-refresh endpoint smoke tests |

---

## Related documents

- `tracker/docs/lineage-tracking.md` — trace and chunk lineage data tracking
- `tracker/docs/honey-token-injection.md` — honey-token lifecycle and trigger detection
- `docs/14_module_tracker_srs_v3.md` — full Tracker SRS (§11b Management Layer)
