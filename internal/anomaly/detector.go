// Package anomaly provides statistical baseline tracking and pattern-based
// anomaly detection for the Tracker management layer.
package anomaly

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/bastion/tracker/internal/config"
	"github.com/bastion/tracker/internal/models"
)

// Sink receives detected anomaly events for further processing (incident creation,
// WebSocket broadcast, NATS publish).
type Sink interface {
	OnAnomaly(ev models.AnomalyEvent)
}

// ─── Baseline tracking ────────────────────────────────────────────────────────

type windowBucket struct {
	count int
	at    time.Time
}

type baselineKey struct {
	module    string
	eventType string
}

type baselineTracker struct {
	mu       sync.Mutex
	windows  map[baselineKey][]windowBucket // sliding 1-minute buckets
	windowH  int
	sigma    float64
	baselines map[baselineKey]*models.AnomalyBaseline
}

func newBaselineTracker(windowH int, sigma float64) *baselineTracker {
	return &baselineTracker{
		windows:   make(map[baselineKey][]windowBucket),
		windowH:   windowH,
		sigma:     sigma,
		baselines: make(map[baselineKey]*models.AnomalyBaseline),
	}
}

func (bt *baselineTracker) record(module, eventType string, at time.Time) bool {
	k := baselineKey{module: module, eventType: eventType}
	bt.mu.Lock()
	defer bt.mu.Unlock()

	cutoff := at.Add(-time.Duration(bt.windowH) * time.Hour)

	// Prune old buckets and add current.
	pruned := bt.windows[k][:0]
	for _, b := range bt.windows[k] {
		if b.at.After(cutoff) {
			pruned = append(pruned, b)
		}
	}
	bt.windows[k] = append(pruned, windowBucket{count: 1, at: at})

	// Compute mean and stddev over the window (events per minute).
	if len(bt.windows[k]) < 10 {
		return false // too few samples to establish baseline
	}

	// Compute per-minute buckets.
	minuteMap := make(map[int64]int)
	for _, b := range bt.windows[k] {
		min := b.at.Unix() / 60
		minuteMap[min] += b.count
	}
	counts := make([]float64, 0, len(minuteMap))
	for _, c := range minuteMap {
		counts = append(counts, float64(c))
	}
	mean, stddev := meanStddev(counts)

	// Update stored baseline.
	bl := &models.AnomalyBaseline{
		Module:      module,
		EventType:   eventType,
		WindowH:     bt.windowH,
		Mean:        mean,
		StdDev:      stddev,
		SigmaThresh: bt.sigma,
		LastUpdated: time.Now(),
	}
	bt.baselines[k] = bl

	// Current minute rate.
	currentMin := at.Unix() / 60
	currentRate := float64(minuteMap[currentMin])

	if stddev > 0 && (currentRate-mean)/stddev > bt.sigma {
		return true // anomaly
	}
	return false
}

func (bt *baselineTracker) listBaselines() []models.AnomalyBaseline {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	out := make([]models.AnomalyBaseline, 0, len(bt.baselines))
	for _, bl := range bt.baselines {
		out = append(out, *bl)
	}
	return out
}

func meanStddev(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))
	if len(values) == 1 {
		return mean, 0
	}
	variance := 0.0
	for _, v := range values {
		d := v - mean
		variance += d * d
	}
	variance /= float64(len(values) - 1)
	return mean, math.Sqrt(variance)
}

// ─── Pattern rules ────────────────────────────────────────────────────────────

// patternWindow tracks events for pattern detection with a sliding time window.
type patternWindow struct {
	mu      sync.Mutex
	entries map[string][]time.Time // key → []timestamp
}

func newPatternWindow() *patternWindow {
	return &patternWindow{entries: make(map[string][]time.Time)}
}

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
	return len(pruned)
}

// honeyLayerTracker tracks per-trace honey-token module hits.
type honeyLayerTracker struct {
	mu      sync.Mutex
	modules map[string]map[string]struct{} // traceID → set of modules
	times   map[string]time.Time
}

func newHoneyLayerTracker() *honeyLayerTracker {
	return &honeyLayerTracker{
		modules: make(map[string]map[string]struct{}),
		times:   make(map[string]time.Time),
	}
}

func (h *honeyLayerTracker) record(traceID, module string, at time.Time) (int, []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Expire entries older than 10 minutes.
	cutoff := at.Add(-10 * time.Minute)
	for tid, t := range h.times {
		if t.Before(cutoff) {
			delete(h.modules, tid)
			delete(h.times, tid)
		}
	}
	if h.modules[traceID] == nil {
		h.modules[traceID] = make(map[string]struct{})
	}
	h.modules[traceID][module] = struct{}{}
	h.times[traceID] = at

	mods := make([]string, 0, len(h.modules[traceID]))
	for m := range h.modules[traceID] {
		mods = append(mods, m)
	}
	return len(mods), mods
}

// ─── Detector ─────────────────────────────────────────────────────────────────

// Detector integrates statistical baseline + pattern rules.
type Detector struct {
	cfg         config.AnomalyConfig
	baseline    *baselineTracker
	blockWindow *patternWindow
	userWindow  *patternWindow
	honeyLayers *honeyLayerTracker
	sink        Sink

	mu       sync.Mutex
	detected []models.AnomalyEvent
}

// New creates a Detector with the given configuration and anomaly sink.
func New(cfg config.AnomalyConfig, sink Sink) *Detector {
	return &Detector{
		cfg:         cfg,
		baseline:    newBaselineTracker(cfg.WindowHours, cfg.SigmaThreshold),
		blockWindow: newPatternWindow(),
		userWindow:  newPatternWindow(),
		honeyLayers: newHoneyLayerTracker(),
		sink:        sink,
		detected:    make([]models.AnomalyEvent, 0),
	}
}

// Inspect examines an inbound event and emits anomaly events when patterns fire.
func (d *Detector) Inspect(ev models.BastionEvent) {
	if !d.cfg.Enabled {
		return
	}
	at := ev.Timestamp
	if at.IsZero() {
		at = time.Now()
	}

	// ── Statistical baseline ──────────────────────────────────────────────────
	if isStatBaseline := d.baseline.record(ev.Module, ev.EventType, at); isStatBaseline {
		d.fire(models.AnomalyEvent{
			AnomalyID:   newID(),
			Pattern:     "statistical_spike",
			Severity:    "warning",
			TenantID:    ev.TenantID,
			UserID:      ev.UserID,
			TraceID:     ev.TraceID,
			DetectedAt:  at,
			Description: fmt.Sprintf("event rate for %s.%s exceeds %.1fσ above baseline", ev.Module, ev.EventType, d.cfg.SigmaThreshold),
			Evidence:    map[string]any{"module": ev.Module, "event_type": ev.EventType},
		})
	}

	// ── High-frequency user ───────────────────────────────────────────────────
	if ev.UserID != "" && d.cfg.HighFreqUserLimit > 0 {
		key := ev.TenantID + ":" + ev.UserID
		count := d.userWindow.add(key, at, time.Minute)
		if count == d.cfg.HighFreqUserLimit {
			d.fire(models.AnomalyEvent{
				AnomalyID:   newID(),
				Pattern:     "high_freq_user",
				Severity:    "warning",
				TenantID:    ev.TenantID,
				UserID:      ev.UserID,
				TraceID:     ev.TraceID,
				DetectedAt:  at,
				Description: fmt.Sprintf("user %s exceeded %d requests/minute", ev.UserID, d.cfg.HighFreqUserLimit),
				Evidence:    map[string]any{"count_per_min": count, "limit": d.cfg.HighFreqUserLimit},
			})
		}
	}

	// ── Repeated block ────────────────────────────────────────────────────────
	if ev.Status == "blocked" && ev.UserID != "" && d.cfg.RepeatedBlockCount > 0 {
		window := 5 * time.Minute
		if d.cfg.RepeatedBlockWindow != "" {
			if parsed, err := time.ParseDuration(d.cfg.RepeatedBlockWindow); err == nil {
				window = parsed
			}
		}
		key := "block:" + ev.TenantID + ":" + ev.UserID
		count := d.blockWindow.add(key, at, window)
		if count >= d.cfg.RepeatedBlockCount {
			d.fire(models.AnomalyEvent{
				AnomalyID:   newID(),
				Pattern:     "repeated_block",
				Severity:    "critical",
				TenantID:    ev.TenantID,
				UserID:      ev.UserID,
				TraceID:     ev.TraceID,
				DetectedAt:  at,
				Description: fmt.Sprintf("user %s blocked %d times in %s", ev.UserID, count, window),
				Evidence:    map[string]any{"block_count": count, "window": window.String()},
			})
		}
	}

	// ── Cross-tenant signal ───────────────────────────────────────────────────
	if ev.EventType == "cross_tenant_attempt" {
		d.fire(models.AnomalyEvent{
			AnomalyID:   newID(),
			Pattern:     "cross_tenant_signal",
			Severity:    "critical",
			TenantID:    ev.TenantID,
			UserID:      ev.UserID,
			TraceID:     ev.TraceID,
			DetectedAt:  at,
			Description: fmt.Sprintf("cross-tenant data access attempt by user %s", ev.UserID),
			Evidence:    map[string]any{"event_id": ev.EventID},
		})
	}

	// ── Honey-token multi-layer ───────────────────────────────────────────────
	isHoney := false
	for _, prefix := range []string{"honey_token_"} {
		if len(ev.EventType) >= len(prefix) && ev.EventType[:len(prefix)] == prefix {
			isHoney = true
			break
		}
	}
	if isHoney && ev.TraceID != "" {
		layerCount, mods := d.honeyLayers.record(ev.TraceID, ev.Module, at)
		if layerCount >= 2 {
			d.fire(models.AnomalyEvent{
				AnomalyID:   newID(),
				Pattern:     "honey_multi_layer",
				Severity:    "critical",
				TenantID:    ev.TenantID,
				UserID:      ev.UserID,
				TraceID:     ev.TraceID,
				DetectedAt:  at,
				Description: fmt.Sprintf("confirmed intrusion: honey-token triggered across %d modules (%v)", layerCount, mods),
				Evidence:    map[string]any{"modules": mods, "layer_count": layerCount},
			})
		}
	}

	// ── Off-hours access ──────────────────────────────────────────────────────
	if d.cfg.ActiveHoursStart != 0 || d.cfg.ActiveHoursEnd != 0 {
		hour := at.Hour()
		if hour < d.cfg.ActiveHoursStart || hour >= d.cfg.ActiveHoursEnd {
			d.fire(models.AnomalyEvent{
				AnomalyID:   newID(),
				Pattern:     "off_hours_access",
				Severity:    "warning",
				TenantID:    ev.TenantID,
				UserID:      ev.UserID,
				TraceID:     ev.TraceID,
				DetectedAt:  at,
				Description: fmt.Sprintf("access at %02d:00 outside active hours (%d–%d)", hour, d.cfg.ActiveHoursStart, d.cfg.ActiveHoursEnd),
				Evidence:    map[string]any{"hour": hour, "active_start": d.cfg.ActiveHoursStart, "active_end": d.cfg.ActiveHoursEnd},
			})
		}
	}
}

// Baselines returns a snapshot of all active statistical baselines.
func (d *Detector) Baselines() []models.AnomalyBaseline {
	return d.baseline.listBaselines()
}

// Recent returns anomaly events detected in the last 24 hours.
func (d *Detector) Recent() []models.AnomalyEvent {
	cutoff := time.Now().Add(-24 * time.Hour)
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]models.AnomalyEvent, 0)
	for _, ev := range d.detected {
		if ev.DetectedAt.After(cutoff) {
			out = append(out, ev)
		}
	}
	return out
}

func (d *Detector) fire(ev models.AnomalyEvent) {
	d.mu.Lock()
	// Keep last 1000 events in memory.
	if len(d.detected) >= 1000 {
		d.detected = d.detected[1:]
	}
	d.detected = append(d.detected, ev)
	d.mu.Unlock()

	if d.sink != nil {
		d.sink.OnAnomaly(ev)
	}
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
