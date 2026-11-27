package metrics

import (
	"regexp"
	"sync"
)

// Other replaces a label value that is malformed or would exceed a label's limit.
const Other = "other"

var labelPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// limiter caps how many distinct values a label can take. Known values are admitted up front; further values
// are admitted first come, first served, until the cap.
type limiter struct {
	mu   sync.RWMutex
	seen map[string]struct{}
	max  int
}

func newLimiter(max int, known ...string) *limiter {
	l := &limiter{seen: make(map[string]struct{}, max), max: max}
	for _, k := range known {
		l.seen[k] = struct{}{}
	}
	return l
}

func (l *limiter) value(v string) string {
	l.mu.RLock()
	_, ok := l.seen[v]
	l.mu.RUnlock()
	if ok {
		return v
	}
	if !labelPattern.MatchString(v) {
		return Other
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.seen[v]; !ok {
		if len(l.seen) >= l.max {
			return Other
		}
		l.seen[v] = struct{}{}
	}
	return v
}

var (
	modules = newLimiter(24, "sentinel", "vault", "navigator", "anchor", "llm", "tracker", "security", "system")
	// Event types named by alert rules and detectors are admitted first so junk cannot crowd them out.
	eventTypes = newLimiter(200,
		"prompt_injection_detected", "cross_tenant_attempt", "module_degraded", "chunk_retrieved",
		"anomaly_detected", "bypass_anomaly_detected", "honey_token_triggered", "honey_token_accessed",
		"honey_token_retrieved", "honey_token_referenced", "honey_token_leaked")
	pipelineTypes = newLimiter(12, "full", "lite", "minimal")
)

// ModuleLabel returns the label value for an event's module.
func ModuleLabel(v string) string { return modules.value(v) }

// EventTypeLabel returns the label value for an event's type.
func EventTypeLabel(v string) string { return eventTypes.value(v) }

// PipelineLabel returns the label value for an event's pipeline type.
func PipelineLabel(v string) string { return pipelineTypes.value(v) }
