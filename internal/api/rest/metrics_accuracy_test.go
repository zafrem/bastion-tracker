package rest

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/zafrem/bastion-tracker/internal/alerts"
	"github.com/zafrem/bastion-tracker/internal/config"
	"github.com/zafrem/bastion-tracker/internal/models"
)

// scrape returns the value of every series on /v1/metrics, keyed by `name{labels}`.
func scrape(t *testing.T, f *testFixture) map[string]float64 {
	t.Helper()
	w := f.get(t, "/v1/metrics")
	mustStatus(t, w, http.StatusOK)
	out := map[string]float64{}
	for _, line := range strings.Split(w.Body.String(), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		if v, err := strconv.ParseFloat(line[i+1:], 64); err == nil {
			out[line[:i]] = v
		}
	}
	return out
}

func countSeries(m map[string]float64, name string) (n int) {
	for k := range m {
		if strings.HasPrefix(k, name+"{") {
			n++
		}
	}
	return n
}

// Event fields come from callers. If each new value became a metric label, anyone able to submit events could
// grow Tracker's memory and the Prometheus database without limit.
func TestMetrics_LabelsStayBoundedForHostileInput(t *testing.T) {
	f := newFixture(t)
	for i := range 1000 {
		mustStatus(t, f.post(t, "/v1/events", models.BastionEvent{
			Module:       fmt.Sprintf("module-%d", i),
			EventType:    fmt.Sprintf("type-%d", i),
			PipelineType: fmt.Sprintf("pipeline-%d", i),
			Status:       "passed",
		}), http.StatusAccepted)
	}
	m := scrape(t, f)
	for name, limit := range map[string]int{
		"tracker_events_received_total":                   600,
		"tracker_events_processed_total":                  40,
		"tracker_event_processing_duration_seconds_count": 40,
		"tracker_pipeline_requests_total":                 100,
	} {
		if got := countSeries(m, name); got > limit {
			t.Errorf("%s has %d series after 1000 distinct values, want at most %d", name, got, limit)
		}
	}
}

func TestMetrics_ActiveAlertsFallsWhenAnAlertIsResolved(t *testing.T) {
	f := newFixture(t)
	al := alerts.New([]config.AlertRule{{Name: "r", Condition: "sentinel.boom", Severity: "warning"}}, f.store, nil)
	before := scrape(t, f)["tracker_active_alerts"]

	fired := al.Evaluate(models.BastionEvent{Module: "sentinel", EventType: "boom"})
	if len(fired) != 1 {
		t.Fatalf("fired %d alerts, want 1", len(fired))
	}
	if got := scrape(t, f)["tracker_active_alerts"]; got != before+1 {
		t.Fatalf("tracker_active_alerts = %v after one alert, want %v", got, before+1)
	}
	mustStatus(t, f.post(t, "/v1/alerts/"+fired[0].AlertID+"/resolve", nil), http.StatusOK)
	if got := scrape(t, f)["tracker_active_alerts"]; got != before {
		t.Errorf("tracker_active_alerts = %v after resolving it, want %v", got, before)
	}
}
