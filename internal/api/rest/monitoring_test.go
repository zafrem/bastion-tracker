package rest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/zafrem/bastion-tracker/internal/metrics"
	"github.com/zafrem/bastion-tracker/internal/monitor"
)

func TestHTTPMetrics_AreLabelledByRoutePattern(t *testing.T) {
	f := newFixture(t)
	count := func() float64 {
		return testutil.ToFloat64(metrics.HTTPRequests.WithLabelValues("GET", "/v1/events/{event_id}", "404"))
	}
	before := count()
	f.get(t, "/v1/events/one")
	f.get(t, "/v1/events/two")
	if got := count() - before; got != 2 {
		t.Errorf("requests counted under the route pattern = %v, want 2", got)
	}
	f.do(t, "BREW", "/v1/health", nil)
	for k := range scrape(t, f) {
		if strings.Contains(k, "BREW") || strings.Contains(k, `/v1/events/one`) {
			t.Errorf("caller-controlled label value in %s", k)
		}
	}
}

func TestHTTPMetrics_KeepWebSocketWorking(t *testing.T) {
	f := newFixture(t)
	srv := httptest.NewServer(f.handler)
	defer srv.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws/events", nil)
	if err != nil {
		t.Fatalf("websocket upgrade failed behind the instrumentation: %v", err)
	}
	defer conn.Close()
	upgrades := metrics.HTTPRequests.WithLabelValues("GET", "/ws/events", "101")
	for deadline := time.Now().Add(5 * time.Second); testutil.ToFloat64(upgrades) == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the upgrade was not counted as 101")
		}
	}
}

func TestPanicsAreCounted(t *testing.T) {
	panics := metrics.Panics.WithLabelValues("http")
	before := testutil.ToFloat64(panics)
	h := countPanics(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	func() {
		defer func() { _ = recover() }() // the Recoverer middleware's job in the server
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	}()
	if got := testutil.ToFloat64(panics) - before; got != 1 {
		t.Errorf("panics counted = %v, want 1", got)
	}
}

func TestHealth_ReportsADownDependency(t *testing.T) {
	up := false
	f := newFixture(t, WithDependency("nats_collector", func() bool { return up }))
	check := func(status, dep string) {
		t.Helper()
		w := f.get(t, "/v1/health")
		mustStatus(t, w, http.StatusOK)
		var res struct {
			Status string            `json:"status"`
			Checks map[string]string `json:"checks"`
		}
		decodeBody(t, w, &res)
		if res.Status != status || res.Checks["nats_collector"] != dep {
			t.Errorf("health = %s / %s, want %s / %s", res.Status, res.Checks["nats_collector"], status, dep)
		}
	}
	check("degraded", "down")
	mustStatus(t, f.get(t, "/v1/health/ready"), http.StatusOK)
	up = true
	check("ok", "up")
}

func TestMetricsEndpoint_CanBeRemovedFromTheRESTPort(t *testing.T) {
	f := newFixture(t, WithoutMetricsEndpoint())
	w := f.get(t, "/v1/metrics")
	if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "tracker_") {
		t.Errorf("GET /v1/metrics = %d, want 404 without metrics", w.Code)
	}
}

func TestMetrics_ReportPendingCheckpoints(t *testing.T) {
	f := newFixture(t)
	f.mon.SetMode(monitor.ModeGate)
	f.mon.CreateCheckpoint("t", "tenant", "vault", nil)
	m := scrape(t, f)
	if m["tracker_monitor_pending_checkpoints"] != 1 {
		t.Errorf("pending checkpoints = %v, want 1", m["tracker_monitor_pending_checkpoints"])
	}
	f.mon.SetMode(monitor.ModeOff)
}
