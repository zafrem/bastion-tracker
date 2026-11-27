package metrics_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zafrem/bastion-tracker/internal/metrics"
)

func sources() metrics.Sources {
	return metrics.Sources{
		Version: "test",
		Store: func() metrics.StoreStats {
			return metrics.StoreStats{Events: 3, EventCapacity: 10, EventsWritten: 3,
				Incidents: map[string]int{"open": 2}, Alerts: map[[2]string]int{{"firing", "critical"}: 4, {"resolved", "critical"}: 9}}
		},
		Monitor: func() metrics.MonitorStats {
			return metrics.MonitorStats{PendingCheckpoints: 1, OldestPendingWaited: 90 * time.Second}
		},
		NATS: []func() metrics.NATSStats{
			func() metrics.NATSStats { return metrics.NATSStats{Client: "collector", Connected: true, Dropped: 7} },
			func() metrics.NATSStats { return metrics.NATSStats{Client: "publisher"} },
		},
	}
}

func TestServer_ServesStateOnItsOwnPort(t *testing.T) {
	srv, err := metrics.Listen("127.0.0.1:0", metrics.Handler(sources()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	res, err := http.Get("http://" + srv.Addr() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	for _, want := range []string{
		`tracker_store_events 3`,
		`tracker_active_alerts 4`,
		`tracker_alerts{severity="critical",status="resolved"} 9`,
		`tracker_incidents{status="open"} 2`,
		`tracker_monitor_oldest_pending_checkpoint_seconds 90`,
		`tracker_nats_connected{client="collector"} 1`,
		`tracker_nats_connected{client="publisher"} 0`,
		`tracker_nats_messages_dropped_total{client="collector"} 7`,
		`tracker_build_info{`,
		`tracker_honey_token_triggers_total`,
		`tracker_panics_total{component="grpc"}`,
		`go_goroutines`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("/metrics lacks %q", want)
		}
	}

	if _, err := metrics.Listen(srv.Addr(), http.NotFoundHandler()); err == nil {
		t.Error("a second listener on the same port did not fail")
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Serve after cancel: %v", err)
	}
}

func TestLabels_AreBoundedButKeepKnownValues(t *testing.T) {
	for i := range 500 {
		metrics.EventTypeLabel("junk_" + strings.Repeat("x", i%40) + string(rune('a'+i%26)) + string(rune('a'+i/26)))
	}
	if got := metrics.EventTypeLabel("another_new_type"); got != metrics.Other {
		t.Errorf("label beyond the limit = %q, want %q", got, metrics.Other)
	}
	if got := metrics.EventTypeLabel("honey_token_leaked"); got != "honey_token_leaked" {
		t.Errorf("a known event type was displaced: %q", got)
	}
	for _, bad := range []string{"", "has space", "line\nbreak", strings.Repeat("a", 65)} {
		if got := metrics.ModuleLabel(bad); got != metrics.Other {
			t.Errorf("ModuleLabel(%q) = %q, want %q", bad, got, metrics.Other)
		}
	}
}
