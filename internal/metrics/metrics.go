// Package metrics registers Prometheus counters and histograms for Tracker.
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	EventsReceived = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tracker_events_received_total",
		Help: "Total events received, partitioned by module and event_type.",
	}, []string{"module", "event_type"})

	EventsProcessed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tracker_events_processed_total",
		Help: "Events successfully processed.",
	}, []string{"module"})

	ProcessingDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "tracker_event_processing_duration_seconds",
		Help:    "Time to process one event.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
	}, []string{"module"})

	WebSocketConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tracker_websocket_connections",
		Help: "Current number of WebSocket client connections.",
	})

	WebSocketBroadcasts = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "tracker_websocket_broadcasts_total",
		Help: "Total WebSocket broadcast messages sent.",
	})

	IncidentsCreated = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tracker_incidents_created_total",
		Help: "Incidents created, by severity.",
	}, []string{"severity"})

	AlertsFired = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tracker_alerts_fired_total",
		Help: "Alert rule firings by rule name.",
	}, []string{"rule", "severity"})

	HoneyTokenTriggers = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "tracker_honey_token_triggers_total",
		Help: "Total honey-token trigger events.",
	})

	PipelineRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tracker_pipeline_requests_total",
		Help: "Requests handled by pipeline type.",
	}, []string{"pipeline_type", "status"})

	ActiveAlerts = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tracker_active_alerts",
		Help: "Number of currently firing alerts.",
	})

	EventsRejected = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "tracker_events_rejected_total",
		Help: "Events rejected by schema validation (dead-lettered).",
	})
)

func init() {
	prometheus.MustRegister(
		EventsReceived,
		EventsProcessed,
		ProcessingDuration,
		WebSocketConnections,
		WebSocketBroadcasts,
		IncidentsCreated,
		AlertsFired,
		HoneyTokenTriggers,
		PipelineRequests,
		ActiveAlerts,
		EventsRejected,
	)
}
