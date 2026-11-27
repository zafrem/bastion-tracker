// Package metrics defines Tracker's Prometheus metrics.
//
// Counters and histograms that components update as things happen are package variables here. Values that
// describe current state (stored alerts, NATS connections and so on) are read at scrape time by the collector
// in state.go, so they cannot drift from the state they describe.
//
// Label values must come from a small fixed set. Anything a caller controls goes through a limiter (labels.go).
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	EventsReceived = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tracker_events_received_total",
		Help: "Events accepted by schema validation, by module and event_type (unusual values are counted as \"other\").",
	}, []string{"module", "event_type"})

	EventsProcessed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tracker_events_processed_total",
		Help: "Events that went through the whole processing pipeline.",
	}, []string{"module"})

	ProcessingDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "tracker_event_processing_duration_seconds",
		Help:    "Time to process one event.",
		Buckets: []float64{0.0001, 0.00025, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
	}, []string{"module"})

	EventsRejected = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "tracker_events_rejected_total",
		Help: "Events rejected by schema validation (dead-lettered).",
	})

	LastEventTimestamp = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tracker_last_event_timestamp_seconds",
		Help: "Unix time at which Tracker last processed an event; 0 if none since start.",
	})

	PipelineRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tracker_pipeline_requests_total",
		Help: "Events carrying a pipeline type, by pipeline type and status.",
	}, []string{"pipeline_type", "status"})

	WebSocketConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tracker_websocket_connections",
		Help: "Current number of WebSocket client connections.",
	})

	WebSocketBroadcasts = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "tracker_websocket_broadcasts_total",
		Help: "Messages handed to live subscribers.",
	})

	BroadcastsDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tracker_broadcast_dropped_total",
		Help: "Live-update messages dropped because a queue was full.",
	}, []string{"reason"})

	IncidentsCreated = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tracker_incidents_created_total",
		Help: "Incidents created, by severity.",
	}, []string{"severity"})

	AlertsFired = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tracker_alerts_fired_total",
		Help: "Alert rule firings by rule name.",
	}, []string{"rule", "severity"})

	Notifications = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tracker_notifications_total",
		Help: "Alert notifications by channel and result (success, failure, unknown_channel).",
	}, []string{"channel", "result"})

	HoneyTokenTriggers = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "tracker_honey_token_triggers_total",
		Help: "Total honey-token trigger events.",
	})

	Anomalies = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tracker_anomalies_total",
		Help: "Anomalies detected, by pattern and severity.",
	}, []string{"pattern", "severity"})

	Logins = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tracker_logins_total",
		Help: "Login attempts by result (success, failure).",
	}, []string{"result"})

	NATSDecodeErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "tracker_nats_decode_errors_total",
		Help: "NATS messages that were not valid events and were discarded.",
	})

	EventsPublished = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tracker_events_published_total",
		Help: "Tracker's own events sent to NATS, by result (success, failure).",
	}, []string{"result"})

	Panics = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tracker_panics_total",
		Help: "Panics recovered while handling a request or message, by component.",
	}, []string{"component"})

	HTTPRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tracker_http_requests_total",
		Help: "HTTP requests by method, route pattern and status code.",
	}, []string{"method", "route", "code"})

	HTTPDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "tracker_http_request_duration_seconds",
		Help:    "HTTP request duration by method and route pattern.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route"})

	HTTPInFlight = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tracker_http_requests_in_flight",
		Help: "HTTP requests being handled now.",
	})

	GRPCRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tracker_grpc_requests_total",
		Help: "Finished gRPC calls by method and status code.",
	}, []string{"method", "code"})

	GRPCDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "tracker_grpc_request_duration_seconds",
		Help:    "Duration of unary gRPC calls by method.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method"})
)

// The Go runtime and process collectors are already registered on the default registry.
func init() {
	prometheus.MustRegister(
		EventsReceived, EventsProcessed, ProcessingDuration, EventsRejected, LastEventTimestamp, PipelineRequests,
		WebSocketConnections, WebSocketBroadcasts, BroadcastsDropped,
		IncidentsCreated, AlertsFired, Notifications, HoneyTokenTriggers, Anomalies, Logins,
		NATSDecodeErrors, EventsPublished, Panics,
		HTTPRequests, HTTPDuration, HTTPInFlight, GRPCRequests, GRPCDuration,
	)
	// Create the series that alerts watch, so increase() sees their first occurrence.
	for _, v := range []string{"success", "failure"} {
		Logins.WithLabelValues(v)
		EventsPublished.WithLabelValues(v)
	}
	for _, c := range []string{"http", "grpc", "nats"} {
		Panics.WithLabelValues(c)
	}
	for _, s := range []string{"critical", "error"} {
		IncidentsCreated.WithLabelValues(s)
	}
	for _, r := range []string{"queue_full", "slow_client", "slow_subscriber"} {
		BroadcastsDropped.WithLabelValues(r)
	}
}
