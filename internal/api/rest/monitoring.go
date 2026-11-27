package rest

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/zafrem/bastion-tracker/internal/metrics"
)

type dependency struct {
	name string
	up   func() bool
}

// WithMetricsHandler sets what /v1/metrics serves. By default it covers the components given to New.
func WithMetricsHandler(h http.Handler) Option {
	return func(o *options) { o.metrics = h }
}

// WithoutMetricsEndpoint removes /v1/metrics, for deployments that scrape the dedicated metrics port and do not
// want metrics on the user-facing one.
func WithoutMetricsEndpoint() Option {
	return func(o *options) { o.noMetrics = true }
}

// WithDependency reports an external dependency in /v1/health; while one is down the status is "degraded".
func WithDependency(name string, up func() bool) Option {
	return func(o *options) { o.dependencies = append(o.dependencies, dependency{name, up}) }
}

var knownMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodPatch: true, http.MethodDelete: true, http.MethodOptions: true,
}

// instrument records request counts and durations. Routes are labelled by pattern ("/v1/events/{event_id}"),
// never by path, so callers cannot create new series.
func instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		metrics.HTTPInFlight.Inc()
		// Deferred so that a request aborted by a panic is counted too.
		defer func() {
			metrics.HTTPInFlight.Dec()
			method := r.Method
			if !knownMethods[method] {
				method = metrics.Other
			}
			route := "unmatched"
			if rc := chi.RouteContext(r.Context()); rc != nil && rc.RoutePattern() != "" {
				route = rc.RoutePattern()
			}
			code := ww.Status()
			if code == 0 {
				code = http.StatusOK
				if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
					code = http.StatusSwitchingProtocols // the connection was taken over by the WebSocket
				}
			}
			metrics.HTTPRequests.WithLabelValues(method, route, strconv.Itoa(code)).Inc()
			metrics.HTTPDuration.WithLabelValues(method, route).Observe(time.Since(start).Seconds())
		}()
		next.ServeHTTP(ww, r)
	})
}

// countPanics sits inside the Recoverer middleware, which turns the panic into a 500 response.
func countPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v != http.ErrAbortHandler {
					metrics.Panics.WithLabelValues("http").Inc()
				}
				panic(v)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
