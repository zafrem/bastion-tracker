// Package rest provides the HTTP REST server for Bastion-Tracker.
package rest

import (
	"context"
	"embed"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/bastion/tracker/internal/alerts"
	"github.com/bastion/tracker/internal/audit"
	"github.com/bastion/tracker/internal/config"
	"github.com/bastion/tracker/internal/demo"
	"github.com/bastion/tracker/internal/honeytoken"
	"github.com/bastion/tracker/internal/hub"
	"github.com/bastion/tracker/internal/incidents"
	"github.com/bastion/tracker/internal/monitor"
	"github.com/bastion/tracker/internal/processor"
	"github.com/bastion/tracker/internal/runbook"
	"github.com/bastion/tracker/internal/store"
)

//go:embed static
var staticFS embed.FS

// Server is the REST + UI HTTP server.
type Server struct {
	httpServer *http.Server
	port       int
}

// New constructs a Server with all routes wired up.
func New(
	s *store.Store,
	h *hub.Hub,
	proc *processor.Processor,
	demoEng *demo.Engine,
	al *alerts.Manager,
	inc *incidents.Manager,
	ht *honeytoken.Manager,
	authCfg *config.AuthConfig,
	signer *audit.Signer,
	mon *monitor.Manager,
	port int,
) *Server {
	rec := demo.NewRecorder()
	proc.AddHook(rec.Record)

	hh := &handlers{
		store:     s,
		hub:       h,
		proc:      proc,
		demo:      demoEng,
		alerts:    al,
		incidents: inc,
		honey:     ht,
		authCfg:   authCfg,
		recorder:  rec,
		runbooks:  runbook.New(),
		signer:    signer,
		mon:       mon,
	}
	srv := &Server{port: port}
	srv.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      srv.routes(hh, h, authCfg),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return srv
}

func (s *Server) routes(h *handlers, ws *hub.Hub, authCfg *config.AuthConfig) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(10 * time.Second))

	// CORS for local dev.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			if req.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, req)
		})
	})

	// Public routes (no auth required).
	r.Get("/v1/health", h.Health)
	r.Get("/v1/health/live", h.Live)
	r.Get("/v1/health/ready", h.Ready)
	r.Handle("/v1/metrics", promhttp.Handler())
	r.Post("/v1/auth/login", h.Login)

	// Protected API — apply JWT middleware when auth is enabled.
	r.Group(func(r chi.Router) {
		if authCfg != nil && authCfg.Enabled {
			r.Use(jwtMiddleware(authCfg.JWTSecret))
		}

		// Events — viewer+
		r.Get("/v1/events", h.ListEvents)
		r.Get("/v1/events/search", h.SearchEvents)
		r.Get("/v1/events/{event_id}", h.GetEvent)

		// Events — operator+
		r.With(operatorOrOpen(authCfg)).Post("/v1/events", h.SubmitEvent)
		r.With(operatorOrOpen(authCfg)).Post("/v1/events/batch", h.SubmitBatch)

		// Traces — viewer+
		r.Get("/v1/traces", h.ListTraces)
		r.Get("/v1/traces/{trace_id}", h.GetTrace)
		r.Get("/v1/traces/{trace_id}/timeline", h.GetTraceTimeline)

		// Lineage — aliases + new query endpoints (SRS doc 22 §6.2)
		r.Get("/v1/lineage/{trace_id}", h.GetTrace)
		r.Get("/v1/lineage/user/{user_id}", h.ListTracesByUser)
		r.Get("/v1/lineage/data/{data_ref}", h.LineageByDataRef)
		r.Get("/v1/lineage/audit", h.LineageAudit)

		// Topology — viewer+
		r.Get("/v1/topology", h.Topology)
		r.Get("/v1/topology/health", h.TopologyHealth)
		r.Get("/v1/pipelines/stats", h.PipelineStats)

		// Security events — viewer+
		r.Get("/v1/security/events", h.GetSecurityEvents)

		// Incidents — viewer GET / operator POST
		r.Get("/v1/security/incidents", h.ListIncidents)
		r.With(operatorOrOpen(authCfg)).Post("/v1/security/incidents/{id}/resolve", h.ResolveIncident)

		// Alerts — viewer GET / operator POST
		r.Get("/v1/alerts", h.ListAlerts)
		r.With(operatorOrOpen(authCfg)).Post("/v1/alerts/{id}/acknowledge", h.AcknowledgeAlert)

		// Honey-tokens — viewer GET / operator write
		r.Get("/v1/honey-tokens", h.ListHoneyTokens)
		r.With(operatorOrOpen(authCfg)).Post("/v1/honey-tokens", h.CreateHoneyToken)
		r.With(operatorOrOpen(authCfg)).Delete("/v1/honey-tokens/{id}", h.DeleteHoneyToken)
		r.Get("/v1/honey-tokens/triggers", h.AllHoneyTokenTriggers) // SRS: all triggers across tokens
		r.Get("/v1/honey-tokens/{id}/triggers", h.HoneyTokenTriggers)

		// Alerts — resolve
		r.With(operatorOrOpen(authCfg)).Post("/v1/alerts/{id}/resolve", h.ResolveAlert)

		// Demo — operator+
		r.Get("/v1/demo/scenarios", h.ListScenarios)
		r.Get("/v1/demo/scenarios/{name}", h.GetScenario)
		r.With(operatorOrOpen(authCfg)).Post("/v1/demo/replay", h.ReplayScenario)
		r.With(operatorOrOpen(authCfg)).Post("/v1/demo/inject", h.InjectEvent)
		r.Get("/v1/demo/active", h.ActiveScenarios)
		r.With(operatorOrOpen(authCfg)).Post("/v1/demo/stop", h.StopScenario)

		// Recording — operator+
		r.With(operatorOrOpen(authCfg)).Post("/v1/demo/record/start", h.StartRecording)
		r.With(operatorOrOpen(authCfg)).Post("/v1/demo/record/stop", h.StopRecording)
		r.Get("/v1/demo/record/status", h.RecordingStatus)

		// Admin — admin only
		r.With(adminOrOpen(authCfg)).Post("/v1/config/reload", h.ReloadConfig)

		// Run books — viewer+
		r.Get("/v1/runbooks", h.ListRunBooks)
		r.Get("/v1/runbooks/{id}", h.GetRunBook)

		// Dead letter — operator+
		r.With(operatorOrOpen(authCfg)).Get("/v1/dead-letter", h.ListDeadLetters)

		// Audit verification — operator+
		r.With(operatorOrOpen(authCfg)).Get("/v1/audit/verify", h.VerifyAuditLog)

		// Pipeline Monitor — viewer GET / operator POST+DELETE
		r.Get("/v1/monitor/mode", h.MonitorGetMode)
		r.With(operatorOrOpen(authCfg)).Post("/v1/monitor/mode", h.MonitorSetMode)

		r.Get("/v1/monitor/sessions", h.MonitorListSessions)
		r.Get("/v1/monitor/sessions/{session_id}", h.MonitorGetSession)
		r.With(operatorOrOpen(authCfg)).Delete("/v1/monitor/sessions/{session_id}", h.MonitorDeleteSession)
		r.With(operatorOrOpen(authCfg)).Post("/v1/monitor/sessions/{session_id}/steps/{step_id}/annotate", h.MonitorAnnotateStep)

		r.Get("/v1/monitor/checkpoints", h.MonitorListCheckpoints)
		r.Get("/v1/monitor/checkpoints/{checkpoint_id}", h.MonitorGetCheckpoint)
		r.With(operatorOrOpen(authCfg)).Post("/v1/monitor/checkpoints/{checkpoint_id}/decide", h.MonitorDecideCheckpoint)
		r.With(operatorOrOpen(authCfg)).Post("/v1/monitor/checkpoints", h.MonitorCreateCheckpoint)
	})

	// WebSocket (public — auth enforced at application level if needed).
	r.Get("/ws/events", ws.ServeWS)

	// Embedded static UI.
	r.Handle("/*", http.FileServer(http.FS(staticFS)))

	return r
}

// operatorOrOpen applies requireMinRole("operator") only when auth is enabled.
func operatorOrOpen(authCfg *config.AuthConfig) func(http.Handler) http.Handler {
	if authCfg == nil || !authCfg.Enabled {
		return func(next http.Handler) http.Handler { return next }
	}
	return requireMinRole("operator")
}

// adminOrOpen applies requireMinRole("admin") only when auth is enabled.
func adminOrOpen(authCfg *config.AuthConfig) func(http.Handler) http.Handler {
	if authCfg == nil || !authCfg.Enabled {
		return func(next http.Handler) http.Handler { return next }
	}
	return requireMinRole("admin")
}

// Start begins serving; blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	log.Printf("[rest] tracker listening on :%d", s.port)
	errCh := make(chan error, 1)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shut)
	}
}
