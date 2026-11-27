package metrics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Handler serves the package metrics together with the given state sources.
func Handler(src Sources) http.Handler {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewStateCollector(src))
	return promhttp.HandlerFor(
		prometheus.Gatherers{prometheus.DefaultGatherer, reg},
		// A scrape that fails part-way still returns what could be gathered.
		promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError, MaxRequestsInFlight: 5},
	)
}

// Server is the dedicated metrics listener. It has no authentication: expose its port to the monitoring
// network only.
type Server struct {
	srv *http.Server
	lis net.Listener
}

// Listen binds addr straight away, so that a port conflict stops startup instead of leaving Tracker running
// without metrics.
func Listen(addr string, h http.Handler) (*Server, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("metrics listen: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", h)
	return &Server{lis: lis, srv: &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}}, nil
}

// Addr is the address the server listens on.
func (s *Server) Addr() string { return s.lis.Addr().String() }

// Serve blocks until ctx is cancelled or serving fails.
func (s *Server) Serve(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() { errCh <- s.srv.Serve(s.lis) }()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.srv.Shutdown(shut)
	}
}
