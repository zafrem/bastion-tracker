package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	"github.com/bastion/tracker/internal/hub"
	"github.com/bastion/tracker/internal/models"
	"github.com/bastion/tracker/internal/processor"
	"github.com/bastion/tracker/internal/store"
)

// Server implements the gRPC TrackerService.
type Server struct {
	UnimplementedTrackerServiceServer
	grpcServer *grpc.Server
	port       int
	store      *store.Store
	proc       *processor.Processor
	hub        *hub.Hub
}

// New creates a gRPC Server.
func New(s *store.Store, proc *processor.Processor, h *hub.Hub, port int) *Server {
	srv := &Server{store: s, proc: proc, hub: h, port: port}
	srv.grpcServer = grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
			Time:              2 * time.Minute,
			Timeout:           20 * time.Second,
		}),
		grpc.UnaryInterceptor(loggingInterceptor),
	)
	RegisterTrackerServiceServer(srv.grpcServer, srv)
	reflection.Register(srv.grpcServer)
	return srv
}

func loggingInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	resp, err := handler(ctx, req)
	if err != nil {
		log.Printf("[grpc] %s error: %v", info.FullMethod, err)
	}
	return resp, err
}

// Start listens on the configured port; blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("grpc listen: %w", err)
	}
	log.Printf("[grpc] tracker listening on :%d", s.port)
	errCh := make(chan error, 1)
	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		s.grpcServer.GracefulStop()
		return nil
	}
}

// ─── Unary method implementations ─────────────────────────────────────────────

func (s *Server) SubmitEvent(_ context.Context, req *models.BastionEvent) (*models.SubmitResponse, error) {
	s.proc.Process(*req)
	return &models.SubmitResponse{EventID: req.EventID, Accepted: true}, nil
}

func (s *Server) SubmitBatchEvents(_ context.Context, req *models.BatchEventRequest) (*models.BatchResponse, error) {
	for _, ev := range req.Events {
		s.proc.Process(ev)
	}
	return &models.BatchResponse{Accepted: len(req.Events)}, nil
}

// QueryEvents streams historical events matching the filter (server-streaming, SRS §6.2).
func (s *Server) QueryEvents(req *models.QueryRequest, stream grpc.ServerStream) error {
	events := s.store.RecentEvents(*req, req.Limit)
	for i := range events {
		if err := stream.SendMsg(&events[i]); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) GetTrace(_ context.Context, req *models.TraceRequest) (*models.TraceResponse, error) {
	tr, ok := s.store.GetTrace(req.TraceID)
	if !ok {
		return &models.TraceResponse{}, nil
	}
	return &models.TraceResponse{Trace: *tr}, nil
}

func (s *Server) GetLineage(_ context.Context, req *models.LineageRequest) (*models.LineageResponse, error) {
	tr, ok := s.store.GetTrace(req.TraceID)
	if !ok {
		return &models.LineageResponse{TraceID: req.TraceID, Found: false}, nil
	}
	return &models.LineageResponse{
		TraceID: req.TraceID,
		Found:   true,
		Spans:   tr.Spans,
	}, nil
}

func (s *Server) GetIncidents(_ context.Context, req *models.IncidentRequest) (*models.IncidentResponse, error) {
	limit := req.Limit
	if limit <= 0 {
		limit = 50
	}
	all := s.store.ListIncidents(req.Status)
	filtered := make([]models.Incident, 0, len(all))
	for _, inc := range all {
		if req.TenantID != "" && inc.TenantID != req.TenantID {
			continue
		}
		filtered = append(filtered, inc)
		if len(filtered) >= limit {
			break
		}
	}
	return &models.IncidentResponse{Incidents: filtered, Total: len(filtered)}, nil
}

func (s *Server) Health(_ context.Context, _ *models.HealthRequest) (*models.HealthStatus, error) {
	return &models.HealthStatus{
		Status:  "ok",
		Version: "3.0.0",
		Checks:  map[string]string{"grpc": "up"},
	}, nil
}

// ─── Streaming implementation ─────────────────────────────────────────────────

// StreamEvents subscribes to the hub and streams matching BastionEvents to the client.
// The client sends a StreamEventsRequest once to specify filters; the server then
// pushes events until the client disconnects.
func (s *Server) StreamEvents(req *models.StreamEventsRequest, stream grpc.ServerStream) error {
	sub := s.hub.Subscribe(256)
	defer s.hub.Unsubscribe(sub)

	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case raw, ok := <-sub.C():
			if !ok {
				return nil
			}
			// Decode the hub envelope.
			var wsMsg models.WSMessage
			if err := json.Unmarshal(raw, &wsMsg); err != nil {
				continue
			}
			if wsMsg.Type != "event" {
				continue
			}
			// Re-marshal payload to extract the BastionEvent.
			evData, _ := json.Marshal(wsMsg.Payload)
			var ev models.BastionEvent
			if err := json.Unmarshal(evData, &ev); err != nil {
				continue
			}
			// Apply client-specified filters.
			if req.Module != "" && ev.Module != req.Module {
				continue
			}
			if req.Severity != "" && ev.Severity != req.Severity {
				continue
			}
			if req.TenantID != "" && ev.TenantID != req.TenantID {
				continue
			}
			if err := stream.SendMsg(&ev); err != nil {
				return err
			}
		}
	}
}
