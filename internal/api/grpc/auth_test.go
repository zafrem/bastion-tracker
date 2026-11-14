package grpc

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/zafrem/bastion-tracker/internal/alerts"
	"github.com/zafrem/bastion-tracker/internal/auth"
	"github.com/zafrem/bastion-tracker/internal/config"
	"github.com/zafrem/bastion-tracker/internal/honeytoken"
	"github.com/zafrem/bastion-tracker/internal/hub"
	"github.com/zafrem/bastion-tracker/internal/incidents"
	"github.com/zafrem/bastion-tracker/internal/models"
	"github.com/zafrem/bastion-tracker/internal/processor"
	"github.com/zafrem/bastion-tracker/internal/store"
)

const testJWTSecret = "unit-test-jwt-secret-at-least-32-bytes!!"

func newAuthTestServer(t *testing.T, enabled bool) *Server {
	t.Helper()
	st := store.New(100)
	hb := hub.New(8)
	al := alerts.New(nil, st, nil)
	inc := incidents.New(st)
	ht := honeytoken.New(st)
	proc := processor.New(st, hb, al, inc, ht)
	srv := New(st, proc, hb, 0)
	srv.EnableAuth(&config.AuthConfig{
		Enabled:   enabled,
		JWTSecret: testJWTSecret,
	})
	return srv
}

func dialPlaintext(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func ctxWithToken(token string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+token)
}

func TestGRPCAuth_DisabledAllowsUnauthenticatedCalls(t *testing.T) {
	srv := newAuthTestServer(t, false)
	if srv.AuthEnabled() {
		t.Fatal("AuthEnabled should be false when disabled")
	}
	conn := dialPlaintext(t, serveOn(t, srv))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var out models.TraceResponse
	if err := conn.Invoke(ctx, "/bastion.tracker.v1.TrackerService/GetTrace", &models.TraceRequest{TraceID: "t-1"}, &out); err != nil {
		t.Fatalf("GetTrace with auth disabled: %v", err)
	}
}

func TestGRPCAuth_HealthRemainsPublicWhenEnabled(t *testing.T) {
	srv := newAuthTestServer(t, true)
	if !srv.AuthEnabled() {
		t.Fatal("AuthEnabled should be true when enabled")
	}
	conn := dialPlaintext(t, serveOn(t, srv))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var out models.HealthStatus
	if err := conn.Invoke(ctx, "/bastion.tracker.v1.TrackerService/Health", &models.HealthRequest{}, &out); err != nil {
		t.Fatalf("Health without token should succeed: %v", err)
	}
	if out.Status != "ok" {
		t.Errorf("status = %q, want ok", out.Status)
	}
}

func TestGRPCAuth_RejectsMissingAndInvalidTokens(t *testing.T) {
	srv := newAuthTestServer(t, true)
	conn := dialPlaintext(t, serveOn(t, srv))

	var out models.TraceResponse
	err := conn.Invoke(context.Background(), "/bastion.tracker.v1.TrackerService/GetTrace", &models.TraceRequest{TraceID: "t-1"}, &out)
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("missing token: got %v, want Unauthenticated", status.Code(err))
	}

	err = conn.Invoke(ctxWithToken("not-a-jwt"), "/bastion.tracker.v1.TrackerService/GetTrace", &models.TraceRequest{TraceID: "t-1"}, &out)
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("bad token: got %v, want Unauthenticated", status.Code(err))
	}

	// Streaming RPC also rejects missing token.
	streamDesc := &grpc.StreamDesc{ServerStreams: true}
	stream, err := conn.NewStream(context.Background(), streamDesc, "/bastion.tracker.v1.TrackerService/QueryEvents")
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SendMsg(&models.QueryRequest{Limit: 5})
	_ = stream.CloseSend()
	var ev models.BastionEvent
	err = stream.RecvMsg(&ev)
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("stream without token: got %v, want Unauthenticated", status.Code(err))
	}
}

func TestGRPCAuth_EnforcesRoleHierarchy(t *testing.T) {
	srv := newAuthTestServer(t, true)
	conn := dialPlaintext(t, serveOn(t, srv))

	viewerToken, err := auth.GenerateToken("bob", "viewer", testJWTSecret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	operatorToken, err := auth.GenerateToken("alice", "operator", testJWTSecret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Viewer can call read RPCs (GetTrace).
	var traceOut models.TraceResponse
	if err := conn.Invoke(ctxWithToken(viewerToken), "/bastion.tracker.v1.TrackerService/GetTrace", &models.TraceRequest{TraceID: "t-1"}, &traceOut); err != nil {
		t.Errorf("viewer GetTrace failed: %v", err)
	}

	// Viewer is rejected on write RPCs (SubmitEvent).
	var subOut models.SubmitResponse
	err = conn.Invoke(ctxWithToken(viewerToken), "/bastion.tracker.v1.TrackerService/SubmitEvent", &models.BastionEvent{
		EventID:   "ev-1",
		Module:    "sentinel",
		EventType: "input_validated",
		Severity:  "info",
		Status:    "ok",
	}, &subOut)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("viewer SubmitEvent: got %v, want PermissionDenied", status.Code(err))
	}

	// Operator succeeds on SubmitEvent.
	if err := conn.Invoke(ctxWithToken(operatorToken), "/bastion.tracker.v1.TrackerService/SubmitEvent", &models.BastionEvent{
		EventID:   "ev-2",
		Module:    "sentinel",
		EventType: "input_validated",
		Severity:  "info",
		Status:    "ok",
	}, &subOut); err != nil {
		t.Errorf("operator SubmitEvent failed: %v", err)
	}
	if !subOut.Accepted {
		t.Error("expected Accepted=true")
	}
}
