package grpc

import (
	"context"
	"net"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zafrem/bastion-tracker/internal/metrics"
)

func TestGRPCMetrics_CountRejectedCalls(t *testing.T) {
	srv := newAuthTestServer(t, true)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.grpcServer.Stop)

	method := "/bastion.tracker.v1.TrackerService/SubmitEvent"
	rejected := metrics.GRPCRequests.WithLabelValues(method, codes.Unauthenticated.String())
	before := testutil.ToFloat64(rejected)
	conn := dialPlaintext(t, lis.Addr().String())
	err = conn.Invoke(context.Background(), method, map[string]string{}, &map[string]any{}, grpc.ForceCodec(jsonCodec{}))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("call = %v, want Unauthenticated", err)
	}
	if got := testutil.ToFloat64(rejected) - before; got != 1 {
		t.Errorf("rejected calls counted = %v, want 1", got)
	}
}

func TestGRPCPanic_BecomesAnInternalError(t *testing.T) {
	panics := metrics.Panics.WithLabelValues("grpc")
	before := testutil.ToFloat64(panics)
	_, err := recoveryUnaryInterceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/s/M"},
		func(context.Context, any) (any, error) { panic("boom") })
	if status.Code(err) != codes.Internal {
		t.Errorf("error = %v, want Internal", err)
	}
	if got := testutil.ToFloat64(panics) - before; got != 1 {
		t.Errorf("panics counted = %v, want 1", got)
	}
}
