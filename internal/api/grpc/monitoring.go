package grpc

import (
	"context"
	"log"
	"runtime/debug"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zafrem/bastion-tracker/internal/metrics"
)

// These interceptors run outermost, so rejected and panicking calls are counted too. Method names are bounded:
// calls to unregistered methods never reach an interceptor.

func metricsUnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	start := time.Now()
	resp, err := handler(ctx, req)
	metrics.GRPCRequests.WithLabelValues(info.FullMethod, status.Code(err).String()).Inc()
	metrics.GRPCDuration.WithLabelValues(info.FullMethod).Observe(time.Since(start).Seconds())
	return resp, err
}

// Streams are counted but not timed: their duration is how long the client stayed connected.
func metricsStreamInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	err := handler(srv, ss)
	metrics.GRPCRequests.WithLabelValues(info.FullMethod, status.Code(err).String()).Inc()
	return err
}

func recoveryUnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	defer recovered(info.FullMethod, &err)
	return handler(ctx, req)
}

func recoveryStreamInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
	defer recovered(info.FullMethod, &err)
	return handler(srv, ss)
}

// recovered turns a panic into an Internal error; without it one bad call would end the process.
func recovered(method string, err *error) {
	if r := recover(); r != nil {
		metrics.Panics.WithLabelValues("grpc").Inc()
		log.Printf("[grpc] panic in %q: %v\n%s", method, r, debug.Stack()) // #nosec G706 -- registered method name, panic value and stack
		*err = status.Error(codes.Internal, "internal error")
	}
}
