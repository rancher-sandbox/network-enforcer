package cniwatcher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/rancher-sandbox/network-enforcer/internal/tlsutil"
	"github.com/rancher-sandbox/network-enforcer/internal/violationbuf"
	agentv1 "github.com/rancher-sandbox/network-enforcer/proto/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	DefaultGRPCPort     = 50051
	gracefulGRPCTimeout = 5 * time.Second
)

type GRPCServerConfig struct {
	// Port to listen on. Defaults to DefaultGRPCPort when 0.
	Port int

	// CertDir is the directory containing tls.crt, tls.key, and ca.crt. When
	// set, the server runs with mutual TLS; when empty it runs in plaintext
	// (insecure) mode, suitable for dev/kind testing.
	CertDir string
}

type GRPCServer struct {
	agentv1.UnimplementedNetworkAgentServer

	logger          *slog.Logger
	violationBuffer *violationbuf.Buffer
}

func NewGRPCServer(logger *slog.Logger, buffer *violationbuf.Buffer) *GRPCServer {
	return &GRPCServer{
		logger:          logger.With("component", "grpc_scrape"),
		violationBuffer: buffer,
	}
}

// ScrapeViolations drains the violation buffer and returns all accumulated
// records since the last scrape in reverse chronological order (newest first).
// Returns an empty response (not an error) when the buffer is empty.
func (s *GRPCServer) ScrapeViolations(
	ctx context.Context,
	_ *agentv1.ScrapeViolationsRequest,
) (*agentv1.ScrapeViolationsResponse, error) {
	if s.violationBuffer == nil {
		s.logger.WarnContext(ctx, "Violation buffer is nil, returning empty response")
		return &agentv1.ScrapeViolationsResponse{}, nil
	}

	records := s.violationBuffer.Drain()

	out := &agentv1.ScrapeViolationsResponse{
		Violations: make([]*agentv1.ViolationRecord, 0, len(records)),
	}

	for _, rec := range records {
		out.Violations = append(out.Violations, &agentv1.ViolationRecord{
			Timestamp:              timestamppb.New(rec.Timestamp),
			NodeName:               rec.NodeName,
			Direction:              rec.Direction,
			SourceNamespace:        rec.SrcNamespace,
			SourceName:             rec.SrcName,
			SourceWorkloads:        rec.SrcWorkloads,
			SourceLabels:           rec.SrcLabels,
			DestNamespace:          rec.DstNamespace,
			DestName:               rec.DstName,
			DestWorkloads:          rec.DstWorkloads,
			DestLabels:             rec.DstLabels,
			Protocol:               string(rec.Protocol),
			DstPort:                rec.DstPort,
			Action:                 string(rec.Action),
			DenyingPolicyNamespace: rec.DenyingPolicyNamespace,
			DenyingPolicyName:      rec.DenyingPolicyName,
		})
	}

	s.logger.DebugContext(ctx, "Scraped violations", "count", len(out.GetViolations()))
	return out, nil
}

// StartGRPCServer starts the gRPC server and blocks until ctx is cancelled.
// It performs graceful shutdown when the context is cancelled.
func StartGRPCServer(
	ctx context.Context,
	logger *slog.Logger,
	buffer *violationbuf.Buffer,
	config GRPCServerConfig,
) error {
	if logger == nil {
		return errors.New("logger must not be nil")
	}
	if buffer == nil {
		return errors.New("violation buffer must not be nil")
	}

	// Load mTLS credentials before binding the listener so we fail fast on
	// invalid certs rather than after a potentially successful bind.
	var grpcOpts []grpc.ServerOption
	if config.CertDir != "" {
		tlsCreds, credsErr := tlsutil.ServerCredentials(config.CertDir)
		if credsErr != nil {
			return fmt.Errorf("failed to create mTLS credentials: %w", credsErr)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(tlsCreds))
		logger.InfoContext(ctx, "mTLS enabled for gRPC server", "cert_dir", config.CertDir)
	} else {
		logger.InfoContext(ctx, "gRPC server running in insecure mode (no mTLS)")
	}

	port := config.Port
	if port == 0 {
		port = DefaultGRPCPort
	}

	addr := fmt.Sprintf(":%d", port)

	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	grpcSrv := grpc.NewServer(grpcOpts...)
	agentv1.RegisterNetworkAgentServer(grpcSrv, NewGRPCServer(logger, buffer))

	logger.InfoContext(ctx, "Starting gRPC ScrapeViolations server", "addr", addr)

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- grpcSrv.Serve(listener)
	}()

	select {
	case err = <-serveErrCh:
		if err != nil {
			return fmt.Errorf("gRPC server.Serve error: %w", err)
		}
		return nil

	case <-ctx.Done():
		logger.InfoContext(ctx, "Shutting down gRPC server gracefully")
		done := make(chan struct{})
		go func() {
			grpcSrv.GracefulStop()
			close(done)
		}()

		select {
		case <-done:
			// graceful stop completed
		case <-time.After(gracefulGRPCTimeout):
			logger.WarnContext(ctx, "GracefulStop timed out; forcing Stop()", "timeout", gracefulGRPCTimeout.String())
			grpcSrv.Stop()
		}

		// wait for Serve to return (usually immediate after Stop/GracefulStop)
		err = <-serveErrCh
		if err != nil {
			return fmt.Errorf("gRPC server.Serve error after shutdown: %w", err)
		}
		return nil
	}
}
