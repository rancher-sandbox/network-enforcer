package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rancher-sandbox/network-enforcer/internal/cniwatcher"
	"github.com/rancher-sandbox/network-enforcer/internal/otel"
	"github.com/rancher-sandbox/network-enforcer/internal/violationbuf"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

const otelShutdownTimeout = 10 * time.Second

func grpcConfigFromFlags() cniwatcher.GRPCServerConfig {
	port := flag.Int("grpc-port", cniwatcher.DefaultGRPCPort,
		"Port for the gRPC ScrapeViolations server.")
	certDir := flag.String("grpc-mtls-cert-dir", "",
		"Directory containing tls.crt, tls.key, and ca.crt for mTLS. "+
			"When empty, the gRPC server runs in insecure mode (no TLS).")
	flag.Parse()

	return cniwatcher.GRPCServerConfig{
		Port:    *port,
		CertDir: *certDir,
	}
}

func newOtelService(ctx context.Context, logger *slog.Logger, grpcConfig cniwatcher.GRPCServerConfig) *otel.Service {
	otlpEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if otlpEndpoint == "" {
		logger.Info("OTLP endpoint not set, OpenTelemetry disabled")
		return nil
	}
	otelCfg := otel.OpenTelemetryConfig{
		Ctx:               ctx,
		Log:               logger,
		CollectorEndpoint: otlpEndpoint,
		CertDir: grpcConfig.CertDir,
	}
	svc := otel.NewOpenTelemetryService(otelCfg)
	if err := svc.Start(); err != nil {
		logger.Warn("Failed to start OpenTelemetry", "err", err)
		return nil
	}
	return svc
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	grpcConfig := grpcConfigFromFlags()

	ctx, cancel := context.WithCancel(context.Background())

	otelService := newOtelService(ctx, logger, grpcConfig)

	ctrlClient, err := client.New(config.GetConfigOrDie(), client.Options{})
	if err != nil {
		logger.Error("unable to create k8s client", "err", err)
		os.Exit(1)
	}

	cniwatcherCfg, err := cniwatcher.NewConfig(os.Getenv("NODE_NAME"), os.Getenv("CNIWATCHER_CNI_TYPE"))
	if err != nil {
		logger.Error("failed to create cniWatcher config", "err", err)
		os.Exit(1)
	}

	// Create the violation ring buffer shared between the watcher and the gRPC server.
	violationBuffer := violationbuf.NewBuffer()

	watcher := cniwatcher.Watcher{
		Ctx:             ctx,
		Client:          ctrlClient,
		Log:             logger,
		NodeName:        cniwatcherCfg.NodeName,
		OtelService:     otelService,
		ViolationBuffer: violationBuffer,
	}

	cniWatcher, err := cniwatcher.NewCNIWatcher(cniwatcherCfg, watcher)
	if err != nil {
		logger.Error("Failed to create cniWatcher", "err", err)
		os.Exit(1)
	}

	shutdownCh := make(chan struct{})

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		logger.Info("Received shutdown signal")
		cancel()
		close(shutdownCh)
	}()

	// Start the gRPC ScrapeViolations server in a goroutine.
	grpcErrCh := make(chan error, 1)
	go func() {
		grpcErrCh <- cniwatcher.StartGRPCServer(ctx, logger, violationBuffer, grpcConfig)
	}()

	// Start the CNI watcher in a goroutine.
	watcherErrCh := make(chan error, 1)
	go func() {
		watcherErrCh <- cniWatcher.Start()
	}()

	// Wait for shutdown signal or an error from either the CNI watcher or gRPC server.
	select {
	case startErr := <-watcherErrCh:
		if startErr != nil {
			logger.Error("Failed to start cniWatcher", "err", startErr)
			os.Exit(1)
		}
	case grpcStartErr := <-grpcErrCh:
		if grpcStartErr != nil {
			logger.Error("Failed to start gRPC server", "err", grpcStartErr)
			os.Exit(1)
		}
	case <-shutdownCh:
		performCleanupAndShutdown(logger, otelService, cniWatcher)
	}

	cancel()
	logger.Info("cniWatcher exited")
}

func performCleanupAndShutdown(logger *slog.Logger, otelService *otel.Service, cniWatcher cniwatcher.CNIWatcher) {
	if otelService != nil {
		ctxOtelShutdown, otelCancel := context.WithTimeout(context.Background(), otelShutdownTimeout)
		defer otelCancel()

		logger.Info("Shutting down OpenTelemetry")
		if shutdownErr := otelService.Shutdown(ctxOtelShutdown); shutdownErr != nil {
			logger.Error("Failed to shutdown OpenTelemetry", "err", shutdownErr)
		}
	}

	logger.Info("Shutting down cniWatcher")
	if shutdownErr := cniWatcher.Shutdown(); shutdownErr != nil {
		logger.Error("Failed to shutdown cniWatcher", "err", shutdownErr)
	}

	// Note: the gRPC server shuts down automatically when ctx is cancelled
	// via the StartGRPCServer function's graceful shutdown logic.
	logger.Info("Shutdown complete")
}
