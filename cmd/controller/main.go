/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	otellog "go.opentelemetry.io/otel/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/go-logr/logr"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/controller"
	"github.com/rancher-sandbox/network-enforcer/internal/events"
	"github.com/rancher-sandbox/network-enforcer/internal/grpcexporter"
	"github.com/rancher-sandbox/network-enforcer/internal/receiver"
	"github.com/rancher-sandbox/network-enforcer/internal/topology"
	// +kubebuilder:scaffold:imports
)

const (
	defaultDrainFlowsInterval = 30 * time.Second
	defaultStatusSyncInterval = 30 * time.Second
	// otlpLogShutdownTimeout bounds the final flush of buffered log records
	// when the manager stops. The manager context is already cancelled at
	// that point, so the shutdown runs against a fresh context.
	otlpLogShutdownTimeout = 10 * time.Second
)

type config struct {
	metricsAddr             string
	metricsCertPath         string
	metricsCertName         string
	metricsCertKey          string
	enableLeaderElection    bool
	probeAddr               string
	secureMetrics           bool
	enableHTTP2             bool
	otlpPort                int
	otlpLogEndpoint         string
	otlpLogProtocol         string
	otlpLogCACert           string
	otlpLogClientCert       string
	otlpLogClientKey        string
	drainFlowsInterval      time.Duration
	statusSyncInterval      time.Duration
	cniwatcherLabelSelector string
	cniwatcherGRPCPort      int
	cniwatcherNamespace     string
	tlsCertDir              string
	tlsOpts                 []func(*tls.Config)
}

func newControllerManager(conf *config) (manager.Manager, error) {
	// Mitigate HTTP/2 Stream Cancellation / Rapid Reset CVEs.
	disableHTTP2 := func(c *tls.Config) {
		c.NextProtos = []string{"http/1.1"}
	}

	if !conf.enableHTTP2 {
		conf.tlsOpts = append(conf.tlsOpts, disableHTTP2)
	}

	metricsServerOptions := metricsserver.Options{
		BindAddress:   conf.metricsAddr,
		SecureServing: conf.secureMetrics,
		TLSOpts:       conf.tlsOpts,
	}

	if conf.secureMetrics {
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	if len(conf.metricsCertPath) > 0 {
		metricsServerOptions.CertDir = conf.metricsCertPath
		metricsServerOptions.CertName = conf.metricsCertName
		metricsServerOptions.KeyName = conf.metricsCertKey
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
	controllerOptions := ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		HealthProbeBindAddress: conf.probeAddr,
		LeaderElection:         conf.enableLeaderElection,
		LeaderElectionID:       "6163c1ee.security.rancher.io",
	}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), controllerOptions)
	if err != nil {
		return nil, fmt.Errorf("unable to start manager: %w", err)
	}
	return mgr, nil
}

// setupOtelLogExporter initialises the OTLP log exporter and registers
// its shutdown runnable. Caller must ensure conf.otlpLogEndpoint is set.
func setupOtelLogExporter(
	ctx context.Context,
	logger *slog.Logger,
	mgr manager.Manager,
	conf *config,
) (otellog.Logger, error) {
	eventLogger, eventShutdown, err := events.Init(
		ctx,
		conf.otlpLogEndpoint,
		conf.otlpLogCACert,
		conf.otlpLogClientCert,
		conf.otlpLogClientKey,
		conf.otlpLogProtocol,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OTLP log exporter: %w", err)
	}
	logger.InfoContext(ctx, "OTLP violation telemetry enabled",
		"endpoint", conf.otlpLogEndpoint,
		"protocol", conf.otlpLogProtocol)

	err = mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		<-ctx.Done()
		if eventShutdown != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), otlpLogShutdownTimeout)
			defer cancel()
			if sErr := eventShutdown(shutdownCtx); sErr != nil {
				logger.Error("failed to shutdown OTLP log provider", "error", sErr)
			}
		}
		return nil
	}))
	if err != nil {
		return nil, fmt.Errorf("unable to register OTLP log shutdown runnable: %w", err)
	}
	return eventLogger, nil
}

func run(ctx context.Context, logger *slog.Logger, conf *config) error {
	mgr, err := newControllerManager(conf)
	if err != nil {
		return fmt.Errorf("unable to create controller manager: %w", err)
	}

	var eventLogger otellog.Logger
	if conf.otlpLogEndpoint != "" {
		eventLogger, err = setupOtelLogExporter(ctx, logger, mgr, conf)
		if err != nil {
			return err
		}
	}

	store := topology.NewStore()

	// The OTLP receiver reuses the same pod cert dir as the ScrapeViolations client.
	receiver := receiver.NewReceiver(store, conf.otlpPort, conf.tlsCertDir, logger)
	err = mgr.Add(receiver)
	if err != nil {
		return fmt.Errorf("unable to add OTLP receiver to manager: %w", err)
	}

	scanner := controller.NewTopologyScanner(mgr.GetClient(), store, logger, conf.drainFlowsInterval)
	err = mgr.Add(scanner)
	if err != nil {
		return fmt.Errorf("unable to add topology scanner to manager: %w", err)
	}

	if err = (&controller.WorkloadNetworkPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to setup WorkloadNetworkPolicyReconciler controller: %w", err)
	}

	if err = (&controller.WorkloadNetworkPolicyProposalReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to setup WorkloadNetworkPolicyProposal controller: %w", err)
	}

	statusSync, err := controller.NewWorkloadNetworkPolicyStatusSync(
		mgr.GetClient(),
		&controller.WorkloadNetworkPolicyStatusSyncConfig{
			AgentPoolConf: grpcexporter.AgentClientPoolConfig{
				AgentFactoryConfig: grpcexporter.AgentFactoryConfig{
					CertDirPath: conf.tlsCertDir,
					Port:        conf.cniwatcherGRPCPort,
				},
				Namespace:           conf.cniwatcherNamespace,
				LabelSelectorString: conf.cniwatcherLabelSelector,
				Logger:              logger,
			},
			UpdateInterval: conf.statusSyncInterval,
			EventLogger:    eventLogger,
		},
	)
	if err != nil {
		return fmt.Errorf("unable to create WorkloadNetworkPolicyStatusSync: %w", err)
	}
	if err = mgr.Add(statusSync); err != nil {
		return fmt.Errorf("unable to add WorkloadNetworkPolicyStatusSync runnable: %w", err)
	}

	// +kubebuilder:scaffold:builder

	if err = mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to add healthz check: %w", err)
	}
	if err = mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to add readyz check: %w", err)
	}

	logger.InfoContext(ctx, "starting manager")
	return mgr.Start(ctx)
}

func main() {
	conf := &config{}
	flag.StringVar(&conf.metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&conf.probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&conf.enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&conf.secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&conf.metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(
		&conf.metricsCertName,
		"metrics-cert-name",
		"tls.crt",
		"The name of the metrics server certificate file.",
	)
	flag.StringVar(&conf.metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&conf.enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics server")
	flag.IntVar(&conf.otlpPort, "otlp-port", 4317, "The port the OTLP gRPC receiver listens on.")
	flag.StringVar(&conf.otlpLogEndpoint, "otlp-log-endpoint",
		os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		"OTLP endpoint for the violation-lifecycle log exporter "+
			"(policy_violation_acknowledged records). Defaults to the "+
			"OTEL_EXPORTER_OTLP_ENDPOINT env var; empty disables OTLP logs.")
	flag.StringVar(&conf.otlpLogProtocol, "otlp-log-protocol",
		os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL"),
		"OTLP protocol for the violation-lifecycle log exporter: grpc or "+
			"http/protobuf. Defaults to the OTEL_EXPORTER_OTLP_PROTOCOL env var.")
	flag.StringVar(&conf.otlpLogCACert, "otlp-log-ca-cert",
		os.Getenv("OTEL_EXPORTER_OTLP_CERTIFICATE"),
		"Path to the CA certificate for verifying the OTLP log collector's "+
			"TLS certificate. Defaults to the OTEL_EXPORTER_OTLP_CERTIFICATE env "+
			"var; empty means insecure.")
	flag.StringVar(&conf.otlpLogClientCert, "otlp-log-client-cert",
		os.Getenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE"),
		"Path to the client TLS certificate for mTLS with the OTLP log "+
			"collector. Defaults to the OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE env var.")
	flag.StringVar(&conf.otlpLogClientKey, "otlp-log-client-key",
		os.Getenv("OTEL_EXPORTER_OTLP_CLIENT_KEY"),
		"Path to the client TLS key for mTLS with the OTLP log collector. "+
			"Defaults to the OTEL_EXPORTER_OTLP_CLIENT_KEY env var.")
	flag.DurationVar(&conf.drainFlowsInterval, "drain-flows-interval",
		defaultDrainFlowsInterval, "The interval at which flows are drained.")
	flag.DurationVar(&conf.statusSyncInterval, "status-sync-interval",
		defaultStatusSyncInterval, "The interval at which WorkloadNetworkPolicy status is synced with cniwatcher pods.")
	flag.StringVar(&conf.cniwatcherLabelSelector, "cniwatcher-label-selector",
		grpcexporter.DefaultCniwatcherLabelSelectorString, "Label selector to discover cniwatcher pods.")
	flag.IntVar(&conf.cniwatcherGRPCPort, "cniwatcher-grpc-port",
		grpcexporter.DefaultAgentPort, "gRPC port of cniwatcher ScrapeViolations server.")
	flag.StringVar(&conf.cniwatcherNamespace, "cniwatcher-namespace", "",
		"Namespace where cniwatcher pods run (default: read from service account).")
	flag.StringVar(&conf.tlsCertDir, "cniwatcher-tls-cert-dir", grpcexporter.DefaultCertDirPath,
		"Directory containing tls.crt, tls.key, and ca.crt for mTLS with cniwatcher pods "+
			"and the OTLP receiver. When empty, connections are insecure.")
	flag.Parse()

	slogHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	slogger := slog.New(slogHandler).With("component", "agent")
	slog.SetDefault(slogger)
	ctrl.SetLogger(logr.FromSlogHandler(slogger.Handler()))

	ctx := ctrl.SetupSignalHandler()

	if err := run(ctx, slogger, conf); err != nil {
		slogger.Error("failed to run", "error", err)
		os.Exit(1)
	}
}
