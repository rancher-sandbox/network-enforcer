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
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

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
	"github.com/rancher-sandbox/network-enforcer/internal/grpcexporter"
	"github.com/rancher-sandbox/network-enforcer/internal/receiver"
	"github.com/rancher-sandbox/network-enforcer/internal/topology"
	// +kubebuilder:scaffold:imports
)

const (
	defaultDrainFlowsInterval      = 30 * time.Second
	defaultWnpStatusUpdateInterval = 30 * time.Second
)

type config struct {
	metricsAddr          string
	metricsCertPath      string
	metricsCertName      string
	metricsCertKey       string
	enableLeaderElection bool
	probeAddr            string
	secureMetrics        bool
	enableHTTP2          bool
	otlpPort             int
	drainFlowsInterval   time.Duration
	tlsOpts              []func(*tls.Config)
	wnpStatusSyncConfig  controller.WorkloadNetworkPolicyStatusSyncConfig
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

func run(logger *slog.Logger, conf *config) error {
	mgr, err := newControllerManager(conf)
	if err != nil {
		return fmt.Errorf("unable to create controller manager: %w", err)
	}

	store := topology.NewStore()

	// The OTLP receiver reuses the same pod cert dir as the ScrapeViolations client.
	receiver := receiver.NewReceiver(store, conf.otlpPort, conf.wnpStatusSyncConfig.AgentPoolConf.CertDirPath, logger)
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

	conf.wnpStatusSyncConfig.AgentPoolConf.Logger = logger.With("component", "agent-pool")
	logger.Info("Setting up WorkloadNetworkPolicyStatusSync with",
		"config", conf.wnpStatusSyncConfig)
	var wnpStatusSync *controller.WorkloadNetworkPolicyStatusSync
	if wnpStatusSync, err = controller.NewWorkloadNetworkPolicyStatusSync(
		mgr.GetClient(),
		&conf.wnpStatusSyncConfig,
	); err != nil {
		return fmt.Errorf("unable to create WorkloadNetworkPolicyStatusSync: %w", err)
	}
	if err = mgr.Add(wnpStatusSync); err != nil {
		return fmt.Errorf("unable to add WorkloadNetworkPolicyStatusSync runnable: %w", err)
	}

	// +kubebuilder:scaffold:builder

	if err = mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to add healthz check: %w", err)
	}
	if err = mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to add readyz check: %w", err)
	}

	logger.Info("starting manager")
	return mgr.Start(ctrl.SetupSignalHandler())
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
	flag.DurationVar(&conf.drainFlowsInterval, "drain-flows-interval",
		defaultDrainFlowsInterval, "The interval at which flows are drained.")
	flag.DurationVar(&conf.wnpStatusSyncConfig.UpdateInterval,
		"wnp-status-reconciler-update-interval",
		defaultWnpStatusUpdateInterval,
		"The interval at which WorkloadNetworkPolicy status is synced with cniwatcher pods.")
	flag.StringVar(
		&conf.wnpStatusSyncConfig.AgentPoolConf.LabelSelectorString,
		"wnp-status-reconciler-cniwatcher-label-selector",
		grpcexporter.DefaultCniwatcherLabelSelectorString,
		"Label selector to discover cniwatcher pods.",
	)
	flag.IntVar(&conf.wnpStatusSyncConfig.AgentPoolConf.Port, "wnp-status-reconciler-cniwatcher-grpc-port",
		grpcexporter.DefaultAgentPort, "gRPC port of cniwatcher ScrapeViolations server.")
	flag.StringVar(
		&conf.wnpStatusSyncConfig.AgentPoolConf.CertDirPath,
		"wnp-status-reconciler-cniwatcher-grpc-mtls-cert-dir",
		grpcexporter.DefaultCertDirPath,
		"Directory containing tls.crt, tls.key, and ca.crt for mTLS with cniwatcher pods "+
			"and the OTLP receiver. When empty, connections are insecure.",
	)
	flag.Parse()

	slogHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	slogger := slog.New(slogHandler).With("component", "agent")
	slog.SetDefault(slogger)
	ctrl.SetLogger(logr.FromSlogHandler(slogger.Handler()))

	if err := run(slogger, conf); err != nil {
		slogger.Error("failed to run", "error", err)
		os.Exit(1)
	}
}
