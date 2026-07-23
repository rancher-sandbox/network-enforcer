package e2e_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/conf"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/support/kind"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

var (
	testEnv env.Environment //nolint:gochecknoglobals // provided by e2e-framework
)

func TestMain(m *testing.M) {
	testSuiteConf := loadSuiteConfig()

	path := conf.ResolveKubeConfigFile()
	cfg := envconf.NewWithKubeConfig(path)
	testEnv = env.NewWithConfig(cfg)

	clusterName := envconf.RandomName(testSuiteConf.namespacePrefix, 20)

	setupFuncs := []env.Func{
		envfuncs.CreateClusterWithConfig(kind.NewProvider(), clusterName, testSuiteConf.kindConfigPath),
		envfuncs.LoadImageToCluster(clusterName, testSuiteConf.controllerImage),
		envfuncs.LoadImageToCluster(clusterName, testSuiteConf.cniWatcherImage),
		// we inject the suite config in the context so that each test can access parameters like the release name, namespace, image, etc.
		injectSuiteConfig(testSuiteConf),
		injectSetupLogger(),
		injectClient(),
		installCNI(testSuiteConf.cni),
		installCertManager(),
		installNetEnforcerChart(&testSuiteConf),
	}

	finishFuncs := []env.Func{
		envfuncs.ExportClusterLogs(clusterName, testSuiteConf.logsDir),
		envfuncs.DestroyCluster(clusterName),
	}

	testEnv.Setup(setupFuncs...)
	testEnv.Finish(finishFuncs...)
	os.Exit(testEnv.Run(m))
}

func installNetEnforcerChart(testCfg *suiteConfig) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
		manager := helm.New(cfg.KubeconfigFile())

		controllerRepo, controllerTag := parseImage(testCfg.controllerImage)
		cniWatcherRepo, cniWatcherTag := parseImage(testCfg.cniWatcherImage)

		helmOpts := []helm.Option{
			helm.WithName(testCfg.releaseName),
			helm.WithNamespace(testCfg.releaseNS),
			helm.WithChart(testCfg.chartPath),
			helm.WithArgs("--create-namespace"),
			helm.WithArgs("--set", fmt.Sprintf("controller.image.repository=%s", controllerRepo)),
			helm.WithArgs("--set", fmt.Sprintf("controller.image.tag=%s", controllerTag)),
			helm.WithArgs("--set", fmt.Sprintf("cniwatcher.image.repository=%s", cniWatcherRepo)),
			helm.WithArgs("--set", fmt.Sprintf("cniwatcher.image.tag=%s", cniWatcherTag)),
			helm.WithArgs("--set", fmt.Sprintf("cniwatcher.cniType=%s", testCfg.cni)),
			helm.WithArgs("--set", fmt.Sprintf("obi.config.data.otel_metrics_export.interval=%s",
				testCfg.drainFlowsInterval.String())),
			helm.WithArgs("--set", fmt.Sprintf("controller.drainFlowsInterval=%s",
				testCfg.drainFlowsInterval.String())),

			helm.WithWait(),
			helm.WithTimeout(defaultHelmTimeout.String()),
		}

		// we want to install these agents on all the nodes (control-plane included)
		helmOpts = append(helmOpts, generateKindControlPlaneTolerations("cniwatcher.")...)
		helmOpts = append(helmOpts, generateKindControlPlaneTolerations("obi.")...)

		logger.InfoContext(ctx, "installing network enforcer chart", "releaseName", testCfg.releaseName)
		if err := manager.RunInstall(helmOpts...); err != nil {
			return ctx, fmt.Errorf("install network enforcer chart: %w", err)
		}

		r, err := resources.New(cfg.Client().RESTConfig())
		if err != nil {
			return ctx, fmt.Errorf("create resources client: %w", err)
		}

		logger.InfoContext(ctx, "waiting for network enforcer controller")
		if err = wait.For(
			conditions.New(r).DeploymentAvailable("network-enforcer-controller-manager", testCfg.releaseNS),
			wait.WithTimeout(defaultOperationTimeout),
		); err != nil {
			return ctx, fmt.Errorf("wait network enforcer deployment ready: %w", err)
		}

		logger.InfoContext(ctx, "waiting for cniwatcher")
		if err = wait.For(
			conditions.New(r).DaemonSetReady(
				&appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "network-enforcer-cniwatcher",
						Namespace: testCfg.releaseNS,
					},
				}),
			wait.WithTimeout(defaultOperationTimeout),
		); err != nil {
			return ctx, fmt.Errorf("wait network enforcer daemonset ready: %w", err)
		}

		return ctx, nil
	}
}

func parseImage(image string) (string, string) {
	if i := strings.LastIndex(image, ":"); i > 0 && i > strings.LastIndex(image, "/") {
		return image[:i], image[i+1:]
	}
	return image, "latest"
}
