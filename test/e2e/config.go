package e2e_test

import (
	"os"
	"strings"
	"time"
)

const (
	defaultChartPath          = "../../charts/network-enforcer"
	defaultLogsDir            = "./logs"
	defaultControllerImage    = "ghcr.io/rancher-sandbox/network-enforcer/controller:latest"
	defaultCNIWatcherImage    = "ghcr.io/rancher-sandbox/network-enforcer/cniwatcher:latest"
	defaultReleaseName        = "network-enforcer"
	defaultReleaseNS          = "network-enforcer"
	defaultNamespacePref      = "network-enforcer-e2e"
	defaultCNI                = cilium
	defaultDrainFlowsInterval = 3 * time.Second // we reduce the time here to have faster feedback on the learning phase

	noCNIConfigPath = "./clusters/no-cni.yaml"
)

const (
	defaultHelmTimeout      = 3 * time.Minute
	defaultOperationTimeout = 2 * time.Minute
	defaultPodExecTimeout   = 45 * time.Second

	// Environment variables used in e2e tests.
	cniEnvVar = "E2E_CNI"
)

type suiteConfig struct {
	kindConfigPath     string
	logsDir            string
	chartPath          string
	releaseName        string
	releaseNS          string
	controllerImage    string
	cniWatcherImage    string
	namespacePrefix    string
	cni                cniType
	drainFlowsInterval time.Duration
}

func loadSuiteConfig() suiteConfig {
	return suiteConfig{
		logsDir:            defaultLogsDir,
		chartPath:          defaultChartPath,
		releaseName:        defaultReleaseName,
		releaseNS:          defaultReleaseNS,
		controllerImage:    defaultControllerImage,
		cniWatcherImage:    defaultCNIWatcherImage,
		namespacePrefix:    defaultNamespacePref,
		cni:                cniType(readEnvOrDefault(cniEnvVar, string(defaultCNI))),
		kindConfigPath:     noCNIConfigPath,
		drainFlowsInterval: defaultDrainFlowsInterval,
	}
}

func readEnvOrDefault(name, defaultValue string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return defaultValue
	}
	return value
}
