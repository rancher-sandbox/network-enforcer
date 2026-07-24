package e2e_test

import (
	"os"
	"strings"
	"time"
)

const (
	defaultChartPath               = "../../charts/network-enforcer"
	defaultLogsDir                 = "./logs"
	defaultControllerImage         = "ghcr.io/rancher-sandbox/network-enforcer/controller:latest"
	defaultCNIWatcherImage         = "ghcr.io/rancher-sandbox/network-enforcer/cniwatcher:latest"
	defaultReleaseName             = "network-enforcer"
	defaultReleaseNS               = "network-enforcer"
	defaultNamespacePref           = "network-enforcer-e2e"
	defaultCNI                     = cilium
	defaultDrainFlowsInterval      = 3 * time.Second // we reduce the time here to have faster feedback on the learning phase
	defaultWnpStatusUpdateInterval = 3 * time.Second // we reduce the time here to have faster feedback from the controller

	noCNIConfigPath = "./clusters/no-cni.yaml"
)

const (
	defaultHelmTimeout      = 3 * time.Minute
	defaultOperationTimeout = 2 * time.Minute
	defaultPodExecTimeout   = 45 * time.Second

	// Environment variables used in e2e tests.
	cniEnvVar        = "E2E_CNI"
	cniVersionEnvVar = "E2E_CNI_VERSION"
)

type suiteConfig struct {
	kindConfigPath          string
	logsDir                 string
	chartPath               string
	releaseName             string
	releaseNS               string
	controllerImage         string
	cniWatcherImage         string
	namespacePrefix         string
	cni                     cniType
	cniVersion              string
	drainFlowsInterval      time.Duration
	wnpStatusUpdateInterval time.Duration
}

func loadSuiteConfig() suiteConfig {
	return suiteConfig{
		logsDir:         defaultLogsDir,
		chartPath:       defaultChartPath,
		releaseName:     defaultReleaseName,
		releaseNS:       defaultReleaseNS,
		controllerImage: defaultControllerImage,
		cniWatcherImage: defaultCNIWatcherImage,
		namespacePrefix: defaultNamespacePref,
		cni:             cniType(readEnvOrDefault(cniEnvVar, string(defaultCNI))),
		// we don't have a default value here, it will be set by CNI specific code.
		cniVersion:              readEnvOrDefault(cniVersionEnvVar, ""),
		kindConfigPath:          noCNIConfigPath,
		drainFlowsInterval:      defaultDrainFlowsInterval,
		wnpStatusUpdateInterval: defaultWnpStatusUpdateInterval,
	}
}

func readEnvOrDefault(name, defaultValue string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return defaultValue
	}
	return value
}
