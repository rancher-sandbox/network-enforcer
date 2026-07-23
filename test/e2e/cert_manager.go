package e2e_test

import (
	"context"
	"fmt"

	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

const (
	jetstackRepoName      = "jetstack"
	jetstackRepoURL       = "https://charts.jetstack.io"
	certManagerNamespace  = "cert-manager"
	certManagerVersion    = "v1.18.2"
	certManagerCSIVersion = "v0.12.0"
)

// installCertManager installs cert-manager and its CSI driver from the jetstack
// Helm repo, both required by the network-enforcer chart's mTLS setup.
func installCertManager() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		manager := helm.New(cfg.KubeconfigFile())

		if err := addLocalChartRepo(ctx, manager, jetstackRepoName, jetstackRepoURL); err != nil {
			return ctx, err
		}

		// cert-manager (and its webhook) must be ready before the CSI driver,
		// which in turn must be ready before any pod mounts a CSI cert volume.
		if err := manager.RunInstall(
			helm.WithName("cert-manager"),
			helm.WithNamespace(certManagerNamespace),
			helm.WithChart(jetstackRepoName+"/cert-manager"),
			helm.WithArgs("--create-namespace"),
			helm.WithArgs("--version", certManagerVersion),
			helm.WithArgs("--set", "crds.enabled=true"),
			helm.WithWait(),
			helm.WithTimeout(defaultHelmTimeout.String()),
		); err != nil {
			return ctx, fmt.Errorf("install cert-manager: %w", err)
		}

		csiOpts := []helm.Option{
			helm.WithName("cert-manager-csi-driver"),
			helm.WithNamespace(certManagerNamespace),
			helm.WithChart(jetstackRepoName + "/cert-manager-csi-driver"),
			helm.WithArgs("--version", certManagerCSIVersion),
			helm.WithWait(),
			helm.WithTimeout(defaultHelmTimeout.String()),
		}
		// we need the CSI driver on each node so that also pods on the control-plane can mount CSI volumes
		csiOpts = append(csiOpts, generateKindControlPlaneTolerations("")...)

		if err := manager.RunInstall(csiOpts...); err != nil {
			return ctx, fmt.Errorf("install cert-manager-csi-driver: %w", err)
		}

		return ctx, nil
	}
}
