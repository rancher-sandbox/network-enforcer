package e2e_test

import (
	"context"
	"fmt"

	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

type cniType string

const (
	kindnet cniType = "kindnet"
	calico  cniType = "calico"
	cilium  cniType = "cilium"
)

func installCilium(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
	manager := helm.New(cfg.KubeconfigFile())

	// Add Cilium Helm repository.
	if err := manager.RunRepo(
		helm.WithArgs("add", "cilium", "https://helm.cilium.io/"),
	); err != nil {
		return ctx, fmt.Errorf("add cilium helm repo: %w", err)
	}

	// Install Cilium with settings appropriate for Kind clusters.
	// kubeProxyReplacement=true lets Cilium replace kube-proxy (functional and
	// well-tested on Kind).
	// autoDirectNodeRoutes=true enables direct pod-to-pod routing across nodes.
	if err := manager.RunInstall(
		helm.WithName("cilium"),
		helm.WithNamespace("kube-system"),
		helm.WithChart("cilium/cilium"),
		helm.WithArgs("--set", "kubeProxyReplacement=true"),
		helm.WithArgs("--set", "hostServices.enabled=false"),
		helm.WithArgs("--set", "ipam.mode=kubernetes"),
		helm.WithArgs("--set", "autoDirectNodeRoutes=true"),
		helm.WithWait(),
		helm.WithTimeout("5m"),
	); err != nil {
		return ctx, fmt.Errorf("install cilium: %w", err)
	}

	return ctx, nil
}

func installCalico(ctx context.Context, _ *envconf.Config) (context.Context, error) {
	// todo!: Install calico CNI
	return ctx, nil
}

func installCNI(t cniType) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		switch t {
		case kindnet:
			// kindnet is already installed by kind, nothing to do
			return ctx, nil
		case calico:
			return installCalico(ctx, cfg)
		case cilium:
			return installCilium(ctx, cfg)
		default:
			return ctx, fmt.Errorf("unknown CNI type: %s", t)
		}
	}
}
