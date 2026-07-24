package e2e_test

import (
	"context"
	"fmt"

	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

type cniType string

const (
	calico cniType = "calico"
	cilium cniType = "cilium"
)

func installCNI() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		cni := getSuiteConfig(ctx).cni
		switch cni {
		case calico:
			return installCalico(ctx, cfg)
		case cilium:
			return installCilium(ctx, cfg)
		default:
			return ctx, fmt.Errorf("unknown CNI type: %s", cni)
		}
	}
}

func getCNIVersion(ctx context.Context, defaultVersion string) string {
	cniVersion := getSuiteConfig(ctx).cniVersion
	if cniVersion != "" {
		return cniVersion
	}
	return defaultVersion
}
