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

func installCNI(t cniType) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		switch t {
		case calico:
			return installCalico(ctx, cfg)
		case cilium:
			return installCilium(ctx, cfg)
		default:
			return ctx, fmt.Errorf("unknown CNI type: %s", t)
		}
	}
}
