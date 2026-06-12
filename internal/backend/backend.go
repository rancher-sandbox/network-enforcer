package backend

import (
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "secuity.rancher.io/network-enforcer/api/v1alpha1"
)

type PolicyBackend interface {
	Name() string
	AddToScheme(s *runtime.Scheme) error
	Build(
		name, namespace string,
		podSelector map[string]string,
		proposal *securityv1alpha1.NetworkPolicyProposal,
	) client.Object
	// Empty returns a zero-value instance for client.Get.
	Empty() client.Object
}
