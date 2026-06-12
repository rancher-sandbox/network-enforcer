package kubernetes

import (
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "secuity.rancher.io/network-enforcer/api/v1alpha1"
)

type Backend struct{}

func (b *Backend) Name() string { return "kubernetes" }

func (b *Backend) AddToScheme(_ *runtime.Scheme) error { return nil }

func (b *Backend) Empty() client.Object {
	return &networkingv1.NetworkPolicy{}
}

func (b *Backend) Build(
	name, namespace string,
	podSelector map[string]string,
	proposal *securityv1alpha1.NetworkPolicyProposal,
) client.Object {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: proposal.Spec.PodSelector,
			PolicyTypes: proposal.Spec.PolicyTypes,
		},
	}

	if len(policy.Spec.PodSelector.MatchLabels) == 0 {
		policy.Spec.PodSelector = metav1.LabelSelector{MatchLabels: podSelector}
	}

	policy.Spec.Ingress = append(policy.Spec.Ingress, proposal.Spec.Ingress...)
	policy.Spec.Egress = append(policy.Spec.Egress, proposal.Spec.Egress...)

	return policy
}
