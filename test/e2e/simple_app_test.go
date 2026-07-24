package e2e_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// todo!: Add other cases
// - service different nodes.
// - deployment communication without service same nodes.
// - deployment communication without service different nodes.
// - external traffic
// - internal traffic through NodePort service.
func TestCompleteFlow(t *testing.T) {
	feature := features.New("Service same node").
		Setup(setupTestNamespace).
		Setup(setupSimpleAppWorkload).
		// we send traffic to the TCP service and we expect it to succeed, this will generate proposals for the client and server deployments.
		Assess("Send traffic to TCP service",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				return assertPacketSentFromClient(ctx, t, corev1.ProtocolTCP)
			}).
		Assess("Check if proposals are generated", assessPolicyProposalsGenerated).
		Assess("Promote proposals into monitor policies", assessPolicyProposalsPromoted).
		Assess("Send traffic to UDP service in monitor mode",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				return assertPacketSentFromClient(ctx, t, corev1.ProtocolUDP)
			}).
		Assess("Check proposals are not regenerated in monitor mode", assessProposalsAreNotRegenerated).
		Assess("Check policies are not updated in monitor mode", assessPoliciesAreNotUpdatedInMonitorMode).
		Assess("Check NetworkPolicies are created in protect mode", assessK8sNetworkPoliciesAreCreated).
		Assess("Send traffic to UDP service in protect mode",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				// we need to try multiple times because it may take some time for the policy to be enforced by the CNI.
				require.Eventually(t, func() bool {
					_, cmd := getProtoCmd(corev1.ProtocolUDP)
					stdout, _ := execInSimpleClientDeployment(ctx, t, cmd)
					// if the policy is enforced the stdout should be empty, because the traffic is blocked.
					if len(stdout) > 0 {
						t.Logf("Policy not yet enforced")
						return false
					}
					return true
				}, defaultOperationTimeout, 1*time.Second, "UDP traffic is not blocked in protect mode")
				return ctx
			}).
		Assess("Check violations are reported", checkViolations).
		Assess("Check TCP traffic is still allowed",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				return assertPacketSentFromClient(ctx, t, corev1.ProtocolTCP)
			}).
		Teardown(teardownSimpleAppWorkload).
		Teardown(teardownTestNamespace).
		Feature()

	testEnv.Test(t, feature)
}

func assessPolicyProposalsGenerated(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)

	const namespaceLabelKey = "kubernetes.io/metadata.name"
	tcpProtocol := corev1.ProtocolTCP
	udpProtocol := corev1.ProtocolUDP
	dstPort := intstr.FromInt(simpleAppTCPServicePort)
	dnsPort := intstr.FromInt(53)

	expectedClientEgressProposal := securityv1alpha1.WorkloadNetworkPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deployment-" + simpleAppClientDeploymentName + "-egress",
			Namespace: namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": simpleAppClientDeploymentName},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Port:     &dstPort,
							Protocol: &tcpProtocol,
						},
					},
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{namespaceLabelKey: namespace},
							},
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"app": simpleAppServerDeploymentName},
							},
						},
					},
				},
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Port:     &dnsPort,
							Protocol: &udpProtocol,
						},
					},
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{namespaceLabelKey: "kube-system"},
							},
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"k8s-app": "kube-dns"},
							},
						},
					},
				},
			},
		},
	}
	expectedServerIngressProposal := securityv1alpha1.WorkloadNetworkPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deployment-" + simpleAppServerDeploymentName + "-ingress",
			Namespace: namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": simpleAppServerDeploymentName},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{namespaceLabelKey: namespace},
							},
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"app": simpleAppClientDeploymentName},
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Port:     &dstPort,
							Protocol: &tcpProtocol,
						},
					},
				},
			},
		},
	}

	var proposals securityv1alpha1.WorkloadNetworkPolicyProposalList
	require.Eventually(t, func() bool {
		err := getSecurityV1Alpha1Client(ctx).WithNamespace(namespace).List(ctx, &proposals)
		require.NoError(t, err, "failed to list network policy proposals")

		foundClientEgress := false
		foundServerIngress := false
		for _, proposal := range proposals.Items {
			switch proposal.Name {
			case expectedClientEgressProposal.Name:
				foundClientEgress = true
			case expectedServerIngressProposal.Name:
				foundServerIngress = true
			default:
				continue
			}
		}
		return foundClientEgress && foundServerIngress
	}, defaultOperationTimeout, 3*time.Second, "expected policy proposals were not generated")

	require.Len(t, proposals.Items, 2, "expected exactly 2 policy proposals to be generated")
	for _, proposal := range proposals.Items {
		switch proposal.Name {
		case expectedClientEgressProposal.Name:
			requireEqualNetworkPolicyProposal(t, expectedClientEgressProposal,
				proposal)
		case expectedServerIngressProposal.Name:
			requireEqualNetworkPolicyProposal(t, expectedServerIngressProposal,
				proposal)
		}
	}
	// We return the proposals so that other tests can use them
	return context.WithValue(ctx, key("proposals"), proposals.Items)
}

func assessPolicyProposalsPromoted(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()

	// we recover the proposal from the context.
	proposals := ctx.Value(key("proposals")).([]securityv1alpha1.WorkloadNetworkPolicyProposal)
	client := getSecurityV1Alpha1Client(ctx)

	policies := make([]securityv1alpha1.WorkloadNetworkPolicy, 0, len(proposals))
	for _, proposal := range proposals {
		// We promote the proposal to a network policy.
		proposal.SetPromotionLabel()
		require.NoError(t, client.Update(ctx, &proposal),
			"failed to promote network policy proposal %q", proposal.NamespacedName().String())

		// We expect the policy to be created.
		var policy securityv1alpha1.WorkloadNetworkPolicy
		require.Eventually(t, func() bool {
			return client.Get(ctx, proposal.Name, proposal.Namespace, &policy) == nil
		}, defaultOperationTimeout, 1*time.Second, "Network policy %q is not created", proposal.NamespacedName().String())

		// Check the policy specs are correct.
		require.True(t, policy.HasPromotedLabel(proposal.Name))
		require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeMonitor, policy.Spec.Mode)
		require.Equal(t, proposal.Spec, policy.Spec.PolicyTemplate)
		policies = append(policies, policy)

		// We expect the proposal to be deleted
		require.Eventually(t, func() bool {
			return apierrors.IsNotFound(client.Get(ctx, proposal.Name, proposal.Namespace, &proposal))
		}, defaultOperationTimeout, 1*time.Second, "network policy proposal %q was not deleted", proposal.NamespacedName().String())
	}
	return context.WithValue(ctx, key("policies"), policies)
}

func assessProposalsAreNotRegenerated(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()

	// we recover the proposal from the context.
	storedProposals := ctx.Value(key("proposals")).([]securityv1alpha1.WorkloadNetworkPolicyProposal)
	client := getSecurityV1Alpha1Client(ctx)

	for _, proposal := range storedProposals {
		require.Never(t, func() bool {
			var p securityv1alpha1.WorkloadNetworkPolicyProposal
			// the error should be always not found
			return !apierrors.IsNotFound(client.Get(ctx, proposal.Name, proposal.Namespace, &p))
		}, 2*getSuiteConfig(ctx).drainFlowsInterval, 1*time.Second, "Network policy proposal %q is created, but it should not be", proposal.NamespacedName().String())
	}
	return ctx
}

func assessPoliciesAreNotUpdatedInMonitorMode(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	storedPolicies := ctx.Value(key("policies")).([]securityv1alpha1.WorkloadNetworkPolicy)
	client := getSecurityV1Alpha1Client(ctx)

	for _, storedPolicy := range storedPolicies {
		require.Never(t, func() bool {
			var policy securityv1alpha1.WorkloadNetworkPolicy
			if err := client.Get(ctx, storedPolicy.Name, storedPolicy.Namespace, &policy); err != nil {
				return false
			}

			if len(policy.Status.Violations) > 0 {
				// todo!: this will change in the future when we will implement violation for monitor mode
				t.Logf(
					"Network policy %q has violations but it shouldn't: %v",
					policy.NamespacedName().String(),
					policy.Status.Violations,
				)
				return true
			}

			// the spec shouldn't change
			return !apiequality.Semantic.DeepEqual(storedPolicy.Spec.PolicyTemplate, policy.Spec.PolicyTemplate)
		}, 2*getSuiteConfig(ctx).drainFlowsInterval, 1*time.Second, "Network policy is updated, but it should not be", storedPolicy.NamespacedName().String())
	}
	return ctx
}

func assessK8sNetworkPoliciesAreCreated(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	storedPolicies := ctx.Value(key("policies")).([]securityv1alpha1.WorkloadNetworkPolicy)
	client := getSecurityV1Alpha1Client(ctx)

	// For each policy we change mode to protect
	for _, policy := range storedPolicies {
		require.Eventually(t, func() bool {
			if err := client.Get(ctx, policy.Name, policy.Namespace, &policy); err != nil {
				t.Logf("failed to get network policy %q: %v", policy.NamespacedName().String(), err)
				return false
			}
			policy.Spec.Mode = securityv1alpha1.WorkloadNetworkPolicyModeProtect
			if err := client.Update(ctx, &policy); err != nil {
				t.Logf("failed to update network policy %q: %v", policy.NamespacedName().String(), err)
				return false
			}
			return true
		}, defaultOperationTimeout, 1*time.Second)
	}

	// Now we check the k8s network policies are created
	// we want to do it in a separate for loop so that k8s network policies are created independently
	for _, policy := range storedPolicies {
		var k8sPolicy networkingv1.NetworkPolicy
		require.Eventually(t, func() bool {
			if err := client.Get(ctx, policy.Name, policy.Namespace, &k8sPolicy); err != nil {
				t.Logf("failed to get k8s network policy %q: %v", policy.NamespacedName().String(), err)
				return false
			}
			return true
		}, defaultOperationTimeout, 1*time.Second)

		require.Equal(
			t,
			policy.Spec.PolicyTemplate,
			k8sPolicy.Spec,
			"Network policy %q spec is not equal to the expected spec",
			policy.NamespacedName().String(),
		)

		require.Equal(
			t,
			[]metav1.OwnerReference{{
				APIVersion:         securityv1alpha1.GroupVersion.String(),
				Kind:               "WorkloadNetworkPolicy",
				Name:               policy.Name,
				UID:                policy.UID,
				Controller:         func(b bool) *bool { return &b }(true),
				BlockOwnerDeletion: func(b bool) *bool { return &b }(true),
			}},
			k8sPolicy.OwnerReferences,
			"K8s Network policy associated with %q doesn't contain the expected owner references",
			policy.NamespacedName().String(),
		)
	}
	return ctx
}

func checkViolations(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	cni := getSuiteConfig(ctx).cni
	if cni == cilium || cni == calico {
		// todo!: With Cilium we will never receive violations in the policies because
		// of this issue https://github.com/rancher-sandbox/network-enforcer/issues/19
		//
		// todo!: we still need to understand why Calico doesn't report violations
		return ctx
	}

	storedPolicies := ctx.Value(key("policies")).([]securityv1alpha1.WorkloadNetworkPolicy)
	client := getSecurityV1Alpha1Client(ctx)

	for _, policy := range storedPolicies {
		require.Eventually(t, func() bool {
			var updatedPolicy securityv1alpha1.WorkloadNetworkPolicy
			if err := client.Get(ctx, policy.Name, policy.Namespace, &updatedPolicy); err != nil {
				return false
			}

			// Check if there are any violations
			return len(updatedPolicy.Status.Violations) > 0
		}, defaultOperationTimeout, 1*time.Second)
	}
	return ctx
}
