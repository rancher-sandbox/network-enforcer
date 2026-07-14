/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
)

// protect mode tests require a CNI that enforces NetworkPolicies (Cilium).
// Run with: E2E_CNI=cilium make test-e2e

const (
	server2DeploymentName = "http-server-2"
	server2Manifest       = "server2.yaml"
)

func TestProtectMode(t *testing.T) {
	if cniType(readEnvOrDefault("E2E_CNI", string(kindnet))) != cilium {
		t.Skip("Protect mode e2e test requires Cilium (set E2E_CNI=cilium)")
	}

	feature := features.New("Protect Mode with Cilium").
		Setup(setupSharedK8sClient).
		Setup(setupTestNamespace).
		Setup(setupSimpleAppWorkload).
		Setup(generateTraffic).
		Assess("Policy proposals are generated for observed traffic",
			assessProtectProposalsGenerated).
		Assess("Promotion to protect mode creates native NetworkPolicy",
			assessPromoteToProtect).
		Assess("Allowed traffic still reaches the server after enforcement",
			assessProtectAllowedTraffic).
		Assess("Traffic to non-allowlisted workloads is blocked by Cilium",
			assessProtectBlockedTraffic).
		Teardown(teardownServer2).
		Teardown(teardownSimpleAppWorkload).
		Teardown(teardownTestNamespace).
		Feature()

	testEnv.Test(t, feature)
}

// assessProtectProposalsGenerated waits for policy proposals to appear and
// stores them in the test context for the promotion step.
func assessProtectProposalsGenerated(
	ctx context.Context,
	t *testing.T,
	_ *envconf.Config,
) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)

	tcpProtocol := corev1.ProtocolTCP
	udpProtocol := corev1.ProtocolUDP
	dstPort := intstr.FromInt(80)
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
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": namespace,
								},
							},
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": simpleAppServerDeploymentName,
								},
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
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": "kube-system",
								},
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
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": namespace,
								},
							},
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": simpleAppClientDeploymentName,
								},
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
		err := getClient(ctx).WithNamespace(namespace).List(ctx, &proposals)
		require.NoError(t, err, "failed to list policy proposals")

		foundClientEgress := false
		foundServerIngress := false
		for _, proposal := range proposals.Items {
			switch proposal.Name {
			case expectedClientEgressProposal.Name:
				foundClientEgress = true
			case expectedServerIngressProposal.Name:
				foundServerIngress = true
			}
		}
		return foundClientEgress && foundServerIngress
	}, defaultOperationTimeout, 3*time.Second,
		"expected policy proposals were not generated")

	require.Len(t, proposals.Items, 2,
		"expected exactly 2 policy proposals to be generated")
	for _, proposal := range proposals.Items {
		switch proposal.Name {
		case expectedClientEgressProposal.Name:
			requireEqualNetworkPolicyProposal(t, expectedClientEgressProposal, proposal)
		case expectedServerIngressProposal.Name:
			requireEqualNetworkPolicyProposal(t, expectedServerIngressProposal, proposal)
		}
	}

	return context.WithValue(ctx, key("protect-proposals"), proposals.Items)
}

// assessPromoteToProtect promotes proposals, flips the resulting
// WorkloadNetworkPolicy to protect mode, and verifies that an actual
// networkingv1.NetworkPolicy resource is created with correct owner references.
func assessPromoteToProtect(
	ctx context.Context,
	t *testing.T,
	_ *envconf.Config,
) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)
	client := getClient(ctx)
	proposals := ctx.Value(key("protect-proposals")).([]securityv1alpha1.WorkloadNetworkPolicyProposal)

	var promotedPolicies []securityv1alpha1.WorkloadNetworkPolicy

	for _, proposal := range proposals {
		proposalName := proposal.Name

		// 1. Set the promotion label so the proposal controller creates a
		//    WorkloadNetworkPolicy in monitor mode.
		proposal.SetPromotionLabel()
		require.NoError(t, client.Update(ctx, &proposal),
			"failed to set promotion label on proposal %q", proposalName)

		// 2. Wait for the WorkloadNetworkPolicy to be created (monitor mode).
		var wnp securityv1alpha1.WorkloadNetworkPolicy
		require.Eventually(t, func() bool {
			return client.Get(ctx, proposalName, namespace, &wnp) == nil
		}, defaultOperationTimeout, 1*time.Second,
			"WorkloadNetworkPolicy %q was not created after promotion", proposalName)

		// 3. Verify it starts in monitor mode (as the proposal controller
		//    hardcodes).
		require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeMonitor,
			wnp.Spec.Mode,
			"expected promoted policy %q to be in monitor mode first", proposalName)

		// 4. Flip the mode to protect.
		wnp.Spec.Mode = securityv1alpha1.WorkloadNetworkPolicyModeProtect
		require.NoError(t, client.Update(ctx, &wnp),
			"failed to flip WorkloadNetworkPolicy %q to protect mode", proposalName)

		// 5. Wait for the native networkingv1.NetworkPolicy to appear.
		var netpol networkingv1.NetworkPolicy
		require.Eventually(t, func() bool {
			return client.Get(ctx, proposalName, namespace, &netpol) == nil
		}, defaultOperationTimeout, 1*time.Second,
			"native NetworkPolicy %q was not created after switching to protect mode",
			proposalName)

		// 6. Verify owner reference points back to the WorkloadNetworkPolicy.
		require.True(t, metav1.IsControlledBy(&netpol, &wnp),
			"NetworkPolicy %q is not owned by WorkloadNetworkPolicy %q",
			proposalName, proposalName)

		// 7. Verify the NetworkPolicy spec matches the proposal spec.
		require.Equal(t, proposal.Spec.PolicyTypes, netpol.Spec.PolicyTypes)
		require.Equal(t, proposal.Spec.PodSelector, netpol.Spec.PodSelector)
		require.ElementsMatch(t, proposal.Spec.Ingress, netpol.Spec.Ingress)
		require.ElementsMatch(t, proposal.Spec.Egress, netpol.Spec.Egress)

		// 8. Verify the proposal is deleted after promotion.
		require.Eventually(t, func() bool {
			var p securityv1alpha1.WorkloadNetworkPolicyProposal
			return apierrors.IsNotFound(client.Get(ctx, proposalName, namespace, &p))
		}, defaultOperationTimeout, 1*time.Second,
			"proposal %q was not deleted after promotion", proposalName)

		promotedPolicies = append(promotedPolicies, wnp)
	}

	return context.WithValue(ctx, key("protect-policies"), promotedPolicies)
}

// assessProtectAllowedTraffic verifies that traffic matching the policy rules
// (client -> server:80) still succeeds after enforcement is active.
func assessProtectAllowedTraffic(
	ctx context.Context,
	t *testing.T,
	_ *envconf.Config,
) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)

	execCtx, cancel := context.WithTimeout(ctx, defaultPodExecTimeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	err := getClient(ctx).ExecInDeployment(
		execCtx,
		namespace,
		simpleAppClientDeploymentName,
		[]string{"curl", "--silent", "--show-error", "--fail", "http://http-service"},
		&stdout,
		&stderr,
	)
	require.NoError(t, err,
		"expected allowed traffic (client -> server:80) to succeed under protect mode")
	require.NotEmpty(t, stdout.String(),
		"expected non-empty response body from allowed curl")

	return ctx
}

// assessProtectBlockedTraffic deploys a second server (server2) that is NOT
// covered by the promoted egress policy and verifies that Cilium blocks
// traffic from the client to it.
func assessProtectBlockedTraffic(
	ctx context.Context,
	t *testing.T,
	_ *envconf.Config,
) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)
	client := getClient(ctx)

	// Deploy a second server whose pods are labelled "app: http-server-2".
	// The client egress policy only allows "app: http-client" -> TCP:80 to
	// "app: http-server", so traffic to server2 should be dropped.
	err := decoder.ApplyWithManifestDir(
		ctx,
		client,
		testFolder,
		server2Manifest,
		[]resources.CreateOption{},
		decoder.MutateNamespace(namespace),
	)
	require.NoError(t, err, "failed to deploy server2 manifest")

	t.Log("Waiting for server2 deployment to become available")
	err = wait.For(
		conditions.New(client).DeploymentAvailable(server2DeploymentName, namespace),
		wait.WithTimeout(defaultOperationTimeout),
	)
	require.NoError(t, err, "server2 deployment did not become ready in time")

	// Attempt to curl server2 from the client. The egress policy only allows
	// TCP:80 to pods with label "app: http-server"; server2 has
	// "app: http-server-2", so Cilium should drop the SYN packets.
	execCtx, cancel := context.WithTimeout(ctx, defaultPodExecTimeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	err = client.ExecInDeployment(
		execCtx,
		namespace,
		simpleAppClientDeploymentName,
		[]string{
			"curl",
			"--silent", "--show-error",
			"--connect-timeout", "5",
			"--max-time", "10",
			"http://http-service-2",
		},
		&stdout,
		&stderr,
	)
	// Require that curl fails (traffic dropped by Cilium policy enforcement).
	require.Error(t, err,
		"expected traffic from client to server2 to be blocked by Cilium policy enforcement")

	return ctx
}

// teardownServer2 deletes the server2 manifest and waits for the deployment
// to be fully removed.
func teardownServer2(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)

	err := decoder.DeleteWithManifestDir(
		ctx,
		getClient(ctx),
		testFolder,
		server2Manifest,
		[]resources.DeleteOption{},
		decoder.MutateNamespace(namespace),
	)
	require.NoError(t, err, "failed to delete server2 manifest")

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: server2DeploymentName, Namespace: namespace},
	}
	err = wait.For(
		conditions.New(getClient(ctx)).ResourceDeleted(deployment),
		wait.WithTimeout(defaultOperationTimeout),
	)
	require.NoError(t, err, "wait server2 deployment deletion")

	return ctx
}
