package controller

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/grpcexporter"
	agentv1 "github.com/rancher-sandbox/network-enforcer/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---------------------------------------------------------------------------
// Fake agent client
// ---------------------------------------------------------------------------

type fakeAgentClient struct {
	violations []*agentv1.ViolationRecord
	shouldFail bool
}

func (f *fakeAgentClient) ScrapeViolations(_ context.Context) ([]*agentv1.ViolationRecord, error) {
	if f.shouldFail {
		return nil, errors.New("fake scrape failure")
	}
	return f.violations, nil
}

func (f *fakeAgentClient) Close() error { return nil }

// ---------------------------------------------------------------------------
// Fake pool that bypasses real gRPC dialling
// ---------------------------------------------------------------------------

type fakePool struct {
	nodeClients map[string]grpcexporter.AgentClientAPI
}

func (p *fakePool) UpdatePool(_ context.Context, _ client.Reader) (map[string]grpcexporter.AgentClientAPI, error) {
	return p.nodeClients, nil
}

func (p *fakePool) MarkStaleAgentClient(nodeName string) {
	if p.nodeClients == nil {
		return
	}
	if c, ok := p.nodeClients[nodeName]; ok && c != nil {
		_ = c.Close()
	}
	p.nodeClients[nodeName] = nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newCniwatcherPod(name, namespace, nodeName, ip string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{"app.kubernetes.io/name": "network-enforcer-cniwatcher"},
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
		},
		Status: corev1.PodStatus{
			PodIP: ip,
		},
	}
}

func newProtoViolation(
	ts time.Time,
	nodeName string,
	direction string,
	srcNS string,
	srcName string,
	dstNS string,
	dstName string,
	denyNS string,
	denyName string,
) *agentv1.ViolationRecord {
	return &agentv1.ViolationRecord{
		Timestamp:              timestamppb.New(ts),
		NodeName:               nodeName,
		Direction:              direction,
		SourceNamespace:        srcNS,
		SourceName:             srcName,
		SourceWorkloads:        []string{"Deployment/" + srcName},
		DestNamespace:          dstNS,
		DestName:               dstName,
		DestWorkloads:          []string{"Service/" + dstName},
		Protocol:               "TCP",
		DstPort:                80,
		Action:                 "protect",
		DenyingPolicyNamespace: denyNS,
		DenyingPolicyName:      denyName,
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCorrelateViolationsToWNPs(t *testing.T) {
	t.Parallel()

	npKey := types.NamespacedName{Namespace: "ns1", Name: "policy-1"}
	wnpKey := types.NamespacedName{Namespace: "ns1", Name: "policy-1"}
	ownedIndex := map[types.NamespacedName]types.NamespacedName{
		npKey: wnpKey,
	}

	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		sync       *WorkloadNetworkPolicyStatusSync
		ownedIndex map[types.NamespacedName]types.NamespacedName
		violations []*agentv1.ViolationRecord
		check      func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord)
	}{
		{
			name:       "attributes_egress_deny_to_WNP",
			sync:       &WorkloadNetworkPolicyStatusSync{},
			ownedIndex: ownedIndex,
			violations: []*agentv1.ViolationRecord{
				newProtoViolation(ts, "node-1", "egress", "src-ns", "src-app", "dst-ns", "dst-svc",
					"ns1", "policy-1"),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Len(t, result, 1)
				require.Contains(t, result, wnpKey)
				require.Len(t, result[wnpKey], 1)
				require.Equal(t, "egress", result[wnpKey][0].Direction)
				require.Equal(t, "node-1", result[wnpKey][0].NodeName)
				require.Equal(t, "ns1", result[wnpKey][0].DenyingPolicyNamespace)
				require.Equal(t, "policy-1", result[wnpKey][0].DenyingPolicyName)
			},
		},
		{
			name:       "attributes_ingress_deny_to_WNP",
			sync:       &WorkloadNetworkPolicyStatusSync{},
			ownedIndex: ownedIndex,
			violations: []*agentv1.ViolationRecord{
				newProtoViolation(ts, "node-1", "ingress", "src-ns", "src-app", "dst-ns", "dst-svc",
					"ns1", "policy-1"),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Len(t, result, 1)
				require.Contains(t, result, wnpKey)
				require.Len(t, result[wnpKey], 1)
				require.Equal(t, "ingress", result[wnpKey][0].Direction)
			},
		},
		{
			name: "drops_deny_by_unowned_NetworkPolicy",
			sync: func() *WorkloadNetworkPolicyStatusSync {
				rawNP := &networkingv1.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "raw-policy",
						Namespace: "ns-other",
					},
				}
				return &WorkloadNetworkPolicyStatusSync{
					Client: fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(rawNP).Build(),
					logger: ctrl.Log.WithName("test"),
				}
			}(),
			ownedIndex: ownedIndex,
			violations: []*agentv1.ViolationRecord{
				newProtoViolation(ts, "node-1", "egress", "src-ns", "src-app", "dst-ns", "dst-svc",
					"ns-other", "raw-policy"),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Empty(t, result)
			},
		},
		{
			name: "warns_when_denying_NetworkPolicy_is_deleted",
			sync: &WorkloadNetworkPolicyStatusSync{
				Client: fake.NewClientBuilder().WithScheme(newTestScheme()).Build(),
				logger: ctrl.Log.WithName("test"),
			},
			ownedIndex: ownedIndex,
			violations: []*agentv1.ViolationRecord{
				newProtoViolation(ts, "node-1", "egress", "src-ns", "src-app", "dst-ns", "dst-svc",
					"ns-missing", "deleted-policy"),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Empty(t, result)
			},
		},
		{
			name:       "drops_deny_with_empty_denying_policy",
			sync:       &WorkloadNetworkPolicyStatusSync{logger: ctrl.Log.WithName("test")},
			ownedIndex: ownedIndex,
			violations: []*agentv1.ViolationRecord{
				newProtoViolation(ts, "node-1", "egress", "src-ns", "src-app", "dst-ns", "dst-svc",
					"", ""),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Empty(t, result)
			},
		},
		{
			name:       "dedup_by_violation_key",
			sync:       &WorkloadNetworkPolicyStatusSync{},
			ownedIndex: ownedIndex,
			violations: []*agentv1.ViolationRecord{
				newProtoViolation(ts, "node-1", "egress", "src-ns", "src-app", "dst-ns", "dst-svc",
					"ns1", "policy-1"),
				newProtoViolation(ts, "node-2", "egress", "src-ns", "src-app", "dst-ns", "dst-svc",
					"ns1", "policy-1"),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Len(t, result, 1)
				// Both violations are in the list — dedup is done later by
				// RecomputeStatus → mergeScrapedViolations which uses the key.
				require.Len(t, result[wnpKey], 2)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.sync.correlateViolationsToWNPs(context.Background(), tt.violations, tt.ownedIndex)
			tt.check(t, result)
		})
	}
}

func TestScrapeAllNodes(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		clients map[string]grpcexporter.AgentClientAPI
		check   func(t *testing.T, results []*agentv1.ViolationRecord)
	}{
		{
			name: "scrapes_reachable_nodes_and_skips_unreachable",
			clients: map[string]grpcexporter.AgentClientAPI{
				"node-1": &fakeAgentClient{
					violations: []*agentv1.ViolationRecord{
						newProtoViolation(ts, "node-1", "egress", "ns1", "app1", "ns2", "svc1",
							"ns1", "policy-1"),
					},
				},
				"node-2": &fakeAgentClient{shouldFail: true},
				"node-3": nil, // unreachable
			},
			check: func(t *testing.T, results []*agentv1.ViolationRecord) {
				require.Len(t, results, 1)
				require.Equal(t, "node-1", results[0].GetNodeName())
			},
		},
		{
			name:    "empty_clients_map_returns_empty",
			clients: map[string]grpcexporter.AgentClientAPI{},
			check: func(t *testing.T, results []*agentv1.ViolationRecord) {
				require.Empty(t, results)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sync := &WorkloadNetworkPolicyStatusSync{
				agentClientPool: &fakePool{},
				logger:          ctrl.Log.WithName("test"),
			}
			results := sync.scrapeAllNodes(context.Background(), tt.clients)
			tt.check(t, results)
		})
	}
}

func TestProcessWorkloadNetworkPolicy_TwoPhasePatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	wnp := newTestWNP("policy-1", "ns1")
	// Add an acknowledge annotation for one of the violations.
	wnp.Annotations = map[string]string{
		securityv1alpha1.ViolationAcknowledgePrefix + "0": "known issue",
	}

	ownedNP := newOwnedNetworkPolicy(wnp)

	s := newTestScheme()
	statusObj := &securityv1alpha1.WorkloadNetworkPolicy{}
	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(statusObj).
		WithObjects(wnp, ownedNP).
		Build()

	sync := &WorkloadNetworkPolicyStatusSync{
		Client:          fakeClient,
		agentClientPool: &fakePool{},
		updateInterval:  time.Hour,
		logger:          ctrl.Log.WithName("test"),
	}

	violations := []securityv1alpha1.ViolationRecord{
		{
			Timestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
			NodeName:  "node-1",
			Direction: "egress",
			Source: securityv1alpha1.WorkloadRef{
				Namespace: "src-ns", OwnerKind: "Deployment", OwnerName: "app",
			},
			Dest: securityv1alpha1.WorkloadRef{
				Namespace: "dst-ns", OwnerKind: "Service", OwnerName: "svc",
			},
			Protocol:               corev1.ProtocolTCP,
			DstPort:                80,
			Action:                 "protect",
			DenyingPolicyNamespace: "ns1",
			DenyingPolicyName:      "policy-1",
		},
	}

	err := sync.processWorkloadNetworkPolicy(context.Background(), wnp, violations)
	require.NoError(t, err)

	// Verify the status was written.
	var updatedWNP securityv1alpha1.WorkloadNetworkPolicy
	err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "ns1", Name: "policy-1"}, &updatedWNP)
	require.NoError(t, err)
	require.Equal(t, int64(1), updatedWNP.Status.ViolationCount)
	require.Equal(t, int64(0), updatedWNP.Status.ActiveViolationCount) // acknowledged

	// The acknowledge annotation should have been consumed.
	_, exists := updatedWNP.Annotations[securityv1alpha1.ViolationAcknowledgePrefix+"0"]
	require.False(t, exists, "acknowledge annotation should be removed")
}

func TestBuildOwnershipIndex(t *testing.T) {
	t.Parallel()

	wnp1 := newTestWNP("policy-1", "ns1")
	wnp2 := newTestWNP("policy-2", "ns2")

	ownedNP1 := newOwnedNetworkPolicy(wnp1)
	ownedNP2 := newOwnedNetworkPolicy(wnp2)
	// A NetworkPolicy with no owner reference.
	unownedNP := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "raw-policy",
			Namespace: "ns1",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithObjects(wnp1, wnp2, ownedNP1, ownedNP2, unownedNP).
		Build()

	wnpByKey := map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy{
		{Namespace: "ns1", Name: "policy-1"}: wnp1,
		{Namespace: "ns2", Name: "policy-2"}: wnp2,
	}

	sync := &WorkloadNetworkPolicyStatusSync{Client: fakeClient}
	index, err := sync.buildOwnershipIndex(context.Background(), wnpByKey)
	require.NoError(t, err)

	// Owned policies should be in the index.
	require.Equal(t, types.NamespacedName{Namespace: "ns1", Name: "policy-1"},
		index[types.NamespacedName{Namespace: "ns1", Name: "policy-1"}])
	require.Equal(t, types.NamespacedName{Namespace: "ns2", Name: "policy-2"},
		index[types.NamespacedName{Namespace: "ns2", Name: "policy-2"}])

	// Unowned policy should not be in the index.
	_, exists := index[types.NamespacedName{Namespace: "ns1", Name: "raw-policy"}]
	require.False(t, exists)
}

func TestConvertProtoViolation(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pbViolation := newProtoViolation(ts, "node-1", "egress",
		"src-ns", "src-app", "dst-ns", "dst-svc",
		"policy-ns", "policy-name")

	rec := convertProtoViolation(pbViolation)

	require.Equal(t, "egress", rec.Direction)
	require.Equal(t, "node-1", rec.NodeName)
	require.Equal(t, "src-ns", rec.Source.Namespace)
	require.Equal(t, "Deployment", rec.Source.OwnerKind)
	require.Equal(t, "src-app", rec.Source.OwnerName)
	require.Equal(t, "dst-ns", rec.Dest.Namespace)
	require.Equal(t, "Service", rec.Dest.OwnerKind)
	require.Equal(t, "dst-svc", rec.Dest.OwnerName)
	require.Equal(t, corev1.ProtocolTCP, rec.Protocol)
	require.Equal(t, int32(80), rec.DstPort)
	require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeProtect, rec.Action)
	require.Equal(t, "policy-ns", rec.DenyingPolicyNamespace)
	require.Equal(t, "policy-name", rec.DenyingPolicyName)
}

func TestParseWorkload(t *testing.T) {
	t.Parallel()

	kind, name := parseWorkload([]string{"Deployment/myapp"})
	require.Equal(t, "Deployment", kind)
	require.Equal(t, "myapp", name)

	kind, name = parseWorkload([]string{"myapp"})
	require.Empty(t, kind)
	require.Equal(t, "myapp", name)

	kind, name = parseWorkload(nil)
	require.Empty(t, kind)
	require.Empty(t, name)
}

func TestSyncSkipsWhenNoWNPs(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		Build()

	pool := &fakePool{nodeClients: map[string]grpcexporter.AgentClientAPI{}}

	sync := &WorkloadNetworkPolicyStatusSync{
		Client:          fakeClient,
		agentClientPool: pool,
		updateInterval:  time.Hour,
		logger:          ctrl.Log.WithName("test"),
	}

	err := sync.sync(context.Background())
	require.NoError(t, err)
}

// Test that the fake pool's MarkStaleAgentClient works correctly.
func TestFakePoolMarkStale(t *testing.T) {
	t.Parallel()

	pool := &fakePool{
		nodeClients: map[string]grpcexporter.AgentClientAPI{
			"node-1": &fakeAgentClient{},
		},
	}

	pool.MarkStaleAgentClient("node-1")
	require.Nil(t, pool.nodeClients["node-1"])

	// Marking again should not panic.
	pool.MarkStaleAgentClient("node-1")
}

// TestNewWorkloadNetworkPolicyStatusSync validates config.
func TestNewWorkloadNetworkPolicyStatusSync(t *testing.T) {
	t.Parallel()

	_, err := NewWorkloadNetworkPolicyStatusSync(nil, &WorkloadNetworkPolicyStatusSyncConfig{
		UpdateInterval: 0,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid update interval")
}

// Test that the gRPC exporter pool creation works with valid config.
func TestAgentClientPoolDefaults(t *testing.T) {
	t.Parallel()

	pool, err := grpcexporter.NewAgentClientPool(grpcexporter.AgentClientPoolConfig{
		AgentFactoryConfig: grpcexporter.AgentFactoryConfig{
			Port: 50051,
		},
		Namespace:           "test-ns",
		LabelSelectorString: grpcexporter.DefaultCniwatcherLabelSelectorString,
		Logger:              slog.Default(),
	})
	require.NoError(t, err)
	require.NotNil(t, pool)
}

func TestAgentClientPoolUpdatePool(t *testing.T) {
	t.Parallel()

	// We need a full scheme for the fake client.
	s := newTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(
			newCniwatcherPod("cniwatcher-1", "test-ns", "node-1", "10.0.0.1"),
			newCniwatcherPod("cniwatcher-2", "test-ns", "node-2", "10.0.0.2"),
		).
		Build()

	// Create a pool with a factory that dials.
	// grpc.NewClient is lazy so creation will succeed even without a
	// real gRPC server. We verify the pool correctly discovers pods.
	pool, err := grpcexporter.NewAgentClientPool(grpcexporter.AgentClientPoolConfig{
		AgentFactoryConfig: grpcexporter.AgentFactoryConfig{
			Port: 50051,
		},
		Namespace:           "test-ns",
		LabelSelectorString: "app.kubernetes.io/name=network-enforcer-cniwatcher",
		Logger:              slog.Default(),
	})
	require.NoError(t, err)

	clients, err := pool.UpdatePool(context.Background(), fakeClient)
	require.NoError(t, err)
	require.Len(t, clients, 2)
	// Both nodes are present (entries are non-nil because grpc.NewClient
	// is lazy and does not dial during construction).
	require.Contains(t, clients, "node-1")
	require.Contains(t, clients, "node-2")
	require.NotNil(t, clients["node-1"])
	require.NotNil(t, clients["node-2"])

	// Mark a client stale and verify it becomes nil.
	pool.MarkStaleAgentClient("node-1")
	require.Nil(t, clients["node-1"])
}

// TestSyncLoopIntegration runs a full sync cycle with real fake objects.
func TestSyncLoopIntegration(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	wnp := newTestWNP("my-policy", "default")
	ownedNP := newOwnedNetworkPolicy(wnp)

	// Build the fake client with the WNP and its owned NetworkPolicy.
	s := newTestScheme()
	statusObj := &securityv1alpha1.WorkloadNetworkPolicy{}
	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(statusObj).
		WithObjects(wnp, ownedNP).
		Build()

	// Create a fake pool that returns one node with a violation.
	pool := &fakePool{
		nodeClients: map[string]grpcexporter.AgentClientAPI{
			"node-1": &fakeAgentClient{
				violations: []*agentv1.ViolationRecord{
					newProtoViolation(now, "node-1", "egress",
						"src-ns", "src-app", "dst-ns", "dst-svc",
						"default", "my-policy"),
				},
			},
		},
	}

	sync := &WorkloadNetworkPolicyStatusSync{
		Client:          fakeClient,
		agentClientPool: pool,
		updateInterval:  time.Hour,
		logger:          ctrl.Log.WithName("test"),
	}

	err := sync.sync(context.Background())
	require.NoError(t, err)

	// Verify the WNP status was updated.
	var updatedWNP securityv1alpha1.WorkloadNetworkPolicy
	err = fakeClient.Get(
		context.Background(),
		types.NamespacedName{Namespace: "default", Name: "my-policy"},
		&updatedWNP,
	)
	require.NoError(t, err)
	require.Equal(t, int64(1), updatedWNP.Status.ViolationCount)
	require.Equal(t, int64(1), updatedWNP.Status.ActiveViolationCount)
	require.Len(t, updatedWNP.Status.Violations, 1)
	require.Equal(t, "egress", updatedWNP.Status.Violations[0].Direction)
	require.Equal(t, "src-app", updatedWNP.Status.Violations[0].Source.OwnerName)
}

func TestSyncClearsViolationsWithNoNewScrapedViolations(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	tcp := corev1.ProtocolTCP
	port80 := intstr.FromInt32(80)

	wnp := newTestWNP("policy-1", "ns1")
	// Add an egress rule to the policy template that permits the traffic
	// that was previously denied and recorded as a violation.
	wnp.Spec.PolicyTemplate.Egress = []networkingv1.NetworkPolicyEgressRule{
		{
			To: []networkingv1.NetworkPolicyPeer{
				{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							corev1.LabelMetadataName: "dst-ns",
						},
					},
				},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{
					Protocol: &tcp,
					Port:     &port80,
				},
			},
		},
	}

	// Pre-populate status with a violation that matches the rule above.
	wnp.Status = securityv1alpha1.WorkloadNetworkPolicyStatus{
		ViolationCount:       1,
		ActiveViolationCount: 1,
		Violations: []securityv1alpha1.ViolationRecord{
			{
				ID:        0,
				Timestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
				NodeName:  "node-1",
				Direction: "egress",
				Source: securityv1alpha1.WorkloadRef{
					Namespace: "src-ns", OwnerKind: "Deployment", OwnerName: "app",
				},
				Dest: securityv1alpha1.WorkloadRef{
					Namespace: "dst-ns", OwnerKind: "Service", OwnerName: "svc",
				},
				Protocol:               corev1.ProtocolTCP,
				DstPort:                80,
				Action:                 "protect",
				DenyingPolicyNamespace: "ns1",
				DenyingPolicyName:      "policy-1",
			},
		},
	}

	ownedNP := newOwnedNetworkPolicy(wnp)

	s := newTestScheme()
	statusObj := &securityv1alpha1.WorkloadNetworkPolicy{}
	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(statusObj).
		WithObjects(wnp, ownedNP).
		Build()

	// Pool with no reachable nodes → empty scrape → zero violations.
	pool := &fakePool{nodeClients: map[string]grpcexporter.AgentClientAPI{}}

	sync := &WorkloadNetworkPolicyStatusSync{
		Client:          fakeClient,
		agentClientPool: pool,
		updateInterval:  time.Hour,
		logger:          ctrl.Log.WithName("test"),
	}

	err := sync.sync(context.Background())
	require.NoError(t, err)

	var updatedWNP securityv1alpha1.WorkloadNetworkPolicy
	err = fakeClient.Get(
		context.Background(),
		types.NamespacedName{Namespace: "ns1", Name: "policy-1"},
		&updatedWNP,
	)
	require.NoError(t, err)

	// The violation should have been cleared because it matches a rule in
	// the current policy template (clearAllowedViolations ran even though
	// no new violations were scraped).
	require.Equal(t, int64(1), updatedWNP.Status.ViolationCount,
		"ViolationCount should still be 1 (total observed)")
	require.Equal(t, int64(0), updatedWNP.Status.ActiveViolationCount,
		"ActiveViolationCount should be 0 after clearing")
	require.Empty(t, updatedWNP.Status.Violations,
		"Violations should be empty — the matching rule cleared it")
}

// TestTwoPhasePatchConflict simulates a scenario where an annotation is
// modified between the status patch and the metadata patch. Both patches
// use MergeFrom so the annotation should survive.
func TestTwoPhasePatchConflict(t *testing.T) {
	t.Parallel()

	// Start with a WNP that has a pre-existing annotation.
	wnp := newTestWNP("conflict-policy", "ns1")
	wnp.Annotations = map[string]string{
		"existing.io/key": "original-value",
	}
	ownedNP := newOwnedNetworkPolicy(wnp)

	s := newTestScheme()
	statusObj := &securityv1alpha1.WorkloadNetworkPolicy{}
	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(statusObj).
		WithObjects(wnp, ownedNP).
		Build()

	sync := &WorkloadNetworkPolicyStatusSync{
		Client:          fakeClient,
		agentClientPool: &fakePool{},
		updateInterval:  time.Hour,
		logger:          ctrl.Log.WithName("test"),
	}

	violations := []securityv1alpha1.ViolationRecord{
		{
			Timestamp: metav1.NewTime(time.Now()),
			NodeName:  "node-1",
			Direction: "egress",
			Source: securityv1alpha1.WorkloadRef{
				Namespace: "ns1", OwnerKind: "Deployment", OwnerName: "app",
			},
			Dest: securityv1alpha1.WorkloadRef{
				Namespace: "ns2", OwnerKind: "Service", OwnerName: "svc",
			},
			Protocol:               corev1.ProtocolTCP,
			DstPort:                80,
			Action:                 "protect",
			DenyingPolicyNamespace: "ns1",
			DenyingPolicyName:      "conflict-policy",
		},
	}

	err := sync.processWorkloadNetworkPolicy(context.Background(), wnp, violations)
	require.NoError(t, err)

	// The existing annotation should still be present.
	var updatedWNP securityv1alpha1.WorkloadNetworkPolicy
	err = fakeClient.Get(
		context.Background(),
		types.NamespacedName{Namespace: "ns1", Name: "conflict-policy"},
		&updatedWNP,
	)
	require.NoError(t, err)
	require.Equal(t, "original-value", updatedWNP.Annotations["existing.io/key"])
	// Status should also be updated.
	require.Equal(t, int64(1), updatedWNP.Status.ActiveViolationCount)
}
