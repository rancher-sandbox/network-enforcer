package controller

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/embedded"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
)

type fakeEventLogger struct {
	embedded.Logger

	mu       sync.Mutex
	count    int
	captured *otellog.Record
}

func (f *fakeEventLogger) Enabled(context.Context, otellog.EnabledParameters) bool {
	return true
}

func (f *fakeEventLogger) Emit(_ context.Context, record otellog.Record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.count++
	if f.captured == nil {
		clone := record.Clone()
		f.captured = &clone
	}
}

func (f *fakeEventLogger) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count
}

type statusFailingClient struct {
	client.Client

	failN int
	mu    sync.Mutex
	fails int
}

func (c *statusFailingClient) Status() client.StatusWriter {
	return &statusFailingWriter{parent: c, inner: c.Client.Status()}
}

type statusFailingWriter struct {
	client.StatusWriter

	parent *statusFailingClient
	inner  client.StatusWriter
}

func (w *statusFailingWriter) Patch(
	ctx context.Context,
	obj client.Object,
	patch client.Patch,
	opts ...client.SubResourcePatchOption,
) error {
	w.parent.mu.Lock()
	if w.parent.fails < w.parent.failN {
		w.parent.fails++
		w.parent.mu.Unlock()
		return errors.New("simulated status patch failure")
	}
	w.parent.mu.Unlock()
	return w.inner.Patch(ctx, obj, patch, opts...)
}

// wnpWithAckAnnotation builds a fresh WorkloadNetworkPolicy in namespace ns1
// carrying one acknowledge annotation for violation id 0. RecomputeStatus,
// given a single scraped egress violation that is not permitted by the policy
// template, will assign it id 0 and then acknowledge it.
func wnpWithAckAnnotation(name string) *securityv1alpha1.WorkloadNetworkPolicy {
	wnp := newTestWNP(name, "ns1")
	wnp.Annotations = map[string]string{
		securityv1alpha1.ViolationAcknowledgePrefix + "0": "known issue",
	}
	return wnp
}

func ackTestViolation(denyingPolicyName string) securityv1alpha1.ViolationRecord {
	return securityv1alpha1.ViolationRecord{
		Timestamp: metav1.NewTime(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
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
		DenyingPolicyName:      denyingPolicyName,
	}
}

// TestAcknowledgedViolationEmitOrderingGuard verifies the ordering guard:
// status patch failure → no log; retry after success → exactly one log.
func TestAcknowledgedViolationEmitOrderingGuard(t *testing.T) {
	t.Parallel()

	s := newTestScheme()
	statusObj := &securityv1alpha1.WorkloadNetworkPolicy{}
	wnp := wnpWithAckAnnotation("ack-policy")
	ownedNP := newOwnedNetworkPolicy(wnp)
	inner := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(statusObj).
		WithObjects(wnp, ownedNP).
		Build()

	failingClient := &statusFailingClient{Client: inner, failN: 1}

	logger := &fakeEventLogger{}

	sync := &WorkloadNetworkPolicyStatusSync{
		Client:          failingClient,
		agentClientPool: &fakePool{},
		updateInterval:  time.Hour,
		eventLogger:     logger,
	}

	violations := []securityv1alpha1.ViolationRecord{ackTestViolation("ack-policy")}

	err := sync.processWorkloadNetworkPolicy(context.Background(),
		wnpWithAckAnnotation("ack-policy"), violations)
	require.Error(t, err, "expected status patch failure")
	require.Contains(t, err.Error(), "failed to patch WorkloadNetworkPolicy status")
	require.Equal(t, 0, logger.Count(), "no log when status patch fails")

	err = sync.processWorkloadNetworkPolicy(context.Background(),
		wnpWithAckAnnotation("ack-policy"), violations)
	require.NoError(t, err, "expected success on retry")
	require.Equal(t, 1, logger.Count(), "retry emits exactly one log")
}

func TestAcknowledgedViolationEventShape(t *testing.T) {
	t.Parallel()

	s := newTestScheme()
	statusObj := &securityv1alpha1.WorkloadNetworkPolicy{}
	wnp := wnpWithAckAnnotation("shape-policy")
	ownedNP := newOwnedNetworkPolicy(wnp)
	inner := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(statusObj).
		WithObjects(wnp, ownedNP).
		Build()

	logger := &fakeEventLogger{}

	sync := &WorkloadNetworkPolicyStatusSync{
		Client:          inner,
		agentClientPool: &fakePool{},
		updateInterval:  time.Hour,
		eventLogger:     logger,
	}

	require.NoError(t, sync.processWorkloadNetworkPolicy(context.Background(),
		wnpWithAckAnnotation("shape-policy"),
		[]securityv1alpha1.ViolationRecord{ackTestViolation("shape-policy")}))

	require.Equal(t, 1, logger.Count())
	require.NotNil(t, logger.captured)

	require.Equal(t, EventNamePolicyViolationAcknowledged, logger.captured.EventName())
	require.Equal(t, otellog.SeverityInfo, logger.captured.Severity())

	attrs := map[string]string{}
	logger.captured.WalkAttributes(func(kv otellog.KeyValue) bool {
		attrs[kv.Key] = kv.Value.String()
		return true
	})

	require.Equal(t, "0", attrs["id"])
	require.Equal(t, "known issue", attrs["reason"])
	require.Equal(t, "egress", attrs["direction"])
	require.Equal(t, "src-ns", attrs["source.namespace"])
	require.Equal(t, "Deployment", attrs["source.workload.kind"])
	require.Equal(t, "app", attrs["source.workload.name"])
	require.Equal(t, "dst-ns", attrs["dest.namespace"])
	require.Equal(t, "Service", attrs["dest.workload.kind"])
	require.Equal(t, "svc", attrs["dest.workload.name"])
	require.Equal(t, "TCP", attrs["protocol"])
	require.Equal(t, "80", attrs["dstPort"])
	require.Equal(t, "protect", attrs["action"])
	require.Equal(t, "node-1", attrs["node.name"])
	require.Equal(t, "ns1", attrs["denyingPolicy.namespace"])
	require.Equal(t, "shape-policy", attrs["denyingPolicy.name"])
}

func TestAcknowledgedViolationEmitNoLoggerIsNoOp(t *testing.T) {
	t.Parallel()

	s := newTestScheme()
	statusObj := &securityv1alpha1.WorkloadNetworkPolicy{}
	wnp := wnpWithAckAnnotation("noop-policy")
	ownedNP := newOwnedNetworkPolicy(wnp)
	inner := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(statusObj).
		WithObjects(wnp, ownedNP).
		Build()

	sync := &WorkloadNetworkPolicyStatusSync{
		Client:          inner,
		agentClientPool: &fakePool{},
		updateInterval:  time.Hour,
		// eventLogger intentionally nil → OTLP disabled.
	}

	require.NoError(t, sync.processWorkloadNetworkPolicy(context.Background(),
		wnpWithAckAnnotation("noop-policy"),
		[]securityv1alpha1.ViolationRecord{ackTestViolation("noop-policy")}))

	// Status still written: the violation moved to acknowledgedViolations.
	var updated securityv1alpha1.WorkloadNetworkPolicy
	require.NoError(t, inner.Get(context.Background(),
		types.NamespacedName{Namespace: "ns1", Name: "noop-policy"}, &updated))
	require.Equal(t, int64(0), updated.Status.ActiveViolationCount)
	require.Len(t, updated.Status.AcknowledgedViolations, 1)
}
