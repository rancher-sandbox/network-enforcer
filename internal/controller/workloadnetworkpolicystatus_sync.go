package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	otellog "go.opentelemetry.io/otel/log"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/grpcexporter"
	agentv1 "github.com/rancher-sandbox/network-enforcer/proto/agent/v1"
)

const EventNamePolicyViolationAcknowledged = "policy_violation_acknowledged"

type AgentClientPoolAPI interface {
	UpdatePool(ctx context.Context, reader client.Reader) (map[string]grpcexporter.AgentClientAPI, error)
	MarkStaleAgentClient(nodeName string)
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadnetworkpolicies/status,verbs=get;patch;update

// WorkloadNetworkPolicyStatusSync scrapes cniwatcher pods, correlates denies
// to the owning WNP, and writes status/annotations via two-phase patch.
// When eventLogger is set it emits policy_violation_acknowledged after a
// successful status patch (ordering guard, no duplicate logs on retry).
type WorkloadNetworkPolicyStatusSync struct {
	client.Client

	agentClientPool AgentClientPoolAPI
	updateInterval  time.Duration
	eventLogger     otellog.Logger
	logger          logr.Logger
}

type WorkloadNetworkPolicyStatusSyncConfig struct {
	AgentPoolConf  grpcexporter.AgentClientPoolConfig
	UpdateInterval time.Duration
	// EventLogger for OTLP policy_violation_acknowledged; nil = disabled.
	EventLogger otellog.Logger
}

func NewWorkloadNetworkPolicyStatusSync(
	c client.Client,
	config *WorkloadNetworkPolicyStatusSyncConfig,
) (*WorkloadNetworkPolicyStatusSync, error) {
	if config.UpdateInterval <= 0 {
		return nil, fmt.Errorf("invalid update interval: %v", config.UpdateInterval)
	}

	agentClientPool, err := grpcexporter.NewAgentClientPool(config.AgentPoolConf)
	if err != nil {
		return nil, fmt.Errorf("failed to create agent client pool: %w", err)
	}

	return &WorkloadNetworkPolicyStatusSync{
		Client:          c,
		agentClientPool: agentClientPool,
		updateInterval:  config.UpdateInterval,
		eventLogger:     config.EventLogger,
	}, nil
}

// Start implements manager.Runnable. Runs the periodic sync loop.
func (r *WorkloadNetworkPolicyStatusSync) Start(ctx context.Context) error {
	r.logger = log.FromContext(ctx).WithName("WorkloadNetworkPolicyStatusSync")
	r.logger.Info("Starting", "interval", r.updateInterval)

	ticker := time.NewTicker(r.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("Closing")
			return nil
		case <-ticker.C:
			if err := r.sync(ctx); err != nil {
				r.logger.Error(err, "Failed to sync")
			}
		}
	}
}

// sync runs one cycle: discover agents, scrape, correlate, patch.
func (r *WorkloadNetworkPolicyStatusSync) sync(ctx context.Context) error {
	var wnpList securityv1alpha1.WorkloadNetworkPolicyList
	if err := r.List(ctx, &wnpList); err != nil {
		return fmt.Errorf("failed to list WorkloadNetworkPolicies: %w", err)
	}
	if len(wnpList.Items) == 0 {
		r.logger.V(1).Info("No WorkloadNetworkPolicies found, skipping sync")
		return nil
	}

	// Build index of WNP by NamespacedName for quick lookup.
	wnpByKey := make(map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy, len(wnpList.Items))
	for i := range wnpList.Items {
		key := types.NamespacedName{Namespace: wnpList.Items[i].Namespace, Name: wnpList.Items[i].Name}
		wnpByKey[key] = &wnpList.Items[i]
	}

	// Build ownership index: NetworkPolicy key -> owning WNP key.
	ownedIndex, err := r.buildOwnershipIndex(ctx, wnpByKey)
	if err != nil {
		return fmt.Errorf("failed to build ownership index: %w", err)
	}

	clients, err := r.agentClientPool.UpdatePool(ctx, r.Client)
	if err != nil {
		return fmt.Errorf("failed to update agent client pool: %w", err)
	}

	scraped := r.scrapeAllNodes(ctx, clients)

	// Group scraped violations by the owning WNP
	violationsByWNP := r.correlateViolationsToWNPs(ctx, scraped, ownedIndex)

	// Process every WNP: those with scraped violations get them merged;
	// those without still get clearAllowedViolations + acknowledgeViolationsFromAnnotations.
	for key, wnp := range wnpByKey {
		if err = r.processWorkloadNetworkPolicy(ctx, wnp, violationsByWNP[key]); err != nil {
			r.logger.Error(err, "Failed to process WorkloadNetworkPolicy",
				"policy", key)
		}
	}

	return nil
}

// buildOwnershipIndex maps NetworkPolicy keys to their owning WNP key.
func (r *WorkloadNetworkPolicyStatusSync) buildOwnershipIndex(
	ctx context.Context,
	wnpByKey map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy,
) (map[types.NamespacedName]types.NamespacedName, error) {
	var npList networkingv1.NetworkPolicyList
	if err := r.List(ctx, &npList); err != nil {
		return nil, fmt.Errorf("failed to list NetworkPolicies: %w", err)
	}

	apiVersion := securityv1alpha1.GroupVersion.String()
	wnpKind := "WorkloadNetworkPolicy"

	index := make(map[types.NamespacedName]types.NamespacedName, len(npList.Items))
	for _, np := range npList.Items {
		npKey := types.NamespacedName{Namespace: np.Namespace, Name: np.Name}
		if wnpKey, ok := findWNPOwnerRef(
			np.OwnerReferences, np.Namespace, apiVersion, wnpKind, wnpByKey,
		); ok {
			index[npKey] = wnpKey
		}
	}
	return index, nil
}

// findWNPOwnerRef returns the owning WNP NamespacedName from a
// NetworkPolicy's OwnerReferences that matches a known WNP.
func findWNPOwnerRef(
	refs []metav1.OwnerReference,
	namespace, apiVersion, kind string,
	wnpByKey map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy,
) (types.NamespacedName, bool) {
	for _, ref := range refs {
		if ref.Controller != nil && *ref.Controller &&
			ref.APIVersion == apiVersion &&
			ref.Kind == kind {
			wnpKey := types.NamespacedName{Namespace: namespace, Name: ref.Name}
			if _, ok := wnpByKey[wnpKey]; ok {
				return wnpKey, true
			}
		}
	}
	return types.NamespacedName{}, false
}

// scrapeAllNodes scrapes violations from all reachable nodes;
// unreachable nodes are marked stale.
func (r *WorkloadNetworkPolicyStatusSync) scrapeAllNodes(
	ctx context.Context,
	clients map[string]grpcexporter.AgentClientAPI,
) []*agentv1.ViolationRecord {
	var all []*agentv1.ViolationRecord

	for nodeName, client := range clients {
		if client == nil {
			r.logger.V(1).Info("Skipping unreachable node", "node", nodeName)
			continue
		}

		violations, err := client.ScrapeViolations(ctx)
		if err != nil {
			r.agentClientPool.MarkStaleAgentClient(nodeName)
			r.logger.Error(err, "Failed to scrape violations", "node", nodeName)
			continue
		}

		all = append(all, violations...)
	}

	return all
}

// correlateViolationsToWNPs groups scraped violations by the owning WNP.
// Violations with no owning WNP are dropped; deleted denying NetPols log a warning.
func (r *WorkloadNetworkPolicyStatusSync) correlateViolationsToWNPs(
	ctx context.Context,
	scraped []*agentv1.ViolationRecord,
	ownedIndex map[types.NamespacedName]types.NamespacedName,
) map[types.NamespacedName][]securityv1alpha1.ViolationRecord {
	result := make(map[types.NamespacedName][]securityv1alpha1.ViolationRecord)
	missingChecked := make(map[types.NamespacedName]struct{})

	for _, v := range scraped {
		npKey := types.NamespacedName{
			Namespace: v.GetDenyingPolicyNamespace(),
			Name:      v.GetDenyingPolicyName(),
		}

		// Scenario 1: NetworkPolicy exists and is owned by a WNP.
		if wnpKey, ok := ownedIndex[npKey]; ok {
			rec := convertProtoViolation(v)
			result[wnpKey] = append(result[wnpKey], rec)
			continue
		}

		// Scenarios 2 & 3: NP not in ownership index.
		if npKey.Name == "" {
			continue
		}
		if _, seen := missingChecked[npKey]; seen {
			continue
		}
		missingChecked[npKey] = struct{}{}

		// Scenario 2: NetworkPolicy was deleted — log a warning.
		// Scenario 3: NetworkPolicy exists but isn't ours — do nothing.
		var np networkingv1.NetworkPolicy
		if err := r.Get(ctx, npKey, &np); err != nil {
			if apierrors.IsNotFound(err) {
				r.logger.Info("Denying NetworkPolicy not found; violation may be orphaned",
					"networkPolicy", npKey.String())
			}
		}
	}

	return result
}

// convertProtoViolation converts a protobuf ViolationRecord to the API type.
func convertProtoViolation(v *agentv1.ViolationRecord) securityv1alpha1.ViolationRecord {
	ownerKind, ownerName := parseWorkload(v.GetSourceWorkloads())
	if ownerName == "" {
		ownerName = v.GetSourceName()
	}
	source := securityv1alpha1.WorkloadRef{
		Namespace: v.GetSourceNamespace(),
		OwnerKind: ownerKind,
		OwnerName: ownerName,
	}

	destKind, destName := parseWorkload(v.GetDestWorkloads())
	if destName == "" {
		destName = v.GetDestName()
	}
	dest := securityv1alpha1.WorkloadRef{
		Namespace: v.GetDestNamespace(),
		OwnerKind: destKind,
		OwnerName: destName,
	}

	return securityv1alpha1.ViolationRecord{
		Timestamp:              metav1.NewTime(v.GetTimestamp().AsTime()),
		NodeName:               v.GetNodeName(),
		Direction:              v.GetDirection(),
		Source:                 source,
		Dest:                   dest,
		Protocol:               corev1.Protocol(v.GetProtocol()),
		DstPort:                v.GetDstPort(),
		Action:                 v.GetAction(),
		DenyingPolicyNamespace: v.GetDenyingPolicyNamespace(),
		DenyingPolicyName:      v.GetDenyingPolicyName(),
	}
}

// parseWorkload splits the first element of workloads at the first '/'.
// Returns (kind, name) or ("", workload) if no separator is found.
func parseWorkload(workloads []string) (string, string) {
	if len(workloads) == 0 {
		return "", ""
	}
	wl := workloads[0]
	const splitParts = 2
	parts := strings.SplitN(wl, "/", splitParts)
	if len(parts) == splitParts {
		return parts[0], parts[1]
	}
	return "", wl
}

// processWorkloadNetworkPolicy patches status then annotations using a
// MergeFrom base. Acknowledged-violation OTLP logs are emitted only after
// the status patch succeeds (ordering guard — prevents duplicate logs on
// retry), matching the runtime-enforcer approach.
func (r *WorkloadNetworkPolicyStatusSync) processWorkloadNetworkPolicy(
	ctx context.Context,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
	violations []securityv1alpha1.ViolationRecord,
) error {
	now := metav1.NewTime(time.Now())

	patchBase := client.MergeFrom(wnp.DeepCopy())
	newPolicy := wnp.DeepCopy()

	acknowledged := newPolicy.RecomputeStatus(violations, now)

	r.logger.V(1).Info("Updating WorkloadNetworkPolicy status",
		"policy", wnp.NamespacedName(),
		"violations", len(violations),
		"acknowledged", len(acknowledged),
		"activeCount", newPolicy.Status.ActiveViolationCount)

	if err := r.Status().Patch(ctx, newPolicy.DeepCopy(), patchBase); err != nil {
		return fmt.Errorf("failed to patch WorkloadNetworkPolicy status for %s: %w",
			wnp.NamespacedName(), err)
	}

	r.emitAcknowledgedViolations(ctx, acknowledged)

	if err := r.Patch(ctx, newPolicy.DeepCopy(), patchBase); err != nil {
		return fmt.Errorf("failed to patch WorkloadNetworkPolicy annotations for %s: %w",
			wnp.NamespacedName(), err)
	}

	return nil
}

func (r *WorkloadNetworkPolicyStatusSync) emitAcknowledgedViolations(
	ctx context.Context,
	acknowledgements []securityv1alpha1.AcknowledgedViolationRecord,
) {
	if r.eventLogger == nil {
		return
	}
	for _, ack := range acknowledgements {
		r.emitAcknowledgedViolationOtelLog(ctx, ack)
	}
}

func (r *WorkloadNetworkPolicyStatusSync) emitAcknowledgedViolationOtelLog(
	ctx context.Context,
	ack securityv1alpha1.AcknowledgedViolationRecord,
) {
	if r.eventLogger == nil {
		return
	}

	violation := ack.Violation
	var rec otellog.Record
	rec.SetEventName(EventNamePolicyViolationAcknowledged)
	rec.SetSeverity(otellog.SeverityInfo)
	rec.SetBody(otellog.StringValue(EventNamePolicyViolationAcknowledged))
	rec.SetTimestamp(time.Now())
	rec.AddAttributes(
		otellog.Int64("id", violation.ID),
		otellog.String("timestamp", violation.Timestamp.UTC().Format(time.RFC3339)),
		otellog.String("reason", ack.Reason),
		otellog.String("direction", violation.Direction),
		otellog.String("source.namespace", violation.Source.Namespace),
		otellog.String("source.workload.kind", violation.Source.OwnerKind),
		otellog.String("source.workload.name", violation.Source.OwnerName),
		otellog.String("dest.namespace", violation.Dest.Namespace),
		otellog.String("dest.workload.kind", violation.Dest.OwnerKind),
		otellog.String("dest.workload.name", violation.Dest.OwnerName),
		otellog.String("protocol", string(violation.Protocol)),
		otellog.Int64("dstPort", int64(violation.DstPort)),
		otellog.String("action", violation.Action),
		otellog.String("node.name", violation.NodeName),
		otellog.String("denyingPolicy.namespace", violation.DenyingPolicyNamespace),
		otellog.String("denyingPolicy.name", violation.DenyingPolicyName),
	)

	r.eventLogger.Emit(ctx, rec)
}

var _ manager.Runnable = (*WorkloadNetworkPolicyStatusSync)(nil)
