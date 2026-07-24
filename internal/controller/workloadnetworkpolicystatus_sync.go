package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
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

type AgentClientPoolAPI interface {
	UpdatePool(ctx context.Context, reader client.Reader) (map[string]grpcexporter.AgentClientAPI, error)
	MarkStaleAgentClient(nodeName string)
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadnetworkpolicies/status,verbs=get;patch;update

// WorkloadNetworkPolicyStatusSync periodically scrapes violation records from
// cniwatcher pods, correlates denies to the owning WorkloadNetworkPolicy, and
// writes status and annotations via a two-phase patch.
type WorkloadNetworkPolicyStatusSync struct {
	client.Client

	agentClientPool AgentClientPoolAPI
	updateInterval  time.Duration
	logger          logr.Logger
}

// WorkloadNetworkPolicyStatusSyncConfig holds the configuration for the sync runnable.
type WorkloadNetworkPolicyStatusSyncConfig struct {
	AgentPoolConf  grpcexporter.AgentClientPoolConfig
	UpdateInterval time.Duration
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
	}, nil
}

// Start implements manager.Runnable. It runs the periodic sync loop until the
// context is cancelled.
func (r *WorkloadNetworkPolicyStatusSync) Start(ctx context.Context) error {
	r.logger = log.FromContext(ctx).WithName("WorkloadNetworkPolicyStatusSync")
	interval := r.updateInterval
	r.logger.Info("Starting with", "interval", interval.String())

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("Closing")
			return nil
		case <-time.After(interval):
			if err := r.sync(ctx); err != nil {
				r.logger.Error(err, "Failed to sync")
			}
		}
	}
}

// sync runs one full sync cycle: discover cniwatcher pods, scrape violations,
// correlate denies to WNPs, and update status + annotations.
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

// buildOwnershipIndex lists all NetworkPolicies and builds a map from
// NetworkPolicy key → owning WNP key. Only NetworkPolicies whose controller
// OwnerReference matches a known WNP are indexed.
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

// findWNPOwnerRef scans the OwnerReferences of a NetworkPolicy and returns
// the NamespacedName of the owning WNP if a matching controller reference
// is found and corresponds to a known WNP in wnpByKey.
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

// scrapeAllNodes iterates over all clients in the pool and scrapes violations
// from reachable nodes. Unreachable nodes are marked stale and skipped.
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

// correlateViolationsToWNPs groups scraped protobuf violations by the WNP
// that owns the denying NetworkPolicy. Violations denied by a NetworkPolicy
// that is not owned by any WNP are dropped. When a violation references a
// denying NetworkPolicy that has been deleted, a warning is logged to help
// operators detect orphaned violations.
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

// parseWorkload extracts the OwnerKind and OwnerName from the first workload
// string in the slice. Workloads are expected in "Kind/Name" format (e.g.
// "Deployment/myapp"). If no separator is found the whole string is treated
// as the name.
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

// processWorkloadNetworkPolicy runs RecomputeStatus and writes the result via
// a two-phase patch: status first, then metadata/annotations. Both patches
// use a MergeFrom base so that any concurrent annotation change made between
// the two calls is preserved. Acknowledged-violation telemetry is stored but
// not emitted here — PR 4 wires the real OTLP log.
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

	if err := r.Patch(ctx, newPolicy.DeepCopy(), patchBase); err != nil {
		return fmt.Errorf("failed to patch WorkloadNetworkPolicy annotations for %s: %w",
			wnp.NamespacedName(), err)
	}

	// Acknowledgement telemetry is stubbed to a no-op in this PR.
	// todo!: wire the real OTLP log emission here.
	_ = acknowledged

	return nil
}

// Ensure WorkloadNetworkPolicyStatusSync implements manager.Runnable.
var _ manager.Runnable = (*WorkloadNetworkPolicyStatusSync)(nil)
