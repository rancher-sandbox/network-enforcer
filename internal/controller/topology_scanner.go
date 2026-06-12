package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	securityv1alpha1 "secuity.rancher.io/network-enforcer/api/v1alpha1"
	"secuity.rancher.io/network-enforcer/internal/topology"
)

type TopologyScanner struct {
	client   client.Client
	store    *topology.Store
	log      *slog.Logger
	interval time.Duration
}

func NewTopologyScanner(c client.Client, store *topology.Store, logger *slog.Logger) *TopologyScanner {
	return &TopologyScanner{
		client:   c,
		store:    store,
		log:      logger.With("component", "topology-scanner"),
		interval: 30 * time.Second,
	}
}

func (ts *TopologyScanner) Start(ctx context.Context) error {
	ts.log.InfoContext(ctx, "starting", "interval", ts.interval)

	ticker := time.NewTicker(ts.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			ts.scan(ctx)
		}
	}
}

func getProposalMetadata(
	workload topology.WorkloadKey,
	direction networkingv1.PolicyType,
) *securityv1alpha1.NetworkPolicyProposal {
	return &securityv1alpha1.NetworkPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf(
				"%s-%s-%s",
				strings.ToLower(workload.OwnerKind),
				workload.OwnerName,
				strings.ToLower(string(direction)),
			),
			Namespace: workload.Namespace,
		},
	}
}

func (ts *TopologyScanner) scan(ctx context.Context) {
	connections := ts.store.DrainFlows()
	ts.log.InfoContext(
		ctx,
		"Drain flows",
		"egress policies",
		len(connections.Egress),
		"ingress policies",
		len(connections.Ingress),
	)
	for workload, peers := range connections.Egress {
		ts.log.InfoContext(
			ctx,
			"Reconciling egress proposal",
			"namespace",
			workload.Namespace,
			"kind",
			workload.OwnerKind,
			"name",
			workload.OwnerName,
			"peers",
			len(peers),
		)
		if err := ts.reconcileProposal(ctx, workload, networkingv1.PolicyTypeEgress, peers); err != nil {
			ts.log.WarnContext(
				ctx,
				"Could not reconcile egress proposal",
				"namespace",
				workload.Namespace,
				"kind",
				workload.OwnerKind,
				"name",
				workload.OwnerName,
				"error",
				err,
			)
		}
	}

	for workload, peers := range connections.Ingress {
		ts.log.InfoContext(
			ctx,
			"Reconciling ingress proposal",
			"namespace",
			workload.Namespace,
			"kind",
			workload.OwnerKind,
			"name",
			workload.OwnerName,
			"peers",
			len(peers),
		)
		if err := ts.reconcileProposal(ctx, workload, networkingv1.PolicyTypeIngress, peers); err != nil {
			ts.log.WarnContext(
				ctx,
				"Could not reconcile ingress proposal",
				"namespace",
				workload.Namespace,
				"kind",
				workload.OwnerKind,
				"name",
				workload.OwnerName,
				"error",
				err,
			)
		}
	}
}

func (ts *TopologyScanner) reconcileProposal(
	ctx context.Context,
	workload topology.WorkloadKey,
	direction networkingv1.PolicyType,
	deltaPeers sets.Set[topology.Peer],
) error {
	if deltaPeers == nil || deltaPeers.Len() == 0 {
		return errors.New("no peers associated to the workload")
	}
	proposal := getProposalMetadata(workload, direction)
	_, err := controllerutil.CreateOrUpdate(ctx, ts.client, proposal, func() error {
		// we recompute the selector only if we are creating the resource the first time.
		// we could continuously recompute the selector if we want to keep track of updates.
		// the policyTypes should be empty only when the resource is new.
		if len(proposal.Spec.PolicyTypes) == 0 {
			workloadSelector, err := selectorFromWorkloadKey(ctx, ts.client, workload)
			if err != nil {
				return fmt.Errorf("resolving workload selector: %w", err)
			}
			proposal.Spec.PodSelector = workloadSelector
			proposal.Spec.PolicyTypes = []networkingv1.PolicyType{direction}
		}

		if err := ts.buildSpec(ctx, direction, &proposal.Spec, deltaPeers); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("create or update proposal %s/%s: %w", proposal.Namespace, proposal.Name, err)
	}

	return nil
}

func findEgressPeer(
	newRule networkingv1.NetworkPolicyEgressRule,
	existing []networkingv1.NetworkPolicyEgressRule,
) bool {
	for _, peer := range existing {
		// todo!: this should be fixed, the order of the internal slices could be different
		if reflect.DeepEqual(peer, newRule) {
			return true
		}
	}
	return false
}

func findIngressPeer(
	newRule networkingv1.NetworkPolicyIngressRule,
	existing []networkingv1.NetworkPolicyIngressRule,
) bool {
	for _, peer := range existing {
		if reflect.DeepEqual(peer, newRule) {
			return true
		}
	}
	return false
}

func (ts *TopologyScanner) buildSpec(
	ctx context.Context,
	direction networkingv1.PolicyType,
	spec *networkingv1.NetworkPolicySpec,
	deltaPeers sets.Set[topology.Peer],
) error {
	switch direction {
	case networkingv1.PolicyTypeEgress:
		deltaRules, err := ts.buildEgressRules(ctx, deltaPeers)
		if err != nil {
			return err
		}
		for _, rule := range deltaRules {
			if findEgressPeer(rule, spec.Egress) {
				continue
			}
			spec.Egress = append(spec.Egress, rule)
		}
	case networkingv1.PolicyTypeIngress:
		deltaRules, err := ts.buildIngressRules(ctx, deltaPeers)
		if err != nil {
			return err
		}

		for _, rule := range deltaRules {
			if findIngressPeer(rule, spec.Ingress) {
				continue
			}
			spec.Ingress = append(spec.Ingress, rule)
		}
	default:
		return fmt.Errorf("unknown direction: %s", direction)
	}

	return nil
}

func (ts *TopologyScanner) buildEgressRules(
	ctx context.Context,
	peers sets.Set[topology.Peer],
) ([]networkingv1.NetworkPolicyEgressRule, error) {
	peerList := peers.UnsortedList()

	rules := make([]networkingv1.NetworkPolicyEgressRule, 0, len(peerList))
	for _, peer := range peerList {
		peerSelector, err := selectorFromWorkloadKey(ctx, ts.client, peer.WorkloadKey)
		if err != nil {
			return nil, fmt.Errorf("resolving egress peer selector: %w", err)
		}

		port := intstr.FromInt32(peer.DstPort)
		rules = append(rules, networkingv1.NetworkPolicyEgressRule{
			To: []networkingv1.NetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"kubernetes.io/metadata.name": peer.Namespace,
					},
				},
				PodSelector: &peerSelector,
			}},
			Ports: []networkingv1.NetworkPolicyPort{{
				Protocol: &peer.Protocol,
				Port:     &port,
			}},
		})
	}

	return rules, nil
}

func (ts *TopologyScanner) buildIngressRules(
	ctx context.Context,
	peers sets.Set[topology.Peer],
) ([]networkingv1.NetworkPolicyIngressRule, error) {
	peerList := peers.UnsortedList()

	rules := make([]networkingv1.NetworkPolicyIngressRule, 0, len(peerList))
	for _, peer := range peerList {
		peerSelector, err := selectorFromWorkloadKey(ctx, ts.client, peer.WorkloadKey)
		if err != nil {
			return nil, fmt.Errorf("resolving ingress peer selector: %w", err)
		}

		port := intstr.FromInt32(peer.DstPort)
		rules = append(rules, networkingv1.NetworkPolicyIngressRule{
			From: []networkingv1.NetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"kubernetes.io/metadata.name": peer.Namespace,
					},
				},
				PodSelector: &peerSelector,
			}},
			Ports: []networkingv1.NetworkPolicyPort{{
				Protocol: &peer.Protocol,
				Port:     &port,
			}},
		})
	}

	return rules, nil
}
