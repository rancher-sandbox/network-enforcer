package v1alpha1

import (
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	DirectionEgress  = "egress"
	DirectionIngress = "ingress"
)

// annotationInfo groups an annotation key with its acknowledge-reason pair.
type annotationInfo struct {
	annotationKey string
	reason        string
}

// ViolationRecordKey is the dedup key for recognising the same logical violation across scrapes.
type ViolationRecordKey struct {
	Direction              string
	SrcNamespace           string
	SrcOwnerKind           string
	SrcOwnerName           string
	DstNamespace           string
	DstOwnerKind           string
	DstOwnerName           string
	Protocol               string
	DstPort                int32
	Action                 WorkloadNetworkPolicyMode
	DenyingPolicyNamespace string
	DenyingPolicyName      string
}

// Key returns the dedup key for a ViolationRecord.
func (v ViolationRecord) Key() ViolationRecordKey {
	return ViolationRecordKey{
		Direction:              v.Direction,
		SrcNamespace:           v.Source.Namespace,
		SrcOwnerKind:           v.Source.OwnerKind,
		SrcOwnerName:           v.Source.OwnerName,
		DstNamespace:           v.Dest.Namespace,
		DstOwnerKind:           v.Dest.OwnerKind,
		DstOwnerName:           v.Dest.OwnerName,
		Protocol:               string(v.Protocol),
		DstPort:                v.DstPort,
		Action:                 v.Action,
		DenyingPolicyNamespace: v.DenyingPolicyNamespace,
		DenyingPolicyName:      v.DenyingPolicyName,
	}
}

// clearAllowedViolations drops violations whose flow matches a policyTemplate
// rule via exact structural comparison (EgressRuleEqual / IngressRuleEqual).
func (wnp *WorkloadNetworkPolicy) clearAllowedViolations() {
	wnp.Status.Violations = slices.DeleteFunc(wnp.Status.Violations, func(v ViolationRecord) bool {
		switch v.Direction {
		case DirectionEgress:
			for _, rule := range wnp.Spec.PolicyTemplate.Egress {
				if EgressRuleEqual(v.ToEgressRule(), rule) {
					return true
				}
			}
		case DirectionIngress:
			for _, rule := range wnp.Spec.PolicyTemplate.Ingress {
				if IngressRuleEqual(v.ToIngressRule(), rule) {
					return true
				}
			}
		}
		return false
	})
}

// ToEgressRule builds an egress rule from the violation for comparison.
func (v ViolationRecord) ToEgressRule() networkingv1.NetworkPolicyEgressRule {
	port := intstr.FromInt32(v.DstPort)
	proto := v.Protocol

	return networkingv1.NetworkPolicyEgressRule{
		To: []networkingv1.NetworkPolicyPeer{
			{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						corev1.LabelMetadataName: v.Dest.Namespace,
					},
				},
			},
		},
		Ports: []networkingv1.NetworkPolicyPort{
			{
				Protocol: &proto,
				Port:     &port,
			},
		},
	}
}

// ToIngressRule builds an ingress rule from the violation for comparison.
func (v ViolationRecord) ToIngressRule() networkingv1.NetworkPolicyIngressRule {
	port := intstr.FromInt32(v.DstPort)
	proto := v.Protocol

	return networkingv1.NetworkPolicyIngressRule{
		From: []networkingv1.NetworkPolicyPeer{
			{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						corev1.LabelMetadataName: v.Source.Namespace,
					},
				},
			},
		},
		Ports: []networkingv1.NetworkPolicyPort{
			{
				Protocol: &proto,
				Port:     &port,
			},
		},
	}
}

// mergeScrapedViolations merges scraped violations into the status with dedup.
// New records get the next monotonic ID; ViolationCount bumps for every observed record.
func (s *WorkloadNetworkPolicyStatus) mergeScrapedViolations(scraped []ViolationRecord) {
	indexByKey := make(map[ViolationRecordKey]int, len(s.Violations))
	for i, r := range s.Violations {
		indexByKey[r.Key()] = i
	}

	for _, v := range scraped {
		key := v.Key()
		if idx, ok := indexByKey[key]; ok {
			// Refresh timestamp only if newer.
			if v.Timestamp.Time.After(s.Violations[idx].Timestamp.Time) {
				s.Violations[idx].Timestamp = v.Timestamp
			}
		} else {
			v.ID = s.ViolationCount
			s.Violations = append(s.Violations, v)
			indexByKey[key] = len(s.Violations) - 1
		}
		s.ViolationCount++
	}

	// Newest-first sort.
	slices.SortStableFunc(s.Violations, func(a, b ViolationRecord) int {
		return b.Timestamp.Time.Compare(a.Timestamp.Time)
	})

	if len(s.Violations) > MaxViolationRecords {
		s.Violations = s.Violations[:MaxViolationRecords]
	}
}

// acknowledgeViolationsFromAnnotations processes security.rancher.io/acknowledge-<id>
// annotations and moves matching violations into AcknowledgedViolations.
func (wnp *WorkloadNetworkPolicy) acknowledgeViolationsFromAnnotations(now metav1.Time) []AcknowledgedViolationRecord {
	annotations := wnp.GetAnnotations()
	if len(annotations) == 0 {
		return nil
	}

	acknowledges := make(map[int64]annotationInfo, len(annotations))

	for k, reason := range annotations {
		idStr, found := strings.CutPrefix(k, ViolationAcknowledgePrefix)
		if !found {
			continue
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			continue
		}

		acknowledges[id] = annotationInfo{
			annotationKey: k,
			reason:        reason,
		}
	}

	if len(acknowledges) == 0 {
		return nil
	}

	if wnp.Status.AcknowledgedViolations == nil {
		wnp.Status.AcknowledgedViolations = make([]AcknowledgedViolationRecord, 0)
	}

	ackToReturn := make([]AcknowledgedViolationRecord, 0)

	wnp.Status.Violations = slices.DeleteFunc(wnp.Status.Violations, func(v ViolationRecord) bool {
		info, ok := acknowledges[v.ID]
		if !ok {
			return false
		}
		delete(annotations, info.annotationKey)

		newAcknowledgement := AcknowledgedViolationRecord{
			Violation:      v,
			Reason:         info.reason,
			AcknowledgedAt: now,
		}
		ackToReturn = append(ackToReturn, newAcknowledgement)
		wnp.Status.AcknowledgedViolations = append(wnp.Status.AcknowledgedViolations, newAcknowledgement)
		return true
	})

	// Newest-first sort.
	slices.SortStableFunc(wnp.Status.AcknowledgedViolations, func(a, b AcknowledgedViolationRecord) int {
		return b.AcknowledgedAt.Time.Compare(a.AcknowledgedAt.Time)
	})

	if len(wnp.Status.AcknowledgedViolations) > MaxViolationRecords {
		wnp.Status.AcknowledgedViolations = wnp.Status.AcknowledgedViolations[:MaxViolationRecords]
	}

	wnp.SetAnnotations(annotations)
	return ackToReturn
}

// RecomputeStatus runs merge → clear → acknowledge and sets ActiveViolationCount
// and ObservedGeneration. Returns newly-acknowledged records.
func (wnp *WorkloadNetworkPolicy) RecomputeStatus(
	scrapedViolations []ViolationRecord,
	now metav1.Time,
) []AcknowledgedViolationRecord {
	if wnp == nil {
		return nil
	}

	wnp.Status.mergeScrapedViolations(scrapedViolations)
	wnp.clearAllowedViolations()
	acknowledged := wnp.acknowledgeViolationsFromAnnotations(now)

	wnp.Status.ActiveViolationCount = int64(len(wnp.Status.Violations))
	wnp.Status.ObservedGeneration = wnp.Generation

	return acknowledged
}
