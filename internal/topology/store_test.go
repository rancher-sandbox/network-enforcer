package topology

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestStore_Record_DeduplicatesSameFlow(t *testing.T) {
	s := NewStore()

	f := &FlowRecord{
		Source:   WorkloadKey{Namespace: "default", OwnerKind: "Deployment", OwnerName: "frontend"},
		Dest:     WorkloadKey{Namespace: "default", OwnerKind: "Deployment", OwnerName: "backend"},
		DstPort:  8080,
		Protocol: corev1.ProtocolTCP,
	}
	s.Record(f)
	s.Record(f)

	adjacency := s.DrainFlows()
	if got := len(adjacency.Egress); got != 1 {
		t.Fatalf("expected 1 egress workload, got %d", got)
	}
	if got := len(adjacency.Ingress); got != 1 {
		t.Fatalf("expected 1 ingress workload, got %d", got)
	}

	sourcePeers := adjacency.Egress[f.Source]
	if sourcePeers.Len() != 1 {
		t.Fatalf("expected 1 deduplicated egress peer, got %d", sourcePeers.Len())
	}

	destPeers := adjacency.Ingress[f.Dest]
	if destPeers.Len() != 1 {
		t.Fatalf("expected 1 deduplicated ingress peer, got %d", destPeers.Len())
	}
}

func TestStore_DrainFlows_ReturnsRecordedFlow(t *testing.T) {
	s := NewStore()
	s.Record(&FlowRecord{
		Source:   WorkloadKey{Namespace: "demo", OwnerKind: "Deployment", OwnerName: "frontend"},
		Dest:     WorkloadKey{Namespace: "demo", OwnerKind: "Deployment", OwnerName: "backend"},
		DstPort:  8080,
		Protocol: corev1.ProtocolTCP,
	})

	adjacency := s.DrainFlows()
	if got := len(adjacency.Egress); got != 1 {
		t.Fatalf("expected 1 drained egress workload, got %d", got)
	}
	if got := len(adjacency.Ingress); got != 1 {
		t.Fatalf("expected 1 drained ingress workload, got %d", got)
	}
}

func TestStore_DrainFlows_DrainsStore(t *testing.T) {
	s := NewStore()
	s.Record(&FlowRecord{
		Source:   WorkloadKey{Namespace: "demo", OwnerKind: "Deployment", OwnerName: "frontend"},
		Dest:     WorkloadKey{Namespace: "demo", OwnerKind: "Deployment", OwnerName: "backend"},
		DstPort:  8080,
		Protocol: corev1.ProtocolTCP,
	})

	first := s.DrainFlows()
	second := s.DrainFlows()

	if len(first.Egress) != 1 || len(first.Ingress) != 1 {
		t.Fatalf(
			"expected first read to contain one egress and one ingress workload, got egress=%d ingress=%d",
			len(first.Egress),
			len(first.Ingress),
		)
	}
	if len(second.Egress) != 0 || len(second.Ingress) != 0 {
		t.Fatalf(
			"expected empty second read after drain, got egress=%d ingress=%d",
			len(second.Egress),
			len(second.Ingress),
		)
	}
}
