package topology

import (
	"k8s.io/apimachinery/pkg/util/sets"

	corev1 "k8s.io/api/core/v1"
)

type WorkloadKey struct {
	Namespace string
	OwnerKind string
	OwnerName string
}

type FlowRecord struct {
	Source     WorkloadKey
	Dest       WorkloadKey
	DstPort    int32
	Protocol   corev1.Protocol
	SrcAddress string
	DstAddress string
}

type FlowKey struct {
	Source   WorkloadKey
	Dest     WorkloadKey
	DstPort  int32
	Protocol corev1.Protocol
}

type Peer struct {
	WorkloadKey

	DstPort  int32
	Protocol corev1.Protocol
}

type WorkloadConnections struct {
	Egress  map[WorkloadKey]sets.Set[Peer]
	Ingress map[WorkloadKey]sets.Set[Peer]
}
