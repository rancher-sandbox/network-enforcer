package topology

import (
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
)

type Store struct {
	mu      sync.RWMutex
	egress  map[WorkloadKey]sets.Set[Peer]
	ingress map[WorkloadKey]sets.Set[Peer]
}

func NewStore() *Store {
	return &Store{
		egress:  make(map[WorkloadKey]sets.Set[Peer]),
		ingress: make(map[WorkloadKey]sets.Set[Peer]),
	}
}

func (s *Store) Record(f *FlowRecord) {
	egressPeer := Peer{
		WorkloadKey: f.Dest,
		DstPort:     f.DstPort,
		Protocol:    f.Protocol,
	}
	ingressPeer := Peer{
		WorkloadKey: f.Source,
		DstPort:     f.DstPort,
		Protocol:    f.Protocol,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.egress[f.Source]; !ok {
		s.egress[f.Source] = sets.New[Peer]()
	}
	s.egress[f.Source].Insert(egressPeer)

	if _, ok := s.ingress[f.Dest]; !ok {
		s.ingress[f.Dest] = sets.New[Peer]()
	}
	s.ingress[f.Dest].Insert(ingressPeer)
}

func (s *Store) DrainFlows() *WorkloadConnections {
	s.mu.Lock()
	defer s.mu.Unlock()

	connections := &WorkloadConnections{
		Egress:  s.egress,
		Ingress: s.ingress,
	}

	s.egress = make(map[WorkloadKey]sets.Set[Peer])
	s.ingress = make(map[WorkloadKey]sets.Set[Peer])

	return connections
}
