// Package violationbuf provides a thread-safe ring buffer for network violation
// records. It is used by the cniwatcher to buffer per-node deny events locally
// and hand them out on demand via gRPC ScrapeViolations.
package violationbuf

import (
	"sync"
	"time"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

// ViolationRecord is a network-flavoured violation record ready for scraping.
type ViolationRecord struct {
	Timestamp time.Time
	NodeName  string
	Direction string // "egress" or "ingress"

	SrcNamespace string
	SrcName      string
	SrcWorkloads []string
	SrcLabels    []string

	DstNamespace string
	DstName      string
	DstWorkloads []string
	DstLabels    []string

	Protocol corev1.Protocol
	DstPort  int32
	Action   securityv1alpha1.WorkloadNetworkPolicyMode

	DenyingPolicyNamespace string
	DenyingPolicyName      string
}

// MaxBufferEntries is the capacity of the ring buffer. When full, the oldest
// entry is overwritten.
const MaxBufferEntries = 10_000

// Buffer is a thread-safe ring buffer for violation records.
// The cniwatcher calls Record() for each deny event; the gRPC server calls
// Drain() when the controller scrapes.
type Buffer struct {
	mtx sync.Mutex
	buf []ViolationRecord
	pos int
}

func NewBuffer() *Buffer {
	return &Buffer{
		buf: make([]ViolationRecord, MaxBufferEntries),
	}
}

// Record appends a violation to the ring buffer. If the buffer is full,
// the oldest entry is overwritten and dropped is returned as true.
func (b *Buffer) Record(rec ViolationRecord) bool {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	dropped := b.pos >= MaxBufferEntries

	b.buf[b.pos%MaxBufferEntries] = rec
	b.pos++

	return dropped
}

// Drain returns all buffered records in reverse chronological order (newest first)
// and resets the buffer.
func (b *Buffer) Drain() []ViolationRecord {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	n := min(b.pos, MaxBufferEntries)
	if n == 0 {
		return nil
	}

	records := make([]ViolationRecord, 0, n)
	for i := range n {
		idx := (b.pos - 1 - i) % MaxBufferEntries
		records = append(records, b.buf[idx])
	}

	b.pos = 0

	return records
}
