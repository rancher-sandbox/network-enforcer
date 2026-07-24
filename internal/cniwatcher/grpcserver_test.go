package cniwatcher_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/rancher-sandbox/network-enforcer/internal/cniwatcher"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/rancher-sandbox/network-enforcer/internal/violationbuf"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestGRPCServer_ScrapeViolations_Empty(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	buf := violationbuf.NewBuffer()
	server := cniwatcher.NewGRPCServer(logger, buf)

	resp, err := server.ScrapeViolations(t.Context(), nil)
	require.NoError(t, err)
	require.Empty(t, resp.GetViolations())
}

func TestGRPCServer_ScrapeViolations_WithRecords(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	buf := violationbuf.NewBuffer()

	// Record in chronological order (oldest first, newest last).
	// Drain returns newest first, so ingress (recorded second) should appear first.
	now := time.Now()
	buf.Record(violationbuf.ViolationRecord{
		Timestamp:              now.Add(-time.Second),
		NodeName:               "node1",
		Direction:              "egress",
		SrcNamespace:           "ns1",
		SrcName:                "pod1",
		SrcLabels:              []string{"app=foo"},
		DstNamespace:           "ns2",
		DstName:                "svc1",
		Protocol:               corev1.ProtocolTCP,
		DstPort:                80,
		Action:                 "protect",
		DenyingPolicyNamespace: "ns1",
		DenyingPolicyName:      "deny-all",
	})

	buf.Record(violationbuf.ViolationRecord{
		Timestamp:              now,
		NodeName:               "node1",
		Direction:              "ingress",
		SrcNamespace:           "ns3",
		SrcName:                "pod2",
		DstNamespace:           "ns1",
		DstName:                "pod1",
		Protocol:               corev1.ProtocolUDP,
		DstPort:                53,
		Action:                 "protect",
		DenyingPolicyNamespace: "ns1",
		DenyingPolicyName:      "block-dns",
	})

	server := cniwatcher.NewGRPCServer(logger, buf)

	resp, err := server.ScrapeViolations(t.Context(), nil)
	require.NoError(t, err)
	v := resp.GetViolations()
	require.Len(t, v, 2)

	// Drain returns newest first (by insertion order), so ingress (recorded second) comes first.
	require.Equal(t, "ingress", v[0].GetDirection())
	require.Equal(t, "pod2", v[0].GetSourceName())
	require.Equal(t, "pod1", v[0].GetDestName())
	require.Equal(t, int32(53), v[0].GetDstPort())
	require.Equal(t, "block-dns", v[0].GetDenyingPolicyName())

	require.Equal(t, "egress", v[1].GetDirection())
	require.Equal(t, "pod1", v[1].GetSourceName())
	require.Equal(t, "svc1", v[1].GetDestName())
	require.Equal(t, int32(80), v[1].GetDstPort())
	require.Equal(t, "deny-all", v[1].GetDenyingPolicyName())

	// Second scrape should be empty (buffer was drained).
	resp2, err := server.ScrapeViolations(t.Context(), nil)
	require.NoError(t, err)
	require.Empty(t, resp2.GetViolations())
}

func TestGRPCServer_ScrapeViolations_Shutdown(t *testing.T) {
	// Test that the server shuts down gracefully on context cancel.
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	buf := violationbuf.NewBuffer()

	ctx, cancel := context.WithCancel(t.Context())

	errCh := make(chan error, 1)
	go func() {
		errCh <- cniwatcher.StartGRPCServer(ctx, logger, buf, cniwatcher.GRPCServerConfig{Port: 0})
	}()

	// Give a moment for the server to start listening, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Should return nil when context is cancelled.
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for gRPC server to shut down")
	}
}

func TestGRPCServer_Start_InvalidCertDir(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	buf := violationbuf.NewBuffer()

	config := cniwatcher.GRPCServerConfig{
		Port:    0,
		CertDir: t.TempDir(), // non-empty dir but missing tls.crt/tls.key
	}

	err := cniwatcher.StartGRPCServer(t.Context(), logger, buf, config)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to create mTLS credentials")
}

func TestProcessPolicyDenyEvent_RecordsToBuffer(t *testing.T) {
	// Verify that ProcessPolicyDenyEvent records into the buffer alongside the OTEL emit.
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	buf := violationbuf.NewBuffer()

	watcher := &cniwatcher.Watcher{
		Ctx:             t.Context(),
		Log:             logger,
		ViolationBuffer: buf,
	}

	event := &types.PolicyDenyEvent{
		Timestamp:    1234567890,
		NodeName:     "test-node",
		CNIType:      "calico",
		Protocol:     corev1.Protocol("tcp"), // we put a lower case on purpose to check if it gets normalized
		SrcNamespace: "ns1",
		SrcName:      "pod1",
		DstNamespace: "ns2",
		DstName:      "svc1",
		DstPort:      443,
		EgressEnforcedBy: []types.Policy{
			{Name: "deny-all", Namespace: "ns1"},
		},
	}

	err := watcher.ProcessPolicyDenyEvent(event)
	// Should error because OtelService is nil...
	require.Error(t, err)
	// ...but buffer should have the record.
	records := buf.Drain()
	require.Len(t, records, 1)
	require.Equal(t, "egress", records[0].Direction)
	require.Equal(t, "pod1", records[0].SrcName)
	require.Equal(t, "svc1", records[0].DstName)
	require.Equal(t, corev1.ProtocolTCP, records[0].Protocol)
	require.Equal(t, int32(443), records[0].DstPort)
	require.Equal(t, "protect", records[0].Action)
	require.Equal(t, "deny-all", records[0].DenyingPolicyName)
	require.Equal(t, "ns1", records[0].DenyingPolicyNamespace)
}
