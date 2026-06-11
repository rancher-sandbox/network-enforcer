package flowcollector

import (
	"context"
	"log/slog"
	"testing"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	"secuity.rancher.io/network-enforcer/internal/topology"
)

type testLogWriter struct {
	t *testing.T
}

func (w *testLogWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", string(p))
	return len(p), nil
}

// NewTestLogger returns an [slog.Logger] that writes to t.Logf.
func NewTestLogger(t *testing.T) *slog.Logger {
	return slog.New(slog.NewJSONHandler(&testLogWriter{t: t}, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})).With("component", t.Name())
}

func TestReceiver_Export_AcceptsValidEgressPodToPodFlow(t *testing.T) {
	store := topology.NewStore()
	r := NewReceiver(store, 0, NewTestLogger(t))

	req := metricRequest([]*commonpb.KeyValue{
		strAttr("iface.direction", "egress"),
		strAttr("k8s.src.namespace", "demo"),
		strAttr("k8s.src.owner.type", "Deployment"),
		strAttr("k8s.src.owner.name", "frontend"),
		strAttr("k8s.dst.namespace", "demo"),
		strAttr("k8s.dst.owner.type", "Deployment"),
		strAttr("k8s.dst.owner.name", "backend"),
		strAttr("dst.port", "8080"),
		strAttr("transport", "TCP"),
		strAttr("src.address", "10.0.0.1"),
		strAttr("dst.address", "10.0.0.2"),
	})

	if _, err := r.Export(context.Background(), req); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	adjacency := store.DrainFlows()
	if got := len(adjacency.Egress); got != 1 {
		t.Fatalf("expected 1 source workload from one recorded datapoint, got %d", got)
	}
	if got := len(adjacency.Ingress); got != 1 {
		t.Fatalf("expected 1 destination workload from one recorded datapoint, got %d", got)
	}
}

func TestReceiver_Export_DropsIngressFlow(t *testing.T) {
	store := topology.NewStore()
	r := NewReceiver(store, 0, NewTestLogger(t))

	req := metricRequest([]*commonpb.KeyValue{
		strAttr("iface.direction", "ingress"),
		strAttr("k8s.src.namespace", "demo"),
		strAttr("k8s.src.owner.type", "Deployment"),
		strAttr("k8s.src.owner.name", "frontend"),
		strAttr("k8s.dst.namespace", "demo"),
		strAttr("k8s.dst.owner.type", "Deployment"),
		strAttr("k8s.dst.owner.name", "backend"),
		strAttr("dst.port", "8080"),
		strAttr("transport", "TCP"),
	})

	if _, err := r.Export(context.Background(), req); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	adjacency := store.DrainFlows()
	if got := len(adjacency.Egress); got != 0 {
		t.Fatalf("expected 0 egress workloads for ingress datapoint, got %d", got)
	}
	if got := len(adjacency.Ingress); got != 0 {
		t.Fatalf("expected 0 ingress workloads for ingress datapoint, got %d", got)
	}
}

func TestReceiver_Export_DropsServiceDestination(t *testing.T) {
	store := topology.NewStore()
	r := NewReceiver(store, 0, NewTestLogger(t))

	req := metricRequest([]*commonpb.KeyValue{
		strAttr("iface.direction", "egress"),
		strAttr("k8s.src.namespace", "demo"),
		strAttr("k8s.src.owner.type", "Deployment"),
		strAttr("k8s.src.owner.name", "frontend"),
		strAttr("k8s.dst.namespace", "demo"),
		strAttr("k8s.dst.owner.type", "Service"),
		strAttr("k8s.dst.owner.name", "backend"),
		strAttr("dst.port", "8080"),
		strAttr("transport", "TCP"),
	})

	if _, err := r.Export(context.Background(), req); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	adjacency := store.DrainFlows()
	if got := len(adjacency.Egress); got != 0 {
		t.Fatalf("expected 0 egress workloads for service destination, got %d", got)
	}
	if got := len(adjacency.Ingress); got != 0 {
		t.Fatalf("expected 0 ingress workloads for service destination, got %d", got)
	}
}

func TestReceiver_Export_DropsInvalidPort(t *testing.T) {
	store := topology.NewStore()
	r := NewReceiver(store, 0, NewTestLogger(t))

	req := metricRequest([]*commonpb.KeyValue{
		strAttr("iface.direction", "egress"),
		strAttr("k8s.src.namespace", "demo"),
		strAttr("k8s.src.owner.type", "Deployment"),
		strAttr("k8s.src.owner.name", "frontend"),
		strAttr("k8s.dst.namespace", "demo"),
		strAttr("k8s.dst.owner.type", "Deployment"),
		strAttr("k8s.dst.owner.name", "backend"),
		strAttr("dst.port", "not-a-port"),
		strAttr("transport", "TCP"),
	})

	if _, err := r.Export(context.Background(), req); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	adjacency := store.DrainFlows()
	if got := len(adjacency.Egress); got != 0 {
		t.Fatalf("expected 0 egress workloads for invalid port, got %d", got)
	}
	if got := len(adjacency.Ingress); got != 0 {
		t.Fatalf("expected 0 ingress workloads for invalid port, got %d", got)
	}
}

func TestReceiver_Export_DropsLowercaseProtocol(t *testing.T) {
	store := topology.NewStore()
	r := NewReceiver(store, 0, NewTestLogger(t))

	req := metricRequest([]*commonpb.KeyValue{
		strAttr("iface.direction", "egress"),
		strAttr("k8s.src.namespace", "demo"),
		strAttr("k8s.src.owner.type", "Deployment"),
		strAttr("k8s.src.owner.name", "frontend"),
		strAttr("k8s.dst.namespace", "demo"),
		strAttr("k8s.dst.owner.type", "Deployment"),
		strAttr("k8s.dst.owner.name", "backend"),
		strAttr("dst.port", "8080"),
		strAttr("transport", "tcp"),
	})

	if _, err := r.Export(context.Background(), req); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	adjacency := store.DrainFlows()
	if got := len(adjacency.Egress); got != 0 {
		t.Fatalf("expected 0 egress workloads for lowercase protocol, got %d", got)
	}
	if got := len(adjacency.Ingress); got != 0 {
		t.Fatalf("expected 0 ingress workloads for lowercase protocol, got %d", got)
	}
}

func metricRequest(attrs []*commonpb.KeyValue) *colmetricspb.ExportMetricsServiceRequest {
	return &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{
			{
				Resource: &resourcepb.Resource{},
				ScopeMetrics: []*metricspb.ScopeMetrics{
					{
						Metrics: []*metricspb.Metric{
							{
								Name: targetMetricName,
								Data: &metricspb.Metric_Sum{
									Sum: &metricspb.Sum{
										DataPoints: []*metricspb.NumberDataPoint{
											{
												Value:      &metricspb.NumberDataPoint_AsInt{AsInt: 1},
												Attributes: attrs,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func strAttr(key, value string) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key: key,
		Value: &commonpb.AnyValue{
			Value: &commonpb.AnyValue_StringValue{StringValue: value},
		},
	}
}
