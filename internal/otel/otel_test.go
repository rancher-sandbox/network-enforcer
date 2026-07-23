package otel_test

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/rancher-sandbox/network-enforcer/internal/otel"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/logtest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestOtelService_Start(t *testing.T) {
	ctx := t.Context()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := otel.OpenTelemetryConfig{
		Ctx:               ctx,
		Log:               logger,
		CollectorEndpoint: "localhost:4317",
	}
	service := otel.NewOpenTelemetryService(cfg)

	err := service.Start()
	if err != nil {
		t.Logf("Expected error in test environment: %v", err)
	} else {
		t.Logf("OpenTelemetry started successfully in test environment")
	}
}

func TestOtelService_EmitPolicyDenyEvent(t *testing.T) {
	ctx := t.Context()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ts := time.Unix(1700000000, 0)

	tests := []struct {
		name           string
		initLogger     bool
		event          *types.PolicyDenyEvent
		wantErr        bool
		wantAttributes []otellog.KeyValue
	}{
		{
			name: "uninitialized",
			event: &types.PolicyDenyEvent{
				Timestamp:    ts.Unix(),
				NodeName:     "test-node",
				CNIType:      "test-cni",
				Protocol:     "TCP",
				SrcNamespace: "default",
				SrcName:      "test-pod",
				DstNamespace: "default",
				DstName:      "test-service",
			},
			wantErr: true,
		},
		{
			name:       "emits full record",
			initLogger: true,
			event: &types.PolicyDenyEvent{
				Timestamp:    ts.Unix(),
				NodeName:     "node-1",
				CNIType:      "cilium",
				Protocol:     "TCP",
				SrcNamespace: "src-ns",
				SrcName:      "src-pod",
				SrcLabels:    []string{"app=frontend"},
				SrcWorkloads: []string{"Deployment/frontend"},
				DstNamespace: "dst-ns",
				DstName:      "dst-pod",
				DstLabels:    []string{"app=backend"},
				DstWorkloads: []string{"Deployment/backend"},
				DstPort:      8080,
				EgressEnforcedBy: []types.Policy{{
					TypeMeta:  metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"},
					Name:      "deny-egress",
					Namespace: "src-ns",
				}},
				IngressEnforcedBy: []types.Policy{{
					TypeMeta:  metav1.TypeMeta{APIVersion: "cilium.io/v2", Kind: "CiliumNetworkPolicy"},
					Name:      "deny-ingress",
					Namespace: "dst-ns",
				}},
			},
			wantAttributes: []otellog.KeyValue{
				otellog.String("cni.type", "cilium"),
				otellog.String("network.protocol", "TCP"),
				otellog.String("node.name", "node-1"),
				otellog.String("source.namespace", "src-ns"),
				otellog.String("source.name", "src-pod"),
				otellog.Slice("source.labels", otellog.StringValue("app=frontend")),
				otellog.Slice("source.workloads", otellog.StringValue("Deployment/frontend")),
				otellog.String("destination.namespace", "dst-ns"),
				otellog.String("destination.name", "dst-pod"),
				otellog.Slice("destination.labels", otellog.StringValue("app=backend")),
				otellog.Slice("destination.workloads", otellog.StringValue("Deployment/backend")),
				otellog.Int64("destination.port", 8080),
				otellog.Slice("egress.enforced_by",
					otellog.StringValue("networking.k8s.io/v1/NetworkPolicy/src-ns/deny-egress")),
				otellog.Slice("ingress.enforced_by",
					otellog.StringValue("cilium.io/v2/CiliumNetworkPolicy/dst-ns/deny-ingress")),
			},
		},
		{
			name:       "omits empty optional attrs",
			initLogger: true,
			event: &types.PolicyDenyEvent{
				Timestamp:    ts.Unix(),
				NodeName:     "node-1",
				CNIType:      "flannel",
				Protocol:     "ICMP",
				SrcNamespace: "src-ns",
				SrcName:      "src-pod",
				DstNamespace: "dst-ns",
				DstName:      "dst-pod",
			},
			wantAttributes: []otellog.KeyValue{
				otellog.String("cni.type", "flannel"),
				otellog.String("network.protocol", "ICMP"),
				otellog.String("node.name", "node-1"),
				otellog.String("source.namespace", "src-ns"),
				otellog.String("source.name", "src-pod"),
				otellog.String("destination.namespace", "dst-ns"),
				otellog.String("destination.name", "dst-pod"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := otel.NewOpenTelemetryService(otel.OpenTelemetryConfig{
				Ctx:               ctx,
				Log:               logger,
				CollectorEndpoint: "localhost:4317",
			})

			var recorder *logtest.Recorder
			if tt.initLogger {
				recorder = logtest.NewRecorder()
				service.Service.Logger = recorder.Logger("cniwatcher")
			}

			err := service.EmitPolicyDenyEvent(tt.event)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			want := logtest.Recording{
				logtest.Scope{Name: "cniwatcher"}: {
					{
						Context:    ctx,
						EventName:  "policy_deny",
						Timestamp:  ts,
						Severity:   otellog.SeverityWarn,
						Body:       otellog.StringValue("Network policy denied traffic"),
						Attributes: tt.wantAttributes,
					},
				},
			}
			logtest.AssertEqual(t, want, recorder.Result())
		})
	}
}

func TestOtelService_Shutdown(t *testing.T) {
	ctx := t.Context()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := otel.OpenTelemetryConfig{
		Ctx:               ctx,
		Log:               logger,
		CollectorEndpoint: "localhost:4317",
	}
	service := otel.NewOpenTelemetryService(cfg)

	err := service.Shutdown(ctx)
	assert.NoError(t, err)
}
