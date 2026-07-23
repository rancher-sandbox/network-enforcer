package otel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/rancher-sandbox/network-enforcer/internal/tlsutil"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
)

const DefaultOtelCollectorEndpoint = "localhost:4317"

type OpenTelemetryConfig struct {
	Ctx               context.Context
	Log               *slog.Logger
	CollectorEndpoint string
	// CertDir enables exporter mTLS; empty means insecure (plaintext).
	CertDir string
}

type OpenTelemetryService struct {
	LoggerProvider *sdklog.LoggerProvider
	Logger         otellog.Logger
}

type Service struct {
	Config  OpenTelemetryConfig
	Service *OpenTelemetryService
}

func NewOpenTelemetryService(cfg OpenTelemetryConfig) *Service {
	return &Service{
		Config:  cfg,
		Service: &OpenTelemetryService{},
	}
}

func (s *Service) Start() error {
	if s.Config.CollectorEndpoint == "" {
		s.Config.CollectorEndpoint = DefaultOtelCollectorEndpoint
	}

	transportOpt, err := s.exporterTransportOption()
	if err != nil {
		return err
	}

	exporter, err := otlploggrpc.New(s.Config.Ctx,
		otlploggrpc.WithEndpoint(s.Config.CollectorEndpoint),
		transportOpt,
	)
	if err != nil {
		return fmt.Errorf("failed to create OTLP log exporter: %w", err)
	}

	res, err := resource.New(s.Config.Ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String("cniwatcher"),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	s.Service.LoggerProvider = sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
		sdklog.WithResource(res),
	)

	s.Service.Logger = s.Service.LoggerProvider.Logger("cniwatcher")
	s.Config.Log.Info("OpenTelemetry initialized", "collector", s.Config.CollectorEndpoint)
	return nil
}

func (s *Service) exporterTransportOption() (otlploggrpc.Option, error) {
	if s.Config.CertDir == "" {
		return otlploggrpc.WithInsecure(), nil
	}

	// The receiver cert is verified against its DNS name, so drop the port.
	serverName, _, err := net.SplitHostPort(s.Config.CollectorEndpoint)
	if err != nil {
		serverName = s.Config.CollectorEndpoint
	}

	creds, err := tlsutil.ClientCredentials(s.Config.CertDir, serverName)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter mTLS credentials: %w", err)
	}

	s.Config.Log.Info("OTLP exporter using mTLS", "cert_dir", s.Config.CertDir, "server_name", serverName)
	return otlploggrpc.WithTLSCredentials(creds), nil
}

func policiesToStrings(policies []types.Policy) []string {
	if policies == nil {
		return nil
	}
	result := make([]string, len(policies))
	for i, p := range policies {
		result[i] = p.String()
	}
	return result
}

func stringSlice(key string, values []string) otellog.KeyValue {
	vals := make([]otellog.Value, len(values))
	for i, v := range values {
		vals[i] = otellog.StringValue(v)
	}
	return otellog.Slice(key, vals...)
}

func appendIfNotEmpty(attrs []otellog.KeyValue, key string, values []string) []otellog.KeyValue {
	if len(values) > 0 {
		return append(attrs, stringSlice(key, values))
	}
	return attrs
}

func (s *Service) EmitPolicyDenyEvent(event *types.PolicyDenyEvent) error {
	if s.Service.Logger == nil {
		return errors.New("OpenTelemetry is not initialized, skip emitting policy deny event")
	}

	s.Config.Log.Info("Emitting policy deny event", "event", event)

	var rec otellog.Record
	rec.SetEventName("policy_deny")
	rec.SetSeverity(otellog.SeverityWarn)
	rec.SetBody(otellog.StringValue("Network policy denied traffic"))
	ts := time.Unix(event.Timestamp, 0)
	rec.SetTimestamp(ts)

	attrs := []otellog.KeyValue{
		otellog.String("cni.type", event.CNIType),
		otellog.String("network.protocol", string(event.Protocol)),
		otellog.String("node.name", event.NodeName),
		otellog.String("source.namespace", event.SrcNamespace),
		otellog.String("source.name", event.SrcName),
		otellog.String("destination.namespace", event.DstNamespace),
		otellog.String("destination.name", event.DstName),
	}
	attrs = appendIfNotEmpty(attrs, "source.labels", event.SrcLabels)
	attrs = appendIfNotEmpty(attrs, "source.workloads", event.SrcWorkloads)
	attrs = appendIfNotEmpty(attrs, "destination.labels", event.DstLabels)
	attrs = appendIfNotEmpty(attrs, "destination.workloads", event.DstWorkloads)
	if event.DstPort != 0 {
		attrs = append(attrs, otellog.Int64("destination.port", int64(event.DstPort)))
	}
	attrs = appendIfNotEmpty(attrs, "egress.enforced_by", policiesToStrings(event.EgressEnforcedBy))
	attrs = appendIfNotEmpty(attrs, "ingress.enforced_by", policiesToStrings(event.IngressEnforcedBy))
	rec.AddAttributes(attrs...)

	s.Service.Logger.Emit(s.Config.Ctx, rec)
	return nil
}

func (s *Service) Shutdown(ctx context.Context) error {
	if s.Service.LoggerProvider == nil {
		return nil
	}

	return s.Service.LoggerProvider.Shutdown(ctx)
}
