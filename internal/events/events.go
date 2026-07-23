// Package events wires the OTLP log exporter for
// policy_violation_acknowledged records. Mirrors runtime-enforcer.
package events

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/rancher-sandbox/network-enforcer/internal/tlsutil"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"google.golang.org/grpc/credentials"
)

type protocol string

const (
	protocolGRPC         protocol = "grpc"
	protocolHTTPProtobuf protocol = "http/protobuf"
)

func stringToProtocol(s string) (protocol, error) {
	switch s {
	case "grpc":
		return protocolGRPC, nil
	case "http/protobuf":
		return protocolHTTPProtobuf, nil
	default:
		return "", fmt.Errorf("unsupported protocol: %s", s)
	}
}

// buildTLSConfig returns a TLS config that re-reads the CA on every
// handshake (certificate rotation) and optionally presents a client cert.
func buildTLSConfig(caCertPath, clientCertPath, clientKeyPath string) (*tls.Config, error) {
	// Validate that the CA certificate is readable at startup.
	if _, err := tlsutil.LoadCACertPool(caCertPath); err != nil {
		return nil, err
	}
	// Fail fast on partial client cert configuration.
	if (clientCertPath != "") != (clientKeyPath != "") {
		return nil, fmt.Errorf("both or neither of client cert and key must be set (cert=%q, key=%q)",
			clientCertPath, clientKeyPath)
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		// Re-read CA on every handshake to handle rotation.
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			certPool, err := tlsutil.LoadCACertPool(caCertPath)
			if err != nil {
				return err
			}
			opts := x509.VerifyOptions{
				Roots:         certPool,
				DNSName:       cs.ServerName,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err = cs.PeerCertificates[0].Verify(opts)
			return err
		},
	}
	if clientCertPath != "" && clientKeyPath != "" {
		clientCert, err := tlsutil.LoadKeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{clientCert}
	}
	return cfg, nil
}

func createGRPCExporter(ctx context.Context,
	endpoint, caCertPath, clientCertPath, clientKeyPath string,
) (sdklog.Exporter, error) {
	// Strip any http(s) prefix, WithEndpoint expects host:port.
	gRPCEndpoint := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
	insecure := caCertPath == ""
	opts := []otlploggrpc.Option{
		otlploggrpc.WithEndpoint(gRPCEndpoint),
	}
	if insecure {
		opts = append(opts, otlploggrpc.WithInsecure())
	} else {
		tlsConfig, err := buildTLSConfig(caCertPath, clientCertPath, clientKeyPath)
		if err != nil {
			return nil, err
		}
		opts = append(opts, otlploggrpc.WithTLSCredentials(credentials.NewTLS(tlsConfig)))
	}
	return otlploggrpc.New(ctx, opts...)
}

func createHTTPExporter(ctx context.Context,
	endpoint, caCertPath, clientCertPath, clientKeyPath string,
) (sdklog.Exporter, error) {
	// Strip any scheme prefix; WithEndpoint expects host:port.
	httpEndpoint := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")

	opts := []otlploghttp.Option{
		otlploghttp.WithEndpoint(httpEndpoint),
	}

	// Empty CA means insecure (matches gRPC behaviour and Init doc comment).
	// An explicit http:// scheme also opts into insecure.
	if caCertPath == "" || strings.HasPrefix(endpoint, "http://") {
		opts = append(opts, otlploghttp.WithInsecure())
	} else {
		tlsConfig, err := buildTLSConfig(caCertPath, clientCertPath, clientKeyPath)
		if err != nil {
			return nil, err
		}
		opts = append(opts, otlploghttp.WithTLSClientConfig(tlsConfig))
	}
	return otlploghttp.New(ctx, opts...)
}

// Init returns an OTLP log logger for the given endpoint.
// Supported protocol values: grpc, http/protobuf.
// caCertPath empty = insecure; clientCertPath+clientKeyPath set = mTLS.
// The caller must call shutdown to flush buffered records on exit.
func Init(
	ctx context.Context,
	endpoint, caCertPath, clientCertPath, clientKeyPath, protocol string,
) (otellog.Logger, func(context.Context) error, error) {
	// Client certs without a CA are silently ignored by the exporters.
	// Reject the combination up front so users don't think mTLS is active.
	if caCertPath == "" && (clientCertPath != "" || clientKeyPath != "") {
		return nil, nil, fmt.Errorf("client certificate requires a CA certificate (caCertPath is empty)")
	}

	var exporter sdklog.Exporter
	proto, err := stringToProtocol(protocol)
	if err != nil {
		return nil, nil, err
	}
	switch proto {
	case protocolGRPC:
		exporter, err = createGRPCExporter(ctx, endpoint, caCertPath, clientCertPath, clientKeyPath)
	case protocolHTTPProtobuf:
		exporter, err = createHTTPExporter(ctx, endpoint, caCertPath, clientCertPath, clientKeyPath)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OTLP log exporter: %w", err)
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
	)

	logger := provider.Logger("network-enforcer")
	return logger, provider.Shutdown, nil
}
