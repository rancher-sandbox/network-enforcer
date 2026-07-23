package grpcexporter

const (
	// DefaultCniwatcherLabelSelectorString is the default label selector used to
	// discover cniwatcher pods across the cluster.
	DefaultCniwatcherLabelSelectorString = "app.kubernetes.io/name=network-enforcer-cniwatcher"

	// DefaultAgentPort is the gRPC port that cniwatcher serves ScrapeViolations on.
	DefaultAgentPort = 50051

	// DefaultCertDirPath is the default directory containing the TLS certificates
	// used for mTLS with cniwatcher pods.
	DefaultCertDirPath = "/etc/network-enforcer/certs"
)
