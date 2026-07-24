package cniwatcher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/jdrews/go-tailer/fswatcher"
	"github.com/jdrews/go-tailer/glob"
	"github.com/rancher-sandbox/network-enforcer/internal/otel"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/rancher-sandbox/network-enforcer/internal/violationbuf"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	initialRetryDelay  = 5 * time.Second
	retryBackoffFactor = 1.5
	retryJitterFactor  = 0.1
	maxRetrySteps      = 10
	maxRetryDelay      = 60 * time.Second
)

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch

type CNIWatcher interface {
	Start() error
	Shutdown() error
}

type Watcher struct {
	Ctx             context.Context
	Client          client.Client
	Log             *slog.Logger
	NodeName        string
	OtelService     *otel.Service
	ViolationBuffer *violationbuf.Buffer
}

type PodOrServiceInfo struct {
	Name      string
	Namespace string
	Type      types.PodOrServiceType
	Labels    []string
}

func NewCNIWatcher(config Config, watcher Watcher) (CNIWatcher, error) {
	switch config.CNIType {
	case types.CNITypeAWSVPC:
		return NewAWSVPCWatcher(watcher)
	case types.CNITypeCalico:
		return NewCalicoWatcher(watcher, config.ConnEndpoint)
	case types.CNITypeCilium:
		return NewCiliumWatcher(watcher, config.ConnEndpoint)
	case types.CNITypeFlannel:
		return NewFlannelWatcher(watcher)
	case types.CNITypeUnknown:
		fallthrough
	default:
		return nil, fmt.Errorf("unsupported CNI type: %q", config.CNIType)
	}
}

func (w *Watcher) ProcessPolicyDenyEvent(event *types.PolicyDenyEvent) error {
	if event == nil {
		return nil
	}

	// It is possible that some CNIs will send the protocol in lower case
	// to avoid issues with case sensitivity, we normalize it to upper case here.
	event.Protocol = corev1.Protocol(strings.ToUpper(string(event.Protocol)))
	switch event.Protocol {
	case corev1.ProtocolTCP:
		event.Protocol = corev1.ProtocolTCP
	case corev1.ProtocolUDP:
		event.Protocol = corev1.ProtocolUDP
	case corev1.ProtocolSCTP:
		fallthrough
	default:
		return fmt.Errorf("unsupported protocol coming from a CNI: %s", event.Protocol)
	}

	if w.ViolationBuffer != nil {
		w.recordToBuffer(event)
	}

	if w.OtelService == nil {
		return errors.New("OpenTelemetry service is not initialized")
	}

	return w.OtelService.EmitPolicyDenyEvent(event)
}

func (w *Watcher) recordToBuffer(event *types.PolicyDenyEvent) {
	direction := "egress"
	denyingPolicyNamespace := ""
	denyingPolicyName := ""

	if len(event.EgressEnforcedBy) > 0 {
		direction = "egress"
		denyingPolicyNamespace = event.EgressEnforcedBy[0].Namespace
		denyingPolicyName = event.EgressEnforcedBy[0].Name
	} else if len(event.IngressEnforcedBy) > 0 {
		direction = "ingress"
		denyingPolicyNamespace = event.IngressEnforcedBy[0].Namespace
		denyingPolicyName = event.IngressEnforcedBy[0].Name
	}

	nodeName := event.NodeName
	if nodeName == "" {
		nodeName = w.NodeName
	}

	rec := violationbuf.ViolationRecord{
		Timestamp:              time.Unix(event.Timestamp, 0),
		NodeName:               nodeName,
		Direction:              direction,
		SrcNamespace:           event.SrcNamespace,
		SrcName:                event.SrcName,
		SrcWorkloads:           event.SrcWorkloads,
		SrcLabels:              event.SrcLabels,
		DstNamespace:           event.DstNamespace,
		DstName:                event.DstName,
		DstWorkloads:           event.DstWorkloads,
		DstLabels:              event.DstLabels,
		Protocol:               event.Protocol,
		DstPort:                event.DstPort,
		Action:                 "protect",
		DenyingPolicyNamespace: denyingPolicyNamespace,
		DenyingPolicyName:      denyingPolicyName,
	}

	w.ViolationBuffer.Record(rec)
}

func (w *Watcher) GetNetworkPolicyAPIVersion(kind string) (string, error) {
	var group, version string
	switch kind {
	case "NetworkPolicy":
		group = "networking.k8s.io"
		version = "v1"
	case "CalicoNetworkPolicy", "GlobalNetworkPolicy":
		group = "projectcalico.org"
		version = "v3"
	case "CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy":
		group = "cilium.io"
		version = "v2"
	default:
		return "", fmt.Errorf("unsupported network policy kind: %s", kind)
	}

	return fmt.Sprintf("%s/%s", group, version), nil
}

func extractLabels(labels map[string]string) []string {
	if len(labels) == 0 {
		return nil
	}

	result := make([]string, 0, len(labels))
	for k, v := range labels {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return result
}

func containsIP(ips []string, target string) bool {
	return slices.Contains(ips, target)
}

// ResolvePodOrServiceByIP resolves a Pod or Service info from an IP address.
// AWSVPC CNI and Flannel don't have the Pod or Service info (i.e. name, namespace, labels) in the policy deny log.
func (w *Watcher) ResolvePodOrServiceByIP(ip string) (PodOrServiceInfo, error) {
	if ip == "" {
		return PodOrServiceInfo{}, errors.New("IP address cannot be empty")
	}

	if net.ParseIP(ip) == nil {
		return PodOrServiceInfo{}, fmt.Errorf("invalid IP address format: %s", ip)
	}

	if info, err := w.resolveServiceByClusterIP(ip); err != nil {
		w.Log.Warn("failed to list services for cluster IP lookup", "ip", ip, "err", err)
	} else {
		return info, nil
	}

	if info, err := w.resolveServiceByExternalIP(ip); err != nil {
		w.Log.Warn("failed to list services for external IP lookup", "ip", ip, "err", err)
	} else {
		return info, nil
	}

	if info, err := w.resolvePodByIP(ip); err != nil {
		w.Log.Warn("failed to list pods", "ip", ip, "err", err)
	} else {
		return info, nil
	}

	return PodOrServiceInfo{}, fmt.Errorf("no endpoint found for IP: %s", ip)
}

// resolveServiceByClusterIP attempts to find a Service with the given ClusterIP.
func (w *Watcher) resolveServiceByClusterIP(ip string) (PodOrServiceInfo, error) {
	services := &corev1.ServiceList{}
	if err := w.Client.List(w.Ctx, services, client.MatchingFields{"spec.clusterIP": ip}); err != nil {
		return PodOrServiceInfo{}, err
	}
	if len(services.Items) == 0 {
		return PodOrServiceInfo{}, errors.New("not found")
	}
	svc := services.Items[0]
	return PodOrServiceInfo{
		Name:      svc.Name,
		Namespace: svc.Namespace,
		Type:      types.PodOrServiceTypeService,
		Labels:    extractLabels(svc.Labels),
	}, nil
}

// resolveServiceByExternalIP attempts to find a Service with the provided external IP in spec.externalIPs.
func (w *Watcher) resolveServiceByExternalIP(ip string) (PodOrServiceInfo, error) {
	services := &corev1.ServiceList{}
	if err := w.Client.List(w.Ctx, services); err != nil {
		return PodOrServiceInfo{}, err
	}
	for _, svc := range services.Items {
		if containsIP(svc.Spec.ExternalIPs, ip) {
			return PodOrServiceInfo{
				Name:      svc.Name,
				Namespace: svc.Namespace,
				Type:      types.PodOrServiceTypeExternalService,
				Labels:    extractLabels(svc.Labels),
			}, nil
		}
	}
	return PodOrServiceInfo{}, errors.New("not found")
}

// resolvePodByIP attempts to find a Pod with the given PodIP.
func (w *Watcher) resolvePodByIP(ip string) (PodOrServiceInfo, error) {
	pods := &corev1.PodList{}
	if err := w.Client.List(w.Ctx, pods, client.MatchingFields{"status.podIP": ip}); err != nil {
		return PodOrServiceInfo{}, err
	}
	if len(pods.Items) == 0 {
		return PodOrServiceInfo{}, errors.New("not found")
	}
	pod := pods.Items[0]
	return PodOrServiceInfo{
		Name:      pod.Name,
		Namespace: pod.Namespace,
		Type:      types.PodOrServiceTypePod,
		Labels:    extractLabels(pod.Labels),
	}, nil
}

func (w *Watcher) CreateFileTailer(logPath string) (fswatcher.FileTailer, error) {
	parsedGlob, err := glob.Parse(logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse log path: %w", err)
	}

	logrusLogger := logrus.New()
	tailer, err := fswatcher.RunFileTailer([]glob.Glob{parsedGlob}, false, true, logrusLogger)
	if err != nil {
		return nil, fmt.Errorf("failed to start file tailer: %w", err)
	}

	return tailer, nil
}

// RetryConnectAndWatchFlows is a helper for CNI watchers to handle connection retry and flow watching loops.
func (w *Watcher) RetryConnectAndWatchFlows(
	connectFunc func() error,
	watchFunc func() error,
	watcherName string,
) error {
	backoff := wait.Backoff{
		Duration: initialRetryDelay,
		Factor:   retryBackoffFactor,
		Jitter:   retryJitterFactor,
		Steps:    maxRetrySteps,
		Cap:      maxRetryDelay,
	}

	for {
		select {
		case <-w.Ctx.Done():
			w.Log.Info(watcherName + " shutting down due to context cancel")
			return nil
		default:
			if err := w.connectAndWatch(connectFunc, watchFunc, backoff); err != nil {
				w.Log.Error("Exhausted all retry attempts", "err", err)
				return fmt.Errorf("failed to establish stable connection after retries: %w", err)
			}

			if w.Ctx.Err() == context.Canceled {
				w.Log.Info(watcherName + " shutting down due to context cancel")
				return nil
			}
		}
	}
}

func (w *Watcher) connectAndWatch(connectFunc func() error, watchFunc func() error, backoff wait.Backoff) error {
	return wait.ExponentialBackoffWithContext(w.Ctx, backoff, func(_ context.Context) (bool, error) {
		if err := connectFunc(); err != nil {
			w.Log.ErrorContext(w.Ctx, "Failed to connect, will retry", "err", err)
			return false, nil
		}

		w.Log.DebugContext(w.Ctx, "Successfully connected, starting to watch flows")

		err := watchFunc()
		if err != nil {
			if w.Ctx.Err() == context.Canceled {
				return true, nil
			}
			w.Log.ErrorContext(w.Ctx, "Error watching flows, will retry connection", "err", err)
			return false, nil
		}

		return true, nil
	})
}
