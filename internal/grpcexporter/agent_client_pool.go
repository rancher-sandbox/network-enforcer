package grpcexporter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type nodeName = string

// AgentClientPoolConfig holds the configuration for the AgentClientPool.
type AgentClientPoolConfig struct {
	AgentFactoryConfig

	// Namespace is the Kubernetes namespace where cniwatcher pods run.
	Namespace string
	// LabelSelectorString is a comma-separated list of key=value labels used
	// to discover cniwatcher pods.
	LabelSelectorString string
	Logger              *slog.Logger
}

// AgentClientPool manages a set of AgentClientAPI instances, one per node
// running a cniwatcher pod.
type AgentClientPool struct {
	clients       map[nodeName]AgentClientAPI
	namespace     string
	labelSelector map[string]string
	factory       *AgentClientFactory
	logger        *slog.Logger
}

// getNamespace reads the current pod's namespace from the in-cluster
// service-account token file.
func getNamespace() (string, error) {
	const namespaceNamePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	// Get the agent namespace from the system.
	// We suppose we are always running inside the same namespace of the cniwatcher.
	data, err := os.ReadFile(namespaceNamePath)
	if err != nil {
		return "", fmt.Errorf("failed to read namespace file: %w", err)
	}
	namespace := strings.TrimSpace(string(data))
	if namespace == "" {
		return "", errors.New("empty agent namespace")
	}
	return namespace, nil
}

// NewAgentClientPool creates a new pool from the given configuration.
func NewAgentClientPool(poolConf AgentClientPoolConfig) (*AgentClientPool, error) {
	labelSelector, err := labels.ConvertSelectorToLabelsMap(poolConf.LabelSelectorString)
	if err != nil {
		return nil, fmt.Errorf("failed to convert agent label selector: %w", err)
	}

	// This is mainly for testing purposes.
	if poolConf.Namespace == "" {
		poolConf.Namespace, err = getNamespace()
		if err != nil {
			return nil, fmt.Errorf("failed to get agent namespace: %w", err)
		}
	}

	factory, err := NewAgentClientFactory(&poolConf.AgentFactoryConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create agent client factory: %w", err)
	}

	return &AgentClientPool{
		clients:       make(map[nodeName]AgentClientAPI),
		namespace:     poolConf.Namespace,
		labelSelector: labelSelector,
		factory:       factory,
		logger:        poolConf.Logger,
	}, nil
}

// UpdatePool refreshes the pool by listing cniwatcher pods via the provided
// reader and creating or reusing clients for each node.
func (p *AgentClientPool) UpdatePool(ctx context.Context, reader client.Reader) (map[string]AgentClientAPI, error) {
	var podList corev1.PodList
	if err := reader.List(ctx, &podList,
		client.InNamespace(p.namespace),
		client.MatchingLabels(p.labelSelector),
	); err != nil {
		return nil, err
	}

	activeNodes := sets.New[nodeName]()
	for _, pod := range podList.Items {
		if pod.Status.PodIP == "" {
			p.logger.WarnContext(ctx, "Skipping cniwatcher pod without PodIP", "pod", pod.Name)
			continue
		}
		// Even if the client will be nil we want to keep it in activeNodes.
		activeNodes.Insert(pod.Spec.NodeName)

		if _, err := p.getOrCreateClient(&pod); err != nil {
			p.logger.WarnContext(ctx, "Failed to get or create agent client for pod",
				"pod", pod.Name, "node", pod.Spec.NodeName, "error", err)
			continue
		}
	}

	// Remove stale clients for nodes that no longer have a cniwatcher pod.
	for node, c := range p.clients {
		if activeNodes.Has(node) {
			continue
		}
		if c != nil {
			_ = c.Close()
		}
		delete(p.clients, node)
	}
	return p.clients, nil
}

// getOrCreateClient returns the existing client for the pod's node or creates
// a new one if none exists. On failure the entry is set to nil so the caller
// can distinguish between "node known, connection failed" and "node unknown".
func (p *AgentClientPool) getOrCreateClient(pod *corev1.Pod) (AgentClientAPI, error) {
	node := pod.Spec.NodeName
	agentClient, ok := p.clients[node]
	if ok && agentClient != nil {
		return agentClient, nil
	}

	c, err := p.factory.NewClient(pod.Status.PodIP, pod.Name, pod.Namespace)
	if err != nil {
		p.clients[node] = nil
		return nil, fmt.Errorf("failed to create connection to pod %s: %w", pod.Name, err)
	}
	p.clients[node] = c
	return c, nil
}

func (p *AgentClientPool) MarkStaleAgentClient(node string) {
	client, ok := p.clients[node]
	if !ok {
		return
	}
	if client != nil {
		_ = client.Close()
	}
	p.clients[node] = nil
}
