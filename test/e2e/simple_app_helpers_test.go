package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

const (
	testFolder                    = "./testdata"
	simpleAppManifest             = "simple_app.yaml"
	simpleAppClientDeploymentName = "http-client"
	simpleAppServerDeploymentName = "http-server"
	simpleAppTCPServicePort       = 18080
	simpleAppUDPServicePort       = 18083

	cniwatcherPodLabel   = "app.kubernetes.io/name=network-enforcer-cniwatcher"
	cniwatcherDenyLogMsg = "Emitting policy deny event"
)

func teardownSimpleAppWorkload(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)

	err := decoder.DeleteWithManifestDir(
		ctx,
		getClient(ctx),
		testFolder,
		simpleAppManifest,
		[]resources.DeleteOption{},
		decoder.MutateNamespace(namespace),
	)
	require.NoError(t, err, "failed to delete simple app manifest")

	clientDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: simpleAppClientDeploymentName, Namespace: namespace},
	}
	err = wait.For(
		conditions.New(getClient(ctx)).ResourceDeleted(clientDeployment),
		wait.WithTimeout(defaultOperationTimeout),
	)
	require.NoError(t, err, "wait client deployment deletion")

	serverDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: simpleAppServerDeploymentName, Namespace: namespace},
	}
	err = wait.For(
		conditions.New(getClient(ctx)).ResourceDeleted(serverDeployment),
		wait.WithTimeout(defaultOperationTimeout),
	)
	require.NoError(t, err, "wait server deployment deletion")

	return ctx
}

func setupSimpleAppWorkload(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	t.Log("installing simple app")
	namespace := getNamespace(ctx)

	err := decoder.ApplyWithManifestDir(
		ctx,
		getClient(ctx),
		testFolder,
		simpleAppManifest,
		[]resources.CreateOption{},
		// we should mutate the nodeSelector here, since we want them both on the same node and on different nodes.
		decoder.MutateNamespace(namespace),
	)
	require.NoError(t, err, "failed to apply simple app manifest")

	err = wait.For(
		conditions.New(getClient(ctx)).DeploymentAvailable(simpleAppClientDeploymentName, namespace),
		wait.WithTimeout(defaultOperationTimeout),
	)
	require.NoError(t, err, "wait client deployment ready")

	err = wait.For(
		conditions.New(getClient(ctx)).DeploymentAvailable(simpleAppServerDeploymentName, namespace),
		wait.WithTimeout(defaultOperationTimeout),
	)
	require.NoError(t, err, "wait server deployment ready")
	return ctx
}

func getProtoCmd(proto corev1.Protocol) (string, []string) {
	const (
		tcpPayload           = "tcp-e2e-payload"
		udpPayload           = "udp-e2e-payload"
		simpleAppServiceName = "http-service"
	)

	switch proto {
	case corev1.ProtocolTCP:
		return tcpPayload, []string{
			"sh",
			"-c",
			fmt.Sprintf(
				"printf %s | nc -w 2 %s %d",
				strconv.Quote(tcpPayload),
				simpleAppServiceName,
				simpleAppTCPServicePort,
			),
		}
	case corev1.ProtocolUDP:
		return udpPayload, []string{
			"sh",
			"-c",
			fmt.Sprintf(
				"printf %s | nc -u -w 2 %s %d",
				strconv.Quote(udpPayload),
				simpleAppServiceName,
				simpleAppUDPServicePort,
			),
		}
	case corev1.ProtocolSCTP:
		fallthrough
	default:
		panic(fmt.Sprintf("unsupported protocol: %v", proto))
	}
}

func execInSimpleClientDeployment(
	ctx context.Context,
	t *testing.T,
	command []string,
) (string, string) {
	t.Helper()

	namespace := getNamespace(ctx)
	r := getClient(ctx)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	execCtx, cancel := context.WithTimeout(ctx, defaultPodExecTimeout)
	defer cancel()

	err := r.ExecInDeployment(
		execCtx,
		namespace,
		simpleAppClientDeploymentName,
		command,
		&stdout,
		&stderr,
	)

	require.NoError(t, err, "failed executing command in deployment %q: %v", simpleAppClientDeploymentName, err)
	return stdout.String(), stderr.String()
}

func assertPacketSentFromClient(
	ctx context.Context,
	t *testing.T,
	proto corev1.Protocol,
) context.Context {
	t.Helper()

	payload, cmd := getProtoCmd(proto)
	stdout, stderr := execInSimpleClientDeployment(ctx, t, cmd)
	require.Empty(t, stderr)
	require.Contains(t, stdout, payload, "client output should contain echoed payload")
	return ctx
}

func fetchCNIWatcherLogs(ctx context.Context) (string, error) {
	suiteCfg := getSuiteConfig(ctx)
	clientset := getClientset(ctx)

	pods, err := clientset.CoreV1().Pods(suiteCfg.releaseNS).List(ctx, metav1.ListOptions{
		LabelSelector: cniwatcherPodLabel,
	})
	if err != nil {
		return "", fmt.Errorf("list cniwatcher pods: %w", err)
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no cniwatcher pods found with selector %q", cniwatcherPodLabel)
	}

	var b strings.Builder
	for _, pod := range pods.Items {
		req := clientset.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
			Container: "cniwatcher",
		})
		stream, logErr := req.Stream(ctx)
		if logErr != nil {
			return "", fmt.Errorf("stream logs for pod %q: %w", pod.Name, logErr)
		}

		data, readErr := io.ReadAll(stream)
		closeErr := stream.Close()
		if readErr != nil {
			return "", fmt.Errorf("read logs for pod %q: %w", pod.Name, readErr)
		}
		if closeErr != nil {
			return "", fmt.Errorf("close log stream for pod %q: %w", pod.Name, closeErr)
		}
		b.Write(data)
		b.WriteByte('\n')
	}

	return b.String(), nil
}

// cniwatcherLogsContainDenyEvent checks that cniwatcher emitted an OTEL deny
// event for a protect-mode UDP deny between the simple_app workloads.
//
// Expected log shape, e.g. Cilium:
//
//	msg="Emitting policy deny event" event="&{... CNIType:cilium Protocol:UDP
//	  SrcNamespace:<ns> SrcName:http-client-... DstNamespace:<ns>
//	  DstName:http-server-... SrcWorkloads:[Deployment/http-client]
//	  DstWorkloads:[Deployment/http-server] DstPort:18081
//	  EgressEnforcedBy:[] IngressEnforcedBy:[]}"
//
// For Calico, at least one of policyNames must appear. Cilium omits denying
// Kubernetes NetworkPolicy names for allowlist denies unless using
// CiliumNetworkPolicy ingressDeny/egressDeny
// (https://github.com/rancher-sandbox/network-enforcer/issues/19).
func cniwatcherLogsContainDenyEvent(
	logs, namespace string,
	cni cniType,
	policyNames []string,
) bool {
	cniTypeField := "CNIType:" + string(cni)
	srcNS := "SrcNamespace:" + namespace
	dstNS := "DstNamespace:" + namespace
	srcName := "SrcName:" + simpleAppClientDeploymentName
	dstName := "DstName:" + simpleAppServerDeploymentName
	srcWorkload := "Deployment/" + simpleAppClientDeploymentName
	dstWorkload := "Deployment/" + simpleAppServerDeploymentName

	for line := range strings.SplitSeq(logs, "\n") {
		if !strings.Contains(line, cniwatcherDenyLogMsg) {
			continue
		}
		if !strings.Contains(line, cniTypeField) {
			continue
		}
		if !strings.Contains(line, srcNS) || !strings.Contains(line, dstNS) {
			continue
		}
		if !strings.Contains(line, srcName) || !strings.Contains(line, dstName) {
			continue
		}
		if !strings.Contains(line, srcWorkload) || !strings.Contains(line, dstWorkload) {
			continue
		}
		if cni == calico && !enforcedByContainsPolicy(line, policyNames) {
			continue
		}
		return true
	}
	return false
}

func enforcedByContainsPolicy(line string, policyNames []string) bool {
	egress := extractBracketField(line, "EgressEnforcedBy:")
	ingress := extractBracketField(line, "IngressEnforcedBy:")
	return containsAny(egress, policyNames) || containsAny(ingress, policyNames)
}

func extractBracketField(line, key string) string {
	_, after, ok := strings.Cut(line, key)
	if !ok {
		return ""
	}
	rest := after
	if !strings.HasPrefix(rest, "[") {
		return ""
	}
	depth := 0
	for j, r := range rest {
		switch r {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return rest[:j+1]
			}
		}
	}
	return ""
}

func containsAny(haystack string, values []string) bool {
	for _, v := range values {
		if v != "" && strings.Contains(haystack, v) {
			return true
		}
	}
	return false
}
