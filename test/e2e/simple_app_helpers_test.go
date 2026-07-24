package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
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
	simpleAppTCPServicePort       = int32(18080)
	simpleAppUDPServicePort       = int32(18083)
	simpleAppUDPServerPort        = int32(18081)
)

func teardownSimpleAppWorkload(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)

	err := decoder.DeleteWithManifestDir(
		ctx,
		getSecurityV1Alpha1Client(ctx),
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
		conditions.New(getSecurityV1Alpha1Client(ctx)).ResourceDeleted(clientDeployment),
		wait.WithTimeout(defaultOperationTimeout),
	)
	require.NoError(t, err, "wait client deployment deletion")

	serverDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: simpleAppServerDeploymentName, Namespace: namespace},
	}
	err = wait.For(
		conditions.New(getSecurityV1Alpha1Client(ctx)).ResourceDeleted(serverDeployment),
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
		getSecurityV1Alpha1Client(ctx),
		testFolder,
		simpleAppManifest,
		[]resources.CreateOption{},
		// we should mutate the nodeSelector here, since we want them both on the same node and on different nodes.
		decoder.MutateNamespace(namespace),
	)
	require.NoError(t, err, "failed to apply simple app manifest")

	err = wait.For(
		conditions.New(getSecurityV1Alpha1Client(ctx)).DeploymentAvailable(simpleAppClientDeploymentName, namespace),
		wait.WithTimeout(defaultOperationTimeout),
	)
	require.NoError(t, err, "wait client deployment ready")

	err = wait.For(
		conditions.New(getSecurityV1Alpha1Client(ctx)).DeploymentAvailable(simpleAppServerDeploymentName, namespace),
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
	r := getSecurityV1Alpha1Client(ctx)
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
