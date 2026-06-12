tilt_settings_file = "./tilt-settings.yaml"
settings = read_yaml(tilt_settings_file)

allow_k8s_contexts(settings.get("clusters"))

update_settings(
    k8s_upsert_timeout_secs=180,
)

# Create the namespace
# This is required since the helm() function doesn't support the create_namespace flag
load("ext://namespace", "namespace_create")
namespace_create("network-enforcer")

controller_image = settings.get("controller").get("image")

cniwatcher_settings = settings.get("cniwatcher", {})
cniwatcher_enabled = cniwatcher_settings.get("enabled", True)
cniwatcher_image = cniwatcher_settings.get("image", "cniwatcher")
cniwatcher_tag = cniwatcher_settings.get("tag", "latest")
cni_type = cniwatcher_settings.get("cniType", "calico")

# OpenTelemetry Collector Deployment
load("ext://helm_resource", "helm_resource", "helm_repo")
helm_repo("open-telemetry", "https://open-telemetry.github.io/opentelemetry-helm-charts")
helm_resource(
    "opentelemetry-collector",    
    "open-telemetry/opentelemetry-collector",
    namespace="network-enforcer",
    flags=[
        "--set", "image.repository=otel/opentelemetry-collector-k8s",
        "--set", "mode=deployment",
        "--set", "replicaCount=1",
        "--set", "config.exporters.debug.verbosity=detailed",
        "--set", "config.processors.memory_limiter.limit_mib=400",
        "--set", "config.processors.memory_limiter.spike_limit_mib=100",
        "--set", "config.processors.memory_limiter.check_interval=5s",
        "--set", "config.service.pipelines.traces.receivers[0]=otlp",
        "--set", "config.service.pipelines.traces.processors[0]=memory_limiter",
        "--set", "config.service.pipelines.traces.exporters[0]=debug"
    ]
)

# For development, handle CNI setup in Kind cluster
if cniwatcher_enabled:
    if cni_type == "cilium":
        cilium_version = "1.19.4"

        # Install and configure Cilium in Kind cluster for real development
        helm_repo("cilium", "https://helm.cilium.io/")
        helm_resource(
            "cilium-helm",
            "cilium/cilium",
            namespace="kube-system",
            flags=[
                "--version", cilium_version,
                "--set", "k8sServiceHost=kind-control-plane",
                "--set", "k8sServicePort=6443",
                "--set", "hubble.enabled=true"
            ]
        )
    elif cni_type == "calico":
        namespace_create("calico-system")

        local_resource(
            "install_calico_operator",
            "kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.30.2/manifests/tigera-operator.yaml",
        )

        local_resource(
            "wait_for_tigera_operator",
            "kubectl wait --for=condition=ready pod -l name=tigera-operator -n tigera-operator --timeout=300s && echo 'Tigera operator is ready!'",
            deps=["install_calico_operator"]
        )

        local_resource(
            "setup_calico_custom_resources",
            "kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.30.2/manifests/custom-resources.yaml",
            deps=["wait_for_tigera_operator"],
        )

        local_resource(
            "install_goldmane",
            "kubectl apply -f - <<EOF\napiVersion: operator.tigera.io/v1\nkind: Goldmane\nmetadata:\n  name: default\n  namespace: calico-system\nEOF",
            deps=["setup_calico_custom_resources"]
        )

        local_resource(
            "extract_goldmane_certs",
            "mkdir -p certs && \
             kubectl get cm -n calico-system goldmane-ca-bundle -o jsonpath='{.data.tigera-ca-bundle\\.crt}' > certs/ca.crt && \
             kubectl -n calico-system get secret goldmane-key-pair -o jsonpath='{.data.tls\\.crt}' | base64 -d > certs/tls.crt && \
             kubectl -n calico-system get secret goldmane-key-pair -o jsonpath='{.data.tls\\.key}' | base64 -d > certs/tls.key",
            deps=["install_goldmane"]
        )

        local_resource(
            "create_goldmane_secret",
            "kubectl create secret generic cniwatcher-goldmane-key-pair --from-file=tls.key=certs/tls.key \
                --from-file=tls.crt=certs/tls.crt --from-file=ca.crt=certs/ca.crt -n calico-system \
                --dry-run=client -o yaml | kubectl apply -f -",
            deps=["extract_goldmane_certs"]
        )
    elif cni_type == "flannel":
        local_resource(
            "setup_flannel_in_kind",
            "docker exec kind-control-plane mkdir -p /var/log/ulog && \
             docker exec kind-control-plane touch /var/log/ulog/syslogemu.log && \
             docker exec kind-control-plane sh -c 'echo \"Jan 1 12:00:00 fake-host kernel: [12345.678901] \
                DROP by policy default/allow-all IN=eth0 OUT=eth1 MAC=00:11:22:33:44:55 SRC=192.168.1.100 \
                DST=192.168.1.200 PROTO=TCP SPT=12345 DPT=80\" > /var/log/ulog/syslogemu.log'",
        )
    elif cni_type == "aws-vpc":
        local_resource(
            "setup_aws_vpc_in_kind",
            "docker exec kind-control-plane mkdir -p /var/log/aws-routed-eni && \
             docker exec kind-control-plane touch /var/log/aws-routed-eni/network-policy-agent.log && \
             docker exec kind-control-plane sh -c 'echo \"2024-01-01T12:00:00Z [INFO] DROP by policy \
                default/aws-policy IN=eni-12345 OUT=eni-67890 SRC=10.0.1.100 DST=10.0.1.200 PROTO=TCP \
                SPT=12345 DPT=80\" > /var/log/aws-routed-eni/network-policy-agent.log'",
        )

# Prepare Helm set values based on CNI type
helm_set_values = [
    "controller.image.repository=" + controller_image,
    "controller.replicas=1",
    "controller.containerSecurityContext.runAsUser=null",
    "controller.podSecurityContext.runAsNonRoot=false",
    "cniwatcher.enabled=" + ("true" if cniwatcher_enabled else "false"),
    "cniwatcher.image.repository=" + cniwatcher_image,
    "cniwatcher.image.tag=" + cniwatcher_tag,
    "cniwatcher.cniType=" + cni_type,
    "cniwatcher.otelEndpoint=opentelemetry-collector.network-enforcer.svc.cluster.local:4317",
]

# Add CNI-specific configuration values
if cniwatcher_enabled:
    if cni_type == "cilium":
        helm_set_values.extend([
            "cniwatcher.cilium.namespace=kube-system",
            "cniwatcher.cilium.hubbleEndpoint=unix:///var/run/cilium/hubble.sock"
        ])
    elif cni_type == "calico":
        helm_set_values.extend([
            "cniwatcher.calico.namespace=calico-system",
            "cniwatcher.calico.goldmaneEndpoint=goldmane.calico-system.svc:7443"
        ])
    elif cni_type == "flannel":
        helm_set_values.extend([
            "cniwatcher.flannel.namespace=kube-system"
        ])
    elif cni_type == "aws-vpc":
        helm_set_values.extend([
            "cniwatcher.awsVPC.namespace=kube-system"
        ])

yaml = helm(
    "./charts/network-enforcer",
    name="network-enforcer",
    namespace="network-enforcer",
    set=helm_set_values
)

k8s_yaml(yaml)

# Hot reloading containers
local_resource(
    "controller_tilt",
    "make controller",
    deps=[
        "go.mod",
        "go.sum",
        "cmd",
        "api",
        "internal",
    ],
)

entrypoint = ["/controller"]
dockerfile = "./hack/Dockerfile.controller.tilt"

load("ext://restart_process", "docker_build_with_restart")
docker_build_with_restart(
    controller_image,
    ".",
    dockerfile=dockerfile,
    entrypoint=entrypoint,
    # `only` here is important, otherwise, the container will get updated
    # on _any_ file change.
    only=[
        "./bin/controller",
    ],
    live_update=[
        sync("./bin/controller", "/controller"),
    ],
)

if cniwatcher_enabled:
    local_resource(
        "cniwatcher_tilt",
        "make cniwatcher",
        deps=[
            "go.mod",
            "go.sum",
            "cmd/cniwatcher",
            "internal/cniwatcher",
            "internal/otel",
            "internal/types",
        ],
    )
    entrypoint = ["/cniwatcher"]
    dockerfile = "./hack/Dockerfile.cniwatcher.tilt"

    docker_build_with_restart(
        cniwatcher_image + ":" + cniwatcher_tag,
        ".",
        dockerfile=dockerfile,
        entrypoint=entrypoint,
        # `only` here is important, otherwise, the container will get updated
        # on _any_ file change.
        only=[
            "./bin/cniwatcher",
        ],
        live_update=[
            sync("./bin/cniwatcher", "/cniwatcher"),
        ],
    )
