tilt_settings_file = "./tilt-settings.yaml"
settings = read_yaml(tilt_settings_file)

allow_k8s_contexts(settings.get("clusters"))

update_settings(
    k8s_upsert_timeout_secs=180,
)

# Create the namespace
# This is required since the helm() function doesn't support the create_namespace flag
release_namespace = "network-enforcer"
load("ext://namespace", "namespace_create")
namespace_create(release_namespace)

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
    namespace=release_namespace,
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
	"cniwatcher.containerSecurityContext.runAsUser=null",
    "cniwatcher.podSecurityContext.runAsNonRoot=false",
    "otel.endpoint=opentelemetry-collector." + release_namespace + ".svc.cluster.local:4317",
]

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

        helm_set_values.extend([
            "cniwatcher.cilium.hubbleEndpoint=unix:///var/run/cilium/hubble.sock"
        ])
    elif cni_type == "calico":
        local_resource(
            "setup_calico",
            "CNIWATCHER_NAMESPACE=" + release_namespace + " bash ./hack/setup-calico.sh"
        )

        helm_set_values.extend([
            "cniwatcher.calico.goldmaneEndpoint=goldmane.calico-system.svc:7443"
        ])
    elif cni_type == "flannel":
        local_resource(
            "setup_flannel_in_kind",
            "docker exec kind-control-plane mkdir -p /var/log/ulog && \
             docker exec kind-control-plane touch /var/log/ulog/syslogemu.log && \
             docker exec kind-control-plane sh -c 'echo \"Jan 1 12:00:00 fake-host kernel: [12345.678901] \
                DROP by policy default/allow-all IN=eth0 OUT=eth1 MAC=00:11:22:33:44:55 SRC=192.168.1.100 \
                DST=192.168.1.200 PROTO=TCP SPT=12345 DPT=80\" > /var/log/ulog/syslogemu.log'",
        )

        helm_set_values.extend([
            "cniwatcher.podSecurityContext.fsGroup=4"
        ])
    elif cni_type == "aws-vpc":
        local_resource(
            "setup_aws_vpc_in_kind",
            "docker exec kind-control-plane mkdir -p /var/log/aws-routed-eni && \
             docker exec kind-control-plane touch /var/log/aws-routed-eni/network-policy-agent.log && \
             docker exec kind-control-plane sh -c 'echo \"2024-01-01T12:00:00Z [INFO] DROP by policy \
                default/aws-policy IN=eni-12345 OUT=eni-67890 SRC=10.0.1.100 DST=10.0.1.200 PROTO=TCP \
                SPT=12345 DPT=80\" > /var/log/aws-routed-eni/network-policy-agent.log'",
        )

yaml = helm(
    "./charts/network-enforcer",
    name="network-enforcer",
    namespace=release_namespace,
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
