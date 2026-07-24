# cniWatcher

The cniWatcher DaemonSet watches CNI policy deny events (Calico Goldmane, Cilium Hubble, Flannel ulog, AWS VPC ENI logs) and exports them as OpenTelemetry logs.

## Build

```bash
make cniwatcher
# or container image:
make build-cniwatcher-image
```

## Helm

```bash
helm upgrade --install network-enforcer ./charts/network-enforcer \
  --namespace network-enforcer --create-namespace \
  --set cniwatcher.cniType=cilium \
  --set cniwatcher.image.repository=<registry>/cniwatcher \
  --set cniwatcher.image.tag=<tag>
```

Set `cniwatcher.otelEndpoint` to your OTLP log collector. If empty, the chart defaults to `<release>-otlp.<namespace>.svc.cluster.local:4317`.

## Local development (Tilt)

1. Copy `tilt-settings.yaml.example` to `tilt-settings.yaml`.
2. Set `cniwatcher.cniType` (defaults to `calico` if omitted) and cluster context.
3. Run `tilt up`.

Tilt installs an OpenTelemetry collector in the `network-enforcer` namespace for log debugging and builds the cniwatcher image with live reload.

## Calico Goldmane proto

Regenerate protobuf stubs after upgrading Calico:

```bash
make generate-calico-goldmane-proto GOLDMANE_VERSION=v3.30.2
```

## Known limitations

### Cilium

cniWatcher reads Cilium flows and maps policy names from `EgressDeniedBy` / `IngressDeniedBy` when Cilium provides them.

Policy attribution (`egress_enforced_by` / `ingress_enforced_by`) is only reliable when denies come from `CiliumNetworkPolicy` or `CiliumClusterwideNetworkPolicy` with explicit spec [`ingressDeny`] or `egressDeny` rules. [Deny policies](https://docs.cilium.io/en/stable/security/policy/deny/) take precedence over allow rules and are how Cilium expresses explicit rejects.

Standard **Kubernetes `NetworkPolicy`** denies (implicit default-deny or allow-list misses) still appear as policy drops in Cilium, but Cilium does not expose which policy caused the deny. For those flows, `egress_enforced_by` and `ingress_enforced_by` are typically empty even though the deny event itself is recorded (endpoints, protocol, timestamp).

### AWS VPC

The AWS VPC CNI network policy agent logs denied flows (source/destination IP, ports, protocol, verdict) but does not expose which Kubernetes NetworkPolicy caused the deny. cniWatcher therefore cannot populate `egress_enforced_by` / `ingress_enforced_by` on deny events for this CNI type. You still get deny visibility at the flow level (endpoints, protocol, timestamp); policy attribution is not available until AWS provides that data in the agent logs.
