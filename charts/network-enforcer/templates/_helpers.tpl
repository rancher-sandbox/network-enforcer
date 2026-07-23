{{/*
Expand the name of the chart.
*/}}
{{- define "network-enforcer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "network-enforcer.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "network-enforcer.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "network-enforcer.labels" -}}
helm.sh/chart: {{ include "network-enforcer.chart" . }}
{{ include "network-enforcer.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "network-enforcer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "network-enforcer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
DNS name of the controller OTLP service; also a SAN on the controller cert.
*/}}
{{- define "network-enforcer.controller.otlpServiceDNS" -}}
{{ include "network-enforcer.fullname" . }}-otlp.{{ .Release.Namespace }}.svc.cluster.local
{{- end -}}



{{/*
Certificate helpers for cniwatcher mTLS (CA issuer and secret share a name).
*/}}
{{- define "network-enforcer.caIssuerName" -}}
{{ include "network-enforcer.fullname" . }}-ca
{{- end -}}
{{- define "network-enforcer.caSecretName" -}}
{{ include "network-enforcer.fullname" . }}-ca
{{- end -}}
{{- define "network-enforcer.cniwatcher.certDir" -}}
/etc/network-enforcer/certs
{{- end -}}

{{/*
Certificate directory for OBI mTLS (shares the same CA as cniwatcher).
*/}}
{{- define "network-enforcer.obi.certDir" -}}
/etc/network-enforcer/certs
{{- end -}}

{{/*
CNI-specific volume mounts for cniwatcher
*/}}
{{- define "network-enforcer.cniwatcher.volumeMounts" -}}
{{- if eq .Values.cniwatcher.cniType "cilium" }}
- name: hubble-sock
  mountPath: /var/run/cilium
{{- else if eq .Values.cniwatcher.cniType "calico" }}
- name: goldmane-key-pair-volume
  mountPath: /etc/goldmane/certs
  readOnly: true
{{- else if eq .Values.cniwatcher.cniType "flannel" }}
- name: flannel-ulog
  mountPath: /var/log/ulog
  readOnly: true
{{- else if eq .Values.cniwatcher.cniType "aws-vpc" }}
- name: aws-eni-logs
  mountPath: /var/log/aws-routed-eni
  readOnly: true
{{- end }}
- name: cniwatcher-mtls-certs
  mountPath: {{ include "network-enforcer.cniwatcher.certDir" . }}
  readOnly: true
{{- end -}}

{{/*
CNI-specific volumes for cniwatcher
*/}}
{{- define "network-enforcer.cniwatcher.volumes" -}}
{{- if eq .Values.cniwatcher.cniType "cilium" }}
- name: hubble-sock
  hostPath:
    path: /var/run/cilium
{{- else if eq .Values.cniwatcher.cniType "calico" }}
- name: goldmane-key-pair-volume
  secret:
    secretName: cniwatcher-goldmane-key-pair
{{- else if eq .Values.cniwatcher.cniType "flannel" }}
- name: flannel-ulog
  hostPath:
    path: /var/log/ulog
    type: Directory
{{- else if eq .Values.cniwatcher.cniType "aws-vpc" }}
- name: aws-eni-logs
  hostPath:
    path: /var/log/aws-routed-eni
    type: Directory
{{- end }}
- name: cniwatcher-mtls-certs
  csi:
    driver: "csi.cert-manager.io"
    readOnly: true
    volumeAttributes:
      csi.cert-manager.io/issuer-name: {{ include "network-enforcer.caIssuerName" . }}
      csi.cert-manager.io/issuer-kind: Issuer
      csi.cert-manager.io/dns-names: ${POD_NAME}.${POD_NAMESPACE}
{{- end -}}
