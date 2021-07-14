{{/* vim: set filetype=mustache: */}}
{{/* Expand the name of the chart. */}}
{{- define "f5-bigip-ingress.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "f5-bigip-ingress.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "f5-bigip-ingress.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "f5-bigip-ingress-backend" -}}
backend:
  serviceName: {{ .backend.serviceName }}
  servicePort: {{ .backend.servicePort }}
{{- end -}}

{{- define "f5-bigip-ingress-path" }}
{{- if .paths -}}
{{ (printf "- http:") | indent 2 }}
{{ (printf "paths:") | indent 6 }}
{{- range $key, $value := .paths }}
{{ (printf "- path: %s" .path ) | indent 6 }}
{{ include "f5-bigip-ingress-backend" . | indent 8 }}
{{- end }}
{{- else if .http }}
  paths:
{{- range $key, $value := .http.paths }}
  - path: {{ .path }}
{{ include "f5-bigip-ingress-backend" . | indent 4 }}
{{- end }}
{{- end }}
{{- end -}}

{{- define "f5-bigip-ingress-host" -}}
- host: {{ .host }}
  http:
{{- include "f5-bigip-ingress-path" . | indent 2 }}
{{- end -}}
