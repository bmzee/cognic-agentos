{{- define "agentos.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "agentos.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "agentos.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "agentos.labels" -}}
app.kubernetes.io/name: {{ include "agentos.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: cognic-agentos
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "agentos.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentos.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "agentos.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{/*
Refuse an ambiguous secret source: at most one of secrets.create / secrets.existingSecret /
externalSecrets.enabled. (At-least-one is enforced by the terminal fail in agentos.secretName.)
*/}}
{{- define "agentos.validateSecretSource" -}}
{{- $n := 0 -}}
{{- if .Values.externalSecrets.enabled -}}{{- $n = add1 $n -}}{{- end -}}
{{- if .Values.secrets.existingSecret -}}{{- $n = add1 $n -}}{{- end -}}
{{- if .Values.secrets.create -}}{{- $n = add1 $n -}}{{- end -}}
{{- if gt $n 1 -}}{{- fail "secrets: configure exactly one source — secrets.create (dev) XOR secrets.existingSecret XOR externalSecrets.enabled" -}}{{- end -}}
{{- end -}}

{{- define "agentos.secretName" -}}
{{- include "agentos.validateSecretSource" . -}}
{{- if .Values.externalSecrets.enabled -}}
  {{- .Values.externalSecrets.targetSecretName | default (printf "%s-secrets" (include "agentos.fullname" .)) -}}
{{- else if .Values.secrets.existingSecret -}}{{ .Values.secrets.existingSecret }}
{{- else if .Values.secrets.create -}}{{ include "agentos.fullname" . }}-secrets
{{- else -}}{{ fail "secrets: set secrets.create=true (smoke/dev, with databaseUrl+vaultToken) OR secrets.existingSecret=<name> OR externalSecrets.enabled=true (production)" }}
{{- end -}}
{{- end -}}

{{- define "agentos.litellmConfigMapName" -}}
{{- if .Values.litellm.existingConfigMap -}}{{ .Values.litellm.existingConfigMap }}{{- else -}}{{ include "agentos.fullname" . }}-litellm{{- end -}}
{{- end -}}
