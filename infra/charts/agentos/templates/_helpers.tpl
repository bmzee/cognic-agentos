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

{{- define "agentos.secretName" -}}
{{- if .Values.secrets.existingSecret -}}{{ .Values.secrets.existingSecret }}
{{- else if .Values.secrets.create -}}{{ include "agentos.fullname" . }}-secrets
{{- else -}}{{ fail "secrets: set secrets.create=true (smoke/dev, with databaseUrl+vaultToken) OR secrets.existingSecret=<name> (production)" }}
{{- end -}}
{{- end -}}

{{- define "agentos.litellmConfigMapName" -}}
{{- if .Values.litellm.existingConfigMap -}}{{ .Values.litellm.existingConfigMap }}{{- else -}}{{ include "agentos.fullname" . }}-litellm{{- end -}}
{{- end -}}
