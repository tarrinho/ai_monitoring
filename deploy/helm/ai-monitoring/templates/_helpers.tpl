{{- define "ai-monitoring.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ai-monitoring.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "ai-monitoring.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ai-monitoring.labels" -}}
app.kubernetes.io/name: {{ include "ai-monitoring.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "ai-monitoring.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ai-monitoring.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "ai-monitoring.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "ai-monitoring.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "ai-monitoring.secretName" -}}
{{- if .Values.secret.existingSecret -}}
{{- .Values.secret.existingSecret -}}
{{- else -}}
{{- include "ai-monitoring.fullname" . -}}
{{- end -}}
{{- end -}}

{{- define "ai-monitoring.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
