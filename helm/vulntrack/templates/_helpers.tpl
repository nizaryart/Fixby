{{- define "vulntrack.labels" -}}
app.kubernetes.io/name: vulntrack
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "vulntrack.selector" -}}
app.kubernetes.io/name: vulntrack
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
