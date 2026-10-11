{{- define "trustgate.fullname" -}}
{{- printf "%s-trustgate" .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}

{{- define "trustgate.labels" -}}
app.kubernetes.io/name: trustgate
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{/* selector labels for one component: include "trustgate.selector" (list $ "proxy") */}}
{{- define "trustgate.selector" -}}
app.kubernetes.io/name: trustgate
app.kubernetes.io/instance: {{ (index . 0).Release.Name }}
app.kubernetes.io/component: {{ index . 1 }}
{{- end -}}

{{- define "trustgate.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{- define "trustgate.secretName" -}}
{{- .Values.secrets.existingSecret | default (printf "%s-secrets" (include "trustgate.fullname" .)) -}}
{{- end -}}

{{- define "trustgate.databaseUrl" -}}
{{- if .Values.postgresql.enabled -}}
postgresql+psycopg://trustgate:{{ required "postgresql.password is required" .Values.postgresql.password }}@{{ include "trustgate.fullname" . }}-postgres:5432/trustgate
{{- else -}}
{{ required "postgresql.externalUrl is required when postgresql.enabled is false" .Values.postgresql.externalUrl }}
{{- end -}}
{{- end -}}

{{/* Shared pod settings for every TrustGate container. */}}
{{- define "trustgate.podSpec" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets: {{ toYaml . | nindent 2 }}
{{- end }}
securityContext: {{ toYaml .Values.podSecurityContext | nindent 2 }}
automountServiceAccountToken: false
{{- with .Values.nodeSelector }}
nodeSelector: {{ toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.tolerations }}
tolerations: {{ toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.affinity }}
affinity: {{ toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/* Container env, mounts and security shared by every TrustGate container. */}}
{{- define "trustgate.containerCommon" -}}
image: {{ include "trustgate.image" . }}
imagePullPolicy: {{ .Values.image.pullPolicy }}
securityContext: {{ toYaml .Values.securityContext | nindent 2 }}
envFrom:
  - configMapRef: {name: {{ include "trustgate.fullname" . }}-env}
  - secretRef: {name: {{ include "trustgate.secretName" . }}-env, optional: true}
{{- end -}}

{{- define "trustgate.writableMounts" -}}
- {name: data, mountPath: /app/data}
- {name: tmp, mountPath: /tmp}
{{- end -}}

{{- define "trustgate.writableVolumes" -}}
- {name: data, emptyDir: {}}
- {name: tmp, emptyDir: {}}
{{- end -}}

{{/* Mount only the named keys of the file secret at /run/secrets/<key>. */}}
{{- define "trustgate.secretVolume" -}}
- name: run-secrets
  secret:
    secretName: {{ include "trustgate.secretName" (index . 0) }}
    optional: true
    items:
    {{- range (index . 1) }}
      - {key: {{ . }}, path: {{ . }}}
    {{- end }}
{{- end -}}
