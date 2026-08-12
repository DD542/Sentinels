{{/* Nom court du chart, éventuellement surchargé. */}}
{{- define "sentinel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Nom complet des ressources (63 caractères max, contrainte Kubernetes). */}}
{{- define "sentinel.fullname" -}}
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

{{- define "sentinel.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "sentinel.labels" -}}
helm.sh/chart: {{ include "sentinel.chart" . }}
{{ include "sentinel.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "sentinel.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sentinel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Sélecteur de l'API seule.

Depuis que la console est déployée par le même chart, ses pods portent
les mêmes labels `name`/`instance` que l'API. Un sélecteur qui s'arrête
là attraperait les deux : le Service de l'API enverrait des requêtes à
nginx, et le ServiceMonitor scruterait /metrics sur la console. D'où le
label de composant.

`spec.selector` du Deployment reste volontairement inchangé : ce champ
est IMMUABLE, y toucher ferait échouer tout `helm upgrade` en place. Il
ne peut pas adopter les pods de la console, qui n'ont pas le hash de son
ReplicaSet.
*/}}
{{- define "sentinel.apiSelectorLabels" -}}
{{ include "sentinel.selectorLabels" . }}
app.kubernetes.io/component: api
{{- end -}}

{{- define "sentinel.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "sentinel.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Nom du Secret : celui fourni, sinon celui créé par le chart. */}}
{{- define "sentinel.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- include "sentinel.fullname" . -}}
{{- end -}}
{{- end -}}

{{/*
Variable d'environnement lue depuis le Secret.
Usage : {{ include "sentinel.secretEnv" (dict "name" "database_url" "key" .Values.secretKeys.databaseUrl "ctx" .) }}
Optionnelle : si la clé manque dans le Secret, le pod démarre quand même.
*/}}
{{- define "sentinel.secretEnv" -}}
- name: {{ .name }}
  valueFrom:
    secretKeyRef:
      name: {{ include "sentinel.secretName" .ctx }}
      key: {{ .key }}
      optional: true
{{- end -}}
