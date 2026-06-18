# Sprint 14B-Z1a — Deployment Substrate Packaging Core — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a real, OpenShift-compatible Helm chart for the AgentOS kernel, validated always-on in CI (lint/template/kubeconform/snapshot) and proven by an env-gated local `kind` Ready-smoke against six real credential-free backends.

**Architecture:** Pure additive infra-as-code under `infra/charts/agentos/` (Helm only, no Kustomize). The chart packages the existing `default-adapters` prod image (`create_prod_app`); it changes **no kernel code** (CC stays 131). Boot facts (verified from source): image `WORKDIR=/app`, `USER cognic` (UID 10001), OPA bundles ship in-image under `/app/policies/_default/`, the **litellm router config is the one boot-blocking file** that is NOT in the image and must be mounted at `/app/infra/litellm/config.yaml`; trust-root/allowlist are not needed for Ready; `cache_driver=none` keeps the memory/scheduler/quota OPA engines unbuilt; writable paths under `readOnlyRootFilesystem=true` are `/tmp`, `/var/lib/cognic-agentos/object-store` (prod `local_object_store_root`), and `/var/lib/cognic/model-artifacts` (prod `model_artifact_root` — a distinct path).

**Tech Stack:** Helm v3 (templates), `kubeconform` (schema validation), `kind` (local k8s smoke), pytest (byte-equality snapshot test), GitHub Actions (`.github/workflows/python.yml`), the committed `infra/litellm/config.yaml` model (Ollama, credential-free).

**Spec:** `docs/superpowers/specs/2026-06-17-sprint-14b-z1a-deployment-substrate-packaging-design.md`

**Prerequisites for the executor (local):** `helm` ≥ 3.14 and `kubeconform` ≥ 0.6 must be on PATH for T1–T5 render/validate verification (T5 pins the CI versions by SHA; install locally to match). `kind` + `docker` for the T6 smoke (env-gated; verified-by-reading is acceptable if the executor lacks a Docker host — flag it).

**Posture:** CC count stays **131**; no kernel edit; no migration; no new on-gate module. The only Python added is the snapshot test (subject to ruff/mypy). The `kind` smoke is env-gated (operator-runnable), not on the always-on CI lane.

---

## File structure

**Created (chart):**
- `infra/charts/agentos/Chart.yaml` — chart metadata.
- `infra/charts/agentos/values.yaml` — the documented values surface + prod-safe defaults.
- `infra/charts/agentos/values.schema.json` — JSON-Schema validation of values.
- `infra/charts/agentos/templates/_helpers.tpl` — name/label helpers.
- `infra/charts/agentos/templates/serviceaccount.yaml` — dedicated SA (no RBAC).
- `infra/charts/agentos/templates/configmap.yaml` — non-secret `COGNIC_*` env.
- `infra/charts/agentos/templates/configmap-litellm.yaml` — the boot-required litellm router config.
- `infra/charts/agentos/templates/secret.yaml` — bootstrap Secret, rendered only when `secrets.create=true`.
- `infra/charts/agentos/templates/deployment.yaml` — the kernel Deployment.
- `infra/charts/agentos/templates/service.yaml` — ClusterIP Service.
- `infra/charts/agentos/templates/migration-job.yaml` — pre-install/pre-upgrade hook Job.
- `infra/charts/agentos/templates/NOTES.txt` — post-install operator guidance.
- `infra/charts/agentos/ci/snapshot-values.yaml` — deterministic inputs for the rendered snapshot.
- `infra/charts/agentos/ci/smoke-values.yaml` — points the chart at the in-cluster smoke backends.

**Created (smoke harness):**
- `infra/charts/agentos/ci/smoke/backends.yaml` — the six real backends (Postgres, Qdrant, Vault, Ollama, Langfuse, LiteLLM) as k8s manifests.
- `infra/charts/agentos/ci/smoke/run-smoke.sh` — the kind smoke driver script.

**Created (tests/CI/docs):**
- `tests/unit/infra/__init__.py` + `tests/unit/infra/test_helm_chart.py` — the rendered-YAML byte-equality snapshot test.
- `tests/unit/infra/helm/agentos_rendered.yaml` — the committed deterministic render (snapshot).
- `docs/operator-runbooks/kind-smoke-deployment.md` — the smoke runbook.
- `docs/operator-runbooks/helm-chart-production-install.md` — the production install runbook.
- `docs/adrs/ADR-024-deployment-substrate-helm-packaging.md` — the packaging ADR.

**Modified:**
- `.github/workflows/python.yml` — add an always-on `helm-chart` job + an env-gated `kind-smoke` job.
- `docs/AS_BUILT_CAPABILITY_MAP.md` — Pillar 5 (partial → packaging-done) + forward item 7.
- `AGENTS.md` — a Sprint 14B-Z1a note.

---

## Task 1: Chart skeleton + ConfigMap + Secret + ServiceAccount + litellm config

**Files:**
- Create: `infra/charts/agentos/Chart.yaml`, `values.yaml`, `values.schema.json`, `templates/_helpers.tpl`, `templates/serviceaccount.yaml`, `templates/configmap.yaml`, `templates/configmap-litellm.yaml`, `templates/secret.yaml`, `templates/NOTES.txt`

- [ ] **Step 1: Create `infra/charts/agentos/Chart.yaml`**

```yaml
apiVersion: v2
name: agentos
description: Cognic AgentOS governance kernel — OpenShift-compatible Helm chart (Sprint 14B-Z1a packaging core).
type: application
version: 0.1.0
appVersion: "0.1.0"
kubeVersion: ">=1.27.0-0"
```

- [ ] **Step 2: Create `infra/charts/agentos/values.yaml`**

```yaml
# Cognic AgentOS — Helm values (Sprint 14B-Z1a packaging core).
# Defaults are prod-safe (strict-profile boot). The smoke overlays ci/smoke-values.yaml.

image:
  repository: ghcr.io/bmzee/cognic-agentos      # the default-adapters image; bank operators re-home
  tag: ""                                        # empty → defaults to .Chart.AppVersion
  pullPolicy: IfNotPresent
  pullSecrets: []

replicaCount: 1
runtimeProfile: prod                             # COGNIC_RUNTIME_PROFILE; strict deploy-safety guards apply
apiPrefix: /api/v1                               # COGNIC_API_PREFIX; probe paths derive from this

qdrant:
  url: http://qdrant:6333                        # COGNIC_QDRANT_URL

vault:
  # Vault is REQUIRED in Z1a. secret_driver defaults to "vault" with NO "none" mode, and
  # VaultAdapter refuses a missing addr — so there is no real "Vault off" path. A true
  # secret_driver=none is Option-C / Z1b. COGNIC_VAULT_ADDR is always rendered; the token
  # is a secret (see `secrets`).
  addr: http://vault:8200                        # COGNIC_VAULT_ADDR

embedding:
  driver: ollama                                 # COGNIC_EMBED_DRIVER
  baseUrl: http://ollama:11434                   # COGNIC_EMBEDDING_BASE_URL
  model: nomic-embed-text                        # COGNIC_EMBEDDING_MODEL — MUST NOT be the dev default qwen3-embedding:8b (G5)
  dimensions: 768                                # COGNIC_EMBEDDING_DIMENSIONS — coherent with nomic-embed-text (768-dim)

langfuse:
  host: http://langfuse:3000                     # COGNIC_LANGFUSE_HOST — host is the only Langfuse setting required for readiness

litellm:
  baseUrl: http://litellm:4000                   # COGNIC_LITELLM_BASE_URL
  existingConfigMap: ""                          # if set, mount this instead of rendering `config`
  config: |                                      # boot-required router config (NOT in the image), mounted at /app/infra/litellm/config.yaml
    model_list:
      - model_name: cognic-tier1-dev
        litellm_params:
          model: ollama/qwen3:8b
          api_base: ${OLLAMA_BASE_URL:-http://ollama:11434}
      - model_name: cognic-tier2-dev
        litellm_params:
          model: ollama/qwen3:32b
          api_base: ${OLLAMA_BASE_URL:-http://ollama:11434}
    litellm_settings:
      drop_params: true
    general_settings:
      master_key: ${LITELLM_MASTER_KEY}

cache:
  enabled: false                                 # Redis off → COGNIC_CACHE_DRIVER=none; scheduler/quotas/memory/kill-switch dormant
  url: ""                                         # COGNIC_REDIS_URL (required only when cache.enabled=true)

sandbox:
  runtimeEnabled: false                          # COGNIC_SANDBOX_RUNTIME_ENABLED
  # G7 fires in strict profile INDEPENDENT of runtimeEnabled; both MUST be non-personal, digest-pinned
  # <ref>@sha256:<64-lowercase-hex>. Operators re-home + re-sign under their canonical trust root.
  canonicalRuntimeImage: "registry.example.com/cognic-agentos/sandbox-runtime-python@sha256:0000000000000000000000000000000000000000000000000000000000000000"
  canonicalEgressProxyImage: "registry.example.com/cognic-agentos/sandbox-egress-proxy@sha256:0000000000000000000000000000000000000000000000000000000000000000"

migrations:
  enabled: true                                  # pre-install/pre-upgrade hook Job runs `alembic upgrade head`

secrets:
  create: false                                  # true ONLY for smoke/dev — DO NOT use in production
  existingSecret: ""                             # production: name of an operator/ESO-managed Secret carrying COGNIC_DATABASE_URL (+ COGNIC_VAULT_TOKEN)
  databaseUrl: ""                                # used only when create=true
  vaultToken: ""                                 # used only when create=true

service:
  type: ClusterIP
  port: 8000

resources:
  requests: { cpu: 250m, memory: 512Mi }
  limits: { cpu: "2", memory: 2Gi }

podSecurityContext: {}                           # OpenShift assigns fsGroup via SCC; non-OpenShift clusters set fsGroup: 10001 (the image GID)

objectStore:
  sizeLimit: 5Gi                                 # emptyDir for /var/lib/cognic-agentos/object-store (readOnlyRootFilesystem=true)
modelArtifacts:
  sizeLimit: 5Gi                                 # emptyDir for /var/lib/cognic/model-artifacts (prod-resolved model_artifact_root; readOnlyRootFilesystem=true)
tmpSizeLimit: 256Mi                              # emptyDir for /tmp
```

- [ ] **Step 3: Create `infra/charts/agentos/templates/_helpers.tpl`**

```
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
```

- [ ] **Step 4: Create `infra/charts/agentos/templates/serviceaccount.yaml`**

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "agentos.fullname" . }}
  labels:
    {{- include "agentos.labels" . | nindent 4 }}
automountServiceAccountToken: false
```

- [ ] **Step 5: Create `infra/charts/agentos/templates/configmap.yaml`** (non-secret `COGNIC_*`)

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "agentos.fullname" . }}-config
  labels:
    {{- include "agentos.labels" . | nindent 4 }}
data:
  COGNIC_RUNTIME_PROFILE: {{ .Values.runtimeProfile | quote }}
  COGNIC_API_PREFIX: {{ .Values.apiPrefix | quote }}
  COGNIC_QDRANT_URL: {{ .Values.qdrant.url | quote }}
  COGNIC_VAULT_ADDR: {{ .Values.vault.addr | quote }}
  COGNIC_EMBED_DRIVER: {{ .Values.embedding.driver | quote }}
  COGNIC_EMBEDDING_BASE_URL: {{ .Values.embedding.baseUrl | quote }}
  COGNIC_EMBEDDING_MODEL: {{ .Values.embedding.model | quote }}
  COGNIC_EMBEDDING_DIMENSIONS: {{ .Values.embedding.dimensions | quote }}
  COGNIC_LANGFUSE_HOST: {{ .Values.langfuse.host | quote }}
  COGNIC_LITELLM_BASE_URL: {{ .Values.litellm.baseUrl | quote }}
  COGNIC_SANDBOX_RUNTIME_ENABLED: {{ .Values.sandbox.runtimeEnabled | quote }}
  COGNIC_SANDBOX_CANONICAL_RUNTIME_PYTHON_IMAGE: {{ .Values.sandbox.canonicalRuntimeImage | quote }}
  COGNIC_SANDBOX_CANONICAL_EGRESS_PROXY_IMAGE: {{ .Values.sandbox.canonicalEgressProxyImage | quote }}
  {{- if .Values.cache.enabled }}
  COGNIC_CACHE_DRIVER: "redis"
  COGNIC_REDIS_URL: {{ .Values.cache.url | quote }}
  {{- else }}
  COGNIC_CACHE_DRIVER: "none"
  {{- end }}
```

- [ ] **Step 6: Create `infra/charts/agentos/templates/configmap-litellm.yaml`** (boot-required router config; rendered only when no `existingConfigMap`)

```yaml
{{- if not .Values.litellm.existingConfigMap }}
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "agentos.fullname" . }}-litellm
  labels:
    {{- include "agentos.labels" . | nindent 4 }}
data:
  config.yaml: |
    {{- .Values.litellm.config | nindent 4 }}
{{- end }}
```

- [ ] **Step 7: Create `infra/charts/agentos/templates/secret.yaml`** (gated on `secrets.create`; smoke/dev only)

```yaml
{{- if .Values.secrets.create }}
apiVersion: v1
kind: Secret
metadata:
  name: {{ include "agentos.fullname" . }}-secrets
  labels:
    {{- include "agentos.labels" . | nindent 4 }}
type: Opaque
stringData:
  COGNIC_DATABASE_URL: {{ required "secrets.databaseUrl is required when secrets.create=true" .Values.secrets.databaseUrl | quote }}
  COGNIC_VAULT_TOKEN: {{ required "secrets.vaultToken is required when secrets.create=true (Vault is required in Z1a)" .Values.secrets.vaultToken | quote }}
{{- end }}
```

- [ ] **Step 8: Create `infra/charts/agentos/templates/NOTES.txt`**

```
Cognic AgentOS ({{ .Chart.AppVersion }}) installed as release "{{ .Release.Name }}".

Service (ClusterIP): {{ include "agentos.fullname" . }}:{{ .Values.service.port }}
Probes: liveness {{ .Values.apiPrefix }}/healthz · readiness {{ .Values.apiPrefix }}/readyz

Verify readiness:
  kubectl -n {{ .Release.Namespace }} port-forward svc/{{ include "agentos.fullname" . }} {{ .Values.service.port }}:{{ .Values.service.port }} &
  curl -fsS http://127.0.0.1:{{ .Values.service.port }}{{ .Values.apiPrefix }}/readyz

{{ if .Values.secrets.create }}WARNING: secrets.create=true renders a chart-managed Secret — smoke/dev ONLY.
For production set secrets.create=false and secrets.existingSecret=<operator/ESO-managed Secret>.{{ end }}
{{ if not .Values.migrations.enabled }}migrations.enabled=false: no migration Job ran. Run `alembic upgrade head` against COGNIC_DATABASE_URL before serving traffic.{{ end }}
Readiness requires all five adapters healthy: Postgres, Qdrant, Vault, the embedding endpoint, and Langfuse.
```

- [ ] **Step 9: Create `infra/charts/agentos/values.schema.json`**

```json
{
  "$schema": "https://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["image", "runtimeProfile", "apiPrefix", "qdrant", "vault", "embedding", "langfuse", "litellm", "sandbox", "migrations", "secrets", "service"],
  "properties": {
    "image": {
      "type": "object",
      "required": ["repository", "pullPolicy"],
      "properties": {
        "repository": { "type": "string", "minLength": 1 },
        "tag": { "type": "string" },
        "pullPolicy": { "type": "string", "enum": ["Always", "IfNotPresent", "Never"] },
        "pullSecrets": { "type": "array" }
      }
    },
    "replicaCount": { "type": "integer", "minimum": 1 },
    "runtimeProfile": { "type": "string", "enum": ["dev", "stage", "prod"] },
    "apiPrefix": { "type": "string", "pattern": "^/" },
    "qdrant": { "type": "object", "required": ["url"], "properties": { "url": { "type": "string" } } },
    "vault": { "type": "object", "required": ["addr"], "properties": { "addr": { "type": "string", "minLength": 1 } } },
    "embedding": {
      "type": "object",
      "required": ["driver", "baseUrl", "model"],
      "properties": {
        "driver": { "type": "string" },
        "baseUrl": { "type": "string" },
        "model": { "type": "string", "not": { "const": "qwen3-embedding:8b" } },
        "dimensions": { "type": "integer", "minimum": 1 }
      }
    },
    "langfuse": { "type": "object", "required": ["host"], "properties": { "host": { "type": "string" } } },
    "litellm": { "type": "object", "required": ["baseUrl"], "properties": { "baseUrl": { "type": "string" }, "config": { "type": "string" }, "existingConfigMap": { "type": "string" } } },
    "cache": { "type": "object", "properties": { "enabled": { "type": "boolean" }, "url": { "type": "string" } } },
    "sandbox": {
      "type": "object",
      "required": ["runtimeEnabled", "canonicalRuntimeImage", "canonicalEgressProxyImage"],
      "properties": {
        "runtimeEnabled": { "type": "boolean" },
        "canonicalRuntimeImage": { "type": "string", "pattern": "@sha256:[0-9a-f]{64}$", "not": { "pattern": "ghcr.io/bmzee" } },
        "canonicalEgressProxyImage": { "type": "string", "pattern": "@sha256:[0-9a-f]{64}$", "not": { "pattern": "ghcr.io/bmzee" } }
      }
    },
    "migrations": { "type": "object", "required": ["enabled"], "properties": { "enabled": { "type": "boolean" } } },
    "secrets": {
      "type": "object",
      "required": ["create"],
      "properties": {
        "create": { "type": "boolean" },
        "existingSecret": { "type": "string" },
        "databaseUrl": { "type": "string" },
        "vaultToken": { "type": "string" }
      },
      "if": { "properties": { "create": { "const": true } } },
      "then": { "required": ["databaseUrl", "vaultToken"], "properties": { "databaseUrl": { "minLength": 1 }, "vaultToken": { "minLength": 1 } } },
      "else": { "required": ["existingSecret"], "properties": { "existingSecret": { "minLength": 1 } } }
    },
    "service": { "type": "object", "required": ["type", "port"], "properties": { "type": { "type": "string" }, "port": { "type": "integer" } } },
    "podSecurityContext": { "type": "object" }
  }
}
```

- [ ] **Step 10: Lint + render to verify the skeleton**

Run (secret values are required by the strict values.schema.json secrets validation, so provide them inline):
```bash
helm lint infra/charts/agentos --set secrets.create=true --set secrets.databaseUrl=postgresql+asyncpg://u:p@postgres:5432/cognic --set secrets.vaultToken=devtoken
helm template rel infra/charts/agentos --namespace cognic --set secrets.create=true --set secrets.databaseUrl=x --set secrets.vaultToken=y | head -40
```
Expected: `helm lint` reports `0 chart(s) failed`; `helm template` renders the ConfigMap(s) + ServiceAccount without error. (Bare `helm lint`/`template` without secret values intentionally FAILS the schema now — that is the finding-2 guard working.)

- [ ] **Step 11: Commit**

```bash
git add infra/charts/agentos/Chart.yaml infra/charts/agentos/values.yaml infra/charts/agentos/values.schema.json infra/charts/agentos/templates/_helpers.tpl infra/charts/agentos/templates/serviceaccount.yaml infra/charts/agentos/templates/configmap.yaml infra/charts/agentos/templates/configmap-litellm.yaml infra/charts/agentos/templates/secret.yaml infra/charts/agentos/templates/NOTES.txt
git commit -m "feat(deploy): Sprint 14B-Z1a T1 — Helm chart skeleton + config/secret/SA (ADR-024)"
```

---

## Task 2: Deployment + Service

**Files:**
- Create: `infra/charts/agentos/templates/deployment.yaml`, `infra/charts/agentos/templates/service.yaml`

- [ ] **Step 1: Create `infra/charts/agentos/templates/deployment.yaml`**

The image provides `USER cognic` (UID 10001) and defaults `COGNIC_HOST/PORT/API_PREFIX/RUNTIME_PROFILE`; the OPA bundles ship in-image; the litellm config is mounted at `/app/infra/litellm/`; `/tmp`, `/var/lib/cognic-agentos/object-store`, and `/var/lib/cognic/model-artifacts` are emptyDirs (readOnlyRootFilesystem). The securityContext is OpenShift-pure (no `runAsUser`/`fsGroup`).

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "agentos.fullname" . }}
  labels:
    {{- include "agentos.labels" . | nindent 4 }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      {{- include "agentos.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "agentos.selectorLabels" . | nindent 8 }}
    spec:
      serviceAccountName: {{ include "agentos.fullname" . }}
      {{- with .Values.image.pullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      securityContext:
        runAsNonRoot: true
        {{- with .Values.podSecurityContext }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
      containers:
        - name: agentos
          image: {{ include "agentos.image" . | quote }}
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
            seccompProfile:
              type: RuntimeDefault
          ports:
            - name: http
              containerPort: {{ .Values.service.port }}
          envFrom:
            - configMapRef:
                name: {{ include "agentos.fullname" . }}-config
          env:
            - name: COGNIC_PORT
              value: {{ .Values.service.port | quote }}
            - name: COGNIC_DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: {{ include "agentos.secretName" . }}
                  key: COGNIC_DATABASE_URL
            - name: COGNIC_VAULT_TOKEN
              valueFrom:
                secretKeyRef:
                  name: {{ include "agentos.secretName" . }}
                  key: COGNIC_VAULT_TOKEN
          startupProbe:
            httpGet:
              path: {{ .Values.apiPrefix }}/healthz
              port: http
            failureThreshold: 30
            periodSeconds: 5
          livenessProbe:
            httpGet:
              path: {{ .Values.apiPrefix }}/healthz
              port: http
            periodSeconds: 15
            timeoutSeconds: 5
          readinessProbe:
            httpGet:
              path: {{ .Values.apiPrefix }}/readyz
              port: http
            periodSeconds: 10
            timeoutSeconds: 5
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
          volumeMounts:
            - name: litellm-config
              mountPath: /app/infra/litellm
              readOnly: true
            - name: tmp
              mountPath: /tmp
            - name: object-store
              mountPath: /var/lib/cognic-agentos/object-store
            - name: model-artifacts
              mountPath: /var/lib/cognic/model-artifacts
      volumes:
        - name: litellm-config
          configMap:
            name: {{ include "agentos.litellmConfigMapName" . }}
        - name: tmp
          emptyDir:
            sizeLimit: {{ .Values.tmpSizeLimit }}
        - name: object-store
          emptyDir:
            sizeLimit: {{ .Values.objectStore.sizeLimit }}
        - name: model-artifacts
          emptyDir:
            sizeLimit: {{ .Values.modelArtifacts.sizeLimit }}
```

- [ ] **Step 2: Create `infra/charts/agentos/templates/service.yaml`**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: {{ include "agentos.fullname" . }}
  labels:
    {{- include "agentos.labels" . | nindent 4 }}
spec:
  type: {{ .Values.service.type }}
  selector:
    {{- include "agentos.selectorLabels" . | nindent 4 }}
  ports:
    - name: http
      port: {{ .Values.service.port }}
      targetPort: http
```

- [ ] **Step 3: Render + verify the Deployment/Service**

Run:
```bash
helm template rel infra/charts/agentos --namespace cognic \
  --set secrets.create=true --set secrets.databaseUrl=postgresql+asyncpg://u:p@postgres:5432/cognic --set secrets.vaultToken=devtoken \
  | grep -E "kind: (Deployment|Service)"
```
Expected: both `kind: Deployment` and `kind: Service` present, no template error.

- [ ] **Step 4: Verify the OpenShift securityContext fields render**

Run:
```bash
helm template rel infra/charts/agentos --set secrets.create=true --set secrets.databaseUrl=x --set secrets.vaultToken=y \
  | grep -E "runAsNonRoot|readOnlyRootFilesystem|allowPrivilegeEscalation|RuntimeDefault|drop"
```
Expected: `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `RuntimeDefault`, and the `ALL` drop all appear. No hardcoded `runAsUser`/`fsGroup`.

- [ ] **Step 5: Commit**

```bash
git add infra/charts/agentos/templates/deployment.yaml infra/charts/agentos/templates/service.yaml
git commit -m "feat(deploy): Sprint 14B-Z1a T2 — kernel Deployment + Service (probes, OpenShift securityContext, emptyDir + litellm mount) (ADR-024)"
```

---

## Task 3: Migration hook Job

**Files:**
- Create: `infra/charts/agentos/templates/migration-job.yaml`

- [ ] **Step 1: Create `infra/charts/agentos/templates/migration-job.yaml`**

Gated by `migrations.enabled`. Pre-install/pre-upgrade hook; fail-loud if `COGNIC_DATABASE_URL` is unset (no silent success). Uses the same image (it bundles alembic + asyncpg + the migrations dir under `/app`).

```yaml
{{- if .Values.migrations.enabled }}
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ include "agentos.fullname" . }}-migrate
  labels:
    {{- include "agentos.labels" . | nindent 4 }}
  annotations:
    "helm.sh/hook": pre-install,pre-upgrade
    "helm.sh/hook-weight": "-5"
    "helm.sh/hook-delete-policy": before-hook-creation,hook-succeeded
spec:
  backoffLimit: 1
  ttlSecondsAfterFinished: 600
  template:
    metadata:
      labels:
        {{- include "agentos.selectorLabels" . | nindent 8 }}
    spec:
      restartPolicy: Never
      serviceAccountName: {{ include "agentos.fullname" . }}
      securityContext:
        runAsNonRoot: true
        {{- with .Values.podSecurityContext }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
      containers:
        - name: migrate
          image: {{ include "agentos.image" . | quote }}
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
            seccompProfile:
              type: RuntimeDefault
          command: ["sh", "-c"]
          args:
            - |
              set -eu
              if [ -z "${COGNIC_DATABASE_URL:-}" ]; then
                echo "FATAL: COGNIC_DATABASE_URL is unset — refusing to run migrations" >&2
                exit 1
              fi
              exec alembic upgrade head
          env:
            - name: COGNIC_DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: {{ include "agentos.secretName" . }}
                  key: COGNIC_DATABASE_URL
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: {{ .Values.tmpSizeLimit }}
{{- end }}
```

- [ ] **Step 2: Verify the Job renders when enabled and is absent when disabled**

Run:
```bash
helm template rel infra/charts/agentos --set secrets.create=true --set secrets.databaseUrl=x --set secrets.vaultToken=y | grep -c "kind: Job"
helm template rel infra/charts/agentos --set migrations.enabled=false --set secrets.create=true --set secrets.databaseUrl=x --set secrets.vaultToken=y | grep -c "kind: Job"
```
Expected: first prints `1`; second prints `0` (no Job rendered when disabled).

- [ ] **Step 3: Verify the hook annotations**

Run:
```bash
helm template rel infra/charts/agentos --set secrets.create=true --set secrets.databaseUrl=x --set secrets.vaultToken=y | grep -E "helm.sh/hook"
```
Expected: `helm.sh/hook: pre-install,pre-upgrade`, `helm.sh/hook-weight: "-5"`, `helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded` all present.

- [ ] **Step 4: Commit**

```bash
git add infra/charts/agentos/templates/migration-job.yaml
git commit -m "feat(deploy): Sprint 14B-Z1a T3 — values-gated pre-install/pre-upgrade migration hook Job (ADR-024)"
```

---

## Task 4: Deterministic snapshot test + always-on render values

**Files:**
- Create: `infra/charts/agentos/ci/snapshot-values.yaml`, `tests/unit/infra/__init__.py`, `tests/unit/infra/test_helm_chart.py`, `tests/unit/infra/helm/agentos_rendered.yaml` (generated)

- [ ] **Step 1: Create `infra/charts/agentos/ci/snapshot-values.yaml`** (deterministic inputs — fixed values so the render is byte-stable)

```yaml
# Deterministic inputs for the rendered-YAML snapshot drift gate.
image:
  repository: registry.example.com/cognic-agentos
  tag: "0.1.0-snapshot"
secrets:
  create: true
  databaseUrl: "postgresql+asyncpg://cognic:cognic@postgres:5432/cognic"
  vaultToken: "snapshot-token"
```

- [ ] **Step 2: Create `tests/unit/infra/__init__.py`** (empty package marker)

```python
```

- [ ] **Step 3: Write the snapshot test `tests/unit/infra/test_helm_chart.py`**

Mirrors `tests/unit/portal/api/ui/test_well_known_routes.py`: byte-equality vs a committed render; first run creates the snapshot and fails (telling you to commit it); regenerate via `rm <file> && uv run pytest …`. Pinned release name `rel` + namespace `cognic` + `ci/snapshot-values.yaml` make the render deterministic. The test skips (does not fail) if `helm` is unavailable, so CI without helm is honest rather than red.

```python
"""Rendered-Helm-YAML snapshot drift gate for the AgentOS chart (Sprint 14B-Z1a).

Mirrors the well-known-schema snapshot convention: `helm template` output with a
pinned release name / namespace / values file is byte-compared to a committed
snapshot. Drift fails the gate with the exact regeneration command.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CHART_DIR = _REPO_ROOT / "infra" / "charts" / "agentos"
_SNAPSHOT_VALUES = _CHART_DIR / "ci" / "snapshot-values.yaml"
_SNAPSHOT = Path(__file__).resolve().parent / "helm" / "agentos_rendered.yaml"


def _render() -> str:
    return subprocess.run(
        [
            "helm",
            "template",
            "rel",
            str(_CHART_DIR),
            "--namespace",
            "cognic",
            "-f",
            str(_SNAPSHOT_VALUES),
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not on PATH")
def test_rendered_chart_matches_snapshot() -> None:
    rendered = _render()
    if not _SNAPSHOT.exists():
        _SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
        _SNAPSHOT.write_text(rendered)
        pytest.fail(
            f"snapshot created at {_SNAPSHOT} — review and commit it, then re-run"
        )
    assert rendered == _SNAPSHOT.read_text(), (
        f"rendered chart drifted from {_SNAPSHOT}. If the drift is intentional, "
        f"regenerate via `rm {_SNAPSHOT} && uv run pytest "
        f"tests/unit/infra/test_helm_chart.py::test_rendered_chart_matches_snapshot -x` "
        f"then commit the new snapshot."
    )


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not on PATH")
def test_chart_lints_clean() -> None:
    result = subprocess.run(
        ["helm", "lint", str(_CHART_DIR), "-f", str(_SNAPSHOT_VALUES)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"helm lint failed:\n{result.stdout}\n{result.stderr}"
```

- [ ] **Step 4: Generate + commit the snapshot**

Run:
```bash
uv run pytest tests/unit/infra/test_helm_chart.py -x
```
Expected: first run FAILS with "snapshot created … review and commit it". Inspect `tests/unit/infra/helm/agentos_rendered.yaml`, confirm it contains the Deployment/Service/ConfigMap(s)/Secret/Job/ServiceAccount, then re-run:
```bash
uv run pytest tests/unit/infra/test_helm_chart.py -x
```
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add infra/charts/agentos/ci/snapshot-values.yaml tests/unit/infra/__init__.py tests/unit/infra/test_helm_chart.py tests/unit/infra/helm/agentos_rendered.yaml
git commit -m "test(deploy): Sprint 14B-Z1a T4 — deterministic rendered-YAML snapshot drift gate (ADR-024)"
```

---

## Task 5: Always-on CI (helm lint/template/kubeconform/snapshot)

**Files:**
- Modify: `.github/workflows/python.yml` (add a `helm-chart` job)

- [ ] **Step 1: Read the existing workflow to match conventions**

Run: `sed -n '1,60p' .github/workflows/python.yml` and locate the binary-pinning pattern (the OPA/cosign SHA-verified download) + the `setup-uv`/`setup-python` block. Match the pinned-binary style.

- [ ] **Step 2: Add the `helm-chart` job to `.github/workflows/python.yml`**

Add this job under the top-level `jobs:` map (sibling of the existing `lint`/`postgres-integration` jobs). It pins `helm` + `kubeconform` by version and verifies each downloaded tarball against its OFFICIAL published checksum file via a real `sha256sum -c` — a concrete integrity check with NO fabricated/hand-filled digest. The pinned versions below are confirmed-at-download: if a version 404s, bump to the current stable from the official releases page; the checksum-file verification keeps any real pinned version safe.

```yaml
  helm-chart:
    name: helm lint + template + kubeconform + snapshot
    runs-on: ubuntu-latest
    timeout-minutes: 6
    env:
      HELM_VERSION: "v3.16.3"
      KUBECONFORM_VERSION: "v0.6.7"
    steps:
      - name: Checkout
        uses: actions/checkout@v6
      - name: Install Helm (pinned + checksum-verified)
        run: |
          set -euo pipefail
          curl -fsSLo helm.tgz "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz"
          curl -fsSLo helm.tgz.sha256sum "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz.sha256sum"
          echo "$(cut -d' ' -f1 helm.tgz.sha256sum)  helm.tgz" | sha256sum -c -
          tar -xzf helm.tgz
          sudo install -m 0755 linux-amd64/helm /usr/local/bin/helm
          helm version --short
      - name: Install kubeconform (pinned + checksum-verified)
        run: |
          set -euo pipefail
          curl -fsSLo kubeconform.tgz "https://github.com/yannh/kubeconform/releases/download/${KUBECONFORM_VERSION}/kubeconform-linux-amd64.tar.gz"
          curl -fsSLo CHECKSUMS "https://github.com/yannh/kubeconform/releases/download/${KUBECONFORM_VERSION}/CHECKSUMS"
          echo "$(grep 'kubeconform-linux-amd64.tar.gz' CHECKSUMS | cut -d' ' -f1)  kubeconform.tgz" | sha256sum -c -
          tar -xzf kubeconform.tgz
          sudo install -m 0755 kubeconform /usr/local/bin/kubeconform
          kubeconform -v
      - name: helm lint
        run: helm lint infra/charts/agentos -f infra/charts/agentos/ci/snapshot-values.yaml
      - name: helm template (deterministic)
        run: |
          helm template rel infra/charts/agentos --namespace cognic \
            -f infra/charts/agentos/ci/snapshot-values.yaml > /tmp/rendered.yaml
      - name: snapshot drift gate
        run: diff -u tests/unit/infra/helm/agentos_rendered.yaml /tmp/rendered.yaml
      - name: kubeconform schema validation
        run: kubeconform -strict -summary -kubernetes-version 1.27.0 /tmp/rendered.yaml
```

Note: the `sha256sum -c` above verifies each tarball against the project's OWN published checksum file (the same integrity check `get-helm-3` performs), version-pinned. For full OPA/cosign-doctrine parity (a hardcoded, PR-reviewed digest), an operator may replace the checksum-file download with a hardcoded `HELM_SHA256`/`KUBECONFORM_SHA256` env (fetched once via the same URLs) and `echo "${HELM_SHA256}  helm.tgz" | sha256sum -c -` — left as an optional hardening because this authoring environment has no network to fetch + review the digest.

- [ ] **Step 3: Verify the workflow YAML is valid + the commands run locally**

Run:
```bash
python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/python.yml')); print('workflow yaml ok')"
helm template rel infra/charts/agentos --namespace cognic -f infra/charts/agentos/ci/snapshot-values.yaml > /tmp/rendered.yaml
diff -u tests/unit/infra/helm/agentos_rendered.yaml /tmp/rendered.yaml && echo "snapshot matches"
kubeconform -strict -summary -kubernetes-version 1.27.0 /tmp/rendered.yaml
```
Expected: workflow YAML parses; snapshot matches; kubeconform reports `0 errors` (hook-annotated Job + all objects valid).

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/python.yml
git commit -m "ci(deploy): Sprint 14B-Z1a T5 — always-on helm lint/template/kubeconform/snapshot gate (ADR-024)"
```

---

## Task 6: Env-gated `kind` Ready-smoke (six real backends)

**Files:**
- Create: `infra/charts/agentos/ci/smoke-values.yaml`, `infra/charts/agentos/ci/smoke/backends.yaml`, `infra/charts/agentos/ci/smoke/run-smoke.sh`
- Modify: `.github/workflows/python.yml` (add an env-gated `kind-smoke` job)

- [ ] **Step 1: Create `infra/charts/agentos/ci/smoke-values.yaml`** (point the chart at the in-cluster backends; `fsGroup` for vanilla-kind emptyDir writes)

```yaml
# kind-smoke overlay: real in-cluster backends, prod profile, chart-created Secret.
image:
  repository: cognic-agentos        # loaded into kind via `kind load docker-image`
  tag: "smoke"
  pullPolicy: IfNotPresent
runtimeProfile: prod
qdrant: { url: http://qdrant:6333 }
vault: { addr: http://vault:8200 }
embedding: { driver: ollama, baseUrl: http://ollama:11434, model: nomic-embed-text, dimensions: 768 }
langfuse: { host: http://langfuse:3000 }
litellm: { baseUrl: http://litellm:4000 }
cache: { enabled: false }
migrations: { enabled: true }
secrets:
  create: true
  databaseUrl: "postgresql+asyncpg://cognic:cognic@postgres:5432/cognic"
  vaultToken: "smoke-root-token"
podSecurityContext:
  fsGroup: 10001                    # vanilla kind has no SCC to assign fsGroup; the image GID makes emptyDirs writable
```

- [ ] **Step 2: Create `infra/charts/agentos/ci/smoke/backends.yaml`** (the six real backends — Deployments + Services)

Full inline manifest. Self-contained (its own `litellm-smoke-config` ConfigMap — no apply-ordering coupling with the chart) + a `postgres-init` ConfigMap that creates the separate `langfuse` database. **Image-tag policy (finding 4):** the five backends with an `infra/dev/docker-compose.yml` precedent reuse the **proven dev-stack tags** (marked inherited-mutable below — the reason is they are the exact tags the dev stack already runs green; for immutable reproducibility the operator digest-pins via `docker buildx imagetools inspect <tag>` at execution). Ollama has **no** dev-stack precedent — `0.5.4` is a chosen conservative pin; the executor confirms/bumps it to the current stable at the T6 live run. The smoke is env-gated/operator-run, so the executor finalizes any off-the-shelf-image env/probe quirks against the live images at T6 (the manifest below is complete + correct-by-construction; only image-version-specific env nuances may need a live nudge).

```yaml
# infra/charts/agentos/ci/smoke/backends.yaml — Sprint 14B-Z1a kind-smoke backends.
# Credential-free, CPU-only. Service names match the chart's adapter URLs.
# Image tags: dev-stack-inherited (proven) where a compose precedent exists; ollama is a chosen pin.
---
apiVersion: v1
kind: ConfigMap
metadata: { name: postgres-init }
data:
  init.sql: |
    CREATE DATABASE langfuse;
---
apiVersion: v1
kind: ConfigMap
metadata: { name: litellm-smoke-config }
data:
  config.yaml: |
    model_list:
      - model_name: cognic-tier1-dev
        litellm_params:
          model: ollama/qwen3:8b
          api_base: ${OLLAMA_BASE_URL:-http://ollama:11434}
      - model_name: cognic-tier2-dev
        litellm_params:
          model: ollama/qwen3:32b
          api_base: ${OLLAMA_BASE_URL:-http://ollama:11434}
    litellm_settings:
      drop_params: true
    general_settings:
      master_key: ${LITELLM_MASTER_KEY}
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: postgres, labels: { app: postgres } }
spec:
  replicas: 1
  selector: { matchLabels: { app: postgres } }
  template:
    metadata: { labels: { app: postgres } }
    spec:
      containers:
        - name: postgres
          image: postgres:16-alpine            # inherited dev-stack tag (mutable; digest-pin at execution)
          env:
            - { name: POSTGRES_USER, value: cognic }
            - { name: POSTGRES_PASSWORD, value: cognic }
            - { name: POSTGRES_DB, value: cognic }
          ports: [{ containerPort: 5432 }]
          volumeMounts:
            - { name: init, mountPath: /docker-entrypoint-initdb.d }
            - { name: data, mountPath: /var/lib/postgresql/data }
          readinessProbe:
            exec: { command: ["pg_isready", "-U", "cognic"] }
            periodSeconds: 5
      volumes:
        - { name: init, configMap: { name: postgres-init } }
        - { name: data, emptyDir: {} }
---
apiVersion: v1
kind: Service
metadata: { name: postgres }
spec: { selector: { app: postgres }, ports: [{ port: 5432, targetPort: 5432 }] }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: qdrant, labels: { app: qdrant } }
spec:
  replicas: 1
  selector: { matchLabels: { app: qdrant } }
  template:
    metadata: { labels: { app: qdrant } }
    spec:
      containers:
        - name: qdrant
          image: qdrant/qdrant:v1.17.1         # fully pinned (dev-stack)
          ports: [{ containerPort: 6333 }]
          readinessProbe:
            httpGet: { path: /readyz, port: 6333 }
            periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata: { name: qdrant }
spec: { selector: { app: qdrant }, ports: [{ port: 6333, targetPort: 6333 }] }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: vault, labels: { app: vault } }
spec:
  replicas: 1
  selector: { matchLabels: { app: vault } }
  template:
    metadata: { labels: { app: vault } }
    spec:
      containers:
        - name: vault
          image: hashicorp/vault:1.18          # inherited dev-stack tag (mutable; digest-pin at execution)
          args: ["server", "-dev"]
          env:
            - { name: VAULT_DEV_ROOT_TOKEN_ID, value: smoke-root-token }
            - { name: VAULT_DEV_LISTEN_ADDRESS, value: "0.0.0.0:8200" }
          securityContext:
            capabilities: { add: ["IPC_LOCK"] }   # vault dev-mode mlock; kind has no SCC restriction
          ports: [{ containerPort: 8200 }]
          readinessProbe:
            httpGet: { path: /v1/sys/health, port: 8200 }
            periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata: { name: vault }
spec: { selector: { app: vault }, ports: [{ port: 8200, targetPort: 8200 }] }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: ollama, labels: { app: ollama } }
spec:
  replicas: 1
  selector: { matchLabels: { app: ollama } }
  template:
    metadata: { labels: { app: ollama } }
    spec:
      containers:
        - name: ollama
          image: ollama/ollama:0.5.4           # chosen pin (no dev-stack precedent); confirm/bump at T6
          ports: [{ containerPort: 11434 }]
          lifecycle:
            postStart:
              exec:
                command: ["/bin/sh", "-c", "until ollama list >/dev/null 2>&1; do sleep 1; done; ollama pull nomic-embed-text"]
          readinessProbe:
            httpGet: { path: /api/tags, port: 11434 }
            periodSeconds: 5
            failureThreshold: 30
---
apiVersion: v1
kind: Service
metadata: { name: ollama }
spec: { selector: { app: ollama }, ports: [{ port: 11434, targetPort: 11434 }] }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: langfuse, labels: { app: langfuse } }
spec:
  replicas: 1
  selector: { matchLabels: { app: langfuse } }
  template:
    metadata: { labels: { app: langfuse } }
    spec:
      containers:
        - name: langfuse
          image: langfuse/langfuse:2           # inherited dev-stack tag (mutable; digest-pin at execution)
          env:
            - { name: DATABASE_URL, value: "postgresql://cognic:cognic@postgres:5432/langfuse" }
            - { name: NEXTAUTH_URL, value: "http://langfuse:3000" }
            - { name: NEXTAUTH_SECRET, value: "smoke-nextauth-secret" }
            - { name: SALT, value: "smoke-salt" }
            - { name: ENCRYPTION_KEY, value: "0000000000000000000000000000000000000000000000000000000000000000" }
            - { name: TELEMETRY_ENABLED, value: "false" }
          ports: [{ containerPort: 3000 }]
          readinessProbe:
            httpGet: { path: /api/public/health, port: 3000 }
            periodSeconds: 10
            failureThreshold: 30
---
apiVersion: v1
kind: Service
metadata: { name: langfuse }
spec: { selector: { app: langfuse }, ports: [{ port: 3000, targetPort: 3000 }] }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: litellm, labels: { app: litellm } }
spec:
  replicas: 1
  selector: { matchLabels: { app: litellm } }
  template:
    metadata: { labels: { app: litellm } }
    spec:
      containers:
        - name: litellm
          image: ghcr.io/berriai/litellm:main-stable   # inherited dev-stack tag (rolling; digest-pin at execution)
          args: ["--config", "/etc/litellm/config.yaml", "--port", "4000"]
          env:
            - { name: LITELLM_MASTER_KEY, value: dev-only-litellm }
            - { name: OLLAMA_BASE_URL, value: "http://ollama:11434" }
          ports: [{ containerPort: 4000 }]
          volumeMounts:
            - { name: cfg, mountPath: /etc/litellm }
          readinessProbe:
            httpGet: { path: /health/liveliness, port: 4000 }
            periodSeconds: 10
            failureThreshold: 30
      volumes:
        - { name: cfg, configMap: { name: litellm-smoke-config } }
---
apiVersion: v1
kind: Service
metadata: { name: litellm }
spec: { selector: { app: litellm }, ports: [{ port: 4000, targetPort: 4000 }] }
```

- [ ] **Step 3: Create `infra/charts/agentos/ci/smoke/run-smoke.sh`** (the driver)

```bash
#!/usr/bin/env bash
# Sprint 14B-Z1a env-gated kind Ready-smoke. Requires: docker, kind, kubectl, helm.
# Proves the real default-adapters image reaches /readyz=200 in k8s against six real backends.
set -euo pipefail

CLUSTER="${KIND_CLUSTER:-cognic-z1a-smoke}"
NS="cognic-smoke"
IMAGE="${COGNIC_IMAGE:-cognic-agentos:smoke}"
CHART="infra/charts/agentos"

cleanup() { kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> build + load the default-adapters image"
docker build -f infra/agentos/Dockerfile --target default-adapters -t "$IMAGE" .
kind create cluster --name "$CLUSTER"
kind load docker-image "$IMAGE" --name "$CLUSTER"

echo "==> bring up the six real backends"
kubectl create namespace "$NS"
kubectl -n "$NS" apply -f "$CHART/ci/smoke/backends.yaml"
kubectl -n "$NS" wait --for=condition=available --timeout=300s deploy --all

echo "==> install the AgentOS chart"
helm install rel "$CHART" -n "$NS" -f "$CHART/ci/smoke-values.yaml"

echo "==> wait for the AgentOS pod to reach Ready (real /readyz: all five adapters ok)"
kubectl -n "$NS" rollout status deploy/rel-agentos --timeout=300s
kubectl -n "$NS" wait --for=condition=ready pod -l app.kubernetes.io/name=agentos --timeout=300s

echo "==> assert /readyz=200"
kubectl -n "$NS" port-forward svc/rel-agentos 8000:8000 >/dev/null 2>&1 &
PF=$!; sleep 4
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/api/v1/readyz)
kill "$PF" 2>/dev/null || true
echo "/readyz => $code"
test "$code" = "200"
echo "SMOKE PASS"
```

Make it executable: `chmod +x infra/charts/agentos/ci/smoke/run-smoke.sh`.

- [ ] **Step 4: Add the env-gated `kind-smoke` job to `.github/workflows/python.yml`**

```yaml
  kind-smoke:
    name: kind Ready-smoke (env-gated)
    runs-on: ubuntu-latest
    timeout-minutes: 25
    if: ${{ vars.COGNIC_RUN_KIND_SMOKE == '1' || github.event_name == 'workflow_dispatch' }}
    steps:
      - name: Checkout
        uses: actions/checkout@v6
      - name: Install kind + helm
        uses: helm/kind-action@v1
        with:
          install_only: true
      - name: Run the kind Ready-smoke
        run: bash infra/charts/agentos/ci/smoke/run-smoke.sh
```

- [ ] **Step 5: Verify (render + lint the smoke values; run the smoke if a Docker host is available)**

Run:
```bash
helm lint infra/charts/agentos -f infra/charts/agentos/ci/smoke-values.yaml
kubectl --dry-run=client apply -f infra/charts/agentos/ci/smoke/backends.yaml 2>/dev/null || python -c "import yaml; list(yaml.safe_load_all(open('infra/charts/agentos/ci/smoke/backends.yaml'))); print('backends yaml ok')"
bash -n infra/charts/agentos/ci/smoke/run-smoke.sh && echo "smoke script syntax ok"
```
Expected: lint passes; backends YAML parses; the script passes `bash -n`. If `docker` + `kind` are available, run `bash infra/charts/agentos/ci/smoke/run-smoke.sh` and expect `SMOKE PASS`. **If no Docker host is available, mark the live smoke verified-by-reading and say so explicitly** (the job is env-gated/operator-run, exactly the Z2/Z3/Z4 posture).

- [ ] **Step 6: Commit**

```bash
git add infra/charts/agentos/ci/smoke-values.yaml infra/charts/agentos/ci/smoke/backends.yaml infra/charts/agentos/ci/smoke/run-smoke.sh .github/workflows/python.yml
git commit -m "test(deploy): Sprint 14B-Z1a T6 — env-gated kind Ready-smoke (six real backends) (ADR-024)"
```

---

## Task 7: Docs — ADR-024 + runbooks + AS_BUILT/AGENTS

**Files:**
- Create: `docs/adrs/ADR-024-deployment-substrate-helm-packaging.md`, `docs/operator-runbooks/kind-smoke-deployment.md`, `docs/operator-runbooks/helm-chart-production-install.md`
- Modify: `docs/AS_BUILT_CAPABILITY_MAP.md`, `AGENTS.md`

- [ ] **Step 1: Create `docs/adrs/ADR-024-deployment-substrate-helm-packaging.md`**

Record: the Helm-only-in-repo decision (Kustomize via `helm template` overlay in bank repos); the chart targets the `default-adapters` image + `create_prod_app`; the five-always-built-adapter Ready truth is accepted (Option A) with Option C (optional-adapter `none`/`noop` drivers) deferred to a future slice; the migration hook-Job posture (honors "operator owns migrations, not the lifespan"); G7 satisfied via non-personal canonical image config; the env-gated kind smoke honesty contract; and that Z1a changes no kernel code (CC stays 131). Status: ACCEPTED. Use the existing ADR format (read `docs/adrs/ADR-022-runtime-scheduler.md` header for the template).

- [ ] **Step 2: Create `docs/operator-runbooks/kind-smoke-deployment.md`**

Match the existing runbook style (`docs/operator-runbooks/checkpoint-reaper.md`). Cover: what the smoke proves (real prod image → Ready in k8s against six real backends), prerequisites (docker/kind/kubectl/helm), `bash infra/charts/agentos/ci/smoke/run-smoke.sh`, expected `SMOKE PASS`, and troubleshooting (a 503 means an adapter is unhealthy — `kubectl logs` the pod, check the five backend pods are Ready; the `/readyz` body names the failing component).

- [ ] **Step 3: Create `docs/operator-runbooks/helm-chart-production-install.md`**

Cover: pre-flight (snapshot/kubeconform are CI gates), production values (`secrets.create=false` + `secrets.existingSecret`; re-homed `image.repository`; re-homed digest-pinned `sandbox.canonical*Image`; real `embedding.model`; the operator's real `litellm.config`/`existingConfigMap`), the migrations decision (`migrations.enabled=true` runs the hook Job; `false` → run `alembic upgrade head` out-of-band — give the exact command), `helm install`/`upgrade`, post-install verify (`/readyz`=200 + pod logs), trust-root note (provide `COGNIC_SIGNING_TRUST_ROOT_PATH` before pack registration — not needed for Ready), and rollback (`helm rollback`).

- [ ] **Step 4: Update `docs/AS_BUILT_CAPABILITY_MAP.md`**

In the Pillar 5 row (Production Deployment Substrate), move "Helm/Kustomize packaging of AgentOS itself" from the gap column to the built column, citing Sprint 14B-Z1a (the chart at `infra/charts/agentos/`, always-on CI gates, env-gated kind Ready-smoke). Update forward-sequence item 7 to mark Z1a done and name Z1b (AKS/cloud bring-up, external-secrets depth, Ingress/Route, observability wiring) as the remainder. Use amend-by-addition; preserve historical entries.

- [ ] **Step 5: Update `AGENTS.md`**

Add a short "Sprint 14B-Z1a" note near the deployment/infra references documenting the chart's existence, the Helm-only decision, and the CC-131/no-kernel-change posture.

- [ ] **Step 6: Verify docs render + links**

Run: `python -c "import pathlib; [print(p) for p in pathlib.Path('docs').rglob('ADR-024*')]"` and confirm the ADR exists; eyeball the two runbooks for the existing-style headers.

- [ ] **Step 7: Commit**

```bash
git add docs/adrs/ADR-024-deployment-substrate-helm-packaging.md docs/operator-runbooks/kind-smoke-deployment.md docs/operator-runbooks/helm-chart-production-install.md docs/AS_BUILT_CAPABILITY_MAP.md AGENTS.md
git commit -m "docs(deploy): Sprint 14B-Z1a T7 — ADR-024 + kind-smoke/production-install runbooks + AS_BUILT/AGENTS (ADR-024)"
```

---

## Task 8: Closeout — full gate + posture confirmation

**Files:** none (verification only)

- [ ] **Step 1: Confirm no kernel change (CC stays 131)**

Run:
```bash
git diff --stat main...HEAD -- src/ | tail -5
```
Expected: NO files under `src/` changed (the only added Python is `tests/unit/infra/`). The 131-module critical-controls gate is therefore unchanged by construction.

- [ ] **Step 2: Lint + format + types on the touched Python**

Run:
```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
```
Expected: all clean (the snapshot test is the only new Python).

- [ ] **Step 3: Full unit suite (proves nothing broke)**

Run:
```bash
uv run pytest tests/unit -q
```
Expected: all pass (the new `tests/unit/infra/test_helm_chart.py` passes when helm is present, skips otherwise).

- [ ] **Step 4: Always-on chart gates green locally**

Run:
```bash
helm lint infra/charts/agentos -f infra/charts/agentos/ci/snapshot-values.yaml
helm template rel infra/charts/agentos --namespace cognic -f infra/charts/agentos/ci/snapshot-values.yaml > /tmp/rendered.yaml
diff -u tests/unit/infra/helm/agentos_rendered.yaml /tmp/rendered.yaml
kubeconform -strict -summary -kubernetes-version 1.27.0 /tmp/rendered.yaml
```
Expected: lint clean, snapshot matches, kubeconform 0 errors.

- [ ] **Step 5: Confirm the env-gated smoke posture**

State explicitly in the closeout whether the live `kind` smoke was run (and `SMOKE PASS`) or verified-by-reading (no Docker host) — the job is env-gated/operator-run either way.

- [ ] **Step 6: Final stop — no commit here** (T1–T7 already committed). Report the full-gate evidence and hold for the PR/merge tokens.

---

## Self-review notes

- **Spec coverage:** §1 boundary (T1–T7 are all additive infra; T8 confirms CC 131) · §2 chart layout (T1–T3) · §3 objects (T1 config/secret/SA, T2 Deployment/Service, T3 migration Job) · §4 values + prod-safe defaults incl. G7 non-personal images + G5 non-dev model (T1 values) · §5 secrets `existingSecret`/`create` (T1 secret.yaml + helper) · §6 six-backend kind smoke (T6) · §7 always-on CI two-lane (T5 + T6 env-gated) · §8 docs/ADR-024 (T7) · the four precision items resolved (writable paths = `/tmp` + object-store + model-artifacts emptyDirs in T2; Langfuse `None` confirmed — no Vault seed; embedding model `nomic-embed-text` 768-dim; checksum-verified helm/kubeconform in T5). The Ingress/Route + ServiceMonitor omission (tightening 1/2) is honored — no such templates or toggles exist. Deterministic snapshot (tightening 3) is the pinned release/namespace/values in T4/T5. CI steps added to the existing `python.yml` (not a new workflow).
- **No placeholders:** every template + test + script + the full `backends.yaml` (six backends + postgres-init + litellm-smoke ConfigMaps) is shown inline. Backend image tags reuse the proven dev-stack tags (marked inherited-mutable, digest-pinned at execution) except ollama (a chosen pin, executor-confirmed at T6). The helm/kubeconform integrity check verifies against official published checksum files (a real `sha256sum -c`, no fabricated digest — this authoring environment has no network to hardcode a reviewed digest).
- **Review round 2 (applied):** (1) Vault is REQUIRED — removed the `vault.enabled` toggle; `COGNIC_VAULT_ADDR` always rendered + `COGNIC_VAULT_TOKEN` always required (no real "Vault off" path exists). (2) secrets if/then/else schema validation + a fail-loud `secretName` helper (create=false ⇒ existingSecret required; create=true ⇒ databaseUrl+vaultToken required). (3) `backends.yaml` expanded to full inline YAML incl. the `postgres-init` ConfigMap creating the `langfuse` DB. (4) image-tag policy made explicit (dev-stack-inherited-mutable + ollama pin). (5) concrete `sha256sum -c` against official checksum files. (6) third writable emptyDir for `/var/lib/cognic/model-artifacts`. (+) `embedding.dimensions` 1024→768 to cohere with nomic-embed-text.
- **Type/name consistency:** the chart fullname `rel-agentos` (release `rel` + chart name `agentos`) is used consistently in the smoke script (`deploy/rel-agentos`, `svc/rel-agentos`) and the helpers; the litellm ConfigMap name flows through `agentos.litellmConfigMapName`; the Secret name flows through `agentos.secretName`; `apiPrefix` drives both the probe paths and `COGNIC_API_PREFIX`.
