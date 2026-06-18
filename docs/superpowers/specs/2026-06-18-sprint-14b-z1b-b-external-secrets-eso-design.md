# Sprint 14B-Z1b-b — External secrets (ESO-first, conditional ExternalSecret) — Design

**Date:** 2026-06-18
**Status:** DRAFT — design approved in brainstorming (2026-06-18); awaiting spec review before planning.
**ADRs:** amends **ADR-024** (Deployment Substrate / Helm Packaging); references ADR-009 (pluggable infra adapters — Vault) + ADR-004 (Vault credential leasing).

## Context

Sprint 14B-Z1a (MERGED `main @ 9fbe7ee`, ADR-024) shipped the kernel Helm chart with a **gated bootstrap Secret**: `secrets.create=true` renders a 2-key Secret (`COGNIC_DATABASE_URL` + `COGNIC_VAULT_TOKEN`); `secrets.existingSecret=<name>` references an operator-managed Secret; the `agentos.secretName` helper resolves the name (`existingSecret` → `create` → `fail`). Sprint 14B-Z1b-a (MERGED `main @ e746e4c`) added external access (Ingress/Route/ServiceMonitor) and the four-scenario snapshot/kubeconform CI gate.

**14B-Z1b is decomposed into four sub-slices:** Z1b-a external access (**DONE**); **Z1b-b — external secrets, ESO-first** (this spec); **Z1b-c** — the Langfuse-OTLP OTel gRPC→HTTP exporter swap (kernel slice); **Z1b-d** — AKS bring-up + cloud-identity (the live cloud exercise). Z1b-b is the smoothest next slice because it anchors on the existing `secrets.existingSecret` seam.

**Recon verdict (greenfield, 2026-06-18):** confirmed ABSENT — no external-secrets / SecretStore / CSI / vault-agent references anywhere in the chart. The `secrets.existingSecret` values comment already anticipates "an operator/**ESO**-managed Secret carrying `COGNIC_DATABASE_URL` (+ `COGNIC_VAULT_TOKEN`)". The kernel consumes those 2 keys via `valueFrom.secretKeyRef` on `{{ agentos.secretName }}` in BOTH `deployment.yaml` AND `migration-job.yaml`. So ESO-first is purely additive: a conditional `ExternalSecret` that **populates the same Secret the kernel already reads** — no kernel change, no deployment/migration-job change.

## Goal

Give an operator a first-class, GitOps-managed way to source the bootstrap Secret from an external store via the **External Secrets Operator (ESO)**: a conditional (default-off) `ExternalSecret` template that materializes the `agentos.secretName` Secret with exactly the 2 kernel keys, referencing an operator-owned `SecretStore`/`ClusterSecretStore`. Validated always-on by extending the Z1b-a snapshot/kubeconform gate to a fifth scenario.

## Non-goals (guards — user-locked)

- **No kernel code change.** Z1b-b is templates + values + schema + CI + docs only; **CC stays 131**, no migration, no new on-gate module. (If any deliverable forces a `src/` change, STOP and re-scope — that is Z1b-c/d territory.)
- **Not live-exercised.** The template is validated by render/lint/kubeconform/byte-snapshot only; the live cluster/ESO proof is **Z1b-d** (AKS).
- **ESO only.** Vault Agent Injector + CSI Secret Store driver are NOT implemented — documented as later alternatives. ESO-first was chosen because the kernel reads env from a Secret (which ESO populates with **no kernel change**), whereas file-injection models would force a kernel read-path change.
- **The chart does NOT create the `SecretStore`/`ClusterSecretStore`** — it carries backend auth and is operator/cluster-owned; the chart only references it by name + kind.
- **The target Secret contract is EXACTLY 2 keys** (`COGNIC_DATABASE_URL` + `COGNIC_VAULT_TOKEN`) — Z1b-b does NOT allow arbitrary extra target keys.

## Design

### 1. The template (conditional, default off)

`templates/externalsecret.yaml` (`external-secrets.io/v1`, a CRD). Rendered when `.Values.externalSecrets.enabled`. The two `data[]` entries are **fixed** to the 2 kernel keys (NOT a loop over operator-supplied keys — the contract is exactly those two); `remoteRef.key` is `required` for both; `property` is optional (emitted only when set, via `{{- with }}`).

```yaml
{{- if .Values.externalSecrets.enabled }}
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: {{ include "agentos.fullname" . }}
  labels:
    {{- include "agentos.labels" . | nindent 4 }}
spec:
  refreshInterval: {{ .Values.externalSecrets.refreshInterval }}
  secretStoreRef:
    name: {{ required "externalSecrets.secretStoreRef.name is required when externalSecrets.enabled=true" .Values.externalSecrets.secretStoreRef.name }}
    kind: {{ .Values.externalSecrets.secretStoreRef.kind }}
  target:
    name: {{ include "agentos.secretName" . }}
    creationPolicy: Owner
  data:
    - secretKey: COGNIC_DATABASE_URL
      remoteRef:
        key: {{ required "externalSecrets.data.databaseUrl.remoteRef.key is required when externalSecrets.enabled=true" .Values.externalSecrets.data.databaseUrl.remoteRef.key }}
        {{- with .Values.externalSecrets.data.databaseUrl.remoteRef.property }}
        property: {{ . }}
        {{- end }}
    - secretKey: COGNIC_VAULT_TOKEN
      remoteRef:
        key: {{ required "externalSecrets.data.vaultToken.remoteRef.key is required when externalSecrets.enabled=true" .Values.externalSecrets.data.vaultToken.remoteRef.key }}
        {{- with .Values.externalSecrets.data.vaultToken.remoteRef.property }}
        property: {{ . }}
        {{- end }}
{{- end }}
```

### 2. Secret-source model — three mutually-exclusive modes

`secrets.create` (dev/smoke) | `secrets.existingSecret` (operator pre-provisioned) | `externalSecrets.enabled` (ESO-managed). The `agentos.secretName` helper resolves the name; a new `agentos.validateSecretSource` helper `fail`s when more than one source is set. To guarantee the guard fires at every secret-wiring site, **`agentos.secretName` invokes `agentos.validateSecretSource` as its first action** (it is the chokepoint — `deployment.yaml`, `migration-job.yaml`, and the new `externalsecret.yaml` `target.name` all call it).

```
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
```

The three exclusion failure cases (each must `fail` the render): `secrets.create=true` + `secrets.existingSecret`; `externalSecrets.enabled=true` + `secrets.create=true`; `externalSecrets.enabled=true` + `secrets.existingSecret`.

### 3. Values surface (additions to `values.yaml`)

```yaml
externalSecrets:
  enabled: false
  targetSecretName: ""           # default <fullname>-secrets (turnkey; override if you need a fixed name)
  refreshInterval: 1h
  secretStoreRef:
    name: ""                     # REQUIRED when enabled — operator-owned SecretStore/ClusterSecretStore (chart never creates it)
    kind: SecretStore            # SecretStore | ClusterSecretStore
  data:
    databaseUrl:
      remoteRef:
        key: ""                  # REQUIRED when enabled — remote key holding COGNIC_DATABASE_URL
        property: ""             # optional — a property within the remote secret
    vaultToken:
      remoteRef:
        key: ""                  # REQUIRED when enabled — remote key holding COGNIC_VAULT_TOKEN
        property: ""             # optional
```

`values.schema.json` extends with the `externalSecrets` block shape (booleans, `kind` enum `["SecretStore","ClusterSecretStore"]`, string fields) AND encodes the three-way mutual exclusion (e.g. an `allOf`/`not` set rejecting any two-source combination). It ALSO enforces the **enabled-mode required fields**: when `externalSecrets.enabled=true`, the schema requires non-empty (e.g. `minLength: 1`) values for `externalSecrets.secretStoreRef.name`, `externalSecrets.data.databaseUrl.remoteRef.key`, and `externalSecrets.data.vaultToken.remoteRef.key` (an `if enabled then required` conditional). The template's `required` calls remain as defense-in-depth, but the schema catches a misconfigured `enabled` block at `helm lint`/install time rather than only at render. Default-off means none render in the default / ingress / route / servicemonitor snapshots.

### 4. CI gate — a fifth orthogonal scenario

The Z1b-a four scenarios become **five** (+ `externalsecret-on`, layered over the base `ci/snapshot-values.yaml`):

| scenario | values | committed snapshot |
|---|---|---|
| default | `ci/snapshot-values.yaml` | `agentos_rendered.yaml` |
| ingress-on | base + `…-ingress.yaml` | `…_ingress.yaml` |
| route-on | base + `…-route.yaml` | `…_route.yaml` |
| servicemonitor-on | base + `…-servicemonitor.yaml` | `…_servicemonitor.yaml` |
| **externalsecret-on** | base + `…-externalsecret.yaml` | `…_externalsecret.yaml` |

- **pytest** (`tests/unit/infra/test_helm_chart.py`): the byte-snapshot test's `_SCENARIOS` extends to five, each still version-gated on the pinned Helm `v4.2.2` generator + the same EOF normalization.
- **The `helm-chart` CI job** renders all five → normalized byte-diff each vs its committed snapshot → `kubeconform` each (with the §5 CRD handling), on both the Helm-4 primary lane and the Helm-3 compatibility lane (the latter no byte-diff).

### 5. CRD schema validation (ExternalSecret)

`ExternalSecret` (`external-secrets.io/v1`) is a CRD the default kubeconform schema set does not know. **Schema-location first:** the CI `kubeconform` invocation already carries `-schema-location default -schema-location '<datreeio/CRDs-catalog template URL>'`; if the catalog publishes `external-secrets.io/ExternalSecret_v1.json`, the externalsecret-on render validates against the real CRD schema. **Scoped-skip fallback:** only if the catalog lacks it, add `ExternalSecret` to the existing scoped skip (i.e. `-skip Route,ExternalSecret`) — documented, never a silent skip, scoped to exactly that kind (ServiceMonitor + core kinds stay validated). **This is network-confirmed during the plan/T3 phase, exactly like the Z1b-a Route finding** — the executor has network; the authoring env did not. The closeout records which path was used.

### 6. Docs & posture

- **ADR-024** gains a `## Sprint 14B-Z1b-b amendment` (amend-by-addition): the conditional `ExternalSecret` template, the three-mode mutually-exclusive secret-source model, the fifth snapshot scenario, and the CRD-schema handling.
- **AS_BUILT** Pillar-5 + forward-item-7's Z1b sub-item updated (Z1b-b DONE; Z1b-c/d forward); **AGENTS.md** note.
- The `docs/operator-runbooks/helm-chart-production-install.md` gains an **"External secrets (ESO)"** section: enabling `externalSecrets`, referencing an operator-owned store, mapping the 2 remote refs — **primary worked example Azure Key Vault + AKS workload identity** (aligns with the Z1b-d AKS bring-up); AWS Secrets Manager + HashiCorp Vault as secondary notes. Also states ESO must be installed in the cluster (the `external-secrets.io` CRDs present) or the manifest has nothing to reconcile against.
- **Posture:** CC stays **131**; no kernel change; no migration; no new on-gate module. The only added Python is the snapshot-test parametrization (the fifth scenario), subject to ruff/mypy.

## Tasks (high-level; the plan expands each)

- **T1** — `templates/externalsecret.yaml` + the `agentos.secretName` ESO arm + the `agentos.validateSecretSource` helper + the `externalSecrets` `values.yaml` block + the `values.schema.json` extension (block shape + three-way mutual exclusion + the enabled-mode required fields: `secretStoreRef.name` + both `remoteRef.key`s non-empty when `enabled=true`). Verify it renders only when enabled, renders nothing in the default snapshot, fails on any two-source combination, fails the schema when `enabled=true` with an empty required field, and lints clean.
- **T2** — the fifth snapshot scenario: `ci/snapshot-values-externalsecret.yaml` overlay + the committed `agentos_rendered_externalsecret.yaml` (machine-generated under Helm 4.2.2) + the pytest parametrization extended to five (version-gated).
- **T3** — extend the `helm-chart` CI job to render + normalize + byte-diff + kubeconform all five scenarios on both lanes, with the ExternalSecret CRD schema-location (scoped-skip fallback recorded).
- **T4** — docs: ADR-024 amendment + AS_BUILT/AGENTS + the production-install runbook external-secrets section.
- **T5** — closeout: full gate (ruff/format/mypy + full suite + the 131-module gate on fresh `--cov-branch`; the five-scenario helm gate green; the CRD-schema path recorded) + confirm `src/` untouched.

## Posture

CC count stays **131**; no migration; no kernel change; no new on-gate module. Z1b-b is the pure-chart external-secrets slice; Z1b-c (the Langfuse-OTLP exporter swap — kernel) and Z1b-d (AKS bring-up + cloud-identity — the live exercise) follow.
