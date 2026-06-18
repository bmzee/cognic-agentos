# Sprint 14B-Z1b-d-1 — Generic chart workload-identity readiness (`serviceAccount.annotations` + `podLabels`) — Design

**Date:** 2026-06-18
**Status:** DRAFT — design approved in brainstorming (2026-06-18); awaiting spec review before planning.
**ADRs:** amends **ADR-024** (Deployment Substrate / Helm Packaging).

## Context

Sprint 14B-Z1b decomposed into four sub-slices; the fourth (Z1b-d, the capstone) is itself **split** at recon into **Z1b-d-1 — generic chart workload-identity readiness** (this; pure chart/docs, fully in-session-verifiable) and **Z1b-d-2 — AKS bring-up + env-gated live cloud smoke** (the separate operator-run capstone; the live cluster proof). The other Z1b slices — **Z1b-a** external access, **Z1b-b** external secrets, **Z1b-c** OTLP exporter — are MERGED.

**Recon verdict (from source, 2026-06-18):** the chart cannot wire cloud workload identity today — **two gaps**:
1. `templates/serviceaccount.yaml` has **no `annotations` field** — so no cloud SA annotation (`azure.workload.identity/client-id` / `iam.gke.io/gcp-service-account` / `eks.amazonaws.com/role-arn`).
2. The deployment pod template labels are only `agentos.selectorLabels` (`deployment.yaml:15`) — **no hook** for an extra pod label (e.g. `azure.workload.identity/use: "true"`).

Both must be **templated** — an out-of-band `kubectl annotate` would be clobbered on `helm upgrade`. The deployment's **`.spec.selector.matchLabels` (`deployment.yaml:11`)** and the **`.spec.template.metadata.labels` (`deployment.yaml:15`)** both currently render `agentos.selectorLabels`; the selector is immutable. No existing AKS/cloud IaC; the env-gated `kind` Ready-smoke (`ci/smoke/run-smoke.sh` + the `kind-smoke` CI job) is the precedent Z1b-d-2's AKS smoke will mirror.

## Goal

Make the chart **workload-identity-ready for any cloud** by exposing two generic extensibility hooks — `serviceAccount.annotations` and `podLabels` — so an operator can federate the chart's ServiceAccount to a cloud IAM identity (Azure WI, GKE workload identity, AWS IRSA) via Helm values, with the cloud-specific annotation/label values living in the runbook examples, NOT the chart. Pure chart/docs; the live cluster exercise is Z1b-d-2.

## Non-goals (guards — user-locked)

- **Generic chart only.** Map names are exactly `serviceAccount.annotations` + `podLabels`; values stay **cloud-agnostic** (plain `type: object` maps — no `azure.*`/enum first-class values). Cloud-specific annotations/labels appear ONLY in the runbook examples + the test snapshot fixture.
- **Selector stability.** `podLabels` merge into the pod **template** labels (`.spec.template.metadata.labels`) ONLY — **NEVER** into `.spec.selector.matchLabels` (a Deployment selector is immutable; mutating it breaks `helm upgrade`).
- **No `podAnnotations`** in this slice (YAGNI for workload identity).
- **No CRD change.** The render is core kinds (ServiceAccount + Deployment); **`-skip Route` remains the only scoped kubeconform skip**.
- **Default render UNCHANGED.** Both hooks default to empty maps → they render nothing → the default render + the **6 existing snapshots are byte-unchanged**.
- **CC stays 131**, no kernel change, no migration, no new on-gate module.
- **Z1b-d-2 is the separate live cloud/AKS proof** — Z1b-d-1 is validated by render / lint / kubeconform / byte-snapshot only.

## Design

### 1. `templates/serviceaccount.yaml` — the annotations hook

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "agentos.fullname" . }}
  labels:
    {{- include "agentos.labels" . | nindent 4 }}
  {{- with .Values.serviceAccount.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
automountServiceAccountToken: false
```
Empty `serviceAccount.annotations: {}` → the `{{- with }}` skips → no `annotations:` block (default render unchanged).

### 2. `templates/deployment.yaml` — `podLabels` merge into the TEMPLATE labels (NOT the selector)

The pod template labels gain `podLabels`, merged AFTER the stable selector labels:
```yaml
  template:
    metadata:
      labels:
        {{- include "agentos.selectorLabels" . | nindent 8 }}
        {{- with .Values.podLabels }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
```
**`.spec.selector.matchLabels` (line 11) is UNTOUCHED** — it stays `agentos.selectorLabels` (the immutable selector). `podLabels` add to the pod's metadata labels only. Empty `podLabels: {}` → renders nothing (default render unchanged).

### 3. Values + schema (generic maps)

**`values.yaml`:**
```yaml
serviceAccount:
  annotations: {}     # cloud workload-identity SA annotation (e.g. azure.workload.identity/client-id) — see the runbook
podLabels: {}         # extra pod-template labels (e.g. azure.workload.identity/use: "true") — merged into the pod labels, NOT the selector
```
**`values.schema.json`:** `serviceAccount` (object → `annotations` object) + `podLabels` (object). Plain maps; **no enums, no cloud-specific keys** (the generic guard).

### 4. The 7th `workload-identity` snapshot scenario

A `ci/snapshot-values-workload-identity.yaml` overlay sets BOTH hooks with an **Azure WI example fixture** (a representative cloud — the chart *values* stay generic; only this test fixture + the runbook name a cloud):
```yaml
serviceAccount:
  annotations:
    azure.workload.identity/client-id: 00000000-0000-0000-0000-000000000000
podLabels:
  azure.workload.identity/use: "true"
```
The committed snapshot `agentos_rendered_workload-identity.yaml` shows: the SA carrying the annotation; the Deployment **pod template labels = selector labels + the WI label**; the **`.spec.selector.matchLabels` unchanged** (the selector-stability invariant, pinned by the snapshot). Core kinds only → kubeconform Valid, no CRD/skip.

### 5. CI gate — 6 → 7 scenarios (no CRD change)

The `helm-chart` job's two loops (Helm-4 primary + Helm-3 compat) extend to a 7th `workload-identity` scenario; **`-skip Route` unchanged** (core kinds only — SA + Deployment, no CRD). The pytest `_SCENARIOS` 6 → 7.

### 6. Runbook — "Cloud workload identity" section

The generic hooks + three cloud worked examples (each = the SA annotation + the pod label that cloud requires; the chart never creates the cloud IAM identity — the operator provisions it + the federation):
- **Azure workload identity** — `serviceAccount.annotations` carries `azure.workload.identity/client-id: <client-id>`; `podLabels` carries `azure.workload.identity/use: "true"`.
- **GKE workload identity** — `serviceAccount.annotations` carries `iam.gke.io/gcp-service-account: <gsa-email>` (no pod label required).
- **AWS IRSA** — `serviceAccount.annotations` carries `eks.amazonaws.com/role-arn: <role-arn>` (no pod label required).

A closing note: **the live cluster exercise (an actual AKS deploy that federates + reaches the cloud secret/identity) is Z1b-d-2**, not Z1b-d-1 — this slice ships the chart capability + the wiring recipe, validated by render/snapshot only.

### 7. Docs & posture

- **ADR-024** gains a `## Sprint 14B-Z1b-d-1 amendment`: the two generic hooks, the **selector-stability invariant** (podLabels → template labels only), the 7th scenario (no CRD change), and the **Z1b-d split** (d-1 chart WI-readiness here; d-2 the live AKS proof).
- **AS_BUILT** Pillar 5 + forward-item-7 — **split the `14B-Z1b-d` forward item into `Z1b-d-1` DONE / `Z1b-d-2` forward** (the live AKS bring-up + cluster smoke); **AGENTS.md** note.
- **Posture:** CC stays **131**; no kernel change; no migration; no new on-gate module. The only Python is the snapshot-test parametrization.

## Tasks (high-level; the plan expands each)

- **T1** — the SA `annotations` hook + the deployment `podLabels` merge (template labels only) + the `values.yaml` block + the `values.schema.json` extension. Verify the **default render is UNCHANGED** + the **`.spec.selector.matchLabels` is untouched** by `podLabels`.
- **T2** — the 7th `workload-identity` overlay (Azure WI fixture) + the committed snapshot + the pytest param (6 → 7). Verify the snapshot shows the SA annotation + the merged pod label + the unchanged selector.
- **T3** — extend the `helm-chart` CI job to 7 scenarios on both lanes (no CRD-schema change; `-skip Route` unchanged).
- **T4** — docs: ADR-024 amendment + AS_BUILT (both surfaces; the Z1b-d split) + AGENTS + the runbook "Cloud workload identity" section.
- **T5** — closeout: full gate (ruff/format/mypy + full suite + the 131-module gate on fresh `--cov-branch`; the seven-scenario helm gate green; default render UNCHANGED) + confirm `src/` untouched.

## Posture

CC count stays **131**; no kernel change; no migration; no new on-gate module. Z1b-d-1 is the generic chart workload-identity-readiness slice; **Z1b-d-2** (AKS bring-up + env-gated live cloud smoke) is the separate operator-run capstone + the live cluster proof. After Z1b-d-2, the whole 14B Deployment Substrate (Z1a + Z1b-a/b/c/d) is complete.
