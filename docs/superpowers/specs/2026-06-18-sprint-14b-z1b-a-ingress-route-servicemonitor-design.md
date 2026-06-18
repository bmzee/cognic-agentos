# Sprint 14B-Z1b-a — External access (Ingress / OpenShift Route) + TLS + ServiceMonitor — Design

**Date:** 2026-06-18
**Status:** DRAFT — design approved in brainstorming (2026-06-18); awaiting spec review before planning.
**ADRs:** amends **ADR-024** (Deployment Substrate / Helm Packaging); references ADR-020 (observability surfaces).

## Context

Sprint 14B-Z1a (MERGED `main @ 9fbe7ee`, ADR-024) shipped the OpenShift-compatible Helm chart for the AgentOS kernel at `infra/charts/agentos/` — Deployment + Service (ClusterIP :8000, reached via `kubectl port-forward`) + ConfigMap + gated Secret + migration hook Job, validated by an always-on Helm-4 + Helm-3-compat CI gate + an env-gated `kind` Ready-smoke. It deliberately omitted Ingress/Route/ServiceMonitor templates (no dead toggles).

**14B-Z1b was decomposed** (this slice is the first of four): **Z1b-a — external access (Ingress/Route) + TLS + ServiceMonitor** (this spec); **Z1b-b** — external secrets (ESO-first, the `secrets.existingSecret` seam); **Z1b-c** — the Langfuse-OTLP OTel gRPC→HTTP exporter swap (kernel slice, touches `core/config.py`); **Z1b-d** — AKS bring-up + cloud-identity. Z1b-a is the **fastest continuation from Z1a** because it is pure chart work.

**Recon verdict (greenfield, 2026-06-18):** confirmed ABSENT today — no Ingress/Route/cert-manager/ServiceMonitor/Prometheus-operator templates or references anywhere (the Z1a chart has exactly its 9 templates). The `/metrics` Prometheus surface exists (`prometheus_fastapi_instrumentator` at `{api_prefix}{prometheus_metrics_path}` → `/api/v1/metrics`). So Z1b-a is purely additive chart templates.

## Goal

Give an operator first-class external access to a deployed AgentOS — a Kubernetes `Ingress` AND an OpenShift `Route` (conditional, default both off) with TLS — plus a `ServiceMonitor` (conditional, default off) so a cluster Prometheus discovers + scrapes the existing `/metrics`. Validated always-on by extending the Z1a render/lint/kubeconform/byte-snapshot gate to four orthogonal scenarios.

## Non-goals (guards — user-locked)

- **No kernel code change.** Z1b-a is templates + values + CI + docs only; **CC stays 131**, no migration, no new on-gate module. (The kernel-code observability/secrets/cloud work is Z1b-b/c/d — if any Z1b-a deliverable forces a `src/` change, STOP and re-scope.)
- **Not live-exercised.** The templates are validated by render/lint/kubeconform/byte-snapshot only; the live cloud/ingress proof is **Z1b-d**. The Z1a `kind` Ready-smoke is UNCHANGED (Service-only; external access is not needed for Ready).
- **No `externalCertificate` Route TLS** (OCP-version-gated `tls.externalCertificate` Secret reference) — deferred as a documented later option.
- **No ESO/Vault-Agent/CSI, no cloud-identity, no exporter swap** — those are Z1b-b/c/d.

## Design

### 1. Templates (all conditional, default off)

- **`templates/ingress.yaml`** (`networking.k8s.io/v1`, a CORE kind — kubeconform-native). Rendered when `.Values.ingress.enabled`. Carries `ingressClassName`, `hosts[]` (each `host` + `paths[]` with `pathType`) routing to the chart Service `:http`, a `tls[]` block (existing-secret model: `secretName` + `hosts`), and operator-supplied `annotations` (cert-manager cluster-issuer, nginx/AGIC class hints, etc.).
- **`templates/route.yaml`** (`route.openshift.io/v1`, a **CRD**). Rendered when `.Values.route.enabled`. Carries `host`, `to:` the chart Service (`kind: Service`, `weight: 100`), `port.targetPort: http`, a `tls:` block (see §2), and operator `annotations`.
- **`templates/servicemonitor.yaml`** (`monitoring.coreos.com/v1`, a **CRD**). Rendered when `.Values.serviceMonitor.enabled`. A `selector.matchLabels` set to the chart Service's **stable `agentos.selectorLabels`** (`app.kubernetes.io/name` + `app.kubernetes.io/instance` — NOT the full labels, whose `helm.sh/chart` value changes per chart version and would break the selector on upgrade); one `endpoints[]` entry with `port: http`, `path: {{ .Values.apiPrefix }}{{ .Values.serviceMonitor.path }}` (→ `/api/v1/metrics`), `interval`, `scrapeTimeout`; and `metadata.labels` merged with operator-supplied `serviceMonitor.labels` (e.g. `release: kube-prometheus-stack`) so the cluster Prometheus discovers it.

All three follow the Z1a chart conventions (the `agentos.labels`/`selectorLabels`/`fullname` helpers; `from __future__`-free n/a — these are YAML).

### 2. TLS

- **Ingress — existing-secret-first** (maps natively to `Ingress.tls[].secretName`): the operator (or cert-manager via `ingress.annotations`) provisions a TLS Secret; the chart references it by name. No cert material in values.
- **Route — `a+b`** (OpenShift Routes do NOT have Ingress-style `secretName` parity, so a distinct shape):
  - **(a) default:** `route.tls.enabled: true` ⇒ `termination: edge`, **no** cert/key (the OpenShift router's default/wildcard cert serves it), and `insecureEdgeTerminationPolicy: Redirect` (HTTP→HTTPS). Portable, zero secret handling, no OCP-version dependency.
  - **(b) optional inline:** operators may set `route.tls.certificate` / `route.tls.key` / `route.tls.caCertificate` (PEM) for explicit cert material, accepting that the cert lives in values.
  - **(c) deferred:** `tls.externalCertificate` Secret reference (OCP ≥ 4.16, feature-gated + router RBAC) — documented as a later option, NOT Z1b-a.
  - `route.tls.termination` is configurable (`edge` | `passthrough` | `reencrypt`); default `edge`.

### 3. Values surface (additions to `values.yaml`)

```yaml
ingress:
  enabled: false
  className: ""                 # operator: nginx / azure-application-gateway / ...
  annotations: {}               # cert-manager.io/cluster-issuer, nginx.*, etc.
  hosts:
    - host: agentos.example.com
      paths:
        - { path: /, pathType: Prefix }
  tls: []                        # [{ secretName: agentos-tls, hosts: [agentos.example.com] }]

route:
  enabled: false
  host: agentos.example.com
  annotations: {}
  tls:
    enabled: true
    termination: edge            # edge | passthrough | reencrypt
    insecureEdgeTerminationPolicy: Redirect
    certificate: ""              # optional inline PEM (b)
    key: ""                      # optional inline PEM (b)
    caCertificate: ""            # optional inline PEM (b)

serviceMonitor:
  enabled: false
  path: /metrics                 # joined with apiPrefix → /api/v1/metrics
  interval: 30s
  scrapeTimeout: 10s
  labels: {}                     # e.g. { release: kube-prometheus-stack } for Prometheus discovery
```
`values.schema.json` extends with shape validation for the three blocks (booleans, `termination` enum, string fields). Default-off means none render in the default snapshot.

### 4. CI gate — four orthogonal pinned snapshots

The Z1a single byte-snapshot becomes **four** (default + the three opt-ins), each layered over the base `ci/snapshot-values.yaml`:

| scenario | values | committed snapshot |
|---|---|---|
| default (Z1a baseline) | `ci/snapshot-values.yaml` | `tests/unit/infra/helm/agentos_rendered.yaml` |
| ingress-on (TLS existing-secret) | base + `ci/snapshot-values-ingress.yaml` | `…/agentos_rendered_ingress.yaml` |
| route-on (TLS edge, default) | base + `ci/snapshot-values-route.yaml` | `…/agentos_rendered_route.yaml` |
| servicemonitor-on | base + `ci/snapshot-values-servicemonitor.yaml` | `…/agentos_rendered_servicemonitor.yaml` |

- **Layered values** (`helm template -f snapshot-values.yaml -f snapshot-values-<scenario>.yaml`) keep the overlays DRY (each adds only its block).
- **Cert-manager** is covered *inside* the ingress/route scenario values (annotations) — no separate cert-manager snapshot.
- **pytest** (`tests/unit/infra/test_helm_chart.py`): the byte-snapshot test parametrizes over the four `(values, snapshot)` pairs, each still version-gated on the pinned Helm `v4.2.2` generator (per the Z1a `d015851` fix — the runner's ambient helm differs); the same EOF-normalization (`raw.rstrip("\n") + "\n"`) applies per scenario. `test_chart_lints_clean` stays single (lint is values-tolerant).
- **The `helm-chart` CI job** renders all four scenarios → normalized byte-diff each vs its committed snapshot → `kubeconform` each (with the §5 CRD handling). The Helm-3 compatibility lane renders all four too (lint + template + kubeconform; NO byte-diff — the snapshot is the primary lane's).

### 5. CRD schema validation (Route + ServiceMonitor)

`Route` (`route.openshift.io/v1`) and `ServiceMonitor` (`monitoring.coreos.com/v1`) are CRDs the default kubeconform schema set does not know. **Schema-location first:** the CI `kubeconform` invocation adds `-schema-location default -schema-location '<CRD-catalog template URL>'` (the version-pinned OpenShift + Prometheus-Operator CRD JSON schemas, e.g. the `datreeio/CRDs-catalog` mirror) so the route-on / servicemonitor-on renders validate against real CRD schemas. **Scoped-skip fallback:** only if schema sourcing proves unreliable, `kubeconform … -skip Route,ServiceMonitor` for those two kinds (documented as the explicit fallback, never a silent skip). The default + ingress-on scenarios need no CRD schemas (core kinds only).

### 6. Docs & posture

- **ADR-024** gains a `## Sprint 14B-Z1b-a amendment` (amend-by-addition): the conditional Ingress/Route/ServiceMonitor templates, the Route-TLS `a+b` decision (+ the `externalCertificate` deferral), the four-snapshot gate, and the CRD-schema handling.
- **AS_BUILT** Pillar-5 + forward-item-7's Z1b sub-item updated (Z1b-a DONE; Z1b-b/c/d forward); **AGENTS.md** note.
- The `docs/operator-runbooks/helm-chart-production-install.md` gains an **"External access (Ingress / OpenShift Route) + TLS + ServiceMonitor"** section.
- **Posture:** CC stays **131**; no kernel change; no migration; no new on-gate module. The only added Python is the snapshot-test parametrization (subject to ruff/mypy). The env-gated `kind` Ready-smoke is unchanged.

## Tasks (high-level; the plan expands each)

- **T1** — the three templates (`ingress.yaml`, `route.yaml`, `servicemonitor.yaml`) + the `values.yaml` blocks + the `values.schema.json` extensions. Verify each renders only when enabled + lints clean.
- **T2** — the four snapshot scenarios: the three `ci/snapshot-values-<scenario>.yaml` overlays + the four committed byte-snapshots (machine-generated by the parametrized test under Helm 4.2.2) + the pytest parametrization (version-gated).
- **T3** — extend the `helm-chart` CI job: render + normalize + byte-diff + kubeconform (with CRD schema-location) for all four scenarios on both the Helm-4 primary lane and the Helm-3 compat lane.
- **T4** — docs: ADR-024 amendment + AS_BUILT/AGENTS + the production-install runbook section.
- **T5** — closeout: full gate (ruff/format/mypy + full suite + the 131-module gate on fresh `--cov-branch`; the four-scenario helm gate green; CRD schemas resolve) + confirm `src/` untouched.

## Posture

CC count stays **131**; no migration; no kernel change; no new on-gate module. Z1b-a is the pure-chart external-access + scrape slice; Z1b-b (external secrets), Z1b-c (the Langfuse-OTLP exporter swap — kernel), and Z1b-d (AKS bring-up + cloud-identity) follow.
