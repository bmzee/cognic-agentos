# ADR-024 — Deployment Substrate / Helm Packaging

## Status
**ACCEPTED** — DRAFT 2026-06-17 → ACCEPTED 2026-06-18. The packaging-core portion (Helm chart + always-on CI render/validation gate + the env-gated `kind` Ready-smoke) is implemented in **Sprint 14B-Z1a**, on branch `feat/sprint-14b-z1a-deployment-packaging`. Z1a is **pure additive infra-as-code**: it changes **no kernel code** (the critical-controls coverage gate stays at **131** modules; the only Python added is the rendered-YAML snapshot test). The AKS/cloud bring-up, external-secrets depth, Ingress/Route + TLS, and observability wiring are deferred to **Z1b**; see §"Out of scope (Z1b)" and the §"Sprint 14B-Z1a implementation closeout" at the foot of this ADR.

## Context

AgentOS is already remarkably Kubernetes-friendly, but it had no packaging of the kernel itself. A read-only recon (2026-06-17) confirmed every prerequisite exists:

- A real 3-stage production image at `infra/agentos/Dockerfile` (`kernel` ≤120 MiB; `default-adapters` ≤385 MiB), serving `create_prod_app` via `uvicorn …:create_prod_app --factory`. The image runs as `USER cognic` (UID 10001), `WORKDIR=/app`, and ships the OPA policy bundles in-image under `/app/policies/_default/`.
- Liveness/readiness/version/metrics surfaces: `/api/v1/healthz`, `/api/v1/readyz`, `/version`, and a Prometheus `/metrics` endpoint; JSON stdout logging with trace/request correlation.
- The G1–G10 deploy-safety guards (the prod profile refuses dev defaults), a CI boot-smoke, and image-size budgets on every PR.
- Operator-run migrations: `alembic upgrade head` is deliberately **not** auto-run in the lifespan — the operator owns schema change-control.

What was **missing** is Helm/Kubernetes packaging of the kernel. The only Kubernetes code in-repo was `sandbox/backends/kubernetes_pod.py` — which deploys *sandboxes*, not AgentOS. Without a chart, an operator had to hand-assemble the kernel Deployment, ConfigMap, Secret, probes, securityContext, volumes, and migration step from loose parts, getting every strict-profile guard right by hand. That is exactly the error-prone bootstrap a packaged chart removes.

Three load-bearing recon findings shaped the design:

1. **`/readyz` is strict.** Readiness is `ready = all(component.status == "ok")`; any `"degraded"`/`"unreachable"` component → 503. On the `create_prod_app` path **five adapters are always built with no `none`/`noop` escape**: relational (Postgres), vector (Qdrant), secret (Vault), embedding (Ollama/openai-compat), observability (Langfuse/Dynatrace). Each returns `"unreachable"` when its backend is down. Only `cache` (Redis) has a `none` bypass (default-none); `object_store=local_fs` is filesystem-only. **So the honest minimal infrastructure to reach Ready is five real backends, not one.**
2. **A credential-free model path already exists, committed.** `infra/litellm/config.yaml` declares `cognic-tier1/2-dev` → `ollama/qwen3:*` at `${OLLAMA_BASE_URL:-http://ollama:11434}` (zero SaaS keys). The LLM gateway makes **no network call at boot** and is **not** probed by `/readyz`, so for Ready, LiteLLM only needs to be up serving its config. The embedding adapter (`embed_driver=ollama`) probes Ollama's `/api/tags`, so the only real model the smoke must pull is **one small embedding model**. This config file is the **one boot-blocking file that is NOT in the image** and must be mounted at `/app/infra/litellm/config.yaml`.
3. **G7 resolved precisely.** G7 fires whenever the profile is strict (stage/prod) AND either `sandbox_canonical_runtime_image` or `sandbox_canonical_egress_proxy_image` contains a personal `ghcr.io/bmzee` ref — **independent of `sandbox_runtime_enabled`**. Both kernel defaults are personal `ghcr.io/bmzee/…@sha256:…`, so both trip G7 in the prod profile even with the sandbox off. The field validator requires a `<ref>@sha256:<64-lowercase-hex>` digest-pinned shape. **Therefore the chart MUST set non-personal, digest-pinned canonical image refs in the ConfigMap** (config-only; the sandbox stays off, the refs are never pulled, and operators re-home them under their own canonical trust root).

## Decision

Ship an OpenShift-compatible Helm chart for the AgentOS kernel at `infra/charts/agentos/`, validated always-on in CI (lint / template / kubeconform / snapshot-drift) and proven end-to-end by an env-gated local `kind` Ready-smoke against six real credential-free backends. **Helm only — no Kustomize in-repo.** Packaging-core only (Z1a); Z1b owns AKS/cloud, external-secrets depth, Ingress/Route + TLS, and observability wiring.

### Chart home & layout

```
infra/charts/agentos/
  Chart.yaml                 # apiVersion: v2; appVersion tracks the image tag
  values.yaml                # documented toggles + prod-safe defaults
  values.schema.json         # JSON-Schema validation of values
  templates/
    _helpers.tpl
    serviceaccount.yaml      # dedicated SA; no cluster perms in Z1a
    configmap.yaml           # non-secret COGNIC_* env
    configmap-litellm.yaml   # the boot-required litellm router config (mounted at /app/infra/litellm/config.yaml)
    secret.yaml              # bootstrap Secret; rendered ONLY when secrets.create=true
    deployment.yaml          # kernel (create_prod_app); probes; securityContext; volumes
    service.yaml             # ClusterIP :8000 (named http); NO Ingress/Route in Z1a
    migration-job.yaml       # Helm pre-install/pre-upgrade hook, gated by migrations.enabled
    NOTES.txt
  ci/
    snapshot-values.yaml     # deterministic inputs for the rendered-YAML snapshot
    smoke-values.yaml        # points the chart at the in-cluster real backends
    smoke/
      backends.yaml          # the six real backends as k8s manifests
      run-smoke.sh           # the kind smoke driver
```

The chart lives under `infra/charts/agentos/` to match the existing `infra/agentos/` Dockerfile convention. No prior helm/k8s/kustomize directory existed anywhere in the repo (confirmed).

### Helm only in-repo (no Kustomize)

Helm is the **single in-repo manifest source**. AGENTS.md draws the OS / overlay boundary: bank-specific themes, OIDC config, and custom adapters live in **bank-overlay repos**, not the kernel repo. A second in-repo rendering technology (Kustomize bases) would duplicate the surface and invite drift between two manifest sources of truth. **Banks needing Kustomize render `helm template` and overlay in their own repos** — the standard pattern for consuming a Helm chart from a Kustomize pipeline. The chart's deterministic render (pinned Helm version + fixed release/namespace/values) makes `helm template` a stable upstream for such overlays.

### Chart target: the `default-adapters` image + `create_prod_app`

The Deployment runs the existing `default-adapters` stage of `infra/agentos/Dockerfile` and inherits its CMD (`uvicorn …:create_prod_app --factory --host $COGNIC_HOST --port $COGNIC_PORT`). The chart packages the kernel as built — it does not introduce a new entrypoint, a new image, or a new boot path. `replicaCount` defaults to 1.

### Helm-3 deployability via `apiVersion: v2` + a two-lane CI gate

`Chart.yaml` is `apiVersion: v2` so the chart stays installable by **Helm 3** banks/OpenShift regardless of which Helm version validates it. Deployability is proven by a **two-lane CI gate** (always-on, cluster-free, in `.github/workflows/python.yml`):

- **Primary lane — Helm 4** (`helm` v4.2.2, the local Homebrew stack): `helm lint` → `helm template <fixed-release> --namespace <fixed-ns> -f ci/snapshot-values.yaml` → **byte-equality snapshot-drift** vs the committed `tests/unit/infra/helm/agentos_rendered.yaml` → `kubeconform` (v0.8.0) schema-validate the rendered output. All binaries pinned by checksum file (the OPA/cosign binary-pinning precedent).
- **Compatibility lane — Helm 3** (`helm3` v3.16.3): installs a pinned Helm 3 binary and runs render + schema validation against it (no byte-snapshot diff on the Helm 3 render — the snapshot is owned by the primary lane).

The byte-snapshot regenerates by deleting the committed render and re-running the snapshot test (the `test_well_known_routes.py` regenerate-on-delete pattern). The snapshot test is the **only Python added by Z1a** (subject to ruff/mypy).

### The chart's Kubernetes objects

- **Deployment.** The `default-adapters` image; `envFrom` the ConfigMap; `env` with `secretKeyRef` for the bootstrap secrets. Probes: **startupProbe → `/api/v1/healthz`** (generous `failureThreshold`, so the slow lifespan boot — runtime + OPA engines + five adapters — does not trip premature liveness kills), **livenessProbe → `/api/v1/healthz`**, **readinessProbe → `/api/v1/readyz`**.
  - **OpenShift-pure securityContext** (mirrors `sandbox/backends/kubernetes_pod.py`): pod `runAsNonRoot: true`, **no `runAsUser` / no `fsGroup`** (the SCC assigns from the namespace's `MustRunAsRange`); container `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `readOnlyRootFilesystem: true`, `seccompProfile.type: RuntimeDefault`.
  - **Writable paths under `readOnlyRootFilesystem=true`** are `emptyDir` mounts at exactly what the prod lifespan writes: `/tmp`, `/var/lib/cognic-agentos/object-store` (the prod-resolved `local_object_store_root`), and `/var/lib/cognic/model-artifacts` (the prod-resolved `model_artifact_root` — a *distinct* path). The boot-required litellm config is a read-only ConfigMap mount at `/app/infra/litellm`.
- **Service.** ClusterIP, port 8000 (named `http`). The smoke reaches it via `kubectl port-forward`; **no Ingress/Route in Z1a**.
- **ConfigMap (non-secret).** The `COGNIC_*` environment, including the non-personal digest-pinned canonical sandbox image refs that satisfy G7.
- **litellm-config ConfigMap (boot-required).** Renders the router config from `litellm.config` (or mounts `litellm.existingConfigMap`), mounted at `/app/infra/litellm/config.yaml` — the one boot-blocking file that is not in the image.
- **Bootstrap Secret (gated).** Renders **only** when `secrets.create=true` (smoke/dev convenience). Production sets `secrets.create=false` + `secrets.existingSecret=<operator/ESO-managed Secret>` carrying `COGNIC_DATABASE_URL` (+ `COGNIC_VAULT_TOKEN`). The `_helpers.tpl` `agentos.secretName` helper **fails the render** (`fail`) if neither path is configured — no silent secretless install.
- **ServiceAccount.** A dedicated SA with **no RBAC bindings** and `automountServiceAccountToken: false` (Z1a needs no cluster API access).
- **Migration Job (values-gated hook).** See §"Migration hook-Job posture".

### Migration hook-Job posture — the operator owns migrations, not the lifespan

The kernel deliberately does **not** auto-run migrations in the lifespan; the operator owns schema change-control. Z1a honors that: migrations run as a Helm **pre-install/pre-upgrade hook Job** (`helm.sh/hook: pre-install,pre-upgrade`, `hook-weight: "-5"`, `hook-delete-policy: before-hook-creation,hook-succeeded`; `backoffLimit: 1` + `ttlSecondsAfterFinished`), running `alembic upgrade head` from the same `default-adapters` image (it bundles alembic + asyncpg + the migrations dir). The Job **fails loud if `COGNIC_DATABASE_URL` is unset** — it `exit 1`s with a `FATAL:` message rather than silently succeeding. No initContainer-migration; no app-lifespan auto-migration.

The Job is gated by `migrations.enabled` (default `true`). When `migrations.enabled=false` **no hook Job renders** — strict operators with their own change-control run `alembic upgrade head` out-of-band before serving traffic (the production-install runbook carries the exact command). This preserves the "operator owns migrations" contract while letting the chart drive them for operators who want it.

### G7 satisfied via non-personal digest-pinned canonical image config (sandbox stays off)

The chart ships prod-safe placeholder canonical sandbox image refs of the shape `registry.example.com/cognic-agentos/<name>@sha256:<64-hex>` for both `sandbox.canonicalRuntimeImage` and `sandbox.canonicalEgressProxyImage`. This is **config-only**: `sandbox.runtimeEnabled` defaults to `false`, the refs are never pulled, and they exist purely to satisfy G7's strict-profile validator (which fires independent of `runtimeEnabled`). Operators re-home + re-sign them under their canonical trust root and override the chart values. A true `secret_driver=none` / optional-adapter shrink (Option C) is out of scope (see §"Five-always-built-adapter Ready truth").

### Five-always-built-adapter Ready truth — ACCEPTED (Option A); Option C DEFERRED

The strict `/readyz` truth — five always-built adapters (relational, vector, secret, embedding, observability) with no `none`/`noop` escape — is **accepted as-is (Option A)**, not changed. The honest minimal infrastructure to reach Ready is five real backends; the chart, the smoke, and the runbooks all reflect that without faking any adapter's health.

**Option C** — adding optional-adapter `none`/`noop` drivers (so an operator could shrink the Ready footprint below five backends, e.g. a `secret_driver=none` mode) — is a **kernel change** and is explicitly **DEFERRED to a future slice**. Z1a is packaging-only and must not force a production-code change; if any deliverable did, the locked rule is STOP-and-re-scope.

### The env-gated `kind` Ready-smoke — honesty contract

A local `kind` smoke proves the **real** `default-adapters` image reaches `/readyz`=200 in Kubernetes against **six real, credential-free, CPU-only backends** — no stub fakes any adapter's health:

1. **Postgres** (`postgres:16-alpine`) — relational (also hosts Langfuse's own DB on the same instance).
2. **Qdrant** (`qdrant/qdrant:v1.17.1`) — vector.
3. **Vault** (`hashicorp/vault:1.18` in `-dev` mode, auto-unsealed) — secret.
4. **Ollama** (`ollama/ollama:0.5.4`, CPU) with one small real embedding model pulled (`nomic-embed-text`, ~270 MB — a non-dev name that satisfies G5 *and* is genuinely functional) — embedding + LiteLLM's upstream.
5. **Langfuse** (`langfuse/langfuse:2`, single-container) — observability.
6. **LiteLLM** (`ghcr.io/berriai/litellm:main-stable`) mounting the committed `infra/litellm/config.yaml` with its own smoke-only `LITELLM_MASTER_KEY` set on the LiteLLM pod — gateway config source. AgentOS's `COGNIC_LITELLM_MASTER_KEY` stays `None`: the gateway is not called at boot nor `/readyz`-probed, so Ready is independent of it (G1-compliant).

Redis is **off**. The AgentOS pod boots the real `create_prod_app` → `build_runtime` path in **`prod` profile** and must reach Ready through the **real** `/readyz` (all five adapters `"ok"`). Proof = `kubectl wait --for=condition=ready` + a `curl /api/v1/readyz` asserting 200, ending in `SMOKE PASS`.

**Honesty contract:** the smoke is **env-gated** (`COGNIC_RUN_KIND_SMOKE=1` / `workflow_dispatch`) and **operator-run** — it is **NOT on the always-on CI lane** (it needs a Docker host + `kind`). It follows the operator-pre-merge-audit pattern (the Z2/Z3/Z4 precedent). Where a Docker host is unavailable, the smoke is verified-by-reading. This ADR does **not** claim the live `kind` smoke runs in CI by default.

### Critical-controls scope

Per AGENTS.md "Critical-controls rule": Z1a adds **no kernel code and no on-gate module**. The critical-controls coverage gate stays at **131**. The chart is infra-as-code (Helm templates + values + CI); the only Python added is the rendered-YAML snapshot test (`tests/unit/infra/test_helm_chart.py`, subject to ruff/mypy). No migration is added. No wire-protocol contract, governance primitive, sandbox/sub-agent boundary, RBAC surface, or evidence-pack format is touched.

## Consequences

### Positive
- Answers the first deployment question — *can an operator install AgentOS on Kubernetes/OpenShift?* — with a real, validated chart instead of a loose-parts bootstrap.
- The strict `/readyz` truth is encoded honestly: the chart + smoke + runbooks all state "five real backends," with no faked adapter health.
- The always-on CI gate (lint/template/kubeconform/snapshot-drift across Helm 4 + Helm 3) catches chart drift and Helm-3-incompatibility on every PR, cluster-free.
- OpenShift-pure securityContext (no `runAsUser`/`fsGroup`) means the chart installs under a default `restricted-v2` SCC without privilege grants.
- The migration hook-Job preserves the "operator owns migrations" contract while offering chart-driven migrations for operators who want them — and fails loud on a missing DB URL.

### Negative
- The minimal Ready footprint is five backends, not one — operators cannot stand up a "kernel-only" Ready instance until Option C lands. This is the honest cost of the strict `/readyz` posture, surfaced in the runbooks.
- No Ingress/Route in Z1a means reaching the Service from outside the cluster requires `kubectl port-forward` (or an operator-supplied Ingress); first-class ingress is Z1b.
- The canonical sandbox image refs ship as `registry.example.com/...` placeholders that operators MUST re-home — an un-re-homed prod install carries non-pullable (but inert, sandbox-off) refs.

### Neutral
- Helm-only-in-repo means Kustomize consumers render `helm template` + overlay in their own repos — the standard pattern, but a deliberate non-bundling of Kustomize bases here.
- The env-gated smoke is operator-run, not always-on CI — deployability-end-to-end proof is opt-in, consistent with the env-gated live-proof pattern elsewhere in the repo.

## Out of scope (Z1b)

The following are deferred to **Sprint 14B-Z1b** (and a separate Option-C slice) and are NOT delivered by Z1a:

- **AKS / cloud bring-up + smoke** — a real cloud environment with cloud-identity wiring.
- **External-secrets depth** — ESO / Vault-Agent / CSI Secret-Store integration (Z1a references an existing Secret by name only).
- **Ingress / OpenShift Route + TLS** — Z1a omits these *templates entirely* (no dead disabled-by-default toggles).
- **Observability wiring** — a `ServiceMonitor` → real Prometheus, and the OTel gRPC→HTTP exporter for Langfuse ingestion (a parked follow-up).
- **Option C** (a separate future slice) — optional-adapter `none`/`noop` drivers to shrink the five-backend Ready footprint. This is a kernel change and is not Z1a.

No ADR-021 backfill (reserved for Phase-5 Studio per CLAUDE.md).

## Sprint 14B-Z1a implementation closeout (2026-06-18)

Sprint 14B-Z1a ships the packaging core this ADR specifies. As-built notes:

1. **Chart objects landed as specified** — Deployment (startup/liveness `/api/v1/healthz`, readiness `/api/v1/readyz`; OpenShift-pure securityContext; the three `emptyDir` writable paths), Service (ClusterIP :8000), ConfigMap, litellm-config ConfigMap (mounted at `/app/infra/litellm/config.yaml`), bootstrap Secret (gated), ServiceAccount (no RBAC, `automountServiceAccountToken: false`), and the values-gated migration hook Job.
2. **CI gate landed two-lane** in `.github/workflows/python.yml`: an always-on `helm-chart` job (Helm v4.2.2 primary lint/template/kubeconform/snapshot-drift + Helm v3.16.3 compatibility render/validate; kubeconform v0.8.0; all checksum-verified) and an env-gated `kind-smoke` job (`COGNIC_RUN_KIND_SMOKE=1` / `workflow_dispatch`).
3. **Snapshot test** is the only Python added (`tests/unit/infra/test_helm_chart.py` + the committed `tests/unit/infra/helm/agentos_rendered.yaml`); byte-equality, deterministic render, regenerate-on-delete.
4. **Posture confirmed** — no kernel edit; no migration; no new on-gate module; CC count stays **131**.
5. **Docs** — the two operator runbooks (`docs/operator-runbooks/kind-smoke-deployment.md`, `docs/operator-runbooks/helm-chart-production-install.md`) + this ADR + the AS_BUILT Pillar-5 / forward-item-7 + the AGENTS.md Z1a note.

## Sprint 14B-Z1b-a amendment (2026-06-18)

Sprint 14B-Z1b-a gives a deployed AgentOS first-class **external access** + **scrape**, all as **conditional, default-off** chart templates on the merged Z1a chart. It is the first of the four Z1b sub-slices (Z1b-a external access / Z1b-b external secrets / Z1b-c Langfuse-OTLP exporter swap / Z1b-d AKS bring-up). Like Z1a it is **pure additive chart work — no kernel code, CC count stays 131, no migration, no new on-gate module**; the only Python touched is the snapshot-test parametrization (subject to ruff/mypy).

### The three conditional templates (default OFF)

The chart was Service-only by default in Z1a (the Service is reached via `kubectl port-forward` unless external access is configured); Z1b-a adds three templates that render **nothing** unless explicitly enabled:

- **`templates/ingress.yaml`** — a Kubernetes `Ingress` (`networking.k8s.io/v1`), rendered when `ingress.enabled=true`. Carries `ingressClassName`, operator `annotations` (e.g. a cert-manager cluster-issuer), `rules[]` host/path → the chart Service `port: http`, and a `tls:` block.
- **`templates/route.yaml`** — an OpenShift `Route` (`route.openshift.io/v1`, a CRD), rendered when `route.enabled=true`. Carries `host`, `to: { kind: Service, name: <chart Service>, weight: 100 }`, `port.targetPort: http`, operator `annotations`, and a `tls:` block (see below).
- **`templates/servicemonitor.yaml`** — a Prometheus-Operator `ServiceMonitor` (`monitoring.coreos.com/v1`, a CRD), rendered when `serviceMonitor.enabled=true`. See "ServiceMonitor scrape contract" below.

All three reuse the Z1a `_helpers.tpl` conventions (`agentos.fullname` / `agentos.labels` / `agentos.selectorLabels`) and the Z1a Service's named `http` port. Default-off means none of them appear in the default rendered snapshot — the default render is byte-unchanged from Z1a.

### TLS posture

- **Ingress TLS — existing-secret-first.** `ingress.tls` is the standard Kubernetes `[{ secretName, hosts }]` list, passed through verbatim. The operator provisions the TLS Secret (typically via cert-manager + the issuer annotation); the chart references it by name and creates no certificate material of its own.
- **Route TLS — `a+b` (Routes have no Ingress-style `secretName` parity, so a distinct shape):**
  - **(a) default:** `route.tls.enabled=true` ⇒ `termination: edge` with **no** cert/key — the **OpenShift router's default/wildcard certificate** serves it — plus `insecureEdgeTerminationPolicy: Redirect` (HTTP→HTTPS). Portable, zero secret handling, no OCP-version dependency. `route.tls.termination` is configurable (`edge` | `passthrough` | `reencrypt`); default `edge`.
  - **(b) optional inline:** `route.tls.certificate` / `route.tls.key` / `route.tls.caCertificate` accept inline PEM material for operators who must serve an explicit certificate.
  - **(deferred):** `tls.externalCertificate` (a Secret reference, OCP ≥ 4.16, feature-gated + router RBAC) is documented as a **later, OCP-version-gated option — NOT Z1b-a**.

### ServiceMonitor scrape contract

The `/metrics` Prometheus surface already exists (`prometheus_fastapi_instrumentator` at `{api_prefix}{prometheus_metrics_path}` → `/api/v1/metrics`). The ServiceMonitor's single `endpoints[]` entry scrapes `port: http`, `path: {{ .Values.apiPrefix }}{{ .Values.serviceMonitor.path }}` (the default `serviceMonitor.path: /metrics` joined with the chart's `apiPrefix` → `/api/v1/metrics`), `interval`, and `scrapeTimeout`. The `selector.matchLabels` is set to the chart Service's **stable `agentos.selectorLabels`** (`app.kubernetes.io/name` + `app.kubernetes.io/instance`) — deliberately **NOT** the full `agentos.labels` set, whose `helm.sh/chart` value changes per chart version and would break the selector on every chart upgrade. `metadata.labels` merges operator-supplied `serviceMonitor.labels` (e.g. `release: kube-prometheus-stack`) so the cluster Prometheus discovers it.

### The four-scenario CI gate + CRD-schema outcome

The Z1a single byte-snapshot becomes **four orthogonal byte-snapshots** — `default`, `ingress`, `route`, `servicemonitor` — each rendered from the base `ci/snapshot-values.yaml` layered with its scenario overlay, diffed byte-for-byte against its committed `tests/unit/infra/helm/agentos_rendered{,_ingress,_route,_servicemonitor}.yaml`, and `kubeconform`-validated. The byte-snapshot generator stays **Helm-4.2.2-pinned** (the Z1a pinned-generator fix); the pytest byte-snapshot is version-gated and the always-on `helm-chart` CI job is the authoritative drift gate. The Helm-3 compatibility lane renders all four too (lint + template + kubeconform; no byte-diff — the snapshot is the primary lane's).

`Route` and `ServiceMonitor` are CRDs the default kubeconform schema set does not know, so the CI adds `-schema-location default -schema-location <CRDs-catalog template URL>` (the `datreeio/CRDs-catalog` mirror). The as-built CRD-schema outcome:

- **ServiceMonitor's CRD schema resolves** via the catalog (`ServiceMonitor_v1.json`) and stays **schema-validated**.
- **Route's CRD schema is absent from that catalog** (confirmed 2026-06-18 — a genuine catalog absence, not a network issue). The CI therefore uses the scoped **`-skip Route`** fallback: the Route still **renders + lints** and is byte-snapshotted; only its kubeconform **schema** validation is skipped. The skip is scoped to `Route` alone — ServiceMonitor and all core kinds stay schema-validated. (This is narrower than the spec §5 broad fallback option, which named `-skip Route,ServiceMonitor`; the as-built scoped it to `Route` only because ServiceMonitor's schema does resolve.)

The default + ingress-on scenarios use core kinds only and need no CRD schemas.

### Posture (Z1b-a)

Pure chart work: **CC count stays 131 / no kernel change / no migration / no new on-gate module.** The live cloud / live-ingress exercise is **Z1b-d** (AKS bring-up) — Z1b-a's templates are proven by render / lint / kubeconform / byte-snapshot only, **not** by a live cluster. Out-of-scope-for-Z1b-a (the remaining Z1b sub-slices): external-secrets depth (Z1b-b), the Langfuse-OTLP OTel gRPC→HTTP exporter swap (Z1b-c, a kernel slice), and AKS / cloud-identity bring-up (Z1b-d).

## Sprint 14B-Z1b-b amendment (2026-06-18)

Sprint 14B-Z1b-b adds **external-secrets depth (ESO-first)**: a conditional, default-off External Secrets Operator (ESO) `ExternalSecret` template that populates the existing 2-key bootstrap Secret from an external store, behind a **three-mode mutually-exclusive secret source**. It is the second of the four Z1b sub-slices (Z1b-a external access / Z1b-b external secrets / Z1b-c Langfuse-OTLP exporter swap / Z1b-d AKS bring-up). Like Z1a/Z1b-a it is **pure additive chart work — no kernel code, CC count stays 131, no migration, no new on-gate module**; the only Python touched is the snapshot-test parametrization (subject to ruff/mypy).

### The conditional `ExternalSecret` template (default OFF)

- **`templates/externalsecret.yaml`** — an ESO `ExternalSecret` (`external-secrets.io/v1`), rendered only when `externalSecrets.enabled=true` (default `false`). It produces the `agentos.secretName` Secret with `target.name` = `agentos.secretName`, `creationPolicy: Owner`, and `refreshInterval` defaulting to `1h`.
- **The two `data[]` entries are FIXED** to exactly the two bootstrap keys `COGNIC_DATABASE_URL` + `COGNIC_VAULT_TOKEN` — there is no arbitrary-extra-target-key surface. For each, `remoteRef.key` is **required** (a `required` template guard fails the render when `externalSecrets.enabled=true` and a key is empty) and `remoteRef.property` is **optional**.
- **`secretStoreRef` is operator-owned.** `secretStoreRef.name` is **required** when enabled and `secretStoreRef.kind` defaults to `SecretStore` (`SecretStore` | `ClusterSecretStore`). **The chart NEVER creates the store** — the operator provisions the `SecretStore`/`ClusterSecretStore` (and ESO itself, the `external-secrets.io` CRDs) in the cluster.
- **`targetSecretName`** defaults to `<fullname>-secrets` (override only for a fixed name).

The template reuses the Z1a/Z1b-a `_helpers.tpl` conventions (`agentos.fullname` / `agentos.labels` / `agentos.secretName`). Default-off means it does not appear in the default rendered snapshot — the default render is byte-unchanged.

### The three-mode mutually-exclusive secret source

Z1a/Z1b-a had two secret sources (chart-created `secrets.create` vs an existing `secrets.existingSecret`); Z1b-b adds the ESO source as a third, mutually exclusive with the other two: **exactly one of `secrets.create` | `secrets.existingSecret` | `externalSecrets.enabled`** may be set. This is enforced in **two layers** (defense-in-depth):

1. **Helm `fail` guard.** A new `agentos.validateSecretSource` helper counts the configured sources and `fail`s the render when more than one is set. It is invoked as the **FIRST action of `agentos.secretName`**, so the mutual-exclusion guard fires at every secret-wiring site (`deployment.yaml`, `migration-job.yaml`, and the new `externalsecret.yaml`). At-least-one is still enforced by the terminal `fail` in `agentos.secretName`.
2. **`values.schema.json` (relocated to a root-level `allOf`).** The in-`secrets` subschema `else` clause from Z1a (`create=false ⇒ existingSecret required`) was **DROPPED**, and the 3-mode logic was **relocated to a root-level `allOf`**. The `allOf` encodes the mutual exclusion (`not` clauses), the relocated "`create=false` ∧ not-ESO ⇒ `existingSecret` required", and the ESO enabled-mode required fields (`secretStoreRef.name` + both `remoteRef.key` non-empty).

**Rationale for dropping the in-`secrets` `else`:** ESO mode is legitimately `create=false` + empty `existingSecret` (the Secret is materialised by ESO, not by the chart and not by the operator pre-creating it), which the old `else` would have rejected. Equally important, the in-`secrets` subschema **cannot see the sibling `externalSecrets.*`** to make the decision; only a root-level `allOf` has both the `secrets.*` and `externalSecrets.*` props in scope. Both layers (the Helm `fail` and the schema `allOf`) coexist as defense-in-depth.

### The fifth snapshot scenario + CRD-schema outcome

The Z1b-a four byte-snapshots (`default` / `ingress` / `route` / `servicemonitor`) become **five** — a fifth `externalsecret` scenario is added (its overlay disables `secrets.create` because the base `ci/snapshot-values.yaml` sets `secrets.create=true` and ESO is mutually exclusive with it). The scenario is rendered Helm-4.2.2-pinned, byte-diffed against its committed `tests/unit/infra/helm/agentos_rendered_externalsecret.yaml`, and `kubeconform`-validated. The Helm-3 compatibility lane renders it too.

**CRD-schema outcome — ExternalSecret is schema-VALIDATED.** The ExternalSecret CRD schema **IS in the `datreeio/CRDs-catalog`** (stored lowercase as `external-secrets.io/externalsecret_v1.json`) and **kubeconform validates it** — the `externalsecret` scenario reports `Valid: 7, Skipped: 0`. So `ExternalSecret` is schema-validated exactly like `ServiceMonitor`. The CI keeps the **narrow `-skip Route`** introduced in Z1b-a: `Route` remains genuinely absent from the catalog (`route.openshift.io/route_v1.json` → 404; kubeconform errors without the skip), so only `Route`'s schema validation is scoped-skipped — `ExternalSecret`, `ServiceMonitor`, and all core kinds stay schema-validated.

**A lesson on the catalog probe.** A raw-URL PascalCase probe (`ExternalSecret_v1.json`) is a **false-negative** for kubeconform's actual behaviour: kubeconform lowercases the kind before resolving the schema, so the authoritative signal is kubeconform itself, not a raw-URL HEAD with the PascalCase filename. The Z1b-b finding therefore corrects any earlier hedge — `ExternalSecret` is validated, not scoped-skipped.

### Posture (Z1b-b)

Pure chart work: **CC count stays 131 / no kernel change / no migration / no new on-gate module.** The only new Python is the snapshot-test parametrization. The live cluster / live-ESO exercise is **Z1b-d** (AKS bring-up) — Z1b-b's `ExternalSecret` template is proven by render / lint / kubeconform (schema-validated) / byte-snapshot only, **not** by a live cluster against a real store. Out-of-scope-for-Z1b-b (the remaining Z1b sub-slices): the Langfuse-OTLP OTel gRPC→HTTP exporter swap (Z1b-c, a kernel slice) and AKS / cloud-identity bring-up (Z1b-d).

## Sprint 14B-Z1b-c amendment (2026-06-18)

Sprint 14B-Z1b-c adds a **generic OTLP transport primitive** to the kernel so a self-hosted Langfuse (or any OTLP/HTTP endpoint) becomes operator-turnkey for span ingestion. It is the third of the four Z1b sub-slices (Z1b-a external access / Z1b-b external secrets / **Z1b-c Langfuse-OTLP exporter swap** / Z1b-d AKS bring-up) and the **first Z1b slice that touches kernel code** — `core/config.py` (a `core/` stop-rule edit) + `observability/otel.py`. Unlike Z1a/Z1b-a/Z1b-b it is NOT pure chart work, but the posture floor holds: **CC count stays 131, no migration, no new on-gate module, and no new dependency** (see Posture below).

### The generic protocol + headers primitive (kernel)

- **Two new `core/config.py` Settings** drive the transport: `otel_exporter_protocol: Literal["grpc", "http"] = "grpc"` and `otel_exporter_headers: dict[str, str]` (`default_factory=dict`, native JSON-env decode mirroring `llm_model_id_map`). The default is unchanged — **`grpc`** with no headers — so existing deployments behave exactly as before.
- **`_build_otlp_exporter` branches on the protocol** and now returns the widened `SpanExporter` type:
  - **`grpc` (default)** — the existing path (endpoint / `insecure` / mTLS-credentials), now **also threading `headers`**.
  - **`http`** — the OTLP/HTTP exporter with `headers`, and the **mTLS triple reused as the http exporter's file-path kwargs** (`certificate_file` / `client_certificate_file` / `client_key_file`).
- **`headers` thread into BOTH exporters.** **`insecure` is gRPC-only** — on the http path security is the endpoint URL scheme (`https://…`), not an `insecure` flag.
- **No new dependency.** The OTLP/HTTP exporter already ships inside the `opentelemetry-exporter-otlp` umbrella the kernel depends on; the http path is a function-local import, not a new requirement.
- **The kernel stays Langfuse-AGNOSTIC.** It knows only `grpc`/`http` + headers + endpoint; the Langfuse URL convention (`{host}/api/public/otel/v1/traces`) and the Basic-auth header live in the chart values / the operator-owned Secret / the runbook — never in kernel code.

### The chart wiring (endpoint-gated; default render UNCHANGED)

- **`values.otel.exporter.{endpoint, protocol, insecure, headersSecretKey}`.** The ConfigMap otel keys (`COGNIC_OTEL_EXPORTER_ENDPOINT` / `_PROTOCOL` / `_INSECURE`) are **gated on `otel.exporter.endpoint`** being set, so with the default (empty) endpoint the otel block does not render — **the default render and all 5 existing Z1a/Z1b-a/Z1b-b snapshots are byte-UNCHANGED**.
- **The sensitive Basic-auth header rides an optional `secretKeyRef` passthrough**, NOT the ConfigMap. When `otel.exporter.headersSecretKey` is set, `deployment.yaml` projects `COGNIC_OTEL_EXPORTER_HEADERS` from that key in the operator-owned `agentos.secretName` Secret (the same Secret that carries the 2 bootstrap keys). The header JSON never appears in the ConfigMap.
- **`secrets.create=true` is NOT compatible with `headersSecretKey`.** A chart-created Secret carries only the 2 bootstrap keys (`COGNIC_DATABASE_URL` + `COGNIC_VAULT_TOKEN`); a `headersSecretKey` `secretKeyRef` against it would dangle. The header is valid only with `secrets.existingSecret` (or a separate ESO `ExternalSecret`) — a Secret the operator populates with the extra header key.

### The sixth snapshot scenario + CRD-schema outcome

The Z1b-b five byte-snapshots (`default` / `ingress` / `route` / `servicemonitor` / `externalsecret`) become **six** — a sixth `otel-http` scenario is added. Its overlay uses `secrets.create:false` + `secrets.existingSecret` (the mutually-exclusive interaction above: `headersSecretKey` is valid only against an operator-populated Secret, never a chart-created 2-key one). The scenario is rendered Helm-4.2.2-pinned, byte-diffed against its committed `tests/unit/infra/helm/agentos_rendered_otel-http.yaml`, and `kubeconform`-validated.

**No kubeconform CRD change.** The otel render is **core kinds only** (ConfigMap + Deployment env) — no new CRD is introduced, so the CI keeps the unchanged narrow **`-skip Route`** (Route alone stays catalog-absent per Z1b-a/Z1b-b); `otel-http` reports all-Valid.

### The env-gated live ingestion proof

A live proof at `tests/integration/observability/test_langfuse_otlp_ingestion.py` is **env-gated** on `COGNIC_RUN_LANGFUSE_OTEL=1` (+ `COGNIC_LANGFUSE_HOST` + the keys; it skips by default and is operator-run, never always-on CI). It exports a span over OTLP/HTTP to `{host}/api/public/otel/v1/traces` carrying the `x-langfuse-ingestion-version: "4"` header (the Langfuse OTel-docs real-time-ingestion recommendation) and reads it back via the Langfuse SDK `client.api.observations.get_many(trace_id=...)`. This is a capability proof, not a claim that a production Langfuse is running.

### Posture (Z1b-c)

**CC count stays 131 / no migration / no new on-gate module / no new dependency.** `observability/otel.py` and `core/config.py` are **off the per-file coverage gate**, but **`core/config.py` is under the AGENTS.md `core/` stop-rule** — the kernel edit carried halt-before-commit human scrutiny. Z1b-c is the kernel slice of the parked Langfuse-OTLP follow-up; the **live cloud / live cluster** exercise remains **Z1b-d** (AKS bring-up) — Z1b-c's chart wiring + http exporter are proven by render / lint / kubeconform / byte-snapshot + unit tests + the env-gated live proof only, **not** by an always-on production Langfuse. Out-of-scope-for-Z1b-c (the remaining Z1b sub-slice): AKS / cloud-identity bring-up + the live ServiceMonitor → Prometheus scrape wiring (Z1b-d).
