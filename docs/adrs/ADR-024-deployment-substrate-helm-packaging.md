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
