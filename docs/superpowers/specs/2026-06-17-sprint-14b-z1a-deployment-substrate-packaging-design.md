# Sprint 14B-Z1a — Deployment Substrate: Packaging Core — Design

**Date:** 2026-06-17
**Status:** DRAFT — design approved in brainstorming (2026-06-17); awaiting spec review before planning.
**ADRs:** new **ADR-024** (Deployment Substrate / Helm Packaging); references ADR-004 (sandbox SecurityContext precedent), ADR-009 (pluggable adapters), ADR-018 (cache/quota posture).

## Context

AgentOS is already remarkably k8s-friendly: a real 3-stage prod image (`infra/agentos/Dockerfile` — kernel ≤120 MiB / `default-adapters` ≤385 MiB, `create_prod_app`), `/healthz` + `/readyz` + `/version` + a Prometheus `/metrics` surface, JSON stdout logging with trace/request correlation, the G1–G10 deploy-safety guards (prod refuses dev defaults), a CI boot-smoke + image-size budgets, and operator-run alembic migrations (`alembic upgrade head`, deliberately NOT auto-run in lifespan). What is **missing** is Helm/Kubernetes packaging of the kernel itself — the only k8s code today is `sandbox/backends/kubernetes_pod.py`, which deploys *sandboxes*, not AgentOS.

14B (Deployment Substrate) was **decomposed**: **Z1a = packaging core only** (this spec); **Z1b** later owns AKS/cloud bring-up, external-secrets depth (ESO/Vault-Agent/CSI), Ingress/Route + TLS, and richer observability wiring (ServiceMonitor → real Prometheus, the OTel gRPC→HTTP exporter for Langfuse). A separate future slice owns "Option C" (optional-adapter `none`/`noop` drivers to shrink the Ready footprint) — explicitly NOT Z1a.

## Recon verdict (the gate)

A read-only recon (2026-06-17) confirmed **Z1a requires zero kernel changes — it is pure additive infra-as-code; CC count stays 131.** Every setting the chart needs already exists; the five-always-built-adapter Ready truth is **accepted** (Option A), not changed (Option C deferred). Three load-bearing findings:

1. **`/readyz` is strict:** `ready = all(comp.status == "ok")` — any `"degraded"`/`"unreachable"` → 503. On the `create_prod_app` path **five adapters are always built with no `none`/`noop` escape**: relational (Postgres), vector (Qdrant), secret (Vault), embedding (Ollama/openai-compat), observability (Langfuse/Dynatrace). Each returns `"unreachable"` when its backend is down. Only `cache` (Redis) has a `none` bypass (default-none); `object_store=local_fs` is filesystem-only (no external service). So the honest minimal infra to reach Ready is **five real backends**, not one.
2. **Credential-free model path already exists, committed:** `infra/litellm/config.yaml` declares `cognic-tier1/2-dev` → `ollama/qwen3:*` at `${OLLAMA_BASE_URL:-http://ollama:11434}` (zero SaaS keys). The LLM gateway makes **no network call at boot** (`PreflightResolver.from_yaml` is file-read-only) and **is not probed by `/readyz`** — so for Ready, LiteLLM only needs to be up serving its config; the chat model need not even be pulled. The embedding adapter (`embed_driver=ollama`) probes Ollama's `/api/tags`, so the only real model pull the smoke needs is **one small embedding model**.
3. **G7 resolved precisely (config.py:1465-1474):** G7 fires whenever `strict` (stage/prod) AND either `sandbox_canonical_*_image` contains `ghcr.io/bmzee` — **independent of `sandbox_runtime_enabled`**. Both kernel defaults are `ghcr.io/bmzee/…@sha256:…`, so both trip G7 in prod profile even with sandbox off. The field validator (config.py:1708-1728) requires `<ref>@sha256:<64-lowercase-hex>` (non-empty, whitespace-free ref). **Therefore the Z1a chart MUST set non-personal, digest-pinned canonical image refs in the ConfigMap** (config-only; sandbox stays off, refs never pulled; operator-overridable).

## Goal

Ship a real, OpenShift-compatible Helm chart for the AgentOS kernel, validated always-on in CI (lint/template/kubeconform/snapshot-drift) and proven end-to-end by an env-gated local `kind` Ready-smoke against six real credential-free backends — so an operator can install AgentOS on Kubernetes/OpenShift without hand-assembling the kernel from loose parts.

## Non-goals (guards — user-locked)

- **No kernel behavior changes.** Z1a is packaging-only; CC count stays **131**. If any deliverable forces a production-code change, **STOP and re-scope**.
- **No optional-adapter `none`/`noop` driver work** (Option C) — its own future slice.
- **No AKS / cloud bring-up, no external-secrets depth, no Ingress/Route, no TLS, no ServiceMonitor wiring** — all Z1b. Z1a omits Ingress/Route + ServiceMonitor *templates entirely* (documented as Z1b), so there are no dead disabled-by-default toggles in Z1a values.
- **No fake readiness:** no stub that fakes Vault/Qdrant/Langfuse health to manufacture Ready. Real lightweight services only (a real LiteLLM with a smoke-only master key + a real Ollama are honest; faking adapter `/health` is not).

## Design

### 1. Chart home & layout
Chart lives at `infra/charts/agentos/` (matches the `infra/agentos/` Dockerfile convention; no existing helm/k8s/kustomize dir anywhere — confirmed). Helm is the **only** in-repo manifest source; banks needing Kustomize render `helm template` and overlay in their own repos.

```
infra/charts/agentos/
  Chart.yaml                 # appVersion tracks the image tag
  values.yaml                # documented toggles + prod-safe defaults
  values.schema.json         # JSON-Schema validation of values
  templates/
    _helpers.tpl
    serviceaccount.yaml      # dedicated SA; no cluster perms in Z1a
    configmap.yaml           # non-secret COGNIC_* + the mounted litellm config file
    secret.yaml              # bootstrap Secret; rendered ONLY when secrets.create=true
    deployment.yaml          # kernel (create_prod_app); probes; securityContext; volumes
    service.yaml             # ClusterIP :8000 (named http); no Ingress/Route in Z1a
    migration-job.yaml       # Helm pre-install/pre-upgrade hook, gated by migrations.enabled
    NOTES.txt
  ci/
    snapshot-values.yaml     # deterministic inputs for the rendered-YAML snapshot
    smoke-values.yaml        # points the chart at the in-cluster real backends
```
Snapshot test + committed render live at `tests/unit/infra/helm/agentos_rendered.yaml` + `tests/unit/infra/test_helm_chart.py`.

### 2. The chart's k8s objects
- **Deployment:** the `default-adapters` image; inherits the image CMD (`uvicorn …:create_prod_app --factory --host $COGNIC_HOST --port $COGNIC_PORT`). `replicas: 1` default. `envFrom` the ConfigMap; `env` with `secretKeyRef` for the bootstrap secret(s). Probes: **liveness → `/api/v1/healthz`**, **readiness → `/api/v1/readyz`**, plus a **startupProbe → `/api/v1/healthz`** with a generous `failureThreshold` (the lifespan builds runtime + OPA engines + five adapters; the startupProbe prevents premature liveness kills during boot).
- **OpenShift-compatible securityContext** (mirrors `sandbox/backends/kubernetes_pod.py`): pod `runAsNonRoot: true`, **no `runAsUser`/`fsGroup`** (let the SCC assign from the namespace range); container `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `readOnlyRootFilesystem: true`, `seccompProfile.type: RuntimeDefault`. Writable paths are `emptyDir` mounts: `/tmp` and the `object_store` local_fs root (the exact writable-path set is a spec-time precision item resolved in the plan by reading what the lifespan writes).
- **Service:** ClusterIP, port 8000 (named `http`). The smoke reaches it via `kubectl port-forward` / an in-cluster probe — no Ingress in Z1a.
- **Migration Job:** annotations `helm.sh/hook: pre-install,pre-upgrade`, `helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded`, `helm.sh/hook-weight: "-5"`; spec `backoffLimit: 1` + `ttlSecondsAfterFinished`. Runs `alembic upgrade head` from the same `default-adapters` image (it bundles alembic + asyncpg + the migrations dir). **Fail-loud if `COGNIC_DATABASE_URL` is unset** — no silent success. Gated by `.Values.migrations.enabled` (default `true`); when set `false` **no hook Job renders**, and strict operators with their own change-control run the documented `alembic upgrade head` out-of-band (the production-install runbook carries the exact command). No initContainer-migration; no app-lifespan auto-migration.
- **ServiceAccount:** a dedicated SA with no RBAC bindings (Z1a needs no cluster API access).

### 3. The values surface + prod-safe defaults
Toggles present in Z1a: `image.{repository,tag,pullPolicy,pullSecrets}`, `runtimeProfile` (default **`prod`**), `redis.enabled` (default **false** → `cache_driver=none`), `vault.{enabled,addr}`, `sandbox.{runtimeEnabled(default false),canonicalRuntimeImage,canonicalEgressProxyImage}`, `migrations.enabled` (default **true**), `secrets.{create,existingSecret}`, `resources`, `replicaCount`, and the per-adapter endpoint/config values. **Dropped from Z1a (→ Z1b, no dead toggles): `serviceMonitor.*`, `ingress.*`, `openshift.route.*`.**

The chart defaults satisfy every strict-profile guard: `cache_driver=none` (G9/G10 ✓), `require_cosign=true` (G4 ✓), a **non-dev embedding model** name (G5 ✓), self-hosted policy keeps dev tier aliases legal (G6 ✓ — inert), service secrets `None`/`vault://` not plaintext (G1 ✓), and **non-personal digest-pinned canonical sandbox image refs** (G7 ✓ — per the recon resolution; `sandbox.canonicalRuntimeImage`/`canonicalEgressProxyImage` ship prod-safe placeholders of shape `registry.example.com/cognic-agentos/<name>@sha256:<64-hex>`, operator-overridable with their real re-homed+re-signed refs).

### 4. Secrets handling (Z1a depth)
The chart **references an existing Secret by name** (`secrets.existingSecret`) for production — it does not bake real secrets. A chart-created Secret renders **only** when `secrets.create: true` (smoke/dev convenience, with an explicit "do not use in prod" note in `NOTES.txt` + values comments). Bootstrap split: `COGNIC_DATABASE_URL` + (when vault on) `COGNIC_VAULT_TOKEN` are the only true secrets; AgentOS service secrets stay `None` in the smoke — `litellm_master_key=None` is G1-compliant and Ready does not depend on it (the gateway makes no boot call and is not `/readyz`-probed). The LiteLLM pod carries its **own** smoke-only `LITELLM_MASTER_KEY` (a value on the LiteLLM deployment, mirroring the dev compose's `dev-only-litellm` — not an AgentOS secret). The Langfuse `/api/public/health` ping is unauthenticated, so the readiness probe does not need `langfuse_secret_key` — the plan verifies whether the observability adapter tolerates `langfuse_secret_key=None` at construction; if it does not, the smoke seeds the key into the already-running Vault and references it via `vault://` (the G1-compliant, no-plaintext fallback, which also exercises the real secret-resolution path). Deeper ESO/Vault-Agent/CSI integration is explicitly **Z1b**.

### 5. The env-gated `kind` Ready-smoke (six real backends, credential-free, CPU-only)
Real lightweight services, no SaaS creds, mirroring the dev stack:
1. **Postgres** (`postgres:16-alpine`) — relational; also hosts Langfuse's own DB (a separate database on the same instance).
2. **Qdrant** (`qdrant/qdrant:v1.17.1`) — vector.
3. **Vault** (`hashicorp/vault:1.18` in `-dev` mode, auto-unsealed+initialized) — secret.
4. **Ollama** (`ollama/ollama`, CPU) with **one small real embedding model** pulled (e.g. `nomic-embed-text`, ~270 MB — satisfies G5 as a non-dev name *and* is genuinely functional) — embedding + LiteLLM's upstream.
5. **Langfuse** (`langfuse/langfuse:2`, single-container) — observability; `/api/public/health` reachable.
6. **LiteLLM** (`ghcr.io/berriai/litellm:main-stable`) mounting the committed `infra/litellm/config.yaml` with its own smoke-only `LITELLM_MASTER_KEY` set on the LiteLLM pod (the config carries `general_settings.master_key: ${LITELLM_MASTER_KEY}`) — gateway config source. AgentOS's `COGNIC_LITELLM_MASTER_KEY` stays `None`: the gateway is not called at boot nor `/readyz`-probed, so Ready is independent of it.

Redis **off**. The AgentOS pod boots the real `create_prod_app`→`build_runtime` path in **`prod` profile** and must reach **Ready through the real `/readyz`** (all five adapters `"ok"`). Proof = `kubectl wait --for=condition=ready` + a `curl /api/v1/readyz` asserting 200. CPU-only (small embedding model) — no GPU.

### 6. CI gates (steps added to the existing `.github/workflows/python.yml`)
- **Always-on** (new job in `python.yml`, no env gate, cluster-free): pinned-by-SHA `helm` + `kubeconform` (the OPA/cosign binary-pinning precedent) → `helm lint` → `helm template <fixed-release> --namespace <fixed-ns> -f ci/snapshot-values.yaml` (pinned helm version + fixed release name/namespace/values for byte-determinism) → **byte-equality snapshot-drift** vs the committed `agentos_rendered.yaml` → `kubeconform` schema-validate the rendered output.
- **Env-gated** (`COGNIC_RUN_KIND_SMOKE=1` / `workflow_dispatch`, opt-in, not on the always-on path): create a `kind` cluster → apply the six backends → `helm install` → `kubectl wait` Ready → `curl /readyz`=200 → teardown. Operator-audit style (the Z2/Z3/Z4 pattern).

### 7. Docs
`docs/operator-runbooks/kind-smoke-deployment.md` (run it, what it proves, troubleshooting) + `docs/operator-runbooks/helm-chart-production-install.md` (pre-flight: snapshot/kubeconform; install; post-install verify via `/readyz` + logs; the `migrations.enabled` decision; rollback) — matching the existing runbook style. **ADR-024 Deployment Substrate / Helm Packaging** records the packaging posture, the Helm-only-in-repo decision, the five-adapter-Ready acceptance (Option A) + Option-C deferral, and the env-gated-smoke honesty contract. No ADR-021 backfill (reserved for Phase-5 Studio per CLAUDE.md). Closeout touches: **AS_BUILT** Pillar 5 (partial → packaging-done) + forward-sequence item 7, **AGENTS.md** (a Z1a note).

### 8. Precision items resolved in the plan (not design forks)
These are concrete values/branches the plan resolves by reading source while building each task — none changes the design, none is a kernel change:
- The exact `readOnlyRootFilesystem` writable-path set (what the `create_prod_app` lifespan writes — `/tmp` + the `object_store` local_fs root at minimum) → the `emptyDir` mount list in `deployment.yaml` (T2).
- Whether the observability adapter tolerates `langfuse_secret_key=None` at construction; if not, the smoke uses a `vault://` seed instead of dropping Langfuse (T6).
- Whether LiteLLM boots with an unset vs set `master_key` — the smoke sets the LiteLLM pod's **own** `LITELLM_MASTER_KEY` (smoke-only, mirroring the dev compose's `dev-only-litellm`), and the plan documents whether a beyond-Ready real completion would require AgentOS to send it (then a `vault://` seed, never plaintext per G1). No fake backend — honest smoke config (T6).
- The concrete non-dev `embeddingModel` default the chart ships (the smoke uses `nomic-embed-text`; G5 only requires it not equal the dev default `qwen3-embedding:8b`) (T1).
- The pinned `helm` / `kubeconform` versions + SHA-256 digests (the OPA/cosign pinning precedent) (T5).

## Tasks (high-level; the plan expands each)

- **T1** — Chart skeleton: `Chart.yaml`, `values.yaml`, `values.schema.json`, `_helpers.tpl`, `NOTES.txt`, `configmap.yaml`, `secret.yaml` (gated render), `serviceaccount.yaml`.
- **T2** — `deployment.yaml` (probes + OpenShift securityContext + volumes + envFrom/secretKeyRef) + `service.yaml`.
- **T3** — `migration-job.yaml` (the values-gated pre-install/pre-upgrade hook; fail-loud on missing DB URL).
- **T4** — The rendered-YAML snapshot test (`tests/unit/infra/test_helm_chart.py` + committed `agentos_rendered.yaml`), byte-equality, deterministic render, regenerate via `rm <file> && uv run pytest …` (mirrors `test_well_known_routes.py`).
- **T5** — CI: add the always-on `helm lint`/`template`/`kubeconform`/snapshot job (pinned binaries) to `python.yml`.
- **T6** — The env-gated `kind` smoke: the six-backend manifests + the smoke script + the env-gated CI job + `ci/smoke-values.yaml`.
- **T7** — Docs: the two operator runbooks + ADR-024 + AS_BUILT/AGENTS updates.
- **T8** — Closeout: confirm no kernel change (CC stays 131); the full gate (ruff check + ruff format --check + full-tree `mypy src tests`; helm lint/template/kubeconform/snapshot green; the env-gated smoke is verified-by-reading + operator-runnable).

## Posture

CC count stays **131**; no migration; no new on-gate module; no kernel edit. The Python surface added is the snapshot test (subject to ruff/mypy). The env-gated `kind` smoke is verified-by-reading + operator-pre-merge-audit-runnable (the Z2/Z3/Z4 pattern), not on the always-on CI lane. Z1a answers the first deployment question — *can an operator install AgentOS on Kubernetes/OpenShift?* — and leaves AKS/cloud-identity/external-secrets/ingress/observability-wiring to Z1b.
