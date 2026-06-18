# Operator runbook — kind Ready-smoke

## What the smoke proves

The `kind` smoke proves the **real** AgentOS production image (`default-adapters`
stage of `infra/agentos/Dockerfile`, running `create_prod_app`) reaches
**`/readyz`=200 in Kubernetes** against **six real, credential-free backends** —
with no stub faking any adapter's health. It is the end-to-end deployability
proof for the Sprint 14B-Z1a Helm chart (ADR-024).

`/readyz` is strict: `ready = all(component.status == "ok")`. On the
`create_prod_app` path **five adapters are always built** — relational
(Postgres), vector (Qdrant), secret (Vault), embedding (Ollama), and
observability (Langfuse) — each returning `"unreachable"` when its backend is
down. So the honest minimal infrastructure to reach Ready is five real
backends, not one. The smoke stands up six (the five plus LiteLLM, which sources
the gateway config) and asserts the AgentOS pod boots in **`prod` profile** and
reaches Ready through the real probe.

## The six backends (credential-free, CPU-only)

| # | Backend | Image | AgentOS adapter |
|---|---|---|---|
| 1 | Postgres | `postgres:16-alpine` | relational (also hosts Langfuse's DB) |
| 2 | Qdrant | `qdrant/qdrant:v1.17.1` | vector |
| 3 | Vault | `hashicorp/vault:1.18` (`-dev` mode) | secret |
| 4 | Ollama | `ollama/ollama:0.5.4` (pulls `nomic-embed-text`) | embedding + LiteLLM upstream |
| 5 | Langfuse | `langfuse/langfuse:2` | observability |
| 6 | LiteLLM | `ghcr.io/berriai/litellm:main-stable` | gateway config source |

Redis is **off** (`cache.enabled=false` → `cache_driver=none`). No GPU; the only
real model pull is the small embedding model.

## This smoke is env-gated (operator-run)

The smoke is **NOT on the always-on CI lane** — it needs a Docker host and
`kind`, so it runs only opt-in (`COGNIC_RUN_KIND_SMOKE=1` /
`workflow_dispatch`), in the operator-pre-merge-audit style. The always-on CI
gate (`helm lint` / `template` / `kubeconform` / byte-snapshot-drift, cluster-free)
is the one that runs on every PR; this smoke is the deeper, operator-run proof.

## Prerequisites

- **docker** — a running Docker host (the script builds + loads the image).
- **kind** — the local Kubernetes cluster runner.
- **kubectl** — to apply backends, wait for Ready, and port-forward.
- **helm** — to install the chart.

## Running it

From the repo root:

```bash
bash infra/charts/agentos/ci/smoke/run-smoke.sh
```

The script (idempotent; it deletes the `kind` cluster on exit via a trap):

1. builds the `default-adapters` image and `kind load`s it;
2. creates the `kind` cluster + the `cognic-smoke` namespace;
3. applies the six backends (`ci/smoke/backends.yaml`) and waits for them to be available;
4. `helm install`s the chart with `ci/smoke-values.yaml` (prod profile, chart-created Secret, real in-cluster backend URLs);
5. waits for the AgentOS pod to reach Ready (the real `/readyz`: all five adapters `"ok"`);
6. port-forwards the Service and asserts `curl /api/v1/readyz` returns `200`.

### Expected output

The run ends with:

```
/readyz => 200
SMOKE PASS
```

`SMOKE PASS` (with a `200`) is the pass condition. Any other `/readyz` code (most
commonly `503`) fails the script.

## Troubleshooting

**A `503` from `/readyz` means at least one adapter is unhealthy.** `/readyz` is
all-or-nothing, and its JSON body **names the failing component**. To diagnose:

1. **Read the `/readyz` body** to see which component is `"unreachable"`/`"degraded"`:
   ```bash
   kubectl -n cognic-smoke port-forward svc/rel-agentos 8000:8000 &
   curl -s http://127.0.0.1:8000/api/v1/readyz | jq .
   ```
2. **`kubectl logs` the AgentOS pod** for the adapter's connection error:
   ```bash
   kubectl -n cognic-smoke logs deploy/rel-agentos
   ```
3. **Confirm all six backend pods are Ready** — a `503` is usually a backend that
   has not finished coming up (Langfuse and Ollama are the slowest):
   ```bash
   kubectl -n cognic-smoke get pods
   ```
   The named component in the `/readyz` body maps to one of the five adapter
   backends (Postgres / Qdrant / Vault / the embedding endpoint / Langfuse). If
   that backend's pod is not `Ready`, fix or wait for it and re-check; the
   readiness probe flips to `200` on its own once every adapter reports `"ok"`.

**The AgentOS pod CrashLoopBackOffs at boot** rather than going un-Ready — check
the logs for a strict-profile deploy-safety guard refusal (G1–G10). The smoke
values are pre-tuned to satisfy every guard; a refusal here usually means a
values override drifted from a guard-compliant shape (e.g. a personal
`ghcr.io/bmzee` canonical sandbox ref tripping G7, or a dev-default embedding
model name tripping G5).

**The migration hook fails** with `FATAL: COGNIC_DATABASE_URL is unset` — the
bootstrap Secret did not render the DB URL. In the smoke this is carried by
`secrets.create=true` + `databaseUrl` in `ci/smoke-values.yaml`; confirm the
Secret rendered (`kubectl -n cognic-smoke get secret`).
