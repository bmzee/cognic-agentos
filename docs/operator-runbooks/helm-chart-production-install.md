# Operator runbook — Helm chart production install

## What this covers

Installing the Sprint 14B-Z1a AgentOS Helm chart (`infra/charts/agentos/`) into a
production Kubernetes / OpenShift cluster: pre-flight, the production values that
matter, the migrations decision, `helm install` / `helm upgrade`, post-install
verification, the trust-root note, and rollback. The chart packages the real
`default-adapters` production image (`create_prod_app`) — it changes no kernel
behaviour (ADR-024).

**Z1a scope.** This is packaging core. There is **no Ingress/Route, no TLS, no
ServiceMonitor** in Z1a (those are Z1b) — reach the Service via `kubectl
port-forward` or an operator-supplied Ingress. External-secrets depth
(ESO/Vault-Agent/CSI) and AKS/cloud bring-up are also Z1b; Z1a references an
existing Secret by name.

## Pre-flight

The chart is guarded by an **always-on CI gate** in `.github/workflows/python.yml`
that runs on every PR, cluster-free — confirm it is green for the revision you
are deploying:

- **`helm lint`** + **`helm template`** (Helm v4.2.2 primary) — render correctness.
- **byte-equality snapshot-drift** vs the committed render
  (`tests/unit/infra/helm/agentos_rendered.yaml`) — catches accidental template drift.
- **`kubeconform`** (v0.8.0) — schema-validates the rendered manifests.
- a **Helm v3.16.3 compatibility lane** — proves the `apiVersion: v2` chart stays
  Helm-3-deployable (banks/OpenShift on Helm 3 install it unchanged).

These gate the chart's *shape*. The deeper end-to-end deployability proof — the
real image reaching `/readyz`=200 in Kubernetes against six real backends — is the
**env-gated `kind` Ready-smoke** (`docs/operator-runbooks/kind-smoke-deployment.md`),
operator-run, not always-on CI.

## Production values

Start from `infra/charts/agentos/values.yaml` and override the following. The
defaults are prod-safe (strict-profile boot), but several MUST be re-homed for
your environment.

### Secrets — reference an existing Secret (never chart-created in prod)

```yaml
secrets:
  create: false                       # MUST be false in production
  existingSecret: agentos-bootstrap   # an operator/ESO-managed Secret you create
```

The referenced Secret MUST carry:

- `COGNIC_DATABASE_URL` — the async Postgres DSN (e.g. `postgresql+asyncpg://…`).
- `COGNIC_VAULT_TOKEN` — the Vault token (Vault is required; see below).

`secrets.create=true` renders a chart-managed Secret and is **smoke/dev only** —
do not use it in production. If neither `secrets.create=true` nor
`secrets.existingSecret` is set, the chart **fails to render** (a `fail` in the
template) rather than installing without secrets.

### Image — re-home the repository

```yaml
image:
  repository: <your-registry>/cognic-agentos   # re-home from the default ghcr.io/bmzee/...
  tag: ""                                       # empty → defaults to Chart.AppVersion
  pullSecrets: []                               # add registry pull secrets if private
```

### Canonical sandbox images — re-home + digest-pin (G7)

The strict prod profile's G7 guard requires non-personal, digest-pinned canonical
sandbox image refs **independent of whether the sandbox is enabled**. The chart
ships `registry.example.com/...@sha256:…` placeholders; re-home them to your
re-signed canonical images:

```yaml
sandbox:
  runtimeEnabled: false                         # sandbox stays off in Z1a
  canonicalRuntimeImage: "<your-registry>/cognic-agentos/sandbox-runtime-python@sha256:<64-hex>"
  canonicalEgressProxyImage: "<your-registry>/cognic-agentos/sandbox-egress-proxy@sha256:<64-hex>"
```

These are config-only when `runtimeEnabled=false` (never pulled), but the refs
MUST be digest-pinned (`<ref>@sha256:<64-lowercase-hex>`) and non-personal or the
prod profile refuses to boot.

### Embedding model — a real, non-dev model name (G5)

```yaml
embedding:
  driver: ollama
  baseUrl: http://<ollama-endpoint>:11434
  model: nomic-embed-text                       # MUST NOT be the dev default qwen3-embedding:8b
  dimensions: 768                                # coherent with the chosen model
```

The embedding adapter probes its endpoint at readiness, so this must point at a
real, reachable Ollama (or openai-compat) endpoint serving the model.

### LiteLLM router config — provide the real config

The litellm router config is the **one boot-blocking file that is not in the
image**; the chart mounts it at `/app/infra/litellm/config.yaml`. Either render
your config inline or point at an existing ConfigMap:

```yaml
litellm:
  baseUrl: http://<litellm-endpoint>:4000
  existingConfigMap: ""                          # if set, mounted instead of rendering `config`
  config: |                                      # your real router config
    model_list:
      - model_name: cognic-tier1
        litellm_params:
          model: <your model>
          api_base: <your upstream>
    # ...
```

### Vault is required

Vault is required in Z1a — `secret_driver` defaults to `vault` with no `none`
mode, and the Vault adapter refuses a missing address. Provide both:

```yaml
vault:
  addr: http://<vault-endpoint>:8200             # COGNIC_VAULT_ADDR
```

and `COGNIC_VAULT_TOKEN` in the referenced Secret (above).

### Other commonly-set values

```yaml
qdrant:
  url: http://<qdrant-endpoint>:6333
langfuse:
  host: http://<langfuse-endpoint>:3000          # host is the only Langfuse setting required for readiness
replicaCount: 1
resources:
  requests: { cpu: 250m, memory: 512Mi }
  limits:   { cpu: "2",  memory: 2Gi }
```

On **non-OpenShift** clusters (vanilla Kubernetes has no SCC to assign an
`fsGroup`), set the image GID so the `emptyDir` mounts are writable under
`readOnlyRootFilesystem=true`:

```yaml
podSecurityContext:
  fsGroup: 10001
```

On **OpenShift** leave `podSecurityContext` empty — the SCC assigns the
`fsGroup`/UID from the namespace range (the chart's securityContext is
OpenShift-pure: no `runAsUser`, no `fsGroup`).

## The migrations decision

The kernel does **not** auto-run migrations in the lifespan — the operator owns
schema change-control. Pick one:

### Option A — chart-driven migrations (default)

```yaml
migrations:
  enabled: true                                  # default
```

The chart renders a Helm **pre-install/pre-upgrade hook Job** that runs `alembic
upgrade head` from the same image before the Deployment rolls. The Job **fails
loud if `COGNIC_DATABASE_URL` is unset** (`FATAL: … refusing to run migrations`,
`exit 1`) — never a silent success.

### Option B — out-of-band migrations (strict change-control)

```yaml
migrations:
  enabled: false                                 # NO hook Job renders
```

With `migrations.enabled=false` **no migration Job is created**. Run the
migration yourself before serving traffic, with `COGNIC_DATABASE_URL` set to the
target database:

```bash
COGNIC_DATABASE_URL="postgresql+asyncpg://<user>:<pass>@<host>:5432/<db>" alembic upgrade head
```

(Run it from the same image / a job that bundles alembic + the migrations dir, or
from a checkout of this repo with the project installed.)

## Install / upgrade

First install:

```bash
helm install agentos infra/charts/agentos \
  --namespace cognic --create-namespace \
  -f your-prod-values.yaml
```

Upgrade (re-runs the pre-upgrade migration hook when `migrations.enabled=true`):

```bash
helm upgrade agentos infra/charts/agentos \
  --namespace cognic \
  -f your-prod-values.yaml
```

## Post-install verification

1. **Wait for the pod to reach Ready** (the real `/readyz`: all five adapters
   `"ok"`):
   ```bash
   kubectl -n cognic rollout status deploy/agentos-agentos --timeout=300s
   ```
   (Release name `agentos` → resources `agentos-agentos`.)
2. **Assert `/readyz`=200:**
   ```bash
   kubectl -n cognic port-forward svc/agentos-agentos 8000:8000 &
   curl -fsS http://127.0.0.1:8000/api/v1/readyz
   ```
   A `200` means every adapter reported `"ok"`. A `503` names the failing
   component in the body — see the kind-smoke runbook's troubleshooting section.
3. **Check the pod logs** for clean boot (no deploy-safety guard refusal, no
   adapter connection error):
   ```bash
   kubectl -n cognic logs deploy/agentos-agentos
   ```

## Trust-root note (pack registration)

Reaching **Ready does not require a signing trust root** — `/readyz` does not
probe pack-registration trust. But before any plugin pack is registered, provide
the per-tenant signing trust root the trust gate verifies against
(`COGNIC_SIGNING_TRUST_ROOT_PATH`). Configure it (via the values/ConfigMap env or
a mounted file) **before** you register packs; it is **not** needed for the kernel
to come up Ready. Trust-root rotation / per-tenant allow-list changes remain
human-only decisions (per AGENTS.md).

## Rollback

Helm rollback reverts the release to a previous revision:

```bash
helm history agentos -n cognic
helm rollback agentos <REVISION> -n cognic
```

A rollback that crosses a schema change re-runs the pre-upgrade migration hook
(when `migrations.enabled=true`); alembic migrations are not auto-downgraded, so
for a rollback spanning a destructive migration, coordinate the schema state with
your change-control process before rolling back the release.
