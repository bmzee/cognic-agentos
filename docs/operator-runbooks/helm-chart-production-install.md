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

## External access (Ingress / OpenShift Route) + TLS + ServiceMonitor

> Added in **Sprint 14B-Z1b-a** (ADR-024). The Z1a chart was Service-only (reach
> it via `kubectl port-forward`). Z1b-a adds three **conditional, default-off**
> templates so you can expose the Service externally and let a cluster Prometheus
> scrape `/metrics`. All three are **opt-in** — they render nothing unless you
> enable them, so the default install is byte-unchanged. For the Route and the
> ServiceMonitor the cluster MUST have the corresponding CRD installed (the
> OpenShift `route.openshift.io` API, and the Prometheus-Operator
> `monitoring.coreos.com` API) or the manifest has nothing to apply against.
> Z1b-a is pure chart work — **no kernel change, no migration**. (The live
> cloud/ingress bring-up is Z1b-d; these templates are CI-validated by
> render/lint/kubeconform/byte-snapshot only.)

### Ingress (vanilla Kubernetes)

Enable an `Ingress` (`networking.k8s.io/v1`), set the ingress class, attach the
cert-manager (or other) annotations, and reference an **existing** TLS Secret you
(or cert-manager) provision — the chart references the Secret by name and creates
no certificate material of its own:

```yaml
ingress:
  enabled: true
  className: nginx                              # or azure-application-gateway, etc.
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: agentos.example.com
      paths:
        - { path: /, pathType: Prefix }
  tls:
    - secretName: agentos-tls                   # the TLS Secret you/cert-manager provision
      hosts: [agentos.example.com]
```

### OpenShift Route

Enable a `Route` (`route.openshift.io/v1`). TLS is **`a+b`**: the default (a)
terminates `edge` with the OpenShift router's **default/wildcard certificate** and
redirects HTTP→HTTPS — zero secret handling, no OCP-version dependency — or (b)
you supply inline PEM material:

```yaml
# (a) default — edge TLS, router default cert, HTTP→HTTPS redirect:
route:
  enabled: true
  host: agentos.example.com
  annotations:
    haproxy.router.openshift.io/timeout: 60s
  tls:
    enabled: true
    termination: edge                           # edge | passthrough | reencrypt
    insecureEdgeTerminationPolicy: Redirect
```

```yaml
# (b) optional — serve an explicit certificate (inline PEM):
route:
  enabled: true
  host: agentos.example.com
  tls:
    enabled: true
    termination: edge
    certificate: |
      -----BEGIN CERTIFICATE-----
      ...
    key: |
      -----BEGIN PRIVATE KEY-----
      ...
    caCertificate: |                            # optional
      -----BEGIN CERTIFICATE-----
      ...
```

The `tls.externalCertificate` Secret-reference form (OCP ≥ 4.16, feature-gated +
router RBAC) is a documented **later option** and is **not** wired in Z1b-a.

> **CI note — Route CRD schema.** The Route still **renders + lints** and is
> byte-snapshotted in CI, but its CRD schema is absent from the public
> `datreeio/CRDs-catalog`, so the CI `kubeconform` step uses a scoped
> **`-skip Route`** (only Route's schema validation is skipped — the
> ServiceMonitor and all core kinds stay schema-validated). Validate the Route
> against your cluster's real `route.openshift.io` CRD with a `--dry-run=server`
> apply if you want a schema check before rollout.

### ServiceMonitor (Prometheus Operator)

Enable a `ServiceMonitor` (`monitoring.coreos.com/v1`) so a cluster Prometheus
discovers + scrapes the existing `/metrics` surface. The scrape path is
`{apiPrefix}{serviceMonitor.path}` → **`/api/v1/metrics`**. The crucial value is
the discovery **`release` label** — it MUST match the label your cluster
Prometheus selects ServiceMonitors by (for the kube-prometheus-stack the default
is its release name):

```yaml
serviceMonitor:
  enabled: true
  path: /metrics                                # joined with apiPrefix → /api/v1/metrics
  interval: 30s
  scrapeTimeout: 10s
  labels:
    release: kube-prometheus-stack              # MUST match your Prometheus's serviceMonitorSelector
```

The ServiceMonitor's selector targets the chart Service via the **stable**
name+instance labels (it does not pin the chart version), so it keeps matching
across chart upgrades. If Prometheus is not discovering the target, the usual
cause is a `serviceMonitor.labels.release` value that does not match the
cluster Prometheus's `serviceMonitorSelector`.

## External secrets (ESO)

> Added in **Sprint 14B-Z1b-b** (ADR-024). Instead of pre-creating the bootstrap
> Secret yourself (`secrets.existingSecret`), you can have the
> [External Secrets Operator (ESO)](https://external-secrets.io) materialise it
> from an external store (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault,
> …). The chart renders a conditional, default-off `ExternalSecret`
> (`external-secrets.io/v1`) that populates the **same** 2-key bootstrap Secret
> the kernel reads. Like the rest of Z1b this is pure chart work — **no kernel
> change, no migration**. (The live cluster/ESO exercise is Z1b-d; the template is
> CI-validated by render/lint/kubeconform/byte-snapshot only.)

**Prerequisite — ESO must be installed in the cluster.** The `ExternalSecret` is
a custom resource of the `external-secrets.io` API. Install ESO (the
`external-secrets.io` CRDs + controller) **before** enabling this, or the manifest
has nothing to reconcile against.

**The chart never creates the store.** You provision the `SecretStore` (namespaced)
or `ClusterSecretStore` (cluster-wide) yourself — it carries the store address +
the auth that lets ESO read from your external secret manager. `externalSecrets`
references it by name only.

### The three-mode secret source (mutually exclusive)

The chart now has **three** ways to wire the bootstrap Secret, and you must
configure **exactly one** — the render `fail`s (and `helm lint` rejects the values
against the schema) if more than one is set:

- `secrets.create: true` — chart-managed Secret (**smoke/dev only**).
- `secrets.existingSecret: <name>` — an operator/ESO-managed Secret you provision.
- `externalSecrets.enabled: true` — the ESO `ExternalSecret` materialises the Secret.

When `externalSecrets.enabled=true`, set `secrets.create=false` and leave
`secrets.existingSecret` empty (ESO mode is legitimately `create=false` + empty
`existingSecret` — the Secret is materialised by ESO).

### The two remote refs (fixed keys)

The `ExternalSecret` writes exactly the two bootstrap keys the kernel reads —
`COGNIC_DATABASE_URL` and `COGNIC_VAULT_TOKEN` — mapping each from a remote key in
your store (`remoteRef.key`; `property` optional). There is no arbitrary-extra-key
surface; only these two are populated.

```yaml
secrets:
  create: false                               # exactly one source — ESO here
externalSecrets:
  enabled: true
  targetSecretName: ""                        # default <fullname>-secrets
  refreshInterval: 1h
  secretStoreRef:
    name: agentos-secret-store                # the SecretStore/ClusterSecretStore YOU created (REQUIRED)
    kind: SecretStore                         # SecretStore | ClusterSecretStore
  data:
    databaseUrl:
      remoteRef:
        key: agentos/database-url             # remote key holding COGNIC_DATABASE_URL (REQUIRED)
        property: ""                          # optional — property within the remote secret
    vaultToken:
      remoteRef:
        key: agentos/vault-token              # remote key holding COGNIC_VAULT_TOKEN (REQUIRED)
        property: ""                          # optional
```

### Primary worked example — Azure Key Vault + AKS workload identity

This aligns with the Z1b-d AKS bring-up. ESO authenticates to Azure Key Vault via
the AKS workload-identity federation (no static credential in the cluster). Create
the store once, then point the chart at it:

```yaml
# SecretStore (provision yourself — the chart never creates it):
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: agentos-secret-store
  namespace: cognic
spec:
  provider:
    azurekv:
      authType: WorkloadIdentity
      vaultUrl: https://agentos-kv.vault.azure.net
      serviceAccountRef:
        name: agentos-agentos                 # the chart SA, wired for workload identity via chart values (see "Cloud workload identity" below)
```

```yaml
# chart values (your-prod-values.yaml):
secrets:
  create: false
externalSecrets:
  enabled: true
  secretStoreRef:
    name: agentos-secret-store
    kind: SecretStore
  data:
    databaseUrl:
      remoteRef: { key: cognic-database-url }   # the Key Vault secret names
    vaultToken:
      remoteRef: { key: cognic-vault-token }
```

The chart SA (`<release>-agentos`) is wired for AKS workload identity **through
chart values** — set `serviceAccount.annotations` (+ the Azure `podLabels`) per the
"Cloud workload identity" section below, so `helm upgrade` keeps the annotation
(NOT a `kubectl annotate` out-of-band, which `helm upgrade` would clobber). The
chart itself grants no cluster RBAC.

### Secondary notes — AWS Secrets Manager / HashiCorp Vault

The same `ExternalSecret` shape works against any ESO provider — only the
operator-owned `SecretStore` changes:

- **AWS Secrets Manager** — a `SecretStore` with `provider.aws` (`service:
  SecretsManager`, region, IRSA via the SA). The two `remoteRef.key`s are the
  Secrets Manager secret names; use `property` to pick a JSON field if the secret
  is a JSON blob.
- **HashiCorp Vault** — a `SecretStore` with `provider.vault` (server address,
  KV mount path, auth — e.g. Kubernetes auth). The two `remoteRef.key`s are the
  KV paths; `property` selects the field within the KV secret.

## OTLP exporter (gRPC/HTTP) + Langfuse OTLP ingestion

> Added in **Sprint 14B-Z1b-c** (ADR-024). The kernel emits a value-free
> `llm.gateway.completion` OTel span on every completion. By default the exporter
> ships over **gRPC**; Z1b-c adds an **OTLP/HTTP + headers** transport so a
> self-hosted Langfuse (or any OTLP/HTTP collector) can ingest spans turnkey. The
> kernel stays **Langfuse-agnostic** — it knows only `grpc`/`http` + endpoint +
> headers; the Langfuse URL convention and the Basic-auth header live here in the
> chart values + your operator-owned Secret.

### The generic knobs

Spans only export when an endpoint is set (the otel ConfigMap keys are
**endpoint-gated**, so leaving `otel.exporter.endpoint` empty leaves the default
install byte-unchanged — there is no console/no-op span shipping).

- `otel.exporter.endpoint` — the OTLP collector endpoint (`COGNIC_OTEL_EXPORTER_ENDPOINT`). Empty ⇒ no export.
- `otel.exporter.protocol` — `grpc` (default) or `http`.
- `otel.exporter.insecure` — **gRPC-only** (skip TLS on the gRPC channel). On the `http` path security is the **endpoint URL scheme** (`https://…`); `insecure` is ignored for http.
- `otel.exporter.headersSecretKey` — optional; a **key in your operator-owned Secret** holding `COGNIC_OTEL_EXPORTER_HEADERS` (see the secret-safe boundary below).

The mTLS file-path settings (CA / client cert / client key) are reused on the
`http` path as the exporter's `certificate_file` / `client_certificate_file` /
`client_key_file`; headers thread into **both** the gRPC and the HTTP exporter.

### Langfuse turnkey (OTLP/HTTP) — worked example

Point the kernel at Langfuse's OTLP endpoint over HTTP and supply the Langfuse
Basic-auth header via the Secret (NOT the ConfigMap — see below):

```yaml
otel:
  exporter:
    endpoint: https://langfuse.example.com/api/public/otel/v1/traces  # {langfuse_host}/api/public/otel/v1/traces
    protocol: http
    headersSecretKey: COGNIC_OTEL_EXPORTER_HEADERS                     # a key in your existing Secret
secrets:
  create: false                                                       # header is NOT valid with create=true
  existingSecret: agentos-secrets                                     # the Secret YOU populate (or ESO)
```

Then put the header JSON into that operator-owned Secret under the
`COGNIC_OTEL_EXPORTER_HEADERS` key — the value is the Langfuse Basic-auth pair
plus the recommended ingestion-version header:

```json
{"Authorization":"Basic <base64(public_key:secret_key)>","x-langfuse-ingestion-version":"4"}
```

`x-langfuse-ingestion-version: "4"` is **Langfuse's recommended real-time
ingestion header** (per the Langfuse OTel docs). Base64-encode the
`public_key:secret_key` pair from your Langfuse project for the `Authorization`
value.

### The secret-safe boundary (critical)

The Basic-auth header is **sensitive** — it MUST go in the **Secret**, never the
ConfigMap. The chart projects it from your Secret via a `secretKeyRef`
(`COGNIC_OTEL_EXPORTER_HEADERS` ← the key named by `headersSecretKey`), into the
**same** Secret the bootstrap keys live in (`agentos.secretName`). The non-secret
endpoint/protocol/insecure values DO ride the ConfigMap.

**`secrets.create=true` is NOT compatible with `headersSecretKey`.** A
chart-created Secret carries only the two bootstrap keys (`COGNIC_DATABASE_URL` +
`COGNIC_VAULT_TOKEN`) — it has no header key for the `secretKeyRef` to resolve, so
the pod would fail to start. Use **`secrets.existingSecret`** (populate the extra
`COGNIC_OTEL_EXPORTER_HEADERS` key yourself) or an **ESO `ExternalSecret`**
(materialise that key from your store). The `otel-http` CI snapshot scenario
exercises exactly this `secrets.create:false` + `existingSecret` mode.

> **Two distinct proofs.** Z1b-c ships the exporter primitive + this chart wiring
> + a **standalone env-gated Langfuse ingestion proof** (`COGNIC_RUN_LANGFUSE_OTEL=1`;
> it exports a span over OTLP/HTTP and reads it back via the Langfuse SDK — a
> capability proof, operator-run, never always-on CI, no production Langfuse
> claimed running). The **live cloud/cluster exercise** (AKS + the chart path
> in-cluster, including ServiceMonitor → Prometheus) is **Z1b-d**.

## Cloud workload identity

> Added in **Sprint 14B-Z1b-d-1** (ADR-024). The chart's ServiceAccount can
> federate to any cloud's IAM identity so the pod gets cloud credentials with **no
> static secret in the cluster**. The chart exposes **two generic, cloud-agnostic
> hooks** — it knows nothing about Azure/GKE/AWS; you pass the cloud's annotation
> (and, where required, pod label) through these maps. The **chart never creates
> the cloud IAM identity** — you provision the cloud-side identity + the federation
> (the trust between the cluster's OIDC issuer and the cloud identity) out-of-band,
> then wire the SA through these hooks. Z1b-d-1 is pure chart work — **no kernel
> change, no migration**. (The live cluster exercise — an actual AKS deploy with
> cloud-identity federation wired end-to-end — is **Z1b-d-2**, not this slice.)

### The two generic hooks

- `serviceAccount.annotations` — a map projected onto the chart ServiceAccount's
  `metadata.annotations`. This carries the cloud's workload-identity SA annotation.
- `podLabels` — a map merged into the Deployment's pod **template** labels only
  (`.spec.template.metadata.labels`), **never** the Deployment selector (the
  selector is immutable; mutating it would break `helm upgrade`). This carries the
  cloud's workload-identity pod label where one is required.

Both default to empty maps and render nothing when unset, so leaving them out
keeps the default install byte-unchanged.

### Azure workload identity (AKS)

Azure workload identity needs **both** a SA annotation (the client ID) **and** a
pod label (`azure.workload.identity/use: "true"`):

```yaml
serviceAccount:
  annotations:
    azure.workload.identity/client-id: <azure-managed-identity-client-id>
podLabels:
  azure.workload.identity/use: "true"
```

Provision the Azure side out-of-band: a user-assigned managed identity, a
federated-identity credential trusting the AKS cluster's OIDC issuer for the chart
SA (`<release>-agentos` in the install namespace), and the Azure RBAC the workload
needs (e.g. Key Vault access for ESO — see the External secrets section above).

### GKE workload identity

GKE workload identity needs **only** a SA annotation (the Google service-account
email); **no pod label**:

```yaml
serviceAccount:
  annotations:
    iam.gke.io/gcp-service-account: <gsa-name>@<project>.iam.gserviceaccount.com
```

Provision the GCP side out-of-band: the Google service account, the IAM
`workloadIdentityUser` binding tying the chart's Kubernetes SA
(`<release>-agentos`) to that GSA, and the GCP roles the workload needs.

### AWS IRSA (EKS)

AWS IAM Roles for Service Accounts (IRSA) needs **only** a SA annotation (the IAM
role ARN); **no pod label**:

```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::<account-id>:role/<role-name>
```

Provision the AWS side out-of-band: the IAM role with a trust policy for the EKS
cluster's OIDC provider scoped to the chart SA (`<release>-agentos`), and the IAM
policies the workload needs.

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
