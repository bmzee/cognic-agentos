# Sprint 14B-Z1b-d-2 — AKS live-cloud capstone (Bicep IaC + env-gated WI/ESO-from-Key-Vault smoke + 8th all-surfaces render) — Design

**Date:** 2026-06-19
**Status:** DRAFT — design approved in brainstorming (2026-06-18 → 2026-06-19); awaiting spec review before planning.
**ADRs:** amends **ADR-024** (Deployment Substrate / Helm Packaging).

## Context

Sprint 14B-Z1b decomposed into four sub-slices; the fourth (Z1b-d, the capstone) was **split at recon** into **Z1b-d-1 — generic chart workload-identity readiness** (MERGED @ `57f3771`, PR #84 — `serviceAccount.annotations` + `podLabels`, pure chart/docs, fully in-session-verifiable) and **Z1b-d-2 — AKS bring-up + env-gated live cloud smoke** (this; the separate operator-run capstone + the live cluster proof). The other Z1b slices are MERGED: **Z1b-a** external access (Ingress/Route/ServiceMonitor + TLS), **Z1b-b** external secrets (ESO `ExternalSecret`, fixed 2-key contract), **Z1b-c** OTLP exporter (grpc/http + headers).

**Z1b-d-2 is the final piece of the whole 14B Deployment Substrate.** After it, the substrate (Z1a + Z1b-a/b/c/d-1/d-2) is complete: an operator can stand up AgentOS on a real cloud Kubernetes (AKS) and exercise every Z1b surface — external access, ESO-from-cloud-secret-store, OTLP export, and cloud workload identity — against the Z1a Ready footprint.

**Recon verdict (from source, 2026-06-18 → 2026-06-19):**
- **No AKS / cloud IaC exists today.** The only deployment-exercise precedent is the env-gated **kind Ready-smoke** at `infra/charts/agentos/ci/smoke/run-smoke.sh` + `infra/charts/agentos/ci/smoke/backends.yaml` + `infra/charts/agentos/ci/smoke-values.yaml`, surfaced by the env-gated `kind-smoke` CI job (skips on PR). Z1b-d-2's AKS smoke **mirrors that pattern**: a standalone, operator-run script that brings up in-cluster backends, installs the chart, and asserts `/readyz=200`.
- **The chart already supports every surface the smoke needs.** ESO mode (`externalSecrets.enabled`) renders the `Owner`, fixed 2-key `ExternalSecret` (`templates/externalsecret.yaml`); the OTLP-header env (`COGNIC_OTEL_EXPORTER_HEADERS`) references `agentos.secretName` (= the ESO target Secret in ESO mode, per `templates/deployment.yaml:60-65` + `_helpers.tpl:38-46`); the chart SA carries `serviceAccount.annotations` + the pod template carries `podLabels` (Z1b-d-1). **No chart change is required** — the chart is already cloud-WI-ready and ESO-ready.
- **The secret-source contract is a strict 3-way XOR** (`agentos.validateSecretSource` Helm `fail` + the root `values.schema.json` `allOf`): exactly one of `secrets.create` / `secrets.existingSecret` / `externalSecrets.enabled`. The OTLP header passthrough (`otel.exporter.headersSecretKey`) is **incompatible with `secrets.create=true`** (the chart-created 2-key Secret would lack the header key) — it requires `existingSecret` **or** ESO mode.
- **Local tooling:** `kubectl`, `helm` (v4.2.2), `kubeconform` are present. **`az`, `bicep`, `terraform`, `shellcheck` are absent** — so the Bicep build + the live smoke are **operator/CI-run, not in-session-runnable**. The one in-session-provable unit is a new **8th "all-surfaces" render scenario** in the always-on `helm-chart` CI gate.

## Goal

Ship the **live-cloud capstone of 14B**: a minimal, cloud-agnostic-where-possible **Bicep reference IaC** that stands up an AKS cluster with OIDC + workload identity, a User-Assigned Managed Identity (UAMI), an **empty** Key Vault, and the federation linking the chart's ServiceAccount to the UAMI; plus a standalone, operator-run **smoke script** that installs ESO, brings up the in-cluster backends, seeds Key Vault, installs the chart with WI + ESO + OTLP all on, and asserts the AgentOS pod reaches Ready. The one always-on in-session/CI proof is an **8th all-surfaces render** showing every accumulated Z1b conditional surface composes in a single `helm template`.

## Non-goals (guards — user-locked)

- **No AKS CI job.** GitHub→Azure OIDC, service-principal secrets, subscription/tenant IDs, and Key Vault write permissions are **bank/operator territory**, not a reusable kernel-repo CI lane. The Bicep + smoke are operator-run; **only the 8th render is always-on CI**. This is documented as a deliberate security posture, not an omission.
- **No chart change.** The chart is already WI-ready (Z1b-d-1) + ESO-ready (Z1b-b) + OTLP-ready (Z1b-c). Z1b-d-2 adds the 8th **render overlay** + the **operator-run IaC/smoke** + docs. **CC stays 131; no kernel change; no migration; no new on-gate module.** The only Python is the 8th snapshot-test parametrization.
- **Chart `ExternalSecret` stays fixed 2-key.** The OTLP header is carried by a **smoke-only auxiliary `ExternalSecret` (`creationPolicy: Merge`)**, NOT by widening the chart's deliberate Z1b-b 2-key bootstrap contract. Extending the chart `ExternalSecret` to take optional extra keys is **rejected** (it weakens the bootstrap contract).
- **Bicep is minimal reference IaC.** Production hardening (private cluster, custom VNet, Log Analytics, Azure Policy, node-pool tuning) stays **bank-overlay** territory — named in the runbook, not modeled in the reference Bicep. A bank standardized on Terraform re-authors in its overlay (mirroring the Helm-only / Kustomize-via-overlay boundary).
- **Selector stability preserved.** The all-surfaces render turns `podLabels` on, so it **re-pins** the Z1b-d-1 invariant: `podLabels` land in `.spec.template.metadata.labels` ONLY, never `.spec.selector.matchLabels`.
- **Default render + the 7 existing snapshots stay byte-unchanged.** The 8th scenario is purely additive (a new overlay + a new committed snapshot).
- **`-skip Route` remains the only scoped kubeconform skip.** The all-surfaces overlay enables Route (whose CRD schema is genuinely absent from the catalog); Ingress / ServiceMonitor / ExternalSecret stay schema-validated.

## Design

### 1. The 8th all-surfaces render scenario (the in-session/CI-provable unit)

A **dedicated** overlay `infra/charts/agentos/ci/snapshot-values-all-surfaces.yaml` that turns on **every** Z1b conditional surface in one render — Ingress + Route + ServiceMonitor + ESO + OTLP-http + workload-identity (SA annotation + pod label):

```yaml
# All-surfaces composition overlay (layered over ci/snapshot-values.yaml).
# DEDICATED, not a stack of the per-surface overlays: the `externalsecret` overlay (ESO mode)
# and the `otel-http` overlay (existingSecret mode) carry MUTUALLY-EXCLUSIVE secret sources, so
# they cannot co-layer. This overlay resolves to a single coherent secret source — ESO mode —
# then adds headersSecretKey on top (schema allows ESO + headersSecretKey; it forbids ESO+create
# and ESO+existingSecret). The 3rd Secret key is the live smoke's auxiliary-Merge concern; at
# render time `helm template` emits the secretKeyRef without checking the key exists.
secrets:
  create: false
externalSecrets:
  enabled: true
  refreshInterval: 1h
  secretStoreRef:
    name: agentos-secret-store
    kind: SecretStore
  data:
    databaseUrl:
      remoteRef:
        key: agentos/database-url       # generic SecretStore key form (cloud-agnostic render)
    vaultToken:
      remoteRef:
        key: agentos/vault-token
otel:
  exporter:
    endpoint: https://langfuse.example.com/api/public/otel/v1/traces
    protocol: http
    insecure: false
    headersSecretKey: COGNIC_OTEL_EXPORTER_HEADERS
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: agentos.example.com
      paths:
        - { path: /, pathType: Prefix }
  tls:
    - { secretName: agentos-tls, hosts: [agentos.example.com] }
route:
  enabled: true
  host: agentos.example.com
  tls:
    enabled: true
    termination: edge
    insecureEdgeTerminationPolicy: Redirect
serviceMonitor:
  enabled: true
  labels:
    release: kube-prometheus-stack
serviceAccount:
  annotations:
    azure.workload.identity/client-id: 00000000-0000-0000-0000-000000000000
podLabels:
  azure.workload.identity/use: "true"
```

**Why dedicated, not stacked (watchpoint 1):** the existing `externalsecret` overlay sets ESO mode (`create:false` + `externalSecrets.enabled:true`); the existing `otel-http` overlay sets `existingSecret` mode. Layering them trips the schema's mutual-exclusion `allOf` (ESO + existingSecret). The all-surfaces overlay therefore picks **one** coherent source (ESO) and threads the header via `headersSecretKey` — which the schema permits with ESO. The chart's `ExternalSecret` renders its fixed 2 keys; the Deployment renders a `secretKeyRef` to the 3rd key (`agentos.secretName` = the same ESO target Secret); `helm template` does not validate the key exists, so the render proves **composition**. The live population of the 3rd key is the smoke's job (§3).

The committed snapshot `tests/unit/infra/helm/agentos_rendered_all-surfaces.yaml` shows, in one document: the ESO `ExternalSecret` (2 keys), the Deployment with the OTLP-header `secretKeyRef` + the WI pod label in `.spec.template.metadata.labels` (and **absent** from `.spec.selector.matchLabels` — selector stability re-pinned), the WI-annotated ServiceAccount, the Ingress, the Route, and the ServiceMonitor. Validation: kubeconform Valid for all kinds except Route (skipped — schema absent). The pytest `_SCENARIOS` list (`tests/unit/infra/test_helm_chart.py`) grows 7 → 8; the `helm-chart` CI job's two loops (Helm-4 primary byte-diff + kubeconform; Helm-3 compat render + kubeconform) grow 7 → 8, `-skip Route` unchanged.

### 2. Bicep reference IaC (operator/CI-run — `infra/azure/aks-smoke/main.bicep`)

A minimal Azure-native reference that provisions the cloud-managed surfaces the live proof needs (and **only** those). Resources:

1. **AKS managed cluster** (`Microsoft.ContainerService/managedClusters`) with `oidcIssuerProfile.enabled: true` + `securityProfile.workloadIdentity.enabled: true`, a single system node pool (`nodeCount`, `nodeVmSize`), `kubernetesVersion` optional (omit → AKS default), `dnsPrefix` derived from `uniqueString(resourceGroup().id)` for global uniqueness, system-assigned identity.
2. **UAMI** (`Microsoft.ManagedIdentity/userAssignedIdentities`) — the workload identity the chart SA federates to.
3. **Key Vault** (`Microsoft.KeyVault/vaults`), **empty** (Bicep provisions NO secrets — the smoke seeds them), `enableRbacAuthorization: true`, name from `uniqueString(...)` (global-DNS-unique).
4. **Federated identity credential** (`...userAssignedIdentities/federatedIdentityCredentials`) — links the UAMI to the AKS OIDC issuer with subject `system:serviceaccount:<agentosNamespace>:<agentosServiceAccountName>` (the chart's ServiceAccount; default `rel-agentos`, the smoke's release name `rel` × chart name `agentos`). The subject is **namespace-scoped**, so the smoke's `AGENTOS_NAMESPACE` MUST equal this `agentosNamespace` exactly (§3).
5. **Role assignments** (both on the Key Vault scope): UAMI → **Key Vault Secrets User** (read — so ESO, impersonating the chart SA federated to the UAMI, reads the seeded secrets); `smokeRunnerObjectId` → **Key Vault Secrets Officer** (write — so the operator running the smoke can seed the 3 secrets).

**Outputs:** AKS cluster name, resource-group name, Key Vault name, UAMI `clientId`, the OIDC issuer URL (for reference). The smoke reads these via `az deployment group show`.

**Minimal params:** `location`, `resourcePrefix`, `kubernetesVersion` (optional, default `''` → AKS default), `nodeCount`, `nodeVmSize`, `agentosNamespace`, `agentosServiceAccountName`, `smokeRunnerObjectId`. Production hardening is bank-overlay (runbook note).

**In-session provability:** `az`/`bicep` are absent locally, so the Bicep **cannot be built in-session**. The spec/plan author validates structure by review; the operator/CI runs `az bicep build --file infra/azure/aks-smoke/main.bicep` (documented in the runbook). This is honestly marked — the IaC is authored, not in-session-compiled.

### 3. The live smoke (operator-run — `infra/azure/aks-smoke/run-aks-smoke.sh`)

Mirrors `ci/smoke/run-smoke.sh`. Preconditions: `az login`; the Bicep deployed; the Bicep outputs available (read via `az deployment group show` or passed as env). Steps:

**Namespace pinning (P1).** Define `AGENTOS_NAMESPACE` from the Bicep output / env (default `cognic-smoke`, mirroring the kind smoke) and create it idempotently (`kubectl get namespace "$AGENTOS_NAMESPACE" >/dev/null 2>&1 || kubectl create namespace "$AGENTOS_NAMESPACE"`). **`AGENTOS_NAMESPACE` MUST equal the Bicep `agentosNamespace` param exactly** — the federated credential subject is `system:serviceaccount:$AGENTOS_NAMESPACE:rel-agentos`, so a mismatch makes the SA-token → UAMI token exchange fail and ESO/WI never resolves the secret. Every AgentOS-scoped `kubectl`/`helm` command below runs with `-n "$AGENTOS_NAMESPACE"`; only the ESO controller install (step 2) uses its own `external-secrets` namespace.

1. `az aks get-credentials` → kubeconfig for the deployed cluster.
2. **Install ESO** via Helm (`helm repo add external-secrets … && helm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace`) — the ESO controller is cluster-wide, in its **own** `external-secrets` namespace (NOT `$AGENTOS_NAMESPACE`); self-contained (reproducible; the runbook notes production clusters often pre-install ESO).
3. **Bring up the in-cluster backends** — `kubectl apply -n "$AGENTOS_NAMESPACE" -f infra/charts/agentos/ci/smoke/backends.yaml` (reused verbatim — **Key Vault is the only Azure-managed surface**; postgres/qdrant/vault/ollama/langfuse/litellm stay in-cluster) + `kubectl -n "$AGENTOS_NAMESPACE" wait --for=condition=available --timeout=300s deploy --all`.
4. **Apply the SecretStore** (`kubectl apply -n "$AGENTOS_NAMESPACE" -f infra/azure/aks-smoke/secretstore.yaml`) — a namespaced `SecretStore` in `$AGENTOS_NAMESPACE` (same namespace as the chart's `ExternalSecret` that references it); `provider.azurekv` with `authType: WorkloadIdentity` + `serviceAccountRef` pointing at the **chart's ServiceAccount** (`rel-agentos`, WI-annotated via the chart's `serviceAccount.annotations`). ESO mints a token for that SA via the TokenRequest API and exchanges it (through the federated credential) for a UAMI token to read Key Vault — independent of the SA's `automountServiceAccountToken: false` and independent of any running pod's projected token. *(Operator-verified mechanism: the exact `serviceAccountRef` + `authType: WorkloadIdentity` behavior is ESO-version-dependent; the runbook flags the operator-validated ESO version — no specific version is invented here.)*
5. **Seed Key Vault** with **3** secrets via `az keyvault secret set` — Azure-KV-compatible names (**no slashes**): `agentos-database-url` = `postgresql+asyncpg://cognic:cognic@postgres:5432/cognic` (in-cluster DNS), `agentos-vault-token` = `smoke-root-token`, `agentos-otel-headers` = the OTLP Basic-auth headers JSON.
6. **Apply the auxiliary Merge `ExternalSecret`** (`kubectl apply -n "$AGENTOS_NAMESPACE" -f infra/azure/aks-smoke/externalsecret-otel-headers.yaml`) — a **smoke-only** `ExternalSecret`, distinct name (`agentos-otel-headers`), `creationPolicy: Merge`, `target.name` = the chart's resolved Secret (`rel-agentos-secrets`), one key `COGNIC_OTEL_EXPORTER_HEADERS` from KV `agentos-otel-headers`. This is the **only** thing that carries the OTLP header into the chart-owned Secret without touching the chart's fixed 2-key `ExternalSecret`.
7. **`helm install` AgentOS** with ESO on + WI on + OTLP on:
   - `externalSecrets.enabled=true`, `externalSecrets.secretStoreRef.name=agentos-secret-store`, `externalSecrets.data.databaseUrl.remoteRef.key=agentos-database-url`, `externalSecrets.data.vaultToken.remoteRef.key=agentos-vault-token` (the **no-slash** Azure KV names — divergent from the generic slash form in the §1 render overlay, which is cloud-agnostic);
   - `serviceAccount.annotations."azure\.workload\.identity/client-id"=<UAMI clientId>` + `podLabels."azure\.workload\.identity/use"="true"` (`--set-string`, per the Z1b-d-1 label-coercion lesson);
   - `otel.exporter.endpoint=<langfuse OTLP>`, `otel.exporter.protocol=http`, `otel.exporter.headersSecretKey=COGNIC_OTEL_EXPORTER_HEADERS`;
   - the in-cluster backend URLs (mirroring `ci/smoke-values.yaml`), **`migrations.enabled=false`**, `secrets.create=false`, release name `rel`, `-n "$AGENTOS_NAMESPACE"`. Install **without `--wait`** (the Deployment is not Ready until migrations run in step 9).

   **Why migrations off + a post-gate Job (P1 ordering fix):** the chart's migration Job is a Helm `pre-install` hook (`templates/migration-job.yaml:9`, weight `-5`) whose pod mounts `COGNIC_DATABASE_URL` from `rel-agentos-secrets`, but the chart `ExternalSecret` is a **normal** resource. Helm runs pre-install hooks **before** normal resources, so in ESO mode the hook would reference `rel-agentos-secrets` before ESO can create it — a deadlock (the hook needs the secret; the secret needs the install to clear the hook) that stalls/fails the install **before** the 3-key gate ever runs. The smoke therefore installs with the hook **off** and runs migrations as a smoke-owned **non-hook** Job **after** the secret exists. (The §1 all-surfaces render keeps the migration Job on — it proves template *composition*; this runtime hook-ordering constraint is a smoke-only concern.)
8. **Fail-loud 3-key wait gate (watchpoint 3)** — BEFORE migrating, poll `kubectl get secret -n "$AGENTOS_NAMESPACE" rel-agentos-secrets` until it carries **all three** of `COGNIC_DATABASE_URL`, `COGNIC_VAULT_TOKEN`, `COGNIC_OTEL_EXPORTER_HEADERS` (or **two**, if the OTLP leg is dropped per §4). Timeout → **loud failure** (`echo "FAIL: secret missing keys …"; exit 1`), never a silent pass. This is the gate that catches an ESO `Owner`/`Merge` field-ownership conflict (watchpoint 4).
9. **Run the smoke-owned migration Job** — `kubectl apply -n "$AGENTOS_NAMESPACE" -f infra/azure/aks-smoke/migrate-job.yaml` (a **plain** Job — no Helm hook annotations — mirroring the chart hook Job's `alembic upgrade head` command + the `COGNIC_DATABASE_URL` `secretKeyRef` to `rel-agentos-secrets`; the smoke injects the AgentOS image it passed to `helm install`) + `kubectl -n "$AGENTOS_NAMESPACE" wait --for=condition=complete job/agentos-migrate --timeout=300s`. Runs only after step 8, so the secret it mounts is guaranteed present.
10. **Roll the Deployment** — `kubectl -n "$AGENTOS_NAMESPACE" rollout restart deploy/rel-agentos` so fresh pods re-evaluate readiness against the now-migrated schema (deterministic whether the app boots-but-unready or crash-loops pre-migration).
11. **Assert Ready** — `kubectl -n "$AGENTOS_NAMESPACE" rollout status deploy/rel-agentos` + `kubectl -n "$AGENTOS_NAMESPACE" wait --for=condition=ready pod -l app.kubernetes.io/name=agentos` + a port-forward (`kubectl -n "$AGENTOS_NAMESPACE" port-forward svc/rel-agentos 8000:8000`) → `/api/v1/readyz` = `200` (mirrors the kind smoke).

The smoke **does not delete the AKS cluster** (the Bicep owns it; the smoke is rerunnable without recreate). The runbook documents Azure teardown (`az group delete`). `shellcheck` is absent locally → the script is authored + reviewed; the operator/CI runs `shellcheck` (runbook note).

### 4. The auxiliary Merge ExternalSecret + the Owner/Merge risk (watchpoints 2 + 4)

```yaml
# infra/azure/aks-smoke/externalsecret-otel-headers.yaml — SMOKE-ONLY.
# Carries COGNIC_OTEL_EXPORTER_HEADERS into the chart-owned Secret WITHOUT widening the chart's
# fixed 2-key ExternalSecret (the deliberate Z1b-b bootstrap contract). creationPolicy: Merge.
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: agentos-otel-headers          # distinct from the chart's <fullname> ExternalSecret
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: agentos-secret-store        # the same SecretStore the chart uses
    kind: SecretStore
  target:
    name: rel-agentos-secrets         # the SAME Secret the chart's Owner ExternalSecret manages
    creationPolicy: Merge
  data:
    - secretKey: COGNIC_OTEL_EXPORTER_HEADERS
      remoteRef:
        key: agentos-otel-headers     # the Key Vault secret holding the OTLP Basic-auth JSON
```

**The risk (operator-verified):** the chart's `ExternalSecret` is `creationPolicy: Owner` over `rel-agentos-secrets`; this auxiliary is `creationPolicy: Merge` over the same Secret. Whether the two coexist cleanly — newer ESO uses server-side-apply field managers so each `ExternalSecret` owns only its own keys; older ESO may have the `Owner` reconcile strip the `Merge`d key — **is ESO-version-dependent**. The spec bakes in three mitigations:
1. The **fail-loud 3-key wait gate** (§3 step 8) — a strip surfaces as a loud timeout, never a silent pass.
2. A **runbook note** documenting the Owner/Merge coexistence caveat + the operator-validated ESO version (named by the operator at validation time — none is invented here).
3. **Graceful degradation (watchpoint 4):** the OTLP header leg is the **one degradable surface** — if `Owner`/`Merge` proves flaky on the operator's ESO version, they drop the OTLP leg (omit the auxiliary `ExternalSecret` + `headersSecretKey`). **WI + ESO-from-Key-Vault + Ready is the primary live proof**; the OTLP composition is already proven by the §1 always-on render, so dropping the live OTLP leg does not weaken the capstone's core claim.

### 5. Proof boundary (honesty framing)

- **In-session / always-on CI (T1):** the 8th all-surfaces render — Helm-4.2.2 byte-snapshot + kubeconform (both `helm-chart` lanes). Proves every accumulated Z1b conditional surface composes in one `helm template`.
- **Operator-run (T2 + T3):** `az bicep build` of the reference IaC; the live AKS smoke (WI + ESO-from-Key-Vault + Ready, + the auxiliary-Merge OTLP header). **Not runnable in-session** (no Azure creds; `az`/`bicep`/`shellcheck` absent). Authored + documented; the operator runs them per the runbook. The same posture as the Z1a kind Ready-smoke + the Z2/Z3/Z4 env-gated proofs.
- **Out of scope here:** the live **Langfuse OTLP ingestion read-back** is Z1b-c's separate env-gated test (`COGNIC_RUN_LANGFUSE_OTEL=1`), not re-litigated. This smoke's OTLP leg proves the header **lands in the Secret** (the 3-key gate) + the AgentOS pod **boots Ready** with the header configured — not ingestion.

### 6. Docs & posture

- **ADR-024** gains a `## Sprint 14B-Z1b-d-2 amendment`: the 8th all-surfaces render; the operator-run Bicep + smoke; the auxiliary-Merge OTLP-header pattern (+ the Owner/Merge risk + the fail-loud gate + graceful degradation); the no-AKS-CI-job security posture; and the statement that **14B is complete** at this commit.
- **AS_BUILT** — both surfaces: the top-level **Pillar 5** current-state row (mark the live-cloud capstone DONE / 14B substrate complete) **and** the **forward-item** (close `Z1b-d` → `Z1b-d-2` DONE). *(The Z1b-a lesson: patch the top-level current-state surface, not only the detailed forward item.)*
- **AGENTS.md** — the deployment-substrate note (line ~317) extended with the Z1b-d-2 capstone + "14B complete."
- **Runbook** (`docs/operator-runbooks/helm-chart-production-install.md` or a new `aks-live-cloud-smoke.md`) — the AKS bring-up section: `az bicep build` + deploy, the smoke run, the seeded KV secrets, the WI/ESO model, the **migrations-off + post-gate migration Job ordering**, the auxiliary-Merge caveat + the operator-validated ESO version, the OTLP-degradation fallback, and Azure teardown.
- **Posture:** CC stays **131**; no kernel change; no migration; no new on-gate module. The only Python is the 8th snapshot-test parametrization.

## Tasks (high-level; the plan expands each)

- **T1 — the all-surfaces render unit (in-session-provable).** Author `ci/snapshot-values-all-surfaces.yaml` (the dedicated ESO + headersSecretKey + ingress + route + servicemonitor + WI overlay); generate + commit the `agentos_rendered_all-surfaces.yaml` snapshot under Helm 4.2.2; grow the pytest `_SCENARIOS` 7 → 8; grow the `helm-chart` CI job's two loops 7 → 8 (`-skip Route` unchanged). Verify: the **default render + the 7 existing snapshots are byte-unchanged**; the new snapshot shows the WI pod label in `.spec.template.metadata.labels` and **absent** from `.spec.selector.matchLabels` (selector stability re-pinned, proven by a real `yaml.safe_load` parse).
- **T2 — Bicep reference IaC.** Author `infra/azure/aks-smoke/main.bicep` (AKS+OIDC+WI, UAMI, empty Key Vault, federated credential, KV read/write role assignments) + the minimal params. Mark `az bicep build` as operator/CI-run (tools absent in-session).
- **T3 — the live smoke + the auxiliary manifests.** Author `infra/azure/aks-smoke/run-aks-smoke.sh` (the §3 flow: namespace-pin `AGENTOS_NAMESPACE` = Bicep `agentosNamespace` → migrations-off install → fail-loud 3-key gate → smoke-owned migration Job → rollout-restart → Ready), `externalsecret-otel-headers.yaml` (the `Merge` aux), `secretstore.yaml` (the Azure WI SecretStore referencing the chart SA), and `migrate-job.yaml` (the plain, non-hook post-gate migration Job). Mark operator-run; `shellcheck` is operator/CI.
- **T4 — docs.** ADR-024 amendment + AS_BUILT (both surfaces; 14B complete) + AGENTS note + the runbook AKS section (incl. the migration-ordering fix, the Owner/Merge caveat + the operator-validated ESO version + the OTLP-degradation fallback + teardown).
- **T5 — closeout.** Full gate: ruff/format/mypy + the full unit suite + the 131-module critical-controls gate on fresh `--cov-branch`; the **8-scenario** helm gate green; default render UNCHANGED; confirm `src/` untouched across the branch.

## Posture

CC count stays **131**; no kernel change; no migration; no new on-gate module. Z1b-d-2 is the operator-run live-cloud capstone + the always-on 8th all-surfaces render. **After this commit, the whole 14B Deployment Substrate (Z1a + Z1b-a/b/c/d-1/d-2) is complete.**
