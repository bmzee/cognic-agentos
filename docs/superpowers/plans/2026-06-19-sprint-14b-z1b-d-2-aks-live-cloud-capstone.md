# Sprint 14B-Z1b-d-2 — AKS live-cloud capstone — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the live-cloud capstone of 14B — an always-on 8th "all-surfaces" composition render (in-session/CI-provable) plus operator-run reference Bicep IaC + an env-gated AKS smoke that exercises workload identity + ESO-from-Key-Vault + Ready end-to-end — completing the 14B Deployment Substrate.

**Architecture:** No chart change (the chart is already WI/ESO/OTLP-ready). One new dedicated render overlay + snapshot + pytest param + CI scenario (the only in-session proof). New operator-run assets under `infra/azure/aks-smoke/` (Bicep + a self-contained smoke script + 3 static manifests + an AKS values overlay), each given an in-session structural/`bash -n`/`yaml.safe_load` regression test (they cannot run live in CI — no Azure creds; `az`/`bicep`/`shellcheck` absent). Docs amended (ADR-024 + AS_BUILT both surfaces + AGENTS + runbook) marking 14B complete.

**Tech Stack:** Helm v4.2.2, kubeconform v0.8.0, pytest + PyYAML, Bicep (Azure), bash, External Secrets Operator (`external-secrets.io/v1`), Azure AKS/Key Vault/UAMI/workload identity, kubectl. Python 3.12 + uv.

**Spec:** `docs/superpowers/specs/2026-06-19-sprint-14b-z1b-d-2-aks-live-cloud-capstone-design.md`.

---

## Execution discipline (controller-owned — overrides the skill's default commit step)

- **The controller commits, not the subagents.** Each task's subagent implements + runs verification + reports "files modified" (NOT staged). The controller then runs the halt-before-commit reviewer gate, requests the user's per-action full-word token, stages by explicit path, runs `git diff --cached --check`, and commits. Subagents NEVER `git add`/`git commit`.
- **Per-action tokens.** A separate token per commit, restated before executing. Branch already exists (`feat/sprint-14b-z1b-d-2-aks-live-cloud-capstone`); the spec is already committed (`f0bece9`).
- **Subagents run on Opus 4.8** (`model: opus` on every dispatch).
- **Protected untracked docs — NEVER stage:** `docs/reviews/` and `docs/superpowers/specs/2026-05-26-agentos-local-managed-agents-gap-analysis.md`.
- **Commit footer:** end every commit with `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- **Posture invariant (verify at T5):** CC stays **131**; no `src/` change; no kernel change; no migration; no new on-gate module. The only Python is test files under `tests/unit/infra/`.

## File Structure

**Created:**
- `infra/charts/agentos/ci/snapshot-values-all-surfaces.yaml` — the dedicated 8th-scenario overlay (T1).
- `tests/unit/infra/helm/agentos_rendered_all-surfaces.yaml` — the committed byte-snapshot (T1, helm-generated).
- `infra/azure/aks-smoke/main.bicep` — minimal reference IaC (T2).
- `infra/azure/aks-smoke/main.bicepparam` — example params (T2).
- `tests/unit/infra/test_aks_smoke_assets.py` — in-session structural/parse/syntax regressions for the operator-run assets (T2 creates; T3 extends).
- `infra/azure/aks-smoke/secretstore.yaml` — Azure Key Vault SecretStore, workload identity (T3).
- `infra/azure/aks-smoke/externalsecret-otel-headers.yaml` — the smoke-only auxiliary `Merge` ExternalSecret (T3).
- `infra/azure/aks-smoke/migrate-job.yaml` — the plain, non-hook post-gate migration Job (T3).
- `infra/azure/aks-smoke/aks-smoke-values.yaml` — AKS-specific Helm overrides layered over `ci/smoke-values.yaml` (T3).
- `infra/azure/aks-smoke/run-aks-smoke.sh` — the env-gated smoke script (T3).

**Modified:**
- `tests/unit/infra/test_helm_chart.py` — add the 8th `_SCENARIOS` param (T1).
- `.github/workflows/python.yml` — add the 8th scenario to both `helm-chart` loops (T1).
- `docs/adrs/ADR-024-deployment-substrate-helm-packaging.md` — append the Z1b-d-2 amendment (T4).
- `docs/AS_BUILT_CAPABILITY_MAP.md` — Pillar-5 row + the Z1b-d-2 forward bullet (T4, both surfaces).
- `AGENTS.md` — extend the deployment-substrate note (T4).
- `docs/operator-runbooks/helm-chart-production-install.md` — add the AKS live-cloud smoke section (T4).

---

## Task 1: The 8th all-surfaces composition render (in-session-provable)

**Files:**
- Create: `infra/charts/agentos/ci/snapshot-values-all-surfaces.yaml`
- Create (helm-generated): `tests/unit/infra/helm/agentos_rendered_all-surfaces.yaml`
- Modify: `tests/unit/infra/test_helm_chart.py` (add the 8th param to `_SCENARIOS`, after the `workload-identity` param at line ~51-55)
- Modify: `.github/workflows/python.yml` (both `helm-chart` loops + the two step names)

- [ ] **Step 1: Write the dedicated all-surfaces overlay**

Create `infra/charts/agentos/ci/snapshot-values-all-surfaces.yaml`:

```yaml
# All-surfaces composition overlay (layered over ci/snapshot-values.yaml).
# DEDICATED, not a stack of the per-surface overlays: the `externalsecret` overlay (ESO mode)
# and the `otel-http` overlay (existingSecret mode) carry MUTUALLY-EXCLUSIVE secret sources and
# cannot co-layer. This overlay resolves to ONE coherent secret source — ESO mode — then adds
# headersSecretKey on top (the schema allows ESO + headersSecretKey; it forbids ESO+create and
# ESO+existingSecret). The base sets secrets.create=true, so create:false is an explicit override.
# The 3rd Secret key is the live smoke's auxiliary-Merge concern; `helm template` emits the
# secretKeyRef without checking the key exists, so this render proves COMPOSITION only.
# migrations is intentionally NOT set here — it inherits values.yaml's default (enabled=true), so
# the render includes the migration Job (the runtime hook-ordering constraint is a smoke concern).
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
        key: agentos/database-url
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

- [ ] **Step 2: Add the 8th pytest param (the failing test)**

In `tests/unit/infra/test_helm_chart.py`, append to `_SCENARIOS` (after the `workload-identity` param):

```python
    pytest.param(
        [_SNAPSHOT_VALUES, _CI / "snapshot-values-all-surfaces.yaml"],
        _HELM_DIR / "agentos_rendered_all-surfaces.yaml",
        id="all-surfaces",
    ),
```

- [ ] **Step 3: Run the test → it generates the snapshot + fails**

Run: `uv run pytest "tests/unit/infra/test_helm_chart.py::test_rendered_chart_matches_snapshot[all-surfaces]" -x`
Expected: FAIL with "snapshot created at …agentos_rendered_all-surfaces.yaml — review and commit it, then re-run" (the test writes the snapshot on first run). If instead it SKIPS, the local helm is not v4.2.2 — install/switch to Helm v4.2.2 (the snapshot generator) before proceeding.

- [ ] **Step 4: Review the generated snapshot for correctness**

Open `tests/unit/infra/helm/agentos_rendered_all-surfaces.yaml` and confirm it contains, in one document: a `kind: ExternalSecret` (2 keys, NO `kind: Secret` — ESO mode), a `kind: Deployment` whose container env has a `COGNIC_OTEL_EXPORTER_HEADERS` `secretKeyRef`, a `kind: ServiceAccount` carrying `azure.workload.identity/client-id`, a `kind: Ingress`, a `kind: Route`, a `kind: ServiceMonitor`, and a `kind: Job` (the migration hook). The Deployment `.spec.selector.matchLabels` must be ONLY `app.kubernetes.io/name` + `app.kubernetes.io/instance` (no WI label).

- [ ] **Step 5: Prove the selector-stability invariant by a real YAML parse**

Run:
```bash
uv run python -c "
import yaml
docs = list(yaml.safe_load_all(open('tests/unit/infra/helm/agentos_rendered_all-surfaces.yaml')))
dep = next(d for d in docs if d and d.get('kind') == 'Deployment')
sel = dep['spec']['selector']['matchLabels']
tmpl = dep['spec']['template']['metadata']['labels']
assert 'azure.workload.identity/use' not in sel, 'WI label LEAKED into selector.matchLabels'
assert tmpl.get('azure.workload.identity/use') == 'true', 'WI label missing from pod template labels'
print('selector-stability OK: WI label in template labels, absent from selector')
"
```
Expected: `selector-stability OK: …`

- [ ] **Step 6: Re-run the 8th scenario → passes (byte-match)**

Run: `uv run pytest "tests/unit/infra/test_helm_chart.py::test_rendered_chart_matches_snapshot[all-surfaces]" -x`
Expected: PASS.

- [ ] **Step 7: Confirm the default + 7 existing snapshots are byte-UNCHANGED**

Run: `uv run pytest tests/unit/infra/test_helm_chart.py -x`
Expected: all 8 scenarios PASS + the lint test PASS (no drift introduced in the existing 7).

- [ ] **Step 8: kubeconform the all-surfaces render (Valid except Route)**

Run:
```bash
CRD='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
helm template rel infra/charts/agentos --namespace cognic \
  -f infra/charts/agentos/ci/snapshot-values.yaml \
  -f infra/charts/agentos/ci/snapshot-values-all-surfaces.yaml \
  | kubeconform -strict -summary -kubernetes-version 1.27.0 -schema-location default -schema-location "$CRD" -skip Route -
```
Expected: a summary with `Valid` for all kinds and `Skipped` only for the Route (its CRD schema is catalog-absent).

- [ ] **Step 9: Add the 8th scenario to BOTH CI loops + bump the step-name counts**

In `.github/workflows/python.yml`:
- Primary (Helm-4) loop `for s in …` (currently ending in the `_workload-identity|…` entry): add a final entry
  `"_all-surfaces|-f infra/charts/agentos/ci/snapshot-values-all-surfaces.yaml"`.
- Helm-3 compat loop `for overlay in …`: add a final entry
  `"-f infra/charts/agentos/ci/snapshot-values-all-surfaces.yaml"`.
- Rename the two step names `… (7 scenarios)` → `… (8 scenarios)` (the `helm template + snapshot-drift + kubeconform` step and the `helm3 lint + template + kubeconform` step). `-skip Route` is unchanged.

- [ ] **Step 10: Lint clean**

Run: `uv run ruff check tests/unit/infra/test_helm_chart.py && uv run ruff format --check tests/unit/infra/test_helm_chart.py`
Expected: clean.

- [ ] **Step 11: Commit (controller-owned, token-gated)**

Controller stages exactly: `infra/charts/agentos/ci/snapshot-values-all-surfaces.yaml`, `tests/unit/infra/helm/agentos_rendered_all-surfaces.yaml`, `tests/unit/infra/test_helm_chart.py`, `.github/workflows/python.yml`. Run `git diff --cached --check`. Commit:
`feat(deploy): Sprint 14B-Z1b-d-2 T1 — 8th all-surfaces composition render scenario (ADR-024)`

---

## Task 2: Reference Bicep IaC (operator-run; in-session structural regression)

**Files:**
- Create: `infra/azure/aks-smoke/main.bicep`
- Create: `infra/azure/aks-smoke/main.bicepparam`
- Create: `tests/unit/infra/test_aks_smoke_assets.py`

- [ ] **Step 1: Write the failing structural test for the Bicep**

Create `tests/unit/infra/test_aks_smoke_assets.py`:

```python
"""In-session regressions for the operator-run AKS-smoke assets (Sprint 14B-Z1b-d-2).

These assets (Bicep + shell + static manifests) CANNOT run live in CI — no Azure creds, and
`az`/`bicep`/`shellcheck` are absent in the kernel authoring env. So the in-session proof is:
structural assertions (resource types / params present), `yaml.safe_load` parse + key checks on
the static manifests, and a `bash -n` syntax check on the smoke script. The live AKS deploy + the
`az bicep build` / `shellcheck` lint are operator-run (see the runbook).
"""

from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_AKS = _REPO_ROOT / "infra" / "azure" / "aks-smoke"


def test_main_bicep_declares_required_resources_and_params() -> None:
    src = (_AKS / "main.bicep").read_text()
    for resource_type in (
        "Microsoft.ContainerService/managedClusters",
        "Microsoft.ManagedIdentity/userAssignedIdentities",
        "Microsoft.KeyVault/vaults",
        "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials",
        "Microsoft.Authorization/roleAssignments",
    ):
        assert resource_type in src, f"main.bicep missing resource {resource_type}"
    for param in (
        "param location",
        "param resourcePrefix",
        "param kubernetesVersion",
        "param nodeCount",
        "param nodeVmSize",
        "param agentosNamespace",
        "param agentosServiceAccountName",
        "param smokeRunnerObjectId",
    ):
        assert param in src, f"main.bicep missing {param}"
    # OIDC + workload identity must be enabled, and the KV must be RBAC-authorized + empty.
    assert "oidcIssuerProfile" in src and "workloadIdentity" in src
    assert "enableRbacAuthorization: true" in src
    # The federated subject must be namespace+SA scoped (the live-proof binding).
    assert "system:serviceaccount:${agentosNamespace}:${agentosServiceAccountName}" in src
```

- [ ] **Step 2: Run the test → it fails (asset absent)**

Run: `uv run pytest tests/unit/infra/test_aks_smoke_assets.py::test_main_bicep_declares_required_resources_and_params -x`
Expected: FAIL (FileNotFoundError — `main.bicep` does not exist yet).

- [ ] **Step 3: Write the Bicep**

Create `infra/azure/aks-smoke/main.bicep`:

```bicep
// infra/azure/aks-smoke/main.bicep
// Sprint 14B-Z1b-d-2 — minimal REFERENCE IaC for the env-gated AKS live-cloud smoke.
// Operator/CI-run (az/bicep are absent in the kernel authoring env). Validate: `az bicep build --file main.bicep`.
// Provisions ONLY the cloud-managed surfaces the smoke needs: AKS (OIDC + workload identity), a UAMI,
// an EMPTY Key Vault, the federated credential (chart SA -> UAMI), and the KV read/write role assignments.
// Production hardening (private cluster, VNet, Log Analytics, policy) is bank-overlay — see the runbook.

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Short prefix for resource names.')
param resourcePrefix string = 'agentosz1bd2'

@description('Optional AKS Kubernetes version; empty string uses the AKS default.')
param kubernetesVersion string = ''

@description('AKS system node pool node count.')
@minValue(1)
param nodeCount int = 2

@description('AKS system node pool VM size.')
param nodeVmSize string = 'Standard_DS2_v2'

@description('Kubernetes namespace the AgentOS chart installs into (MUST equal the smoke AGENTOS_NAMESPACE).')
param agentosNamespace string = 'cognic-smoke'

@description('The chart ServiceAccount name (release name x chart name; default rel-agentos).')
param agentosServiceAccountName string = 'rel-agentos'

@description('Object ID of the principal that runs the smoke (granted Key Vault write to seed secrets).')
param smokeRunnerObjectId string

var suffix = uniqueString(resourceGroup().id)
var clusterName = '${resourcePrefix}-aks-${suffix}'
var uamiName = '${resourcePrefix}-uami-${suffix}'
var keyVaultName = take('${resourcePrefix}kv${suffix}', 24)
// Built-in role definition IDs (stable across Azure): Key Vault Secrets User (read) + Secrets Officer (write).
var kvSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'
var kvSecretsOfficerRoleId = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'

resource aks 'Microsoft.ContainerService/managedClusters@2024-09-01' = {
  name: clusterName
  location: location
  identity: { type: 'SystemAssigned' }
  properties: union({
    dnsPrefix: '${resourcePrefix}-${suffix}'
    enableRBAC: true
    oidcIssuerProfile: { enabled: true }
    securityProfile: { workloadIdentity: { enabled: true } }
    agentPoolProfiles: [
      {
        name: 'system'
        mode: 'System'
        count: nodeCount
        vmSize: nodeVmSize
        osType: 'Linux'
      }
    ]
  }, empty(kubernetesVersion) ? {} : { kubernetesVersion: kubernetesVersion })
}

resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: uamiName
  location: location
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    // EMPTY — the smoke seeds the 3 secrets via `az keyvault secret set`.
  }
}

resource fedCred 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = {
  parent: uami
  name: 'agentos-chart-sa'
  properties: {
    issuer: aks.properties.oidcIssuerProfile.issuerURL
    subject: 'system:serviceaccount:${agentosNamespace}:${agentosServiceAccountName}'
    audiences: [ 'api://AzureADTokenExchange' ]
  }
}

resource uamiKvRead 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, uami.id, kvSecretsUserRoleId)
  scope: keyVault
  properties: {
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', kvSecretsUserRoleId)
  }
}

resource runnerKvWrite 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, smokeRunnerObjectId, kvSecretsOfficerRoleId)
  scope: keyVault
  properties: {
    principalId: smokeRunnerObjectId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', kvSecretsOfficerRoleId)
  }
}

output clusterName string = aks.name
output resourceGroupName string = resourceGroup().name
output keyVaultName string = keyVault.name
output uamiClientId string = uami.properties.clientId
output oidcIssuerUrl string = aks.properties.oidcIssuerProfile.issuerURL
```

- [ ] **Step 4: Write the example params file**

Create `infra/azure/aks-smoke/main.bicepparam`:

```bicep
// Example params for main.bicep. Fill smokeRunnerObjectId with the object ID of the principal that
// runs run-aks-smoke.sh (`az ad signed-in-user show --query id -o tsv`). agentosNamespace MUST equal
// the smoke's AGENTOS_NAMESPACE. Deploy: `az deployment group create -g <rg> -f main.bicep -p main.bicepparam`.
using './main.bicep'

param location = 'eastus'
param resourcePrefix = 'agentosz1bd2'
param nodeCount = 2
param nodeVmSize = 'Standard_DS2_v2'
param agentosNamespace = 'cognic-smoke'
param agentosServiceAccountName = 'rel-agentos'
param smokeRunnerObjectId = '00000000-0000-0000-0000-000000000000'
```

- [ ] **Step 5: Run the structural test → passes**

Run: `uv run pytest tests/unit/infra/test_aks_smoke_assets.py::test_main_bicep_declares_required_resources_and_params -x`
Expected: PASS.

- [ ] **Step 6: Lint the test**

Run: `uv run ruff check tests/unit/infra/test_aks_smoke_assets.py && uv run ruff format --check tests/unit/infra/test_aks_smoke_assets.py && uv run mypy tests/unit/infra/test_aks_smoke_assets.py`
Expected: clean. (Note: `az bicep build` is operator-run — `bicep` is absent here; the structural test + the runbook command are the in-session contract.)

- [ ] **Step 7: Commit (controller-owned, token-gated)**

Stage exactly: `infra/azure/aks-smoke/main.bicep`, `infra/azure/aks-smoke/main.bicepparam`, `tests/unit/infra/test_aks_smoke_assets.py`. `git diff --cached --check`. Commit:
`feat(deploy): Sprint 14B-Z1b-d-2 T2 — AKS reference Bicep IaC (ADR-024)`

---

## Task 3: The env-gated AKS smoke + static manifests (operator-run; in-session structural/parse/syntax regressions)

**Files:**
- Create: `infra/azure/aks-smoke/secretstore.yaml`
- Create: `infra/azure/aks-smoke/externalsecret-otel-headers.yaml`
- Create: `infra/azure/aks-smoke/migrate-job.yaml`
- Create: `infra/azure/aks-smoke/aks-smoke-values.yaml`
- Create: `infra/azure/aks-smoke/run-aks-smoke.sh`
- Modify: `tests/unit/infra/test_aks_smoke_assets.py` (extend with manifest + script regressions)

- [ ] **Step 1: Extend the test file — first widen the imports, then append the helper + tests**

The T2 file imports only `Path`. These T3 tests add `shutil`/`subprocess`/`yaml` consumers + a strict-mypy-clean YAML helper, so **first replace the T2 import block** at the top of `tests/unit/infra/test_aks_smoke_assets.py` with:

```python
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import yaml
```

Then **append** the YAML helper + the regression tests:

```python
def _load_yaml(name: str) -> dict[str, Any]:
    return cast("dict[str, Any]", yaml.safe_load((_AKS / name).read_text()))


def test_secretstore_is_workload_identity_azurekv() -> None:
    doc = _load_yaml("secretstore.yaml")
    assert doc["kind"] == "SecretStore"
    azurekv = doc["spec"]["provider"]["azurekv"]
    assert azurekv["authType"] == "WorkloadIdentity"
    assert azurekv["serviceAccountRef"]["name"] == "rel-agentos"


def test_aux_externalsecret_is_merge_single_key() -> None:
    doc = _load_yaml("externalsecret-otel-headers.yaml")
    assert doc["kind"] == "ExternalSecret"
    assert doc["spec"]["target"]["creationPolicy"] == "Merge"
    assert doc["spec"]["target"]["name"] == "rel-agentos-secrets"
    keys = [d["secretKey"] for d in doc["spec"]["data"]]
    assert keys == ["COGNIC_OTEL_EXPORTER_HEADERS"]


def test_migrate_job_is_plain_non_hook() -> None:
    doc = _load_yaml("migrate-job.yaml")
    assert doc["kind"] == "Job"
    annotations = doc["metadata"].get("annotations") or {}
    assert not any(k.startswith("helm.sh/hook") for k in annotations), "migrate Job must NOT be a Helm hook"
    container = doc["spec"]["template"]["spec"]["containers"][0]
    assert "alembic upgrade head" in " ".join(container["args"])
    env = {e["name"]: e for e in container["env"]}
    assert env["COGNIC_DATABASE_URL"]["valueFrom"]["secretKeyRef"]["name"] == "rel-agentos-secrets"


def test_aks_smoke_values_is_eso_mode_migrations_off_wi_otel() -> None:
    doc = _load_yaml("aks-smoke-values.yaml")
    assert doc["secrets"]["create"] is False
    assert doc["migrations"]["enabled"] is False
    assert doc["externalSecrets"]["enabled"] is True
    assert doc["podLabels"]["azure.workload.identity/use"] == "true"
    assert doc["otel"]["exporter"]["headersSecretKey"] == "COGNIC_OTEL_EXPORTER_HEADERS"


def test_smoke_script_syntax_valid() -> None:
    assert shutil.which("bash") is not None
    result = subprocess.run(
        ["bash", "-n", str(_AKS / "run-aks-smoke.sh")], capture_output=True, text=True
    )
    assert result.returncode == 0, f"bash -n failed:\n{result.stderr}"


def test_smoke_script_pins_namespace_image_migrations_and_otlp_toggle() -> None:
    src = (_AKS / "run-aks-smoke.sh").read_text()
    assert "set -euo pipefail" in src
    assert "AGENTOS_NAMESPACE" in src
    # every AgentOS-scoped kubectl/helm is namespace-pinned.
    assert '-n "$AGENTOS_NAMESPACE"' in src
    for key in ("COGNIC_DATABASE_URL", "COGNIC_VAULT_TOKEN", "COGNIC_OTEL_EXPORTER_HEADERS"):
        assert key in src
    # migrations off at install; the migration Job is applied AFTER the gate.
    assert "migrate-job.yaml" in src
    assert "rollout restart" in src
    # the Deployment image is the operator's (NOT smoke-values' hardcoded cognic-agentos:smoke).
    assert "--set-string image.repository" in src
    assert "--set-string image.tag" in src
    assert "image.pullPolicy=Always" in src
    assert "COGNIC_IMAGE_REPOSITORY" in src
    assert "COGNIC_IMAGE_TAG" in src
    # OTLP is a first-class toggle (ENABLE_OTLP) with a 2-key fallback gate.
    assert "ENABLE_OTLP" in src
    # the cluster is NOT deleted by the smoke (the Bicep owns it).
    assert "az group delete" not in src
    assert "kind delete cluster" not in src
```

- [ ] **Step 2: Run the new tests → they fail (assets absent)**

Run: `uv run pytest tests/unit/infra/test_aks_smoke_assets.py -x`
Expected: FAIL (the manifests + script do not exist yet).

- [ ] **Step 3: Write the SecretStore**

Create `infra/azure/aks-smoke/secretstore.yaml`:

```yaml
# infra/azure/aks-smoke/secretstore.yaml — Sprint 14B-Z1b-d-2 Azure Key Vault SecretStore (workload identity).
# Namespaced — applied with `kubectl apply -n "$AGENTOS_NAMESPACE"`. References the chart SA (rel-agentos),
# WI-annotated via the chart's serviceAccount.annotations; ESO mints a TokenRequest token for that SA and
# exchanges it (via the federated credential) for a UAMI token to read Key Vault. run-aks-smoke.sh substitutes
# __KEY_VAULT_URI__ (https://<kv-name>.vault.azure.net). The exact serviceAccountRef + WorkloadIdentity
# behavior is ESO-version-dependent — the runbook flags the operator-validated ESO version.
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: agentos-secret-store
spec:
  provider:
    azurekv:
      authType: WorkloadIdentity
      vaultUrl: __KEY_VAULT_URI__
      serviceAccountRef:
        name: rel-agentos
```

- [ ] **Step 4: Write the auxiliary Merge ExternalSecret**

Create `infra/azure/aks-smoke/externalsecret-otel-headers.yaml`:

```yaml
# infra/azure/aks-smoke/externalsecret-otel-headers.yaml — SMOKE-ONLY auxiliary (creationPolicy: Merge).
# Carries COGNIC_OTEL_EXPORTER_HEADERS into the chart-owned Secret WITHOUT widening the chart's fixed
# 2-key ExternalSecret (the deliberate Z1b-b bootstrap contract). Applied with `-n "$AGENTOS_NAMESPACE"`.
# RISK (operator-verified): the chart's ExternalSecret is creationPolicy: Owner over rel-agentos-secrets;
# this is Merge over the same Secret. Coexistence is ESO-version-dependent (server-side-apply field
# managers). The smoke's fail-loud 3-key gate catches a strip; the OTLP leg is the degradable surface.
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: agentos-otel-headers
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: agentos-secret-store
    kind: SecretStore
  target:
    name: rel-agentos-secrets
    creationPolicy: Merge
  data:
    - secretKey: COGNIC_OTEL_EXPORTER_HEADERS
      remoteRef:
        key: agentos-otel-headers
```

- [ ] **Step 5: Write the plain (non-hook) migration Job**

Create `infra/azure/aks-smoke/migrate-job.yaml`:

```yaml
# infra/azure/aks-smoke/migrate-job.yaml — Sprint 14B-Z1b-d-2 SMOKE-OWNED, NON-HOOK migration Job.
# Applied by run-aks-smoke.sh AFTER the 3-key Secret gate. Mirrors the chart hook Job
# (templates/migration-job.yaml) MINUS the Helm hook annotations — the chart hook can't be used in ESO
# mode (pre-install hook references the ExternalSecret-managed Secret before ESO creates it -> deadlock).
# run-aks-smoke.sh substitutes __AGENTOS_IMAGE__ with the image it passed to `helm install`.
apiVersion: batch/v1
kind: Job
metadata:
  name: agentos-migrate
spec:
  backoffLimit: 1
  ttlSecondsAfterFinished: 600
  template:
    spec:
      restartPolicy: Never
      securityContext:
        runAsNonRoot: true
      containers:
        - name: migrate
          image: __AGENTOS_IMAGE__
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
            seccompProfile:
              type: RuntimeDefault
          command: ["sh", "-c"]
          args:
            - |
              set -eu
              if [ -z "${COGNIC_DATABASE_URL:-}" ]; then
                echo "FATAL: COGNIC_DATABASE_URL is unset — refusing to run migrations" >&2
                exit 1
              fi
              exec alembic upgrade head
          env:
            - name: COGNIC_DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: rel-agentos-secrets
                  key: COGNIC_DATABASE_URL
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir: {}
```

- [ ] **Step 6: Write the AKS Helm values overlay**

Create `infra/azure/aks-smoke/aks-smoke-values.yaml`:

```yaml
# infra/azure/aks-smoke/aks-smoke-values.yaml — AKS-specific overrides, layered over ci/smoke-values.yaml.
# Switches the secret source from chart-created (smoke-values) to ESO-from-Key-Vault, turns migrations OFF
# (post-gate non-hook Job — see run-aks-smoke.sh), and turns on workload identity + OTLP/HTTP export.
# The dynamic serviceAccount.annotations."azure.workload.identity/client-id" is --set-string at install
# (it comes from the Bicep uamiClientId output).
secrets:
  create: false                      # override smoke-values' create:true -> ESO mode (3-mode XOR satisfied)
migrations:
  enabled: false                     # post-gate non-hook Job (avoids the pre-install-hook vs ESO-secret deadlock)
externalSecrets:
  enabled: true
  secretStoreRef:
    name: agentos-secret-store
    kind: SecretStore
  data:
    databaseUrl:
      remoteRef:
        key: agentos-database-url    # Azure Key Vault secret name — NO slash (KV forbids '/')
    vaultToken:
      remoteRef:
        key: agentos-vault-token
podLabels:
  azure.workload.identity/use: "true"
otel:
  exporter:
    endpoint: http://langfuse:3000/api/public/otel/v1/traces
    protocol: http
    insecure: false
    headersSecretKey: COGNIC_OTEL_EXPORTER_HEADERS
```

- [ ] **Step 7: Write the smoke script**

Create `infra/azure/aks-smoke/run-aks-smoke.sh`:

```bash
#!/usr/bin/env bash
# Sprint 14B-Z1b-d-2 env-gated AKS live-cloud smoke. Operator-run (requires: az, kubectl, helm; `az login` done).
# Exercises Z1b-b (ESO-from-Key-Vault) + Z1b-d-1 (workload identity) + Z1a (Ready) end-to-end on real AKS.
# PREREQ: deploy infra/azure/aks-smoke/main.bicep first (this reads its outputs). The smoke does NOT create
# or delete the AKS cluster — the Bicep owns it; it is rerunnable. Azure teardown is `az group delete` (runbook).
# NOT runnable in the kernel authoring env (no Azure creds; az/bicep/shellcheck absent there).
set -euo pipefail

# --- inputs (Bicep deployment outputs / env) ---
RG="${AZ_RESOURCE_GROUP:?set AZ_RESOURCE_GROUP to the Bicep deployment resource group}"
DEPLOYMENT="${AZ_DEPLOYMENT:-aks-smoke}"
AGENTOS_NAMESPACE="${AGENTOS_NAMESPACE:-cognic-smoke}"   # MUST equal the Bicep agentosNamespace param
RELEASE="rel"
CHART="infra/charts/agentos"
COGNIC_IMAGE_REPOSITORY="${COGNIC_IMAGE_REPOSITORY:?set COGNIC_IMAGE_REPOSITORY to a registry your AKS can pull (the default-adapters image)}"
COGNIC_IMAGE_TAG="${COGNIC_IMAGE_TAG:?set COGNIC_IMAGE_TAG to the image tag}"
IMAGE="${COGNIC_IMAGE_REPOSITORY}:${COGNIC_IMAGE_TAG}"   # the Deployment AND the migration Job use this
ENABLE_OTLP="${ENABLE_OTLP:-1}"                          # 1 = OTLP on (3-key gate); 0 = OTLP off (2-key fallback)
OTEL_HEADERS_JSON="${OTEL_HEADERS_JSON:-{}}"             # e.g. {"Authorization":"Basic <b64>"} (used only when ENABLE_OTLP=1)

out() { az deployment group show -g "$RG" -n "$DEPLOYMENT" --query "properties.outputs.$1.value" -o tsv; }
CLUSTER="$(out clusterName)"
KEYVAULT="$(out keyVaultName)"
UAMI_CLIENT_ID="$(out uamiClientId)"
KV_URI="https://${KEYVAULT}.vault.azure.net"
SECRET="${RELEASE}-agentos-secrets"

echo "==> get kubeconfig for $CLUSTER"
az aks get-credentials -g "$RG" -n "$CLUSTER" --overwrite-existing

echo "==> pin the AgentOS namespace ($AGENTOS_NAMESPACE) — MUST match the Bicep agentosNamespace"
kubectl get namespace "$AGENTOS_NAMESPACE" >/dev/null 2>&1 || kubectl create namespace "$AGENTOS_NAMESPACE"

echo "==> install ESO (its own namespace, not \$AGENTOS_NAMESPACE)"
helm repo add external-secrets https://charts.external-secrets.io >/dev/null 2>&1 || true
helm repo update >/dev/null
helm upgrade --install external-secrets external-secrets/external-secrets \
  -n external-secrets --create-namespace --wait

echo "==> bring up the six in-cluster backends"
kubectl apply -n "$AGENTOS_NAMESPACE" -f "$CHART/ci/smoke/backends.yaml"
kubectl -n "$AGENTOS_NAMESPACE" wait --for=condition=available --timeout=300s deploy --all

echo "==> apply the Azure Key Vault SecretStore (workload identity -> chart SA)"
sed "s|__KEY_VAULT_URI__|$KV_URI|" infra/azure/aks-smoke/secretstore.yaml \
  | kubectl apply -n "$AGENTOS_NAMESPACE" -f -

echo "==> seed Key Vault (2 bootstrap secrets; Azure KV names have NO slashes)"
az keyvault secret set --vault-name "$KEYVAULT" --name agentos-database-url \
  --value "postgresql+asyncpg://cognic:cognic@postgres:5432/cognic" >/dev/null
az keyvault secret set --vault-name "$KEYVAULT" --name agentos-vault-token \
  --value "smoke-root-token" >/dev/null

if [[ "$ENABLE_OTLP" == "1" ]]; then
  echo "==> OTLP on: seed the header secret + apply the auxiliary Merge ExternalSecret"
  az keyvault secret set --vault-name "$KEYVAULT" --name agentos-otel-headers \
    --value "$OTEL_HEADERS_JSON" >/dev/null
  kubectl apply -n "$AGENTOS_NAMESPACE" -f infra/azure/aks-smoke/externalsecret-otel-headers.yaml
else
  echo "==> OTLP off (ENABLE_OTLP=0): skipping the header secret + the auxiliary Merge ExternalSecret"
fi

echo "==> helm install AgentOS (ESO + WI on; migrations OFF -> post-gate Job; OTLP per ENABLE_OTLP)"
# smoke-values.yaml hardcodes the kind-loaded image (cognic-agentos:smoke); override it with the
# operator's REGISTRY image so the AKS Deployment pulls a real image (NOT just the migration Job).
otlp_overrides=()
if [[ "$ENABLE_OTLP" != "1" ]]; then
  # blank the endpoint (export becomes a no-op) + the header key (no OTLP-header env) so the 3rd
  # Secret key is not required and the gate below drops to 2 keys.
  otlp_overrides+=(--set otel.exporter.endpoint= --set otel.exporter.headersSecretKey=)
fi
helm upgrade --install "$RELEASE" "$CHART" -n "$AGENTOS_NAMESPACE" \
  -f "$CHART/ci/smoke-values.yaml" \
  -f infra/azure/aks-smoke/aks-smoke-values.yaml \
  --set-string image.repository="$COGNIC_IMAGE_REPOSITORY" \
  --set-string image.tag="$COGNIC_IMAGE_TAG" \
  --set-string image.pullPolicy=Always \
  --set-string serviceAccount.annotations."azure\.workload\.identity/client-id"="$UAMI_CLIENT_ID" \
  ${otlp_overrides[@]+"${otlp_overrides[@]}"}

KEY_COUNT=$([[ "$ENABLE_OTLP" == "1" ]] && echo 3 || echo 2)
echo "==> fail-loud ${KEY_COUNT}-key gate: ESO (+ the Merge aux when OTLP on) must populate $SECRET"
deadline=$(( SECONDS + 300 ))
have_keys() {
  local data
  data="$(kubectl -n "$AGENTOS_NAMESPACE" get secret "$SECRET" -o jsonpath='{.data}' 2>/dev/null || true)"
  [[ "$data" == *COGNIC_DATABASE_URL* && "$data" == *COGNIC_VAULT_TOKEN* ]] || return 1
  if [[ "$ENABLE_OTLP" == "1" ]]; then
    [[ "$data" == *COGNIC_OTEL_EXPORTER_HEADERS* ]] || return 1
  fi
  return 0
}
until have_keys; do
  if (( SECONDS > deadline )); then
    echo "FAIL: $SECRET missing a required key after 300s (ESO/WI failure or, with OTLP on, an Owner+Merge conflict — retry with ENABLE_OTLP=0)" >&2
    kubectl -n "$AGENTOS_NAMESPACE" get secret "$SECRET" -o jsonpath='{.data}' >&2 || true
    exit 1
  fi
  sleep 5
done
echo "    all ${KEY_COUNT} keys present"

echo "==> run the smoke-owned (non-hook) migration Job"
sed "s|__AGENTOS_IMAGE__|$IMAGE|" infra/azure/aks-smoke/migrate-job.yaml \
  | kubectl apply -n "$AGENTOS_NAMESPACE" -f -
kubectl -n "$AGENTOS_NAMESPACE" wait --for=condition=complete job/agentos-migrate --timeout=300s

echo "==> roll the Deployment so fresh pods see the migrated schema"
kubectl -n "$AGENTOS_NAMESPACE" rollout restart deploy/"${RELEASE}-agentos"
kubectl -n "$AGENTOS_NAMESPACE" rollout status deploy/"${RELEASE}-agentos" --timeout=300s
kubectl -n "$AGENTOS_NAMESPACE" wait --for=condition=ready pod -l app.kubernetes.io/name=agentos --timeout=300s

echo "==> assert /readyz=200"
kubectl -n "$AGENTOS_NAMESPACE" port-forward "svc/${RELEASE}-agentos" 8000:8000 >/dev/null 2>&1 &
PF=$!; sleep 4
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/api/v1/readyz)
kill "$PF" 2>/dev/null || true
echo "/readyz => $code"
test "$code" = "200"
echo "AKS SMOKE PASS"
```

- [ ] **Step 8: Make the script executable + run the regression tests → pass**

Run:
```bash
chmod +x infra/azure/aks-smoke/run-aks-smoke.sh
uv run pytest tests/unit/infra/test_aks_smoke_assets.py -x
```
Expected: all tests PASS (incl. `bash -n` syntax-valid + the manifest parse/key checks).

- [ ] **Step 9: Lint**

Run: `uv run ruff check tests/unit/infra/test_aks_smoke_assets.py && uv run ruff format --check tests/unit/infra/test_aks_smoke_assets.py && uv run mypy tests/unit/infra/test_aks_smoke_assets.py`
Expected: clean. (`shellcheck` on `run-aks-smoke.sh` is operator-run — absent here; `bash -n` is the in-session syntax gate.)

- [ ] **Step 10: Commit (controller-owned, token-gated)**

Stage exactly the 5 new asset files + `tests/unit/infra/test_aks_smoke_assets.py`. `git diff --cached --check`. Commit:
`feat(deploy): Sprint 14B-Z1b-d-2 T3 — env-gated AKS live-cloud smoke (ADR-024)`

---

## Task 4: Docs (ADR-024 + AS_BUILT both surfaces + AGENTS + runbook)

**Files:**
- Modify: `docs/adrs/ADR-024-deployment-substrate-helm-packaging.md` (append the amendment)
- Modify: `docs/AS_BUILT_CAPABILITY_MAP.md` (Pillar-5 row line 17 + the Z1b-d-2 forward bullet line 62)
- Modify: `AGENTS.md` (line 317 deployment-substrate note)
- Modify: `docs/operator-runbooks/helm-chart-production-install.md` (new section after `## Cloud workload identity`)

- [ ] **Step 1: Append the ADR-024 amendment**

At the END of `docs/adrs/ADR-024-deployment-substrate-helm-packaging.md` (after the `## Sprint 14B-Z1b-d-1 amendment` block), append:

```markdown
## Sprint 14B-Z1b-d-2 amendment (2026-06-19)

Sprint 14B-Z1b-d-2 is the **live-cloud capstone of 14B** — the fourth/final Z1b sub-slice (after Z1b-d-1). It adds one always-on in-session proof + operator-run AKS assets + docs; it makes **no chart change** (the chart is already WI/ESO/OTLP-ready) and **no kernel change**. **CC count stays 131, no migration, no new on-gate module**; the only Python is test files under `tests/unit/infra/`. After this commit the whole 14B Deployment Substrate (Z1a + Z1b-a/b/c/d-1/d-2) is **complete**.

### The 8th "all-surfaces" composition render (always-on CI)
A dedicated `ci/snapshot-values-all-surfaces.yaml` overlay turns on **every** Z1b conditional surface in one render — Ingress + Route + ServiceMonitor + ESO + OTLP/HTTP + workload identity. It is **dedicated, not a stack** of the per-surface overlays: the `externalsecret` overlay (ESO mode) and the `otel-http` overlay (`existingSecret` mode) carry mutually-exclusive secret sources, so the all-surfaces overlay resolves to one coherent **ESO mode** + `headersSecretKey` (the schema permits ESO + headersSecretKey; the chart `ExternalSecret` renders its fixed 2 keys, and the Deployment renders a `secretKeyRef` to the 3rd key — `helm template` does not check key existence, so the render proves **composition**). Validated by an 8th byte-snapshot + kubeconform scenario in both `helm-chart` CI lanes (core + the existing CRDs; the narrow `-skip Route` is unchanged). The render re-pins the Z1b-d-1 selector-stability invariant (the WI pod label is in `.spec.template.metadata.labels`, absent from `.spec.selector.matchLabels`).

### Operator-run AKS assets (`infra/azure/aks-smoke/`)
A minimal **reference Bicep** (`main.bicep`) provisions only the cloud-managed surfaces the live proof needs: AKS (OIDC issuer + workload-identity addon), a UAMI, an **empty** Key Vault, the federated credential (chart SA → UAMI, subject `system:serviceaccount:<agentosNamespace>:<agentosServiceAccountName>`), and the KV read (UAMI) / write (`smokeRunnerObjectId`) role assignments. Minimal params; production hardening (private cluster, VNet, Log Analytics, policy) is bank-overlay. A self-contained **smoke** (`run-aks-smoke.sh`) installs ESO, applies the in-cluster `backends.yaml` (Key Vault is the only Azure-managed surface), seeds Key Vault (3 no-slash secrets), applies an Azure WI `SecretStore` referencing the chart SA, installs the chart (ESO + WI + OTLP, migrations OFF), gates on the Secret, runs migrations, rolls the Deployment, and asserts `/readyz=200`.

### Two enforced ordering/identity contracts
- **Namespace pinning.** The federated-credential subject is namespace-scoped, so the smoke pins `AGENTOS_NAMESPACE` (= the Bicep `agentosNamespace`) through every AgentOS-scoped `kubectl`/`helm` command (ESO installs in its own `external-secrets` namespace). A mismatch breaks the SA-token → UAMI exchange.
- **Migration ordering.** The chart migration Job is a Helm `pre-install` hook, but in ESO mode the chart `ExternalSecret` is a normal resource — Helm runs the hook before normal resources, so the hook would reference the Secret before ESO creates it (deadlock). The smoke installs with `migrations.enabled=false` and runs migrations as a smoke-owned **non-hook** Job after the 3-key Secret gate, then rolls the Deployment.

### The OTLP header — auxiliary `Merge`, fixed 2-key contract preserved
The chart `ExternalSecret` stays **fixed 2-key**. The OTLP Basic-auth header is carried by a smoke-only **auxiliary `ExternalSecret` (`creationPolicy: Merge`)** targeting the same Secret. Owner/Merge coexistence is **ESO-version-dependent** (server-side-apply field managers); the smoke's **fail-loud 3-key wait gate** catches a strip (timeout → loud failure), and the OTLP leg is the one **degradable** surface: `ENABLE_OTLP=0` is a first-class fallback that skips the auxiliary `ExternalSecret`, blanks the chart's OTLP endpoint/header key, and gates on 2 keys (WI + ESO-from-Key-Vault + Ready is the primary live proof; OTLP composition is already proven by the 8th render).

### Honesty / posture
- **No AKS CI job** — GitHub→Azure auth + Key Vault write are bank/operator territory, a deliberate security posture, not an omission. The 8th render is the only always-on CI addition; the Bicep + smoke are operator-run (`az`/`bicep`/`shellcheck` absent in the kernel env). In-session regressions: the byte-snapshot, a structural Bicep test, `yaml.safe_load` parse + key checks on the static manifests, and `bash -n` on the smoke script.
- The live **Langfuse OTLP ingestion read-back** remains Z1b-c's separate env-gated test; this smoke's OTLP leg proves only that the header lands in the Secret + the pod boots Ready.
```

- [ ] **Step 2: Update AS_BUILT — the Pillar-5 row (line 17)**

In `docs/AS_BUILT_CAPABILITY_MAP.md` line 17 (the Pillar 5 row), make these phrase replacements:
- Current-state cell: `chart workload-identity readiness DONE 14B-Z1b-d-1; AKS bring-up + live cloud-ingress exercise forward in Z1b-d-2)` → `chart workload-identity readiness DONE 14B-Z1b-d-1; AKS live-cloud capstone DONE 14B-Z1b-d-2 — 14B substrate COMPLETE)`.
- Evidence cell: after the `**14B-Z1b-d-1 (ADR-024)** adds the two generic … the narrow -skip Route is unchanged)` sentence, append: `**14B-Z1b-d-2 (ADR-024)** is the live-cloud capstone — an 8th **all-surfaces** composition byte-snapshot/kubeconform scenario (every Z1b conditional surface in one render; dedicated ESO-mode overlay; `-skip Route` unchanged) + operator-run reference Bicep IaC (`infra/azure/aks-smoke/main.bicep` — AKS OIDC+WI, UAMI, empty Key Vault, federated credential, KV roles) + a self-contained env-gated AKS smoke (`run-aks-smoke.sh` — ESO-from-Key-Vault + workload identity + Ready; namespace-pinned; migrations-off + post-gate non-hook Job; auxiliary `Merge` ExternalSecret for the OTLP header with a fail-loud 3-key gate + a first-class `ENABLE_OTLP=0` 2-key fallback); **no AKS CI job** (a deliberate security posture); CC stays 131 / no kernel change / no migration.`
- Gap cell: replace the four `… is Z1b-d-2)` deferrals (`live cloud-ingress exercise (… is Z1b-d-2)`, `live ESO exercise (… is Z1b-d-2)`, `the live cloud-identity-federation exercise is Z1b-d-2)`, `only the live in-cluster proof is Z1b-d-2)`) by marking them DONE: change each trailing `… is Z1b-d-2)` to `… DONE in Z1b-d-2 (operator-run AKS smoke))`. Leave `Option C …`, `complete operator runbook set`, and `release/evidence checklist` as remaining gaps.
- Owner cell: `**Sprint 14B-Z1b-d-2 — AKS/live-cloud forward**` → `**Sprint 14B-Z1b-d-2 — AKS live-cloud capstone DONE**`.

- [ ] **Step 3: Update AS_BUILT — the Z1b-d-2 forward bullet (line 62)**

Replace line 62 (`- **14B-Z1b-d-2 — AKS bring-up + env-gated live cloud smoke (forward).** …`) with:

```markdown
     - **14B-Z1b-d-2 — AKS live-cloud capstone: DONE 2026-06-19.** The final Z1b sub-slice + the 14B capstone. One always-on in-session proof — an **8th `all-surfaces` byte-snapshot/kubeconform scenario** that renders every Z1b conditional surface together (Ingress + Route + ServiceMonitor + ESO + OTLP/HTTP + workload identity) via a **dedicated** ESO-mode overlay (not a stack — the `externalsecret` and `otel-http` overlays carry mutually-exclusive secret sources; the all-surfaces overlay resolves to ESO + `headersSecretKey`); `-skip Route` unchanged; re-pins the selector-stability invariant. Plus operator-run assets under `infra/azure/aks-smoke/`: a minimal reference **Bicep** (AKS OIDC + workload identity, UAMI, empty Key Vault, the federated credential `system:serviceaccount:<ns>:<sa>`, KV read/write roles; production hardening is bank-overlay) and a self-contained env-gated **smoke** (`run-aks-smoke.sh`) that installs ESO, applies the in-cluster `backends.yaml`, seeds Key Vault (3 no-slash secrets), applies an Azure WI `SecretStore` → chart SA, installs the chart (ESO + WI + OTLP, **migrations off**, the operator's registry image), runs a **fail-loud 3-key gate** (first-class 2-key fallback via `ENABLE_OTLP=0`), runs a smoke-owned **non-hook** migration Job, rolls the Deployment, and asserts `/readyz=200`. Two enforced contracts: **namespace pinning** (`AGENTOS_NAMESPACE` = Bicep `agentosNamespace`, threaded through every command — the federated subject is namespace-scoped) and **migration ordering** (the chart migration hook would deadlock on the ESO-managed Secret, so migrations run post-gate as a non-hook Job). The OTLP header rides a smoke-only **auxiliary `Merge` ExternalSecret** (the chart's 2-key contract is preserved); Owner/Merge coexistence is ESO-version-dependent, caught by the 3-key gate, and the OTLP leg is the degradable surface (WI + ESO + Ready is the primary live proof). **No AKS CI job** (a deliberate security posture — GitHub→Azure auth is bank/operator territory); in-session regressions are the byte-snapshot + a structural Bicep test + `yaml.safe_load` manifest checks + `bash -n` on the script. **CC count stays 131 / no kernel change / no migration / no new on-gate module.** Runbook `docs/operator-runbooks/helm-chart-production-install.md` gains an "AKS live-cloud smoke" section. **After this commit the whole 14B Deployment Substrate is complete.** See ADR-024.
```

- [ ] **Step 4: Extend the AGENTS.md deployment-substrate note (line 317)**

At the END of the line-317 paragraph (after the `… the live AKS exercise is Z1b-d-2.` sentence that closes the Z1b-d-1 clause), append:

```
 **Sprint 14B-Z1b-d-2** then shipped the live-cloud capstone — an always-on 8th `all-surfaces` byte-snapshot scenario (every Z1b conditional surface in one dedicated ESO-mode render; `-skip Route` unchanged) + operator-run reference Bicep (`infra/azure/aks-smoke/main.bicep`: AKS OIDC+WI, UAMI, empty Key Vault, federated credential, KV roles) + a self-contained env-gated AKS smoke (`run-aks-smoke.sh`: ESO-from-Key-Vault + workload identity + Ready; namespace-pinned to the Bicep `agentosNamespace`; migrations-off + a post-gate non-hook migration Job to avoid the pre-install-hook-vs-ESO-secret deadlock; an auxiliary `Merge` ExternalSecret for the OTLP header preserving the chart's fixed 2-key contract, behind a fail-loud 3-key gate with a first-class `ENABLE_OTLP=0` 2-key fallback). **No AKS CI job** (a deliberate security posture); still **CC 131, no kernel change, no migration**. With Z1b-d-2 the whole 14B Deployment Substrate (Z1a + Z1b-a/b/c/d-1/d-2) is **complete**.
```

- [ ] **Step 5: Add the runbook AKS section**

In `docs/operator-runbooks/helm-chart-production-install.md`, insert a new section AFTER the `## Cloud workload identity` section (i.e., before `## Trust-root note (pack registration)`):

````markdown
## AKS live-cloud smoke (env-gated, operator-run)

A reference end-to-end exercise of the chart on a real AKS cluster — workload identity + ESO-from-Key-Vault + Ready. Assets live under `infra/azure/aks-smoke/`. This is **operator-run** (it needs Azure credentials + `az`/`bicep`); it is not part of CI. Production hardening (private cluster, custom VNet, Log Analytics, Azure Policy) is your overlay's concern — this Bicep is a minimal reference.

### 1. Provision the cloud surfaces (Bicep)

```bash
az bicep build --file infra/azure/aks-smoke/main.bicep      # validate
az group create -n <rg> -l <region>
# set smokeRunnerObjectId to YOUR object id: az ad signed-in-user show --query id -o tsv
az deployment group create -g <rg> -n aks-smoke \
  -f infra/azure/aks-smoke/main.bicep -p infra/azure/aks-smoke/main.bicepparam
```

The Bicep provisions AKS (OIDC + workload identity), a UAMI, an **empty** Key Vault, the federated credential (chart SA → UAMI), and the KV read (UAMI) / write (you) roles. **`agentosNamespace` MUST equal the smoke's `AGENTOS_NAMESPACE`** — the federated subject is `system:serviceaccount:<namespace>:rel-agentos`.

### 2. Run the smoke

```bash
export AZ_RESOURCE_GROUP=<rg>
export AGENTOS_NAMESPACE=cognic-smoke          # MUST match the Bicep agentosNamespace
export COGNIC_IMAGE_REPOSITORY=<registry your AKS can pull, e.g. myregistry.azurecr.io/cognic-agentos>
export COGNIC_IMAGE_TAG=<image tag>
export OTEL_HEADERS_JSON='{"Authorization":"Basic <base64 user:pass>"}'   # only with OTLP on (ENABLE_OTLP=1, the default)
# export ENABLE_OTLP=0    # uncomment to skip the OTLP leg entirely (2-key gate; WI + ESO + Ready only)
bash infra/azure/aks-smoke/run-aks-smoke.sh
```

The smoke installs ESO, brings up the in-cluster backends, seeds Key Vault (2 bootstrap secrets — plus the OTLP header when `ENABLE_OTLP=1`; **no slashes** in the KV names), applies the Azure WI `SecretStore` (referencing the chart SA), installs the chart with the operator's image (`COGNIC_IMAGE_REPOSITORY`/`_TAG`) and **migrations off**, waits for the fail-loud **2- or 3-key Secret gate**, runs a smoke-owned **non-hook** migration Job, rolls the Deployment, and asserts `/readyz=200`.

### Notes + caveats

- **ESO version (operator-validated).** The Azure `SecretStore` uses `authType: WorkloadIdentity` + `serviceAccountRef`; validate against the ESO version you run.
- **Owner/Merge coexistence.** The chart's `ExternalSecret` is `creationPolicy: Owner`; the OTLP header rides a smoke-only auxiliary `ExternalSecret` with `creationPolicy: Merge` over the same Secret. Coexistence is ESO-version-dependent — the 3-key gate catches a strip. If your ESO version conflicts, set **`ENABLE_OTLP=0`** (the smoke then skips the header secret + the auxiliary `ExternalSecret`, blanks the chart's OTLP endpoint/header key, and gates on 2 keys); WI + ESO + Ready is the primary proof.
- **Migration ordering.** Migrations run as a post-gate non-hook Job (the chart's pre-install migration hook would deadlock on the ESO-managed Secret).
- **Teardown.** The smoke does not delete the cluster (it is rerunnable). Remove everything with `az group delete -n <rg> --yes`.
````

- [ ] **Step 6: Verify docs render + both AS_BUILT surfaces updated**

Run:
```bash
grep -n "Sprint 14B-Z1b-d-2 amendment" docs/adrs/ADR-024-deployment-substrate-helm-packaging.md
grep -n "AKS live-cloud capstone DONE 14B-Z1b-d-2" docs/AS_BUILT_CAPABILITY_MAP.md          # Pillar-5 row
grep -n "14B-Z1b-d-2 — AKS live-cloud capstone: DONE" docs/AS_BUILT_CAPABILITY_MAP.md         # forward bullet
grep -n "Sprint 14B-Z1b-d-2 then shipped the live-cloud capstone" AGENTS.md
grep -n "## AKS live-cloud smoke" docs/operator-runbooks/helm-chart-production-install.md
```
Expected: each grep returns a line (both AS_BUILT surfaces present). Confirm no stale "forward in Z1b-d-2" / "is Z1b-d-2)" deferrals remain on the Pillar-5 row (`grep -n "forward in Z1b-d-2\|exercise is Z1b-d-2\|proof is Z1b-d-2" docs/AS_BUILT_CAPABILITY_MAP.md` → only acceptable matches are the now-"DONE in Z1b-d-2" rewrites).

- [ ] **Step 7: Commit (controller-owned, token-gated)**

Stage exactly the 4 doc files. `git diff --cached --check`. Commit:
`docs(deploy): Sprint 14B-Z1b-d-2 T4 — ADR-024 + AS_BUILT + AGENTS + runbook (14B complete) (ADR-024)`

---

## Task 5: Closeout gate

**Files:** none (verification only; a fixup commit only if the gate surfaces an issue).

- [ ] **Step 1: Lint + format + types (whole tree)**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy src tests`
Expected: clean.

- [ ] **Step 2: Full unit suite on fresh `--cov-branch`**

Run: `uv run pytest -q --cov=cognic_agentos --cov-branch --cov-report=json:coverage.json`
Expected: all pass, 0 failed (record the pass count).

- [ ] **Step 3: The 131-module critical-controls gate (fresh coverage)**

Run: `uv run python tools/check_critical_coverage.py`
Expected: `131/131` modules at/above floor; exit 0. (No new on-gate module — the only new Python is `tests/unit/infra/`.)

- [ ] **Step 4: The 8-scenario helm gate + default render UNCHANGED**

Run: `uv run pytest tests/unit/infra/ -v`
Expected: all `test_rendered_chart_matches_snapshot` (8 scenarios) + `test_chart_lints_clean` + the AKS-asset tests PASS. Re-run the Step-5 selector-stability `yaml.safe_load` one-liner from Task 1 → OK.

- [ ] **Step 5: Confirm `src/` untouched + clean tree**

Run: `git diff --stat origin/main...HEAD -- src/ && git status --porcelain`
Expected: NO `src/` changes across the branch; `git status` shows only the 2 protected untracked docs (`docs/reviews/`, the 2026-05-26 gap-analysis spec) — nothing else uncommitted.

- [ ] **Step 6: Finish the branch**

Use superpowers:finishing-a-development-branch → push + open the PR (controller-owned, token-gated; `--squash --delete-branch` at merge, never `--auto`). The closeout memory + MEMORY.md update follow the merge.

---

## Self-Review (controller, after writing — fix inline)

- **Spec coverage:** every spec section maps to a task — §1 all-surfaces render → T1; §2 Bicep → T2; §3 smoke + §4 auxiliary Merge → T3; §5 proof boundary → honesty notes across T1-T3 + T5; §6 docs → T4; the posture invariant → T5.
- **Placeholders:** none — the `__KEY_VAULT_URI__` / `__AGENTOS_IMAGE__` tokens are deliberate `sed`-substitution markers (documented in-file + asserted by the structural test), not unfilled placeholders.
- **Type/name consistency:** release `rel` → SA `rel-agentos` → Secret `rel-agentos-secrets` is consistent across the Bicep federated subject, the SecretStore `serviceAccountRef`, the auxiliary `Merge` target, the migrate Job `secretKeyRef`, and the smoke script. The all-surfaces overlay uses ESO mode (matching the schema) + the generic slash-form `remoteRef.key` (render is cloud-agnostic) while the smoke/values use the no-slash Azure KV names.
