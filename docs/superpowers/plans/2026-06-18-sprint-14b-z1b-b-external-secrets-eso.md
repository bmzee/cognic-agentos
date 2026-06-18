# Sprint 14B-Z1b-b — External secrets (ESO-first) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a conditional, default-off ESO `ExternalSecret` template to the AgentOS kernel Helm chart that populates the existing 2-key bootstrap Secret from an external store, behind a three-mode mutually-exclusive secret-source model, validated by a fifth snapshot/kubeconform CI scenario.

**Architecture:** Pure additive chart work on the Z1b-a chart at `infra/charts/agentos/`. A new `templates/externalsecret.yaml` (`external-secrets.io/v1`) produces the `agentos.secretName` Secret; `agentos.secretName` gains an ESO arm + a `validateSecretSource` mutual-exclusion guard; `values.yaml`/`values.schema.json` gain the `externalSecrets` block; the CI gate goes from four to five scenarios. No `src/` change — **CC stays 131**.

**Tech Stack:** Helm v4.2.2 (primary) + v3.16.3 (compat), kubeconform v0.8.0, External Secrets Operator (`external-secrets.io/v1`), pytest (snapshot parametrization), GitHub Actions.

---

## File structure

- Create: `infra/charts/agentos/templates/externalsecret.yaml` — the conditional `ExternalSecret`.
- Modify: `infra/charts/agentos/templates/_helpers.tpl` — `agentos.secretName` ESO arm + new `agentos.validateSecretSource`.
- Modify: `infra/charts/agentos/values.yaml` — the `externalSecrets` block.
- Modify: `infra/charts/agentos/values.schema.json` — `externalSecrets` shape + root-level 3-mode `allOf` (drop the in-`secrets` `else`).
- Create: `infra/charts/agentos/ci/snapshot-values-externalsecret.yaml` — the 5th scenario overlay.
- Create: `tests/unit/infra/helm/agentos_rendered_externalsecret.yaml` — machine-generated snapshot.
- Modify: `tests/unit/infra/test_helm_chart.py` — `_SCENARIOS` → 5.
- Modify: `.github/workflows/python.yml` — helm-chart job → 5 scenarios + ExternalSecret CRD handling.
- Modify: `docs/adrs/ADR-024-deployment-substrate-helm-packaging.md`, `docs/AS_BUILT_CAPABILITY_MAP.md`, `AGENTS.md`, `docs/operator-runbooks/helm-chart-production-install.md`.

---

## Task 1: ExternalSecret template + secret-source helpers + values + schema

**Files:**
- Create: `infra/charts/agentos/templates/externalsecret.yaml`
- Modify: `infra/charts/agentos/templates/_helpers.tpl`
- Modify: `infra/charts/agentos/values.yaml`
- Modify: `infra/charts/agentos/values.schema.json`

- [ ] **Step 1: Add the `externalSecrets` block to `values.yaml`** (append after the `serviceMonitor:` block at the end of the file)

```yaml

# --- Sprint 14B-Z1b-b: external secrets (ESO ExternalSecret, conditional, default OFF) ---
externalSecrets:
  enabled: false
  targetSecretName: ""           # default <fullname>-secrets (turnkey; override only if you need a fixed name)
  refreshInterval: 1h
  secretStoreRef:
    name: ""                     # REQUIRED when enabled — an operator-owned SecretStore/ClusterSecretStore (the chart never creates it)
    kind: SecretStore            # SecretStore | ClusterSecretStore
  data:
    databaseUrl:
      remoteRef:
        key: ""                  # REQUIRED when enabled — remote key holding COGNIC_DATABASE_URL
        property: ""             # optional — property within the remote secret
    vaultToken:
      remoteRef:
        key: ""                  # REQUIRED when enabled — remote key holding COGNIC_VAULT_TOKEN
        property: ""             # optional
```

- [ ] **Step 2: Add `agentos.validateSecretSource` and extend `agentos.secretName` in `_helpers.tpl`**

Replace the existing `agentos.secretName` define:

```
{{- define "agentos.secretName" -}}
{{- if .Values.secrets.existingSecret -}}{{ .Values.secrets.existingSecret }}
{{- else if .Values.secrets.create -}}{{ include "agentos.fullname" . }}-secrets
{{- else -}}{{ fail "secrets: set secrets.create=true (smoke/dev, with databaseUrl+vaultToken) OR secrets.existingSecret=<name> (production)" }}
{{- end -}}
{{- end -}}
```

with (note: `agentos.secretName` invokes the validator FIRST so the mutual-exclusion guard fires at every secret-wiring site — `deployment.yaml`, `migration-job.yaml`, and `externalsecret.yaml`):

```
{{/*
Refuse an ambiguous secret source: at most one of secrets.create / secrets.existingSecret /
externalSecrets.enabled. (At-least-one is enforced by the terminal fail in agentos.secretName.)
*/}}
{{- define "agentos.validateSecretSource" -}}
{{- $n := 0 -}}
{{- if .Values.externalSecrets.enabled -}}{{- $n = add1 $n -}}{{- end -}}
{{- if .Values.secrets.existingSecret -}}{{- $n = add1 $n -}}{{- end -}}
{{- if .Values.secrets.create -}}{{- $n = add1 $n -}}{{- end -}}
{{- if gt $n 1 -}}{{- fail "secrets: configure exactly one source — secrets.create (dev) XOR secrets.existingSecret XOR externalSecrets.enabled" -}}{{- end -}}
{{- end -}}

{{- define "agentos.secretName" -}}
{{- include "agentos.validateSecretSource" . -}}
{{- if .Values.externalSecrets.enabled -}}
  {{- .Values.externalSecrets.targetSecretName | default (printf "%s-secrets" (include "agentos.fullname" .)) -}}
{{- else if .Values.secrets.existingSecret -}}{{ .Values.secrets.existingSecret }}
{{- else if .Values.secrets.create -}}{{ include "agentos.fullname" . }}-secrets
{{- else -}}{{ fail "secrets: set secrets.create=true (smoke/dev, with databaseUrl+vaultToken) OR secrets.existingSecret=<name> OR externalSecrets.enabled=true (production)" }}
{{- end -}}
{{- end -}}
```

- [ ] **Step 3: Create `infra/charts/agentos/templates/externalsecret.yaml`**

```yaml
{{- if .Values.externalSecrets.enabled }}
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: {{ include "agentos.fullname" . }}
  labels:
    {{- include "agentos.labels" . | nindent 4 }}
spec:
  refreshInterval: {{ .Values.externalSecrets.refreshInterval }}
  secretStoreRef:
    name: {{ required "externalSecrets.secretStoreRef.name is required when externalSecrets.enabled=true" .Values.externalSecrets.secretStoreRef.name }}
    kind: {{ .Values.externalSecrets.secretStoreRef.kind }}
  target:
    name: {{ include "agentos.secretName" . }}
    creationPolicy: Owner
  data:
    - secretKey: COGNIC_DATABASE_URL
      remoteRef:
        key: {{ required "externalSecrets.data.databaseUrl.remoteRef.key is required when externalSecrets.enabled=true" .Values.externalSecrets.data.databaseUrl.remoteRef.key }}
        {{- with .Values.externalSecrets.data.databaseUrl.remoteRef.property }}
        property: {{ . }}
        {{- end }}
    - secretKey: COGNIC_VAULT_TOKEN
      remoteRef:
        key: {{ required "externalSecrets.data.vaultToken.remoteRef.key is required when externalSecrets.enabled=true" .Values.externalSecrets.data.vaultToken.remoteRef.key }}
        {{- with .Values.externalSecrets.data.vaultToken.remoteRef.property }}
        property: {{ . }}
        {{- end }}
{{- end }}
```

- [ ] **Step 4: Extend `infra/charts/agentos/values.schema.json`** — three edits:

(4a) In the `"secrets"` object, **remove the `"else"` clause** (it requires `existingSecret` when `create=false`, which is incompatible with ESO mode where `create=false` + empty `existingSecret`). Keep `if`/`then`. The `secrets` block becomes:

```json
    "secrets": {
      "type": "object",
      "required": ["create"],
      "properties": {
        "create": { "type": "boolean" },
        "existingSecret": { "type": "string" },
        "databaseUrl": { "type": "string" },
        "vaultToken": { "type": "string" }
      },
      "if": { "properties": { "create": { "const": true } } },
      "then": { "required": ["databaseUrl", "vaultToken"], "properties": { "databaseUrl": { "minLength": 1 }, "vaultToken": { "minLength": 1 } } }
    },
```

(4b) Add the `"externalSecrets"` property to the root `"properties"` object (e.g. after `"serviceMonitor"`):

```json
    "externalSecrets": {
      "type": "object",
      "properties": {
        "enabled": { "type": "boolean" },
        "targetSecretName": { "type": "string" },
        "refreshInterval": { "type": "string" },
        "secretStoreRef": {
          "type": "object",
          "properties": {
            "name": { "type": "string" },
            "kind": { "type": "string", "enum": ["SecretStore", "ClusterSecretStore"] }
          }
        },
        "data": {
          "type": "object",
          "properties": {
            "databaseUrl": { "type": "object", "properties": { "remoteRef": { "type": "object", "properties": { "key": { "type": "string" }, "property": { "type": "string" } } } } },
            "vaultToken": { "type": "object", "properties": { "remoteRef": { "type": "object", "properties": { "key": { "type": "string" }, "property": { "type": "string" } } } } }
          }
        }
      }
    }
```

(4c) Add a root-level `"allOf"` (sibling of the root `"properties"`/`"required"`, at the top object) encoding the 3-mode logic — mutual exclusion (3 `not` clauses), the relocated "create=false ∧ not-ESO ⇒ existingSecret required", and the ESO enabled-mode required fields:

```json
  "allOf": [
    { "not": { "required": ["secrets"], "properties": { "secrets": { "required": ["create", "existingSecret"], "properties": { "create": { "const": true }, "existingSecret": { "minLength": 1 } } } } } },
    { "not": { "allOf": [
      { "required": ["externalSecrets"], "properties": { "externalSecrets": { "required": ["enabled"], "properties": { "enabled": { "const": true } } } } },
      { "required": ["secrets"], "properties": { "secrets": { "required": ["create"], "properties": { "create": { "const": true } } } } }
    ] } },
    { "not": { "allOf": [
      { "required": ["externalSecrets"], "properties": { "externalSecrets": { "required": ["enabled"], "properties": { "enabled": { "const": true } } } } },
      { "required": ["secrets"], "properties": { "secrets": { "required": ["existingSecret"], "properties": { "existingSecret": { "minLength": 1 } } } } }
    ] } },
    {
      "if": { "allOf": [
        { "required": ["secrets"], "properties": { "secrets": { "required": ["create"], "properties": { "create": { "const": false } } } } },
        { "not": { "required": ["externalSecrets"], "properties": { "externalSecrets": { "required": ["enabled"], "properties": { "enabled": { "const": true } } } } } }
      ] },
      "then": { "properties": { "secrets": { "required": ["existingSecret"], "properties": { "existingSecret": { "minLength": 1 } } } } }
    },
    {
      "if": { "required": ["externalSecrets"], "properties": { "externalSecrets": { "required": ["enabled"], "properties": { "enabled": { "const": true } } } } },
      "then": { "properties": { "externalSecrets": {
        "required": ["secretStoreRef", "data"],
        "properties": {
          "secretStoreRef": { "required": ["name"], "properties": { "name": { "minLength": 1 } } },
          "data": { "required": ["databaseUrl", "vaultToken"], "properties": {
            "databaseUrl": { "required": ["remoteRef"], "properties": { "remoteRef": { "required": ["key"], "properties": { "key": { "minLength": 1 } } } } },
            "vaultToken": { "required": ["remoteRef"], "properties": { "remoteRef": { "required": ["key"], "properties": { "key": { "minLength": 1 } } } } }
          } }
        }
      } } }
    }
  ],
```

After editing, confirm the JSON is valid: `python -c "import json; json.load(open('infra/charts/agentos/values.schema.json'))"`.

- [ ] **Step 5: Verify the guards + default-unchanged + lint**

```bash
cd /Users/bmz/development/cognic-agentos
# (a) ESO scenario renders the ExternalSecret + NO bootstrap Secret (create disabled):
helm template rel infra/charts/agentos --namespace cognic \
  --set secrets.create=false --set externalSecrets.enabled=true \
  --set externalSecrets.secretStoreRef.name=s --set externalSecrets.data.databaseUrl.remoteRef.key=k1 \
  --set externalSecrets.data.vaultToken.remoteRef.key=k2 \
  | grep -E 'kind: (ExternalSecret|Secret)$'    # expect ONLY "kind: ExternalSecret"
# (b) mutual-exclusion fails (create=true + ESO):
helm template rel infra/charts/agentos --namespace cognic \
  --set secrets.create=true --set externalSecrets.enabled=true 2>&1 | grep -i "exactly one source" && echo "GUARD OK"
# (c) required field fails (ESO enabled, empty store name):
helm template rel infra/charts/agentos --namespace cognic \
  --set secrets.create=false --set externalSecrets.enabled=true 2>&1 | grep -i "secretStoreRef.name is required" && echo "REQUIRED OK"
# (d) schema rejects mutual-exclusion + empty-required at lint time:
helm lint infra/charts/agentos --set secrets.create=true --set externalSecrets.enabled=true 2>&1 | grep -i "don't validate\|schema" && echo "SCHEMA REJECTS DUAL"
helm lint infra/charts/agentos --set secrets.create=false --set externalSecrets.enabled=true 2>&1 | grep -i "don't validate\|schema" && echo "SCHEMA REJECTS EMPTY-REQ"
# (e) default render unchanged (the existing default snapshot still matches):
helm template rel infra/charts/agentos --namespace cognic -f infra/charts/agentos/ci/snapshot-values.yaml > /tmp/def.yaml
printf '%s\n' "$(cat /tmp/def.yaml)" | diff -u tests/unit/infra/helm/agentos_rendered.yaml - && echo "DEFAULT UNCHANGED ✓"
# (f) base lint clean:
helm lint infra/charts/agentos -f infra/charts/agentos/ci/snapshot-values.yaml
```
Expected: (a) only `kind: ExternalSecret`; (b) `GUARD OK`; (c) `REQUIRED OK`; (d) both `SCHEMA REJECTS …`; (e) `DEFAULT UNCHANGED ✓`; (f) `0 chart(s) failed`.

- [ ] **Step 6: Commit** (controller-gated — the implementer does NOT stage/commit; the controller runs the halt-before-commit gate then `git diff --cached --check && git commit`)

```bash
git add infra/charts/agentos/templates/externalsecret.yaml infra/charts/agentos/templates/_helpers.tpl infra/charts/agentos/values.yaml infra/charts/agentos/values.schema.json
git diff --cached --check
git commit -m "feat(deploy): Sprint 14B-Z1b-b T1 — conditional ExternalSecret template + 3-mode secret source (ADR-024)"
```

---

## Task 2: Fifth snapshot scenario + pytest parametrization

**Files:**
- Create: `infra/charts/agentos/ci/snapshot-values-externalsecret.yaml`
- Create: `tests/unit/infra/helm/agentos_rendered_externalsecret.yaml` (machine-generated)
- Modify: `tests/unit/infra/test_helm_chart.py`

- [ ] **Step 1: Create the overlay** `infra/charts/agentos/ci/snapshot-values-externalsecret.yaml` (note: the base sets `secrets.create: true`; ESO is mutually exclusive, so this overlay MUST disable create)

```yaml
# ExternalSecret-on scenario overlay (layered over ci/snapshot-values.yaml).
# The base sets secrets.create=true; ESO is mutually exclusive with it, so disable create here.
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
```

- [ ] **Step 2: Add the 5th `_SCENARIOS` param in `tests/unit/infra/test_helm_chart.py`** (append inside the `_SCENARIOS` list, after the `servicemonitor` param)

```python
    pytest.param(
        [_SNAPSHOT_VALUES, _CI / "snapshot-values-externalsecret.yaml"],
        _HELM_DIR / "agentos_rendered_externalsecret.yaml",
        id="externalsecret",
    ),
```

- [ ] **Step 3: Generate + commit the snapshot.** The byte-snapshot test writes the snapshot on first run when absent, then fails asking you to commit it. Run it once to generate:

```bash
cd /Users/bmz/development/cognic-agentos
uv run pytest "tests/unit/infra/test_helm_chart.py::test_rendered_chart_matches_snapshot[externalsecret]" -v
```
Expected: first run FAILS with "snapshot created at …agentos_rendered_externalsecret.yaml — review and commit it". Then inspect the generated file: it MUST contain `kind: ExternalSecret` and MUST NOT contain a bootstrap `kind: Secret` (create=false). Re-run to confirm it now PASSES.

- [ ] **Step 4: Verify all 5 pass**

```bash
uv run pytest tests/unit/infra/test_helm_chart.py -v
```
Expected: `6 passed` (5 snapshot params + `test_chart_lints_clean`), 0 skipped (Helm 4.2.2 local).

- [ ] **Step 5: Commit** (controller-gated)

```bash
git add infra/charts/agentos/ci/snapshot-values-externalsecret.yaml tests/unit/infra/helm/agentos_rendered_externalsecret.yaml tests/unit/infra/test_helm_chart.py
git diff --cached --check
git commit -m "test(deploy): Sprint 14B-Z1b-b T2 — 5th externalsecret snapshot scenario (ADR-024)"
```

---

## Task 3: CI `helm-chart` job — five scenarios + ExternalSecret CRD schema

**Files:** Modify `.github/workflows/python.yml`

- [ ] **Step 1: Network-confirm whether the ExternalSecret CRD schema is in the catalog** (the executor has network; mirror the Z1b-a Route finding). Run:

```bash
curl -fsS "https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/external-secrets.io/ExternalSecret_v1.json" -o /dev/null && echo "ExternalSecret_v1 PRESENT" || echo "ExternalSecret_v1 ABSENT"
```
Record the result. If PRESENT → keep `-skip Route` (ExternalSecret stays schema-validated). If ABSENT → the skip scope becomes `-skip Route,ExternalSecret`.

- [ ] **Step 2: Extend BOTH loops in the `helm-chart` job** (the Helm-4 primary loop and the Helm-3 compat loop) to include the 5th scenario, and set the kubeconform `-skip` scope per Step 1. In the primary loop, add the externalsecret entry to the `for s in …` list:

```bash
                   "_externalsecret|-f infra/charts/agentos/ci/snapshot-values-externalsecret.yaml"; do
```
and in the Helm-3 compat loop add to its `for overlay in …` list:

```bash
                         "-f infra/charts/agentos/ci/snapshot-values-externalsecret.yaml"; do
```
Set the kubeconform `-skip` flag in BOTH loops to the Step-1 result (`-skip Route` if ExternalSecret present; `-skip Route,ExternalSecret` if absent). Update the in-CI comment to record the ExternalSecret catalog outcome alongside the existing Route note.

- [ ] **Step 3: Verify locally** (run the full 5-scenario primary loop under `bash`; `$overlay` must word-split, so use `bash`)

```bash
cd /Users/bmz/development/cognic-agentos
bash -c '
set -uo pipefail
BASE="infra/charts/agentos/ci/snapshot-values.yaml"
CRD="https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"
SKIP="<Route or Route,ExternalSecret per Step 1>"
for s in "|" "_ingress|-f infra/charts/agentos/ci/snapshot-values-ingress.yaml" \
         "_route|-f infra/charts/agentos/ci/snapshot-values-route.yaml" \
         "_servicemonitor|-f infra/charts/agentos/ci/snapshot-values-servicemonitor.yaml" \
         "_externalsecret|-f infra/charts/agentos/ci/snapshot-values-externalsecret.yaml"; do
  suffix="${s%%|*}"; overlay="${s#*|}"; snap="tests/unit/infra/helm/agentos_rendered${suffix}.yaml"
  helm template rel infra/charts/agentos --namespace cognic -f "$BASE" $overlay > /tmp/raw.yaml
  printf "%s\n" "$(cat /tmp/raw.yaml)" > /tmp/rendered.yaml
  diff -q "$snap" /tmp/rendered.yaml && echo "${suffix:-_default}: MATCH"
  kubeconform -strict -summary -kubernetes-version 1.27.0 -schema-location default -schema-location "$CRD" -skip "$SKIP" /tmp/rendered.yaml
done'
```
Expected: all 5 MATCH; kubeconform Valid for all (the externalsecret scenario either Valid via the ExternalSecret schema, or 1 Skipped if `-skip` includes ExternalSecret).

- [ ] **Step 4: Commit** (controller-gated)

```bash
git add .github/workflows/python.yml
git diff --cached --check
git commit -m "ci(deploy): Sprint 14B-Z1b-b T3 — 5-scenario helm gate + ExternalSecret CRD schema (<present|scoped-skip per Step 1>) (ADR-024)"
```

---

## Task 4: Docs

**Files:**
- Modify: `docs/adrs/ADR-024-deployment-substrate-helm-packaging.md`, `docs/AS_BUILT_CAPABILITY_MAP.md`, `AGENTS.md`, `docs/operator-runbooks/helm-chart-production-install.md`

- [ ] **Step 1: Add `## Sprint 14B-Z1b-b amendment` to ADR-024** (amend-by-addition, after the Z1b-a amendment, at file end). Cover: the conditional `ExternalSecret` (`external-secrets.io/v1`, default off) producing the `agentos.secretName` Secret with the EXACT 2 keys; the three-mode mutually-exclusive secret source (`create` | `existingSecret` | `externalSecrets.enabled`) via the `agentos.validateSecretSource` guard + the root-level schema `allOf` (and the dropped in-`secrets` `else`, with rationale — ESO mode is `create=false` + empty `existingSecret`); `secretStoreRef` operator-owned (default `SecretStore`); `targetSecretName` default `<fullname>-secrets`; `refreshInterval: 1h`; `creationPolicy: Owner`; the fifth snapshot scenario; the ExternalSecret CRD-schema outcome (per T3 Step 1 — schema-validated, or scoped `-skip Route,ExternalSecret` on catalog absence). CC stays 131 / no kernel change / no migration.

- [ ] **Step 2: Update `docs/AS_BUILT_CAPABILITY_MAP.md`** — patch BOTH surfaces (the Z1b-a lesson): (a) the **Pillar 5 row** current-state ("external secrets ESO DONE 14B-Z1b-b" added; "external secrets" removed from the remaining-gap; sprint-owner Z1b-b DONE) + the evidence cell pointer; (b) forward-item-7's `14B-Z1b-b` sub-item → `DONE 2026-06-18` with a one-line description, leaving `Z1b-c`/`Z1b-d` forward. Amend-by-addition; preserve history.

- [ ] **Step 3: Add an AGENTS.md note** near the Z1b-a deployment-substrate note: Z1b-b added the conditional ESO `ExternalSecret` template + the 3-mode mutually-exclusive secret source (CC 131, no kernel change).

- [ ] **Step 4: Add an "External secrets (ESO)" section to `docs/operator-runbooks/helm-chart-production-install.md`** — enabling `externalSecrets`, referencing an operator-owned `SecretStore`/`ClusterSecretStore` (the chart never creates it), mapping the 2 remote refs; the three-mode mutual-exclusivity; a primary worked example **Azure Key Vault + AKS workload identity** (aligns with Z1b-d), AWS Secrets Manager + HashiCorp Vault as secondary notes; and that ESO (the `external-secrets.io` CRDs) must be installed in the cluster.

- [ ] **Step 5: Verify docs + commit** (controller-gated)

Run: `rg -n "Z1b-b" docs/adrs/ADR-024-deployment-substrate-helm-packaging.md docs/AS_BUILT_CAPABILITY_MAP.md AGENTS.md | head` and confirm balanced fences in the runbook (`grep -c '^[[:space:]]*```' docs/operator-runbooks/helm-chart-production-install.md` is even). Then:
```bash
git add docs/adrs/ADR-024-deployment-substrate-helm-packaging.md docs/AS_BUILT_CAPABILITY_MAP.md AGENTS.md docs/operator-runbooks/helm-chart-production-install.md
git diff --cached --check
git commit -m "docs(deploy): Sprint 14B-Z1b-b T4 — ADR-024 amendment + AS_BUILT/AGENTS + runbook external-secrets section (ADR-024)"
```

---

## Task 5: Closeout

**Files:** none (verification only)

- [ ] **Step 1: Confirm no kernel change (CC stays 131)**

Run: `[ -z "$(git diff --stat main..HEAD -- src/)" ] && echo "src/ UNTOUCHED ✓ (CC 131)" || git diff --stat main..HEAD -- src/`

- [ ] **Step 2: Lint + format + types**

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
```
Expected: all clean (the only new Python is the snapshot-test parametrization).

- [ ] **Step 3: Full unit suite + the 131-module gate (the one authoritative sweep)**

```bash
uv run coverage run --branch -m pytest tests/unit -m "not postgres and not oracle"
uv run coverage json -o coverage.json
uv run python tools/check_critical_coverage.py
```
Expected: full suite passes; `Per-file critical-controls coverage gate: passed` (131/131).

- [ ] **Step 4: The five-scenario helm gate green locally**

```bash
helm lint infra/charts/agentos -f infra/charts/agentos/ci/snapshot-values.yaml
uv run pytest tests/unit/infra/test_helm_chart.py -v   # 6 passed (5 snapshot params + lint)
```
Plus the T3 Step-3 loop (5 scenarios → byte-diff + kubeconform). State which CRD-schema path was used for ExternalSecret (schema-location vs scoped-skip).

- [ ] **Step 5: Final stop — no commit here** (T1–T4 already committed). Report the full-gate evidence + the ExternalSecret CRD-schema outcome, and hold for the PR/merge tokens.

---

## Self-review notes

- **Spec coverage:** §1 template (T1 Step 3) · §2 three-mode model + validateSecretSource + secretName arm (T1 Step 2) · §3 values + schema incl. enabled-mode required + mutual exclusion (T1 Steps 1, 4) · §4 fifth scenario + version-gated pytest (T2) + CI 5-scenario gate (T3) · §5 ExternalSecret CRD schema-location-first / scoped-skip fallback (T3 Steps 1-2) · §6 docs + posture (T4 + T5). The default render is explicitly verified UNCHANGED in T1 Step 5(e).
- **No placeholders:** every template, values block, schema fragment, the parametrized test param, the overlay, and both CI loop edits are shown in full. The one network-dependent value (whether `ExternalSecret_v1.json` is in the catalog) is a concrete T3 Step-1 probe with both branches specified + the closeout records the path used (exactly the Z1b-a Route pattern).
- **Type/name consistency:** `agentos.fullname`/`labels`/`secretName` reused; the Service port name `http` unchanged; the snapshot filename `agentos_rendered_externalsecret.yaml` is identical across T2 (pytest), T3 (CI loop), and the file-structure map; the scenario id/suffix `externalsecret`/`_externalsecret` matches between the pytest `_SCENARIOS` id and the CI loop suffix. The schema `allOf` clauses reference only `secrets.*` + `externalSecrets.*` (the two top-level secret-source props).
- **Critical interaction handled:** the base `ci/snapshot-values.yaml` sets `secrets.create=true`; the externalsecret overlay overrides `secrets.create=false` so the mutual-exclusion guard does not fire (T2 Step 1), and the dropped in-`secrets` `else` (T1 Step 4a) is what lets ESO mode (`create=false` + empty `existingSecret`) pass the schema.
