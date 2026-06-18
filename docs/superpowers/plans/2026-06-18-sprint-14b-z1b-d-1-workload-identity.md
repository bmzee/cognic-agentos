# Sprint 14B-Z1b-d-1 — Generic chart workload-identity readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose two generic chart hooks — `serviceAccount.annotations` + `podLabels` — so the AgentOS Helm chart's ServiceAccount can federate to any cloud IAM identity (Azure WI / GKE WI / AWS IRSA), with cloud-specifics in the runbook, validated by a 7th snapshot scenario.

**Architecture:** Pure additive chart/docs work on the merged Z1b-c chart at `infra/charts/agentos/`. `serviceaccount.yaml` gains a `{{- with }}` annotations hook; `deployment.yaml` merges `podLabels` into the pod **template** labels only (the immutable `.spec.selector.matchLabels` stays untouched); `values.yaml`/`values.schema.json` gain generic maps; the CI gate goes 6→7 scenarios. **CC stays 131, no kernel change, no migration.**

**Tech Stack:** Helm v4.2.2 (+ v3.16.3 compat), kubeconform v0.8.0, pytest, GitHub Actions.

---

## File structure

- Modify: `infra/charts/agentos/templates/serviceaccount.yaml` — the `annotations` hook.
- Modify: `infra/charts/agentos/templates/deployment.yaml` — the `podLabels` merge (template labels only).
- Modify: `infra/charts/agentos/values.yaml` — `serviceAccount.annotations` + `podLabels`.
- Modify: `infra/charts/agentos/values.schema.json` — the two generic-map shapes.
- Create: `infra/charts/agentos/ci/snapshot-values-workload-identity.yaml` — the 7th overlay (Azure WI fixture).
- Create: `tests/unit/infra/helm/agentos_rendered_workload-identity.yaml` — machine-generated snapshot.
- Modify: `tests/unit/infra/test_helm_chart.py` — `_SCENARIOS` 6→7.
- Modify: `.github/workflows/python.yml` — helm-chart job 6→7 scenarios.
- Modify: `docs/adrs/ADR-024-…md`, `docs/AS_BUILT_CAPABILITY_MAP.md`, `AGENTS.md`, `docs/operator-runbooks/helm-chart-production-install.md`.

---

## Task 1: The two generic hooks (SA annotations + podLabels) + values + schema

**Files:**
- Modify: `infra/charts/agentos/templates/serviceaccount.yaml`
- Modify: `infra/charts/agentos/templates/deployment.yaml`
- Modify: `infra/charts/agentos/values.yaml`
- Modify: `infra/charts/agentos/values.schema.json`

- [ ] **Step 1: Add the `annotations` hook to `serviceaccount.yaml`** — replace the whole file with:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "agentos.fullname" . }}
  labels:
    {{- include "agentos.labels" . | nindent 4 }}
  {{- with .Values.serviceAccount.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
automountServiceAccountToken: false
```

- [ ] **Step 2: Merge `podLabels` into the pod TEMPLATE labels in `deployment.yaml`** (the `.spec.template.metadata.labels` block at ~line 14-15). Change:

```yaml
  template:
    metadata:
      labels:
        {{- include "agentos.selectorLabels" . | nindent 8 }}
```
to:
```yaml
  template:
    metadata:
      labels:
        {{- include "agentos.selectorLabels" . | nindent 8 }}
        {{- with .Values.podLabels }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
```
**Do NOT touch `.spec.selector.matchLabels` (line ~11)** — it stays `agentos.selectorLabels` (the immutable selector). `podLabels` only add to the pod's metadata labels.

- [ ] **Step 3: Add the two blocks to `values.yaml`** (append after the `otel:` block at the end)

```yaml

# --- Sprint 14B-Z1b-d-1: generic cloud workload-identity hooks (default empty → render nothing) ---
serviceAccount:
  annotations: {}     # cloud workload-identity SA annotation (e.g. azure.workload.identity/client-id) — see the runbook
podLabels: {}         # extra pod-template labels (e.g. azure.workload.identity/use: "true") — merged into the pod labels, NOT the selector
```

- [ ] **Step 4: Extend `values.schema.json`** — add two properties to the root `"properties"` object (after `"otel"`):

```json
    "serviceAccount": {
      "type": "object",
      "properties": {
        "annotations": { "type": "object" }
      }
    },
    "podLabels": { "type": "object" }
```
Confirm JSON parses: `python3 -c "import json; json.load(open('infra/charts/agentos/values.schema.json'))"`.

- [ ] **Step 5: Verify the hooks + the two critical invariants**

```bash
cd /Users/bmz/development/cognic-agentos
# (a) DEFAULT RENDER UNCHANGED (hooks default-empty → render nothing):
helm template rel infra/charts/agentos --namespace cognic -f infra/charts/agentos/ci/snapshot-values.yaml > /tmp/def.yaml
printf '%s\n' "$(cat /tmp/def.yaml)" | diff -u tests/unit/infra/helm/agentos_rendered.yaml - && echo "DEFAULT UNCHANGED ✓"
# (b) hooks render when set: the SA gets the annotation, the pod gets the extra label:
helm template rel infra/charts/agentos --namespace cognic \
  -f infra/charts/agentos/ci/snapshot-values.yaml \
  --set-string serviceAccount.annotations."azure\.workload\.identity/client-id"=abc \
  --set-string podLabels."azure\.workload\.identity/use"=true > /tmp/wi.yaml
grep -q 'azure.workload.identity/client-id: abc' /tmp/wi.yaml && echo "SA ANNOTATION ✓"
# (c) SELECTOR STABILITY: the podLabel is in the pod template labels but NOT in .spec.selector.matchLabels:
uv run python -c "
import yaml
docs = list(yaml.safe_load_all(open('/tmp/wi.yaml')))
dep = next(d for d in docs if d and d.get('kind') == 'Deployment')
sel = dep['spec']['selector']['matchLabels']
tpl = dep['spec']['template']['metadata']['labels']
assert 'azure.workload.identity/use' not in sel, f'LEAKED INTO SELECTOR: {sel}'
assert tpl.get('azure.workload.identity/use') == 'true', f'MISSING FROM POD LABELS: {tpl}'
print('SELECTOR STABLE ✓ (podLabel in template labels, NOT the selector)')
"
# (d) base lint clean:
helm lint infra/charts/agentos -f infra/charts/agentos/ci/snapshot-values.yaml
```
Expected: `DEFAULT UNCHANGED ✓`; `SA ANNOTATION ✓`; `SELECTOR STABLE ✓`; `0 chart(s) failed`.

- [ ] **Step 6: Commit** (controller-gated — `git diff --cached --check`)

```bash
git add infra/charts/agentos/templates/serviceaccount.yaml infra/charts/agentos/templates/deployment.yaml infra/charts/agentos/values.yaml infra/charts/agentos/values.schema.json
git diff --cached --check
git commit -m "feat(deploy): Sprint 14B-Z1b-d-1 T1 — generic SA-annotations + podLabels workload-identity hooks (ADR-024)"
```

---

## Task 2: The 7th `workload-identity` snapshot scenario

**Files:**
- Create: `infra/charts/agentos/ci/snapshot-values-workload-identity.yaml`
- Create: `tests/unit/infra/helm/agentos_rendered_workload-identity.yaml` (machine-generated)
- Modify: `tests/unit/infra/test_helm_chart.py`

- [ ] **Step 1: Create the overlay** `infra/charts/agentos/ci/snapshot-values-workload-identity.yaml` (the Azure WI **example fixture** — the chart values stay generic; only this test fixture names a cloud; no secret-mode change needed — the hooks are independent of the secret source, so the base `secrets.create:true` is fine)

```yaml
# Workload-identity-on scenario overlay (layered over ci/snapshot-values.yaml).
# Azure WI is the EXAMPLE fixture; the chart values (serviceAccount.annotations / podLabels)
# are cloud-agnostic maps — only this fixture + the runbook name a cloud.
serviceAccount:
  annotations:
    azure.workload.identity/client-id: 00000000-0000-0000-0000-000000000000
podLabels:
  azure.workload.identity/use: "true"
```

- [ ] **Step 2: Add the 7th `_SCENARIOS` param in `tests/unit/infra/test_helm_chart.py`** (append after the `otel-http` param)

```python
    pytest.param(
        [_SNAPSHOT_VALUES, _CI / "snapshot-values-workload-identity.yaml"],
        _HELM_DIR / "agentos_rendered_workload-identity.yaml",
        id="workload-identity",
    ),
```

- [ ] **Step 3: Generate + verify the snapshot**

```bash
uv run pytest "tests/unit/infra/test_helm_chart.py::test_rendered_chart_matches_snapshot[workload-identity]" -v
```
Expected: first run FAILS ("snapshot created … review and commit"). **Inspect** `agentos_rendered_workload-identity.yaml`: the ServiceAccount carries `annotations: {azure.workload.identity/client-id: …}`; the Deployment pod template labels include BOTH the selector labels AND `azure.workload.identity/use: "true"`; the Deployment `.spec.selector.matchLabels` does **NOT** contain the WI label. Re-run → PASS.

- [ ] **Step 4: Verify all 7 pass**

```bash
uv run pytest tests/unit/infra/test_helm_chart.py -v
```
Expected: `8 passed` (7 snapshot params + `test_chart_lints_clean`), 0 skipped (Helm v4.2.2 local).

- [ ] **Step 5: Commit** (controller-gated)

```bash
git add infra/charts/agentos/ci/snapshot-values-workload-identity.yaml tests/unit/infra/helm/agentos_rendered_workload-identity.yaml tests/unit/infra/test_helm_chart.py
git diff --cached --check
git commit -m "test(deploy): Sprint 14B-Z1b-d-1 T2 — 7th workload-identity snapshot scenario (ADR-024)"
```

---

## Task 3: CI `helm-chart` job — seven scenarios (no CRD change)

**Files:** Modify `.github/workflows/python.yml`

- [ ] **Step 1: Add the workload-identity scenario to BOTH loops.** Primary Helm-4 `for s in …` list — append:

```bash
                   "_workload-identity|-f infra/charts/agentos/ci/snapshot-values-workload-identity.yaml"; do
```
Helm-3 compat `for overlay in …` list — append:
```bash
                         "-f infra/charts/agentos/ci/snapshot-values-workload-identity.yaml"; do
```
Update both step names / section headers from "6 scenarios" to "7 scenarios". The `-skip Route` scope is **UNCHANGED** (the WI render is core kinds only — SA + Deployment — no CRD).

- [ ] **Step 2: Verify locally (the 7-scenario primary loop under `bash`, `set -euo pipefail`)**

```bash
cd /Users/bmz/development/cognic-agentos
bash -c '
set -euo pipefail
BASE="infra/charts/agentos/ci/snapshot-values.yaml"
CRD="https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"
for s in "|" "_ingress|-f infra/charts/agentos/ci/snapshot-values-ingress.yaml" \
         "_route|-f infra/charts/agentos/ci/snapshot-values-route.yaml" \
         "_servicemonitor|-f infra/charts/agentos/ci/snapshot-values-servicemonitor.yaml" \
         "_externalsecret|-f infra/charts/agentos/ci/snapshot-values-externalsecret.yaml" \
         "_otel-http|-f infra/charts/agentos/ci/snapshot-values-otel-http.yaml" \
         "_workload-identity|-f infra/charts/agentos/ci/snapshot-values-workload-identity.yaml"; do
  suffix="${s%%|*}"; overlay="${s#*|}"; snap="tests/unit/infra/helm/agentos_rendered${suffix}.yaml"
  helm template rel infra/charts/agentos --namespace cognic -f "$BASE" $overlay > /tmp/raw.yaml
  printf "%s\n" "$(cat /tmp/raw.yaml)" > /tmp/rendered.yaml
  diff -q "$snap" /tmp/rendered.yaml && echo "${suffix:-_default}: MATCH"
  kubeconform -strict -summary -kubernetes-version 1.27.0 -schema-location default -schema-location "$CRD" -skip Route /tmp/rendered.yaml
done'
```
Expected: all 7 MATCH; kubeconform Valid for all (workload-identity is core kinds → Valid, 0 skipped). Confirm the YAML parses with 7 jobs: `python3 -c "import yaml; d=yaml.safe_load(open('.github/workflows/python.yml')); print(list(d['jobs'].keys()))"`.

- [ ] **Step 3: Commit** (controller-gated)

```bash
git add .github/workflows/python.yml
git diff --cached --check
git commit -m "ci(deploy): Sprint 14B-Z1b-d-1 T3 — 7-scenario helm gate (workload-identity) (ADR-024)"
```

---

## Task 4: Docs

**Files:** Modify `docs/adrs/ADR-024-…md`, `docs/AS_BUILT_CAPABILITY_MAP.md`, `AGENTS.md`, `docs/operator-runbooks/helm-chart-production-install.md`

- [ ] **Step 1: Add `## Sprint 14B-Z1b-d-1 amendment` to ADR-024** (amend-by-addition, after the Z1b-c amendment, at file end). Cover: the two generic hooks (`serviceAccount.annotations` + `podLabels`); the **selector-stability invariant** (`podLabels` → `.spec.template.metadata.labels` only, NEVER `.spec.selector.matchLabels`); the cloud-agnostic chart (Azure/GKE/AWS only in examples); the 7th `workload-identity` scenario (core kinds — no CRD change, `-skip Route` unchanged); the default-render-unchanged guarantee; and the **Z1b-d split** (d-1 = chart WI-readiness here; **d-2** = the live AKS bring-up + cluster smoke). CC 131 / no kernel / no migration.

- [ ] **Step 2: Update `docs/AS_BUILT_CAPABILITY_MAP.md` — BOTH surfaces** (the Z1b-a/b/c lesson): (a) the **Pillar 5 row** (current-state: chart workload-identity readiness DONE 14B-Z1b-d-1; sprint-owner d-1 DONE / d-2 forward; an evidence-cell pointer); (b) **split forward-item-7's `14B-Z1b-d`** into `14B-Z1b-d-1 — chart workload-identity readiness: DONE 2026-06-18` + `14B-Z1b-d-2 — AKS bring-up + env-gated live cloud smoke (forward)` (the live cluster proof: chart-path-in-cluster incl. ServiceMonitor → Prometheus + live Langfuse OTLP ingestion). Amend-by-addition; preserve history.

- [ ] **Step 3: Add an AGENTS.md note** near the Z1b-c deployment-substrate note: Z1b-d-1 added the generic `serviceAccount.annotations` + `podLabels` workload-identity hooks (selector-stable; CC 131, no kernel change); Z1b-d-2 owns the live AKS exercise.

- [ ] **Step 4: Add a "Cloud workload identity" section to the runbook.** The two generic hooks; three cloud worked examples — **Azure WI** (`serviceAccount.annotations.azure.workload.identity/client-id` + `podLabels.azure.workload.identity/use: "true"`), **GKE workload identity** (`serviceAccount.annotations.iam.gke.io/gcp-service-account`, no pod label), **AWS IRSA** (`serviceAccount.annotations.eks.amazonaws.com/role-arn`, no pod label); the chart never creates the cloud IAM identity (operator provisions it + the federation); and that **the live cluster exercise is Z1b-d-2**.

- [ ] **Step 5: Verify docs + commit** (controller-gated). `rg -n "Z1b-d-1" docs/adrs/ADR-024-…md docs/AS_BUILT_CAPABILITY_MAP.md AGENTS.md | head`; balanced fences in the runbook + ADR.
```bash
git add docs/adrs/ADR-024-deployment-substrate-helm-packaging.md docs/AS_BUILT_CAPABILITY_MAP.md AGENTS.md docs/operator-runbooks/helm-chart-production-install.md
git diff --cached --check
git commit -m "docs(deploy): Sprint 14B-Z1b-d-1 T4 — ADR-024 amendment + AS_BUILT/AGENTS + runbook workload-identity section (ADR-024)"
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
Expected: all clean (the only Python touched is the snapshot-test parametrization).

- [ ] **Step 3: Full unit suite + the 131-module gate (the one authoritative sweep)**

```bash
uv run coverage run --branch -m pytest tests/unit -m "not postgres and not oracle"
uv run coverage json -o coverage.json
uv run python tools/check_critical_coverage.py
```
Expected: full suite passes; `Per-file critical-controls coverage gate: passed` (131/131).

- [ ] **Step 4: The seven-scenario helm gate green locally**

```bash
helm lint infra/charts/agentos -f infra/charts/agentos/ci/snapshot-values.yaml
uv run pytest tests/unit/infra/test_helm_chart.py -v   # 8 passed (7 snapshot params + lint)
```
Plus the T3 Step-2 loop (7 scenarios → byte-diff + kubeconform; workload-identity is core kinds → Valid). Re-confirm the **default render UNCHANGED** + the **selector-stability** check from T1 Step 5(a)/(c).

- [ ] **Step 5: Final stop — no commit here** (T1–T4 already committed). Report the full-gate evidence + confirm CC stays 131 + `src/` untouched, and hold for the PR/merge tokens.

---

## Self-review notes

- **Spec coverage:** §1 SA annotations hook (T1 Step 1) · §2 podLabels template-only merge + selector untouched (T1 Step 2 + the Step-5(c) selector-stability check) · §3 values + schema generic maps (T1 Steps 3-4) · §4 7th workload-identity scenario, Azure fixture (T2) + CI 6→7 (T3) · §6 runbook WI section (T4 Step 4) · §7 docs + posture (T4 + T5). The default render UNCHANGED is explicitly verified in T1 Step 5(a) + T5 Step 4.
- **No placeholders:** every template edit, values block, schema fragment, the overlay, the pytest param, the selector-stability yaml check, and both CI loop edits are shown in full.
- **Type/name consistency:** the snapshot filename `agentos_rendered_workload-identity.yaml` + the scenario id/suffix `workload-identity`/`_workload-identity` match across T2 (pytest), T3 (CI loop), and the file-structure map; `agentos.selectorLabels` (the stable selector) is reused unchanged for the selector; `serviceAccount.annotations` + `podLabels` are the only new generic map names.
- **The two critical invariants** are actively TESTED, not just asserted: (1) default render byte-unchanged (T1 Step 5a — the hooks are `{{- with }}`-gated on empty maps); (2) **selector stability** — T1 Step 5(c) parses the rendered Deployment and asserts the WI label is in `.spec.template.metadata.labels` but NOT in `.spec.selector.matchLabels`.
- **No CRD change** — the WI render is core kinds (SA + Deployment); the `-skip Route` scope is unchanged (T3).
