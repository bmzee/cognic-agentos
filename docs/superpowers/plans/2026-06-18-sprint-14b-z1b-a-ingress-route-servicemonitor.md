# Sprint 14B-Z1b-a — Ingress / Route / ServiceMonitor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add conditional (default-off) Kubernetes `Ingress` + OpenShift `Route` (with TLS) + `ServiceMonitor` templates to the AgentOS Helm chart, validated by a four-scenario CI snapshot + kubeconform gate.

**Architecture:** Pure additive chart work on the merged Z1a chart (`infra/charts/agentos/`). Three new conditional templates + their `values.yaml`/`values.schema.json` surfaces; the Z1a single byte-snapshot becomes four orthogonal snapshots (default + ingress-on + route-on + servicemonitor-on), each diffed (Helm-4.2.2-pinned per the Z1a `d015851` fix) + kubeconform'd (CRD schemas for Route/ServiceMonitor via `-schema-location`). **No kernel code — CC stays 131, no migration.**

**Tech Stack:** Helm v4 (templates), `kubeconform` + `datreeio/CRDs-catalog` schemas, pytest (parametrized byte-snapshot), GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-06-18-sprint-14b-z1b-a-ingress-route-servicemonitor-design.md`

**Prerequisites (local):** `helm` **v4.2.2** + `kubeconform` v0.8.0 on PATH (the snapshot byte-test is gated on the pinned `v4.2.2` generator). Network for the CRD-catalog schemas at T3 (the executor has it; the authoring env did not).

**Posture:** CC **131**; no `src/` change; no migration; no new on-gate module. The only Python touched is the snapshot-test parametrization (ruff/mypy).

---

## File structure

**Create (templates):**
- `infra/charts/agentos/templates/ingress.yaml` — conditional k8s Ingress.
- `infra/charts/agentos/templates/route.yaml` — conditional OpenShift Route.
- `infra/charts/agentos/templates/servicemonitor.yaml` — conditional Prometheus ServiceMonitor.

**Create (CI scenario overlays + snapshots):**
- `infra/charts/agentos/ci/snapshot-values-ingress.yaml`
- `infra/charts/agentos/ci/snapshot-values-route.yaml`
- `infra/charts/agentos/ci/snapshot-values-servicemonitor.yaml`
- `tests/unit/infra/helm/agentos_rendered_ingress.yaml` (generated)
- `tests/unit/infra/helm/agentos_rendered_route.yaml` (generated)
- `tests/unit/infra/helm/agentos_rendered_servicemonitor.yaml` (generated)

**Modify:**
- `infra/charts/agentos/values.yaml` — add `ingress`, `route`, `serviceMonitor` blocks.
- `infra/charts/agentos/values.schema.json` — add their shape validation.
- `tests/unit/infra/test_helm_chart.py` — parametrize the byte-snapshot test over the 4 scenarios.
- `.github/workflows/python.yml` — extend the `helm-chart` job to all 4 scenarios + CRD schemas.
- `docs/adrs/ADR-024-deployment-substrate-helm-packaging.md` — Z1b-a amendment.
- `docs/AS_BUILT_CAPABILITY_MAP.md` + `AGENTS.md` — Z1b-a notes.
- `docs/operator-runbooks/helm-chart-production-install.md` — external-access section.

---

## Task 1: The three templates + values + schema

**Files:**
- Create: `infra/charts/agentos/templates/ingress.yaml`, `route.yaml`, `servicemonitor.yaml`
- Modify: `infra/charts/agentos/values.yaml`, `infra/charts/agentos/values.schema.json`

- [ ] **Step 1: Create `infra/charts/agentos/templates/ingress.yaml`**

```yaml
{{- if .Values.ingress.enabled }}
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ include "agentos.fullname" . }}
  labels:
    {{- include "agentos.labels" . | nindent 4 }}
  {{- with .Values.ingress.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  {{- with .Values.ingress.className }}
  ingressClassName: {{ . }}
  {{- end }}
  {{- with .Values.ingress.tls }}
  tls:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  rules:
    {{- range .Values.ingress.hosts }}
    - host: {{ .host | quote }}
      http:
        paths:
          {{- range .paths }}
          - path: {{ .path }}
            pathType: {{ .pathType }}
            backend:
              service:
                name: {{ include "agentos.fullname" $ }}
                port:
                  name: http
          {{- end }}
    {{- end }}
{{- end }}
```

- [ ] **Step 2: Create `infra/charts/agentos/templates/route.yaml`**

```yaml
{{- if .Values.route.enabled }}
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: {{ include "agentos.fullname" . }}
  labels:
    {{- include "agentos.labels" . | nindent 4 }}
  {{- with .Values.route.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  host: {{ .Values.route.host | quote }}
  to:
    kind: Service
    name: {{ include "agentos.fullname" . }}
    weight: 100
  port:
    targetPort: http
  {{- if .Values.route.tls.enabled }}
  tls:
    termination: {{ .Values.route.tls.termination }}
    {{- with .Values.route.tls.insecureEdgeTerminationPolicy }}
    insecureEdgeTerminationPolicy: {{ . }}
    {{- end }}
    {{- with .Values.route.tls.certificate }}
    certificate: |
      {{- . | nindent 6 }}
    {{- end }}
    {{- with .Values.route.tls.key }}
    key: |
      {{- . | nindent 6 }}
    {{- end }}
    {{- with .Values.route.tls.caCertificate }}
    caCertificate: |
      {{- . | nindent 6 }}
    {{- end }}
  {{- end }}
{{- end }}
```

- [ ] **Step 3: Create `infra/charts/agentos/templates/servicemonitor.yaml`**

```yaml
{{- if .Values.serviceMonitor.enabled }}
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: {{ include "agentos.fullname" . }}
  labels:
    {{- include "agentos.labels" . | nindent 4 }}
    {{- with .Values.serviceMonitor.labels }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
spec:
  selector:
    matchLabels:
      {{- include "agentos.selectorLabels" . | nindent 6 }}
  endpoints:
    - port: http
      path: {{ .Values.apiPrefix }}{{ .Values.serviceMonitor.path }}
      interval: {{ .Values.serviceMonitor.interval }}
      scrapeTimeout: {{ .Values.serviceMonitor.scrapeTimeout }}
{{- end }}
```

- [ ] **Step 4: Append the three blocks to `infra/charts/agentos/values.yaml`** (after the `tmpSizeLimit` line at the end)

```yaml

# --- Sprint 14B-Z1b-a: external access + scrape (all conditional, default OFF) ---
ingress:
  enabled: false
  className: ""                 # operator: nginx / azure-application-gateway / ...
  annotations: {}               # cert-manager.io/cluster-issuer, nginx.*, etc.
  hosts:
    - host: agentos.example.com
      paths:
        - { path: /, pathType: Prefix }
  tls: []                        # [{ secretName: agentos-tls, hosts: [agentos.example.com] }] — existing-secret model

route:
  enabled: false
  host: agentos.example.com
  annotations: {}
  tls:
    enabled: true
    termination: edge            # edge | passthrough | reencrypt
    insecureEdgeTerminationPolicy: Redirect
    certificate: ""              # optional inline PEM (operators who need explicit cert material)
    key: ""                      # optional inline PEM
    caCertificate: ""            # optional inline PEM

serviceMonitor:
  enabled: false
  path: /metrics                 # joined with apiPrefix → /api/v1/metrics
  interval: 30s
  scrapeTimeout: 10s
  labels: {}                     # e.g. { release: kube-prometheus-stack } for Prometheus discovery
```

- [ ] **Step 5: Extend `infra/charts/agentos/values.schema.json`** — add three properties after the `podSecurityContext` line (inside `properties`, before the closing braces). Change:

```json
    "podSecurityContext": { "type": "object" }
```
to:
```json
    "podSecurityContext": { "type": "object" },
    "ingress": {
      "type": "object",
      "properties": {
        "enabled": { "type": "boolean" },
        "className": { "type": "string" },
        "annotations": { "type": "object" },
        "hosts": { "type": "array" },
        "tls": { "type": "array" }
      }
    },
    "route": {
      "type": "object",
      "properties": {
        "enabled": { "type": "boolean" },
        "host": { "type": "string" },
        "annotations": { "type": "object" },
        "tls": {
          "type": "object",
          "properties": {
            "enabled": { "type": "boolean" },
            "termination": { "type": "string", "enum": ["edge", "passthrough", "reencrypt"] },
            "insecureEdgeTerminationPolicy": { "type": "string", "enum": ["None", "Allow", "Redirect"] },
            "certificate": { "type": "string" },
            "key": { "type": "string" },
            "caCertificate": { "type": "string" }
          }
        }
      }
    },
    "serviceMonitor": {
      "type": "object",
      "properties": {
        "enabled": { "type": "boolean" },
        "path": { "type": "string", "pattern": "^/" },
        "interval": { "type": "string" },
        "scrapeTimeout": { "type": "string" },
        "labels": { "type": "object" }
      }
    }
```

- [ ] **Step 6: Verify — default render UNCHANGED, lint clean, each template renders only when enabled**

Run (the default render must NOT change — the new templates produce nothing when disabled, so the existing default snapshot still matches):
```bash
SV="-f infra/charts/agentos/ci/snapshot-values.yaml"
helm lint infra/charts/agentos $SV
# default: no Ingress/Route/ServiceMonitor:
helm template rel infra/charts/agentos --namespace cognic $SV | grep -cE "^kind: (Ingress|Route|ServiceMonitor)" || echo "0 (none when off ✓)"
# each renders when enabled:
helm template rel infra/charts/agentos --namespace cognic $SV --set ingress.enabled=true | grep -c "^kind: Ingress"
helm template rel infra/charts/agentos --namespace cognic $SV --set route.enabled=true | grep -c "^kind: Route"
helm template rel infra/charts/agentos --namespace cognic $SV --set serviceMonitor.enabled=true | grep -c "^kind: ServiceMonitor"
# the default byte-snapshot still matches (templates off → render unchanged):
helm template rel infra/charts/agentos --namespace cognic $SV > /tmp/raw.yaml
printf '%s\n' "$(cat /tmp/raw.yaml)" > /tmp/def.yaml
diff -u tests/unit/infra/helm/agentos_rendered.yaml /tmp/def.yaml && echo "default snapshot unchanged ✓"
```
Expected: `helm lint` 0 failed; default has `0` of those kinds; each `--set …enabled=true` prints `1`; the default snapshot diff is empty (the default render is unchanged — only the conditional templates were added).

- [ ] **Step 7: Commit**

```bash
git add infra/charts/agentos/templates/ingress.yaml infra/charts/agentos/templates/route.yaml infra/charts/agentos/templates/servicemonitor.yaml infra/charts/agentos/values.yaml infra/charts/agentos/values.schema.json
git commit -m "feat(deploy): Sprint 14B-Z1b-a T1 — conditional Ingress/Route/ServiceMonitor templates + values (ADR-024)"
```

---

## Task 2: Four-scenario snapshots + pytest parametrization

**Files:**
- Create: `infra/charts/agentos/ci/snapshot-values-ingress.yaml`, `-route.yaml`, `-servicemonitor.yaml`
- Modify: `tests/unit/infra/test_helm_chart.py`
- Create (generated): the three `tests/unit/infra/helm/agentos_rendered_<scenario>.yaml`

- [ ] **Step 1: Create `infra/charts/agentos/ci/snapshot-values-ingress.yaml`** (overlay — adds only the ingress block; cert-manager covered via annotations)

```yaml
# Ingress-on scenario overlay (layered over ci/snapshot-values.yaml).
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
    - secretName: agentos-tls
      hosts: [agentos.example.com]
```

- [ ] **Step 2: Create `infra/charts/agentos/ci/snapshot-values-route.yaml`** (overlay — Route, default edge TLS)

```yaml
# Route-on scenario overlay (layered over ci/snapshot-values.yaml).
route:
  enabled: true
  host: agentos.example.com
  annotations:
    haproxy.router.openshift.io/timeout: 60s
  tls:
    enabled: true
    termination: edge
    insecureEdgeTerminationPolicy: Redirect
```

- [ ] **Step 3: Create `infra/charts/agentos/ci/snapshot-values-servicemonitor.yaml`** (overlay)

```yaml
# ServiceMonitor-on scenario overlay (layered over ci/snapshot-values.yaml).
serviceMonitor:
  enabled: true
  interval: 30s
  scrapeTimeout: 10s
  labels:
    release: kube-prometheus-stack
```

- [ ] **Step 4: Parametrize the byte-snapshot test in `tests/unit/infra/test_helm_chart.py`** — replace the `_render()` function + the `test_rendered_chart_matches_snapshot` test. Add `_CI` + `_HELM_DIR` near the other module paths:

Change `_SNAPSHOT_VALUES`/`_SNAPSHOT` block to also define the dirs:
```python
_CI = _CHART_DIR / "ci"
_SNAPSHOT_VALUES = _CI / "snapshot-values.yaml"
_HELM_DIR = Path(__file__).resolve().parent / "helm"
_SNAPSHOT = _HELM_DIR / "agentos_rendered.yaml"

# (default + the three Z1b-a opt-in scenarios; each layered over the base values)
_SCENARIOS = [
    pytest.param([_SNAPSHOT_VALUES], _SNAPSHOT, id="default"),
    pytest.param(
        [_SNAPSHOT_VALUES, _CI / "snapshot-values-ingress.yaml"],
        _HELM_DIR / "agentos_rendered_ingress.yaml",
        id="ingress",
    ),
    pytest.param(
        [_SNAPSHOT_VALUES, _CI / "snapshot-values-route.yaml"],
        _HELM_DIR / "agentos_rendered_route.yaml",
        id="route",
    ),
    pytest.param(
        [_SNAPSHOT_VALUES, _CI / "snapshot-values-servicemonitor.yaml"],
        _HELM_DIR / "agentos_rendered_servicemonitor.yaml",
        id="servicemonitor",
    ),
]
```

Replace `_render()` to take the values-file list:
```python
def _render(values_files: list[Path]) -> str:
    cmd = ["helm", "template", "rel", str(_CHART_DIR), "--namespace", "cognic"]
    for vf in values_files:
        cmd += ["-f", str(vf)]
    raw = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    # `helm template` ends its combined output with a trailing blank line; normalize
    # to exactly one final newline so the committed snapshot is git-clean.
    return raw.rstrip("\n") + "\n"
```

Replace the snapshot test with the parametrized form:
```python
@pytest.mark.skipif(
    not _helm_matches_snapshot_version(),
    reason=f"byte-snapshot is generated by Helm {_SNAPSHOT_HELM_VERSION}; "
    "the pinned-Helm-4 CI `helm-chart` job is the authoritative drift gate",
)
@pytest.mark.parametrize(("values_files", "snapshot"), _SCENARIOS)
def test_rendered_chart_matches_snapshot(values_files: list[Path], snapshot: Path) -> None:
    rendered = _render(values_files)
    if not snapshot.exists():
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_text(rendered)
        pytest.fail(f"snapshot created at {snapshot} — review and commit it, then re-run")
    assert rendered == snapshot.read_text(), (
        f"rendered chart drifted from {snapshot}. If the drift is intentional, "
        f"regenerate via `rm {snapshot} && uv run pytest "
        f"tests/unit/infra/test_helm_chart.py::test_rendered_chart_matches_snapshot -x` "
        f"then commit the new snapshot."
    )
```
(`test_chart_lints_clean` is unchanged — lint is values-tolerant.)

- [ ] **Step 5: Generate the three new snapshots + run the suite green**

Run (the parametrized test creates the three missing snapshots on first run, then passes):
```bash
uv run pytest tests/unit/infra/test_helm_chart.py -x   # 1st: creates the 3 new snapshots, fails ("snapshot created")
uv run pytest tests/unit/infra/test_helm_chart.py -v    # 2nd: all 4 params + lint PASS
```
Inspect each new snapshot contains its kind:
```bash
grep -c "^kind: Ingress" tests/unit/infra/helm/agentos_rendered_ingress.yaml
grep -c "^kind: Route" tests/unit/infra/helm/agentos_rendered_route.yaml
grep -c "^kind: ServiceMonitor" tests/unit/infra/helm/agentos_rendered_servicemonitor.yaml
uv run ruff check tests/unit/infra/test_helm_chart.py && uv run ruff format --check tests/unit/infra/test_helm_chart.py
```
Expected: 2nd pytest → 5 passed (4 snapshot params + the lint test); each scenario snapshot carries its kind; ruff clean.

- [ ] **Step 6: Commit**

```bash
git add infra/charts/agentos/ci/snapshot-values-ingress.yaml infra/charts/agentos/ci/snapshot-values-route.yaml infra/charts/agentos/ci/snapshot-values-servicemonitor.yaml tests/unit/infra/test_helm_chart.py tests/unit/infra/helm/agentos_rendered_ingress.yaml tests/unit/infra/helm/agentos_rendered_route.yaml tests/unit/infra/helm/agentos_rendered_servicemonitor.yaml
git commit -m "test(deploy): Sprint 14B-Z1b-a T2 — 4-scenario snapshot parametrization (default/ingress/route/servicemonitor) (ADR-024)"
```

---

## Task 3: CI `helm-chart` job — four scenarios + CRD schemas

**Files:**
- Modify: `.github/workflows/python.yml` (the `helm-chart` job, lines ~592–615)

- [ ] **Step 1: Replace the primary-gate + helm3-gate steps with four-scenario loops**

Replace the steps from `# --- primary gate (Helm 4): …` (line ~592) through the final `kubeconform … (Helm 3 output)` step (line ~615) with:

```yaml
      # --- primary gate (Helm 4): lint + 4-scenario template/snapshot/kubeconform ---
      - name: helm lint (primary, Helm 4)
        run: helm lint infra/charts/agentos -f infra/charts/agentos/ci/snapshot-values.yaml
      - name: helm template + snapshot-drift + kubeconform (4 scenarios)
        run: |
          set -euo pipefail
          BASE="infra/charts/agentos/ci/snapshot-values.yaml"
          # Route + ServiceMonitor are CRDs; pull their schemas from the CRDs-catalog.
          CRD='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
          # "scenario-suffix|overlay-flag" ; default has no suffix + no overlay
          for s in "|" \
                   "_ingress|-f infra/charts/agentos/ci/snapshot-values-ingress.yaml" \
                   "_route|-f infra/charts/agentos/ci/snapshot-values-route.yaml" \
                   "_servicemonitor|-f infra/charts/agentos/ci/snapshot-values-servicemonitor.yaml"; do
            suffix="${s%%|*}"; overlay="${s#*|}"
            snap="tests/unit/infra/helm/agentos_rendered${suffix}.yaml"
            echo "::group::scenario ${suffix:-default}"
            helm template rel infra/charts/agentos --namespace cognic -f "$BASE" $overlay > /tmp/raw.yaml
            printf '%s\n' "$(cat /tmp/raw.yaml)" > /tmp/rendered.yaml
            diff -u "$snap" /tmp/rendered.yaml
            kubeconform -strict -summary -kubernetes-version 1.27.0 \
              -schema-location default -schema-location "$CRD" /tmp/rendered.yaml
            echo "::endgroup::"
          done
      # --- Helm 3 compatibility gate: render + schema ONLY (no byte-diff), 4 scenarios ---
      - name: helm3 lint + template + kubeconform (4 scenarios)
        run: |
          set -euo pipefail
          BASE="infra/charts/agentos/ci/snapshot-values.yaml"
          CRD='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
          helm3 lint infra/charts/agentos -f "$BASE"
          for overlay in "" \
                         "-f infra/charts/agentos/ci/snapshot-values-ingress.yaml" \
                         "-f infra/charts/agentos/ci/snapshot-values-route.yaml" \
                         "-f infra/charts/agentos/ci/snapshot-values-servicemonitor.yaml"; do
            helm3 template rel infra/charts/agentos --namespace cognic -f "$BASE" $overlay > /tmp/rendered-helm3.yaml
            kubeconform -strict -summary -kubernetes-version 1.27.0 \
              -schema-location default -schema-location "$CRD" /tmp/rendered-helm3.yaml
          done
```

- [ ] **Step 2: Verify the workflow parses + the local 4-scenario primary gate is green + CRD schemas resolve**

Run (simulates the CI primary gate locally; the executor HAS network for the CRD schemas):
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/python.yml')); print('workflow yaml ok')"
BASE="infra/charts/agentos/ci/snapshot-values.yaml"
CRD='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
for s in "|" "_ingress|-f infra/charts/agentos/ci/snapshot-values-ingress.yaml" "_route|-f infra/charts/agentos/ci/snapshot-values-route.yaml" "_servicemonitor|-f infra/charts/agentos/ci/snapshot-values-servicemonitor.yaml"; do
  suffix="${s%%|*}"; overlay="${s#*|}"
  helm template rel infra/charts/agentos --namespace cognic -f "$BASE" $overlay > /tmp/raw.yaml
  printf '%s\n' "$(cat /tmp/raw.yaml)" > /tmp/rendered.yaml
  diff -u "tests/unit/infra/helm/agentos_rendered${suffix}.yaml" /tmp/rendered.yaml && echo "scenario ${suffix:-default} snapshot ✓"
  kubeconform -strict -summary -kubernetes-version 1.27.0 -schema-location default -schema-location "$CRD" /tmp/rendered.yaml
done
```
Expected: workflow parses; all four scenarios byte-match their snapshots; kubeconform `Valid` with `0 Errors` for each (Route + ServiceMonitor resolve via the CRD catalog).

**If the CRD schema-location does NOT resolve** (404 / case mismatch — the catalog filenames are lowercase-kind, e.g. `servicemonitor_v1.json`): confirm the exact catalog path for `route.openshift.io/Route` + `monitoring.coreos.com/ServiceMonitor`; if the template's `{{.ResourceKind}}` case is wrong, adjust to the catalog's case, **or** apply the documented fallback — append `-skip Route,ServiceMonitor` to the `kubeconform` invocations (scoped skip ONLY for the two CRDs; core kinds still validated). Record which path was used in the T5 closeout.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/python.yml
git commit -m "ci(deploy): Sprint 14B-Z1b-a T3 — 4-scenario helm gate + CRD schema validation (Route/ServiceMonitor) (ADR-024)"
```

---

## Task 4: Docs

**Files:**
- Modify: `docs/adrs/ADR-024-deployment-substrate-helm-packaging.md`, `docs/AS_BUILT_CAPABILITY_MAP.md`, `AGENTS.md`, `docs/operator-runbooks/helm-chart-production-install.md`

- [ ] **Step 1: Add `## Sprint 14B-Z1b-a amendment` to ADR-024** (amend-by-addition, before `## References`/end). Cover: the conditional Ingress (`networking.k8s.io/v1`) + Route (`route.openshift.io/v1`) + ServiceMonitor (`monitoring.coreos.com/v1`) templates, default all off; Ingress TLS existing-secret-first; **Route TLS `a+b`** (default `edge` + router-default cert + `insecureEdgeTerminationPolicy: Redirect`; optional inline `certificate`/`key`/`caCertificate`; `externalCertificate` deferred as an OCP-version-gated later option); ServiceMonitor path `{apiPrefix}{serviceMonitor.path}` (→ `/api/v1/metrics`) + stable `selectorLabels` selector; the four-scenario byte-snapshot + kubeconform gate with CRD `-schema-location` (scoped-skip fallback); CC stays 131 / no kernel change.

- [ ] **Step 2: Update `docs/AS_BUILT_CAPABILITY_MAP.md`** — in forward-item-7's `14B-Z1b` sub-item, split out `14B-Z1b-a — external access (Ingress/Route) + TLS + ServiceMonitor: DONE 2026-06-18` (the chart templates + the 4-scenario gate) and mark `Z1b-b` (external secrets ESO), `Z1b-c` (Langfuse-OTLP exporter swap), `Z1b-d` (AKS bring-up + cloud-identity) as the remaining forward sub-items. Amend-by-addition; preserve history.

- [ ] **Step 3: Add an AGENTS.md note** near the Sprint 14B-Z1a deployment-substrate note: Z1b-a added the conditional Ingress/Route/ServiceMonitor templates (CC 131, no kernel change).

- [ ] **Step 4: Add an "External access (Ingress / OpenShift Route) + TLS + ServiceMonitor" section to `docs/operator-runbooks/helm-chart-production-install.md`** — how to enable Ingress (className + cert-manager annotations + existing TLS secret) OR Route (edge/router-default vs inline cert), and the ServiceMonitor (enable + the `release` label for the cluster Prometheus).

- [ ] **Step 5: Verify docs + commit**

Run: `grep -n "Z1b-a" docs/adrs/ADR-024-deployment-substrate-helm-packaging.md docs/AS_BUILT_CAPABILITY_MAP.md AGENTS.md | head` and confirm balanced fences in the runbook (`grep -c '^```' docs/operator-runbooks/helm-chart-production-install.md` is even).
```bash
git add docs/adrs/ADR-024-deployment-substrate-helm-packaging.md docs/AS_BUILT_CAPABILITY_MAP.md AGENTS.md docs/operator-runbooks/helm-chart-production-install.md
git commit -m "docs(deploy): Sprint 14B-Z1b-a T4 — ADR-024 amendment + AS_BUILT/AGENTS + runbook external-access section (ADR-024)"
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

- [ ] **Step 4: The four-scenario helm gate green locally**

```bash
helm lint infra/charts/agentos -f infra/charts/agentos/ci/snapshot-values.yaml
uv run pytest tests/unit/infra/test_helm_chart.py -v   # 5 passed (4 snapshot params + lint)
```
Plus the T3 Step-2 loop (4 scenarios → byte-diff + kubeconform). State which CRD-schema path was used (schema-location vs scoped-skip).

- [ ] **Step 5: Final stop — no commit here** (T1–T4 already committed). Report the full-gate evidence + the CRD-schema outcome, and hold for the PR/merge tokens.

---

## Self-review notes

- **Spec coverage:** §1 boundary (T1–T4 additive; T5 confirms CC 131) · §2 templates (T1) · §2 TLS Route a+b + Ingress existing-secret (T1 route.yaml/ingress.yaml + values) · §3 values surface incl. serviceMonitor.path joined with apiPrefix + stable selectorLabels (T1) · §4 four pinned snapshots + layered values + version-gated pytest (T2) + the CI 4-scenario gate (T3) · §5 CRD schema-location-first/scoped-skip-fallback (T3 Step 1 + the fallback note in Step 2) · §6 docs + posture (T4 + T5). The default render is explicitly verified UNCHANGED in T1 Step 6 (default-off templates ⇒ the existing default snapshot still matches — no default regen).
- **No placeholders:** every template, values block, schema fragment, the parametrized test, and both CI loops are shown in full. The one network-dependent value (the CRDs-catalog schema URL) is given as the concrete standard pattern + a T3 verification step + the documented scoped-skip fallback — the executor confirms the exact catalog case at execution (it has network; the authoring env did not).
- **Type/name consistency:** `agentos.fullname`/`labels`/`selectorLabels` reused from `_helpers.tpl`; the Service port name `http` matches the Z1a `service.yaml`; the snapshot filenames (`agentos_rendered{_ingress,_route,_servicemonitor}.yaml`) are identical across T2 (pytest), T3 (CI), and the file-structure map; the four scenario suffixes (``/`_ingress`/`_route`/`_servicemonitor`) match between the pytest `_SCENARIOS` ids and the CI loop suffixes.
