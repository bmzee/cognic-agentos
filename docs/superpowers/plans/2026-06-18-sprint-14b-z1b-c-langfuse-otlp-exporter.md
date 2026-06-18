# Sprint 14B-Z1b-c — OTLP exporter protocol primitive (gRPC/HTTP) + Langfuse-OTLP chart wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a generic OTLP transport primitive (`grpc`/`http` + headers) to `observability/otel.py`, behind two new `core/config.py` Settings, and wire it through the Helm chart (values + endpoint-gated ConfigMap + a secret-safe header passthrough) so Langfuse OTLP/HTTP ingestion is operator-turnkey — kernel stays Langfuse-agnostic.

**Architecture:** Kernel slice (`observability/otel.py` + `core/config.py`, both off the per-file coverage gate; `core/config.py` is under the AGENTS.md `core/` stop-rule) + chart slice on the Z1b-b chart at `infra/charts/agentos/`. **CC stays 131** (no gate module moves); **no new dependency** (the http exporter is already in the `opentelemetry-exporter-otlp` umbrella); no migration.

**Tech Stack:** Python 3.12, pydantic-settings, OpenTelemetry (grpc + http OTLP exporters), Helm v4.2.2 (+ v3.16.3 compat), kubeconform v0.8.0, pytest, GitHub Actions.

---

## File structure

- Modify: `src/cognic_agentos/core/config.py` — 2 Settings (`otel_exporter_protocol`, `otel_exporter_headers`). **`core/` stop-rule edit — halt-before-commit human scrutiny.**
- Modify: `src/cognic_agentos/observability/otel.py` — `_build_otlp_exporter` protocol branch + return-type widen to `SpanExporter`.
- Modify: `tests/unit/test_otel.py` — http-path cases (keep the 6 gRPC cases).
- Modify: `tests/unit/test_config.py` — focused otel-Settings cases (default / JSON-env-parse / invalid-protocol-reject).
- Create: `tests/integration/observability/test_langfuse_otlp_ingestion.py` — env-gated `COGNIC_RUN_LANGFUSE_OTEL=1` live ingestion proof.
- Modify: `infra/charts/agentos/values.yaml` — the `otel` block.
- Modify: `infra/charts/agentos/templates/configmap.yaml` — endpoint-gated non-secret otel keys.
- Modify: `infra/charts/agentos/templates/deployment.yaml` — conditional header `secretKeyRef` env.
- Modify: `infra/charts/agentos/values.schema.json` — the `otel` block shape.
- Create: `infra/charts/agentos/ci/snapshot-values-otel-http.yaml` — the 6th scenario overlay.
- Create: `tests/unit/infra/helm/agentos_rendered_otel-http.yaml` — machine-generated snapshot.
- Modify: `tests/unit/infra/test_helm_chart.py` — `_SCENARIOS` 5→6.
- Modify: `.github/workflows/python.yml` — helm-chart job 5→6 scenarios.
- Modify: `docs/adrs/ADR-024-deployment-substrate-helm-packaging.md`, `docs/AS_BUILT_CAPABILITY_MAP.md`, `AGENTS.md`, `docs/operator-runbooks/helm-chart-production-install.md`.

---

## Task 1: Kernel — the generic OTLP primitive (`core/` stop-rule)

**Files:**
- Modify: `src/cognic_agentos/core/config.py`
- Modify: `src/cognic_agentos/observability/otel.py`
- Modify: `tests/unit/test_otel.py`
- Create: `tests/integration/observability/test_langfuse_otlp_ingestion.py`

> **Stop-rule note:** `core/config.py` is under the AGENTS.md `core/` stop-rule. This task gets halt-before-commit human scrutiny + focused config tests, even though CC stays 131.

- [ ] **Step 1: Write the failing http-protocol test** in `tests/unit/test_otel.py` (append; mirrors the existing gRPC `test_endpoint_set_installs_otlp_exporter`)

```python
def test_http_protocol_installs_http_otlp_exporter() -> None:
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
        OTLPSpanExporter as HTTPSpanExporter,
    )

    settings = prod_settings(
        otel_exporter_endpoint="https://lf.example.com/api/public/otel/v1/traces",
        otel_exporter_protocol="http",
        otel_exporter_headers={"Authorization": "Basic eHk6eg=="},
    )
    provider = configure_tracing(settings)
    procs = _processors(provider)
    proc = next(p for p in procs if isinstance(p, BatchSpanProcessor))
    assert isinstance(proc.span_exporter, HTTPSpanExporter)


def test_http_build_threads_headers_and_file_tls_no_insecure(monkeypatch, tmp_path) -> None:
    from cognic_agentos.observability import otel as otel_mod

    captured: dict[str, object] = {}

    class _FakeHTTP:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

    # The http exporter is lazily imported inside _build_otlp_exporter, so the
    # patch on its source module is picked up at call time.
    monkeypatch.setattr(
        "opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter",
        _FakeHTTP,
    )
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    settings = prod_settings(
        otel_exporter_endpoint="https://lf/api/public/otel/v1/traces",
        otel_exporter_protocol="http",
        otel_exporter_headers={"Authorization": "Basic abc"},
        otel_exporter_ca_cert_path=ca,
    )
    otel_mod._build_otlp_exporter(settings)
    assert captured["endpoint"].endswith("/v1/traces")
    assert captured["headers"] == {"Authorization": "Basic abc"}
    assert captured["certificate_file"] == str(ca)
    assert "insecure" not in captured  # http: insecure is gRPC-only


def test_grpc_path_still_threads_headers(monkeypatch) -> None:
    from cognic_agentos.observability import otel as otel_mod

    captured: dict[str, object] = {}

    class _FakeGRPC:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(otel_mod, "OTLPSpanExporter", _FakeGRPC)
    settings = prod_settings(
        otel_exporter_endpoint="collector:4317",
        otel_exporter_insecure=True,
        otel_exporter_headers={"x-tenant": "acme"},
    )
    otel_mod._build_otlp_exporter(settings)
    assert captured["insecure"] is True
    assert captured["headers"] == {"x-tenant": "acme"}
```

Also add focused `core/config.py` Settings tests to `tests/unit/test_config.py` (TDD — these fail until Step 3 adds the Settings; `ValidationError` is already imported there at `:9`; import `prod_settings` from `tests.support.settings_fixtures` as `test_otel.py` does):

```python
def test_otel_exporter_protocol_defaults_to_grpc() -> None:
    s = prod_settings()
    assert s.otel_exporter_protocol == "grpc"
    assert s.otel_exporter_headers == {}


def test_otel_exporter_headers_parse_from_json_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COGNIC_OTEL_EXPORTER_HEADERS", '{"Authorization": "Basic abc123"}')
    s = prod_settings()  # headers not in prod_settings' overrides → read from env
    assert s.otel_exporter_headers == {"Authorization": "Basic abc123"}


def test_otel_exporter_protocol_rejects_invalid_value() -> None:
    with pytest.raises(ValidationError):
        prod_settings(otel_exporter_protocol="thrift")
```

- [ ] **Step 2: Run them — verify they FAIL** (the Settings + the http branch don't exist yet)

Run: `uv run pytest tests/unit/test_otel.py tests/unit/test_config.py -k "http or threads_headers or otel_exporter" -v`
Expected: FAIL — `Settings` has no `otel_exporter_protocol`/`otel_exporter_headers` (validation error) and/or the http branch isn't there.

- [ ] **Step 3: Add the two Settings to `core/config.py`** (insert after `otel_exporter_client_key_path` at ~line 198, before `prometheus_metrics_path`). `Literal` is already imported (used by `cache_driver`):

```python
    otel_exporter_protocol: Literal["grpc", "http"] = Field(
        default="grpc",
        description=(
            "OTLP exporter transport. 'grpc' (default, back-compat) uses the "
            "gRPC exporter with the otel_exporter_* TLS settings; 'http' uses "
            "the OTLP/HTTP exporter (for backends like Langfuse that require "
            "HTTP + auth headers). HTTP transport security is the endpoint URL "
            "scheme (https://); otel_exporter_insecure is gRPC-only."
        ),
    )
    otel_exporter_headers: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "OTLP exporter headers, threaded into both grpc + http exporters. "
            "Env-var form is JSON-encoded (e.g. "
            '\'{"Authorization": "Basic <base64(public:secret)>"}\'); invalid '
            "JSON / non-string keys or values fail at settings-load time via "
            "the dict[str, str] annotation. For Langfuse OTLP/HTTP, supply the "
            "Authorization Basic-auth header here via a Secret-sourced env."
        ),
    )
```

- [ ] **Step 4: Refactor `_build_otlp_exporter` in `observability/otel.py`** — widen the return type + add the http branch. First extend the SDK-export import (add `SpanExporter`):

```python
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
    SpanExporter,
)
```

Then replace the body of `_build_otlp_exporter`:

```python
def _build_otlp_exporter(settings: Settings) -> SpanExporter:
    """Construct an OTLP exporter for the configured protocol + TLS posture.

    grpc (default): the gRPC exporter with endpoint / insecure / mTLS-credentials.
    http: the OTLP/HTTP exporter with endpoint + file-based TLS (for backends
    like Langfuse that need HTTP + auth headers). Headers thread into both.
    Defaults to **secure** (TLS) on grpc; http security is the endpoint URL scheme.
    """

    headers = dict(settings.otel_exporter_headers) or None

    if settings.otel_exporter_protocol == "http":
        # Lazy import — same opentelemetry-exporter-otlp umbrella as the gRPC
        # exporter; kept off the module's hot import path.
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter as HTTPSpanExporter,
        )

        http_kwargs: dict[str, object] = {"endpoint": settings.otel_exporter_endpoint}
        if headers is not None:
            http_kwargs["headers"] = headers
        # The mTLS triple maps to the http exporter's file-path kwargs; insecure
        # is gRPC-only (http security is the endpoint URL scheme).
        if settings.otel_exporter_ca_cert_path:
            http_kwargs["certificate_file"] = str(settings.otel_exporter_ca_cert_path)
        if settings.otel_exporter_client_cert_path:
            http_kwargs["client_certificate_file"] = str(
                settings.otel_exporter_client_cert_path
            )
        if settings.otel_exporter_client_key_path:
            http_kwargs["client_key_file"] = str(settings.otel_exporter_client_key_path)
        return HTTPSpanExporter(**http_kwargs)  # type: ignore[arg-type]

    # grpc (default) — the existing path, now also threading headers.
    kwargs: dict[str, object] = {
        "endpoint": settings.otel_exporter_endpoint,
        "insecure": settings.otel_exporter_insecure,
    }
    if headers is not None:
        kwargs["headers"] = headers
    if settings.otel_exporter_ca_cert_path:
        ca_bytes = settings.otel_exporter_ca_cert_path.read_bytes()
        client_cert = (
            settings.otel_exporter_client_cert_path.read_bytes()
            if settings.otel_exporter_client_cert_path
            else None
        )
        client_key = (
            settings.otel_exporter_client_key_path.read_bytes()
            if settings.otel_exporter_client_key_path
            else None
        )
        import grpc  # type: ignore[import-untyped]

        kwargs["credentials"] = grpc.ssl_channel_credentials(
            root_certificates=ca_bytes,
            private_key=client_key,
            certificate_chain=client_cert,
        )
    return OTLPSpanExporter(**kwargs)  # type: ignore[arg-type]
```

(`_build_processor` is unchanged — still gated on `otel_exporter_endpoint` → `BatchSpanProcessor(_build_otlp_exporter(settings))`.)

- [ ] **Step 5: Run the new tests + the full otel suite — verify PASS**

Run: `uv run pytest tests/unit/test_otel.py tests/unit/test_config.py -k "http or threads_headers or otel_exporter or grpc or endpoint or console or resource or returns_new" -v`
Expected: PASS — `test_otel.py`'s 6 gRPC cases + the 3 new http/headers cases (9 total) + the 3 new `test_config.py` otel-Settings cases, 0 failures. The gRPC tests prove no regression (the default path is unchanged).

- [ ] **Step 6: Add the env-gated live proof** `tests/integration/observability/test_langfuse_otlp_ingestion.py` (the Gateway-Observability Z2 pattern — fail-loud when opted in, skip by default)

```python
"""Env-gated live proof: spans INGEST into a real Langfuse via the OTLP/HTTP exporter.

Opt in with COGNIC_RUN_LANGFUSE_OTEL=1 + COGNIC_LANGFUSE_HOST + the keys.
Fail-loud (NOT skip) when opted in but misconfigured — never a silent pass.
"""

from __future__ import annotations

import base64
import os
import time

import pytest

_OPT_IN = os.environ.get("COGNIC_RUN_LANGFUSE_OTEL") == "1"

pytestmark = pytest.mark.skipif(
    not _OPT_IN,
    reason="set COGNIC_RUN_LANGFUSE_OTEL=1 (+ COGNIC_LANGFUSE_HOST + keys) to run",
)


def test_span_ingests_into_langfuse_via_http_otlp() -> None:
    host = os.environ["COGNIC_LANGFUSE_HOST"].rstrip("/")
    public = os.environ["COGNIC_LANGFUSE_PUBLIC_KEY"]
    secret = os.environ["COGNIC_LANGFUSE_SECRET_KEY"]
    token = base64.b64encode(f"{public}:{secret}".encode()).decode()

    from langfuse import Langfuse
    from opentelemetry import trace

    from cognic_agentos.observability.otel import configure_tracing
    from tests.support.settings_fixtures import prod_settings

    # prod_settings(...) supplies the strict-profile-safe fields (G5 embedding,
    # digest-pinned sandbox images); a bare Settings(runtime_profile="prod")
    # fails validation on the dev embedding default.
    settings = prod_settings(
        otel_exporter_endpoint=f"{host}/api/public/otel/v1/traces",
        otel_exporter_protocol="http",
        otel_exporter_headers={
            "Authorization": f"Basic {token}",
            # Langfuse's recommended header for real-time OTLP ingestion
            # visibility (Langfuse OTel docs).
            "x-langfuse-ingestion-version": "4",
        },
    )
    provider = configure_tracing(settings)
    try:
        tracer = trace.get_tracer("cognic_agentos.test")
        with tracer.start_as_current_span("z1bc-otlp-proof") as span:
            trace_id = format(span.get_span_context().trace_id, "032x")
            span.set_attribute("test.marker", "z1bc")
        # force_flush returns True once export() runs — that alone does NOT prove
        # ingestion, so query Langfuse's public API for the trace below.
        assert provider.force_flush(timeout_millis=10_000) is True

        # Source-grounded read: the Langfuse Python SDK's documented
        # `api.observations.get_many(trace_id=...)` (Langfuse maps the OTLP
        # trace_id to its traceId). Bounded retry for ingestion lag; fail-loud.
        client = Langfuse(host=host, public_key=public, secret_key=secret)
        deadline_s, waited_s = 30.0, 0.0
        while True:
            observations = client.api.observations.get_many(trace_id=trace_id)
            if observations.data:
                break
            assert waited_s < deadline_s, (
                f"trace {trace_id} not ingested into Langfuse within {deadline_s:.0f}s"
            )
            time.sleep(2.0)
            waited_s += 2.0
    finally:
        provider.shutdown()
```

- [ ] **Step 7: lint/format/types on the touched kernel files**

Run: `uv run ruff check src/cognic_agentos/core/config.py src/cognic_agentos/observability/otel.py tests/unit/test_otel.py tests/unit/test_config.py tests/integration/observability/test_langfuse_otlp_ingestion.py && uv run ruff format --check . && uv run mypy src tests`
Expected: clean.

- [ ] **Step 8: Commit** (controller-gated — `core/` stop-rule scrutiny + `git diff --cached --check`)

```bash
git add src/cognic_agentos/core/config.py src/cognic_agentos/observability/otel.py tests/unit/test_otel.py tests/unit/test_config.py tests/integration/observability/test_langfuse_otlp_ingestion.py
git diff --cached --check
git commit -m "feat(observability): Sprint 14B-Z1b-c T1 — OTLP exporter protocol primitive (grpc/http + headers) (ADR-024)"
```

---

## Task 2: Chart wiring (endpoint-gated; default render UNCHANGED)

**Files:**
- Modify: `infra/charts/agentos/values.yaml`, `templates/configmap.yaml`, `templates/deployment.yaml`, `values.schema.json`
- Create: `infra/charts/agentos/ci/snapshot-values-otel-http.yaml`, `tests/unit/infra/helm/agentos_rendered_otel-http.yaml`
- Modify: `tests/unit/infra/test_helm_chart.py`

- [ ] **Step 1: Add the `otel` block to `values.yaml`** (append after the `externalSecrets:` block)

```yaml

# --- Sprint 14B-Z1b-c: OTLP trace exporter (gated on endpoint; default no-op) ---
otel:
  exporter:
    endpoint: ""                 # COGNIC_OTEL_EXPORTER_ENDPOINT; when set, traces export (else no-op/console)
    protocol: grpc               # grpc | http
    insecure: false              # gRPC-only; HTTP security is the endpoint URL scheme
    headersSecretKey: ""         # optional: a key in the operator-owned Secret holding COGNIC_OTEL_EXPORTER_HEADERS (e.g. the Langfuse Basic-auth JSON)
```

- [ ] **Step 2: Add the endpoint-gated keys to `templates/configmap.yaml`** (inside `data:`, after the cache block; non-secret only)

```yaml
  {{- if .Values.otel.exporter.endpoint }}
  COGNIC_OTEL_EXPORTER_ENDPOINT: {{ .Values.otel.exporter.endpoint | quote }}
  COGNIC_OTEL_EXPORTER_PROTOCOL: {{ .Values.otel.exporter.protocol | quote }}
  COGNIC_OTEL_EXPORTER_INSECURE: {{ .Values.otel.exporter.insecure | quote }}
  {{- end }}
```

- [ ] **Step 3: Add the conditional header env to `templates/deployment.yaml`** (in the container `env:` list, after the `COGNIC_VAULT_TOKEN` secretKeyRef block)

```yaml
            {{- if .Values.otel.exporter.headersSecretKey }}
            - name: COGNIC_OTEL_EXPORTER_HEADERS
              valueFrom:
                secretKeyRef:
                  name: {{ include "agentos.secretName" . }}
                  key: {{ .Values.otel.exporter.headersSecretKey }}
            {{- end }}
```

- [ ] **Step 4: Extend `values.schema.json`** — add the `otel` property to the root `properties` (after `externalSecrets`):

```json
    "otel": {
      "type": "object",
      "properties": {
        "exporter": {
          "type": "object",
          "properties": {
            "endpoint": { "type": "string" },
            "protocol": { "type": "string", "enum": ["grpc", "http"] },
            "insecure": { "type": "boolean" },
            "headersSecretKey": { "type": "string" }
          }
        }
      }
    }
```
Confirm JSON parses: `python3 -c "import json; json.load(open('infra/charts/agentos/values.schema.json'))"`.

- [ ] **Step 5: Verify the default render is UNCHANGED + lint**

```bash
cd /Users/bmz/development/cognic-agentos
helm template rel infra/charts/agentos --namespace cognic -f infra/charts/agentos/ci/snapshot-values.yaml > /tmp/def.yaml
printf '%s\n' "$(cat /tmp/def.yaml)" | diff -u tests/unit/infra/helm/agentos_rendered.yaml - && echo "DEFAULT UNCHANGED ✓"
helm lint infra/charts/agentos -f infra/charts/agentos/ci/snapshot-values.yaml
```
Expected: `DEFAULT UNCHANGED ✓` (the otel block is endpoint-gated, so the default render — endpoint empty — emits no otel keys); `0 chart(s) failed`. The 5 existing snapshots are likewise unchanged.

- [ ] **Step 6: Create the 6th overlay** `infra/charts/agentos/ci/snapshot-values-otel-http.yaml` (existingSecret mode — a chart-created Secret would lack the header key per the spec §4)

```yaml
# OTLP-http-on scenario overlay (layered over ci/snapshot-values.yaml).
# headersSecretKey points at an extra key in an operator-owned Secret, so this
# overlay uses existingSecret mode (NOT the base secrets.create:true, whose
# 2-key chart Secret would lack COGNIC_OTEL_EXPORTER_HEADERS).
secrets:
  create: false
  existingSecret: agentos-secrets
otel:
  exporter:
    endpoint: https://langfuse.example.com/api/public/otel/v1/traces
    protocol: http
    insecure: false
    headersSecretKey: COGNIC_OTEL_EXPORTER_HEADERS
```

- [ ] **Step 7: Add the 6th `_SCENARIOS` param in `tests/unit/infra/test_helm_chart.py`** (append after the `externalsecret` param)

```python
    pytest.param(
        [_SNAPSHOT_VALUES, _CI / "snapshot-values-otel-http.yaml"],
        _HELM_DIR / "agentos_rendered_otel-http.yaml",
        id="otel-http",
    ),
```

- [ ] **Step 8: Generate + verify the snapshot**

```bash
uv run pytest "tests/unit/infra/test_helm_chart.py::test_rendered_chart_matches_snapshot[otel-http]" -v
```
Expected: first run FAILS ("snapshot created … review and commit"). **Inspect** `agentos_rendered_otel-http.yaml`: the ConfigMap carries `COGNIC_OTEL_EXPORTER_ENDPOINT`/`_PROTOCOL`/`_INSECURE`; the Deployment has the `COGNIC_OTEL_EXPORTER_HEADERS` `secretKeyRef` env; NO bootstrap `kind: Secret` (existingSecret mode). Re-run → PASS. Then the full file: `uv run pytest tests/unit/infra/test_helm_chart.py -v` → `7 passed` (6 scenarios + lint).

- [ ] **Step 9: Commit** (controller-gated)

```bash
git add infra/charts/agentos/values.yaml infra/charts/agentos/templates/configmap.yaml infra/charts/agentos/templates/deployment.yaml infra/charts/agentos/values.schema.json infra/charts/agentos/ci/snapshot-values-otel-http.yaml tests/unit/infra/helm/agentos_rendered_otel-http.yaml tests/unit/infra/test_helm_chart.py
git diff --cached --check
git commit -m "feat(deploy): Sprint 14B-Z1b-c T2 — chart OTLP exporter wiring + 6th otel-http scenario (ADR-024)"
```

---

## Task 3: CI `helm-chart` job — six scenarios (no CRD change)

**Files:** Modify `.github/workflows/python.yml`

- [ ] **Step 1: Add the otel-http scenario to BOTH loops.** Primary Helm-4 `for s in …` list — append:

```bash
                   "_otel-http|-f infra/charts/agentos/ci/snapshot-values-otel-http.yaml"; do
```
Helm-3 compat `for overlay in …` list — append:
```bash
                         "-f infra/charts/agentos/ci/snapshot-values-otel-http.yaml"; do
```
Update both step names / section headers from "5 scenarios" to "6 scenarios". The `-skip Route` scope is UNCHANGED (the otel render is core kinds only — ConfigMap + Deployment — no CRD).

- [ ] **Step 2: Verify locally (the 6-scenario primary loop under `bash`)**

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
         "_otel-http|-f infra/charts/agentos/ci/snapshot-values-otel-http.yaml"; do
  suffix="${s%%|*}"; overlay="${s#*|}"; snap="tests/unit/infra/helm/agentos_rendered${suffix}.yaml"
  helm template rel infra/charts/agentos --namespace cognic -f "$BASE" $overlay > /tmp/raw.yaml
  printf "%s\n" "$(cat /tmp/raw.yaml)" > /tmp/rendered.yaml
  diff -q "$snap" /tmp/rendered.yaml && echo "${suffix:-_default}: MATCH"
  kubeconform -strict -summary -kubernetes-version 1.27.0 -schema-location default -schema-location "$CRD" -skip Route /tmp/rendered.yaml
done'
```
Expected: all 6 MATCH; kubeconform Valid for all (otel-http is core kinds → Valid, 0 skipped). Confirm YAML parses with 7 jobs: `python3 -c "import yaml; d=yaml.safe_load(open('.github/workflows/python.yml')); print(list(d['jobs'].keys()))"`.

- [ ] **Step 3: Commit** (controller-gated)

```bash
git add .github/workflows/python.yml
git diff --cached --check
git commit -m "ci(deploy): Sprint 14B-Z1b-c T3 — 6-scenario helm gate (otel-http) (ADR-024)"
```

---

## Task 4: Docs

**Files:** Modify `docs/adrs/ADR-024-…md`, `docs/AS_BUILT_CAPABILITY_MAP.md`, `AGENTS.md`, `docs/operator-runbooks/helm-chart-production-install.md`

- [ ] **Step 1: Add `## Sprint 14B-Z1b-c amendment` to ADR-024** (amend-by-addition, after the Z1b-b amendment, at file end). Cover: the generic `otel_exporter_protocol` (`grpc`/`http`) + `otel_exporter_headers` primitive; headers thread into both exporters; the http path reuses the mTLS triple as file-path kwargs; `insecure` is gRPC-only; the chart's endpoint-gated ConfigMap keys + the secret-safe `headersSecretKey` passthrough; the 6th `otel-http` scenario (existingSecret mode); CC stays 131 (`otel.py` + `core/config.py` off the coverage gate, `core/config.py` under the `core/` stop-rule); no migration; no new dependency. Note the kernel stays Langfuse-agnostic (the Langfuse URL/auth conventions live in the chart/runbook).

- [ ] **Step 2: Update `docs/AS_BUILT_CAPABILITY_MAP.md` — BOTH surfaces** (the Z1b-a/Z1b-b lesson): (a) the **Pillar 5 row** (current-state: observability OTLP exporter DONE 14B-Z1b-c; the Langfuse-OTLP follow-up closed; remaining-gap drops the OTel gRPC→HTTP exporter item; sprint-owner Z1b-c DONE / Z1b-d forward); (b) forward-item-7's `14B-Z1b-c` sub-item → `DONE 2026-06-18`. Also update the **Cross-cutting "Observability"** bullet (line ~25: "Langfuse OTLP ingestion is a parked follow-up (exporter is gRPC-only today)") → the http exporter now exists; ingestion is operator-configurable. Amend-by-addition; preserve history.

- [ ] **Step 3: Add an AGENTS.md note** near the Z1b-b deployment-substrate note: Z1b-c added the generic OTLP `grpc`/`http`+headers exporter primitive + the chart wiring (CC 131; `core/config.py` `core/` stop-rule edit).

- [ ] **Step 4: Add an "OTLP exporter (gRPC/HTTP) + Langfuse OTLP ingestion" section to the runbook.** The generic knobs (`otel.exporter.protocol`/`endpoint`/`insecure`); the Langfuse turnkey (`protocol: http`, `endpoint: {langfuse_host}/api/public/otel/v1/traces`, `headersSecretKey`); the **header is secret-safe** — the Basic-auth JSON (`{"Authorization":"Basic base64(public:secret)}"`) goes in the operator-owned Secret referenced by `secrets.existingSecret` (or a separate ExternalSecret), **NOT** the ConfigMap and **NOT** `secrets.create` mode.

- [ ] **Step 5: Verify docs + commit** (controller-gated). `rg -n "Z1b-c" docs/adrs/…md docs/AS_BUILT_CAPABILITY_MAP.md AGENTS.md | head`; balanced fences in the runbook + ADR.
```bash
git add docs/adrs/ADR-024-deployment-substrate-helm-packaging.md docs/AS_BUILT_CAPABILITY_MAP.md AGENTS.md docs/operator-runbooks/helm-chart-production-install.md
git diff --cached --check
git commit -m "docs(deploy): Sprint 14B-Z1b-c T4 — ADR-024 amendment + AS_BUILT/AGENTS + runbook OTLP-exporter section (ADR-024)"
```

---

## Task 5: Closeout

**Files:** none (verification only)

- [ ] **Step 1: Confirm CC stays 131 (no gate module moved)**

Run: `uv run python tools/check_critical_coverage.py 2>/dev/null | tail -1` after the sweep (Step 3); and confirm the gate module list is unchanged (the touched `src/` files — `core/config.py`, `observability/otel.py` — are off-gate).

- [ ] **Step 2: Lint + format + types**

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
```
Expected: all clean.

- [ ] **Step 3: Full unit suite + the 131-module gate (the one authoritative sweep)**

```bash
uv run coverage run --branch -m pytest tests/unit -m "not postgres and not oracle"
uv run coverage json -o coverage.json
uv run python tools/check_critical_coverage.py
```
Expected: full suite passes (incl. `test_otel.py` 9 cases + the helm `test_helm_chart.py` 7); `Per-file critical-controls coverage gate: passed` (131/131).

- [ ] **Step 4: The six-scenario helm gate green locally**

```bash
helm lint infra/charts/agentos -f infra/charts/agentos/ci/snapshot-values.yaml
uv run pytest tests/unit/infra/test_helm_chart.py -v   # 7 passed (6 snapshot params + lint)
```
Plus the T3 Step-2 loop (6 scenarios → byte-diff + kubeconform; otel-http is core-kinds → Valid).

- [ ] **Step 5: Final stop — no commit here** (T1–T4 already committed). Report the full-gate evidence + confirm CC stays 131 + the default render is byte-unchanged, and hold for the PR/merge tokens.

---

## Self-review notes

- **Spec coverage:** §1 kernel primitive (T1 Steps 3-4) + tests (T1 Steps 1, 5, 6) · §2 chart endpoint-gated wiring + secret-safe header (T2 Steps 1-4) · §3 Langfuse turnkey (T4 Step 4 runbook) · §4 6th otel-http scenario, existingSecret mode (T2 Steps 6-8) + CI (T3) · §5 env-gated live proof (T1 Step 6) · §6 docs + posture (T4 + T5). The default render UNCHANGED is explicitly verified in T2 Step 5.
- **No placeholders:** every Settings block, the full `_build_otlp_exporter` body, the three unit tests, the env-gated proof, the values/configmap/deployment/schema fragments, the overlay, and both CI loop edits are shown in full.
- **Type/name consistency:** `otel_exporter_headers` mirrors `llm_model_id_map` (`default_factory=dict`, native JSON-env decode, no `NoDecode`); `Literal["grpc","http"]` mirrors `cache_driver`'s Literal style; the snapshot filename `agentos_rendered_otel-http.yaml` + the scenario id/suffix `otel-http`/`_otel-http` match across T2 (pytest), T3 (CI loop), and the file-structure map; `agentos.secretName` is reused for the header `secretKeyRef`.
- **Stop-rule:** `core/config.py` is a `core/` stop-rule edit — T1 carries halt-before-commit scrutiny (flagged in the task header + Step 8) even though CC stays 131.
- **Critical interaction handled:** the `otel-http` overlay uses `secrets.create:false` + `secrets.existingSecret` (T2 Step 6) so the `headersSecretKey` `secretKeyRef` doesn't reference a missing key in a chart-created 2-key Secret (the spec §4 runtime-failure fix); the otel ConfigMap block is endpoint-gated so the 5 existing snapshots + the default render stay byte-unchanged.
