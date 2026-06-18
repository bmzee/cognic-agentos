# Sprint 14B-Z1b-c — OTLP exporter protocol primitive (gRPC/HTTP) + Langfuse-OTLP chart wiring — Design

**Date:** 2026-06-18
**Status:** DRAFT — design approved in brainstorming (2026-06-18); awaiting spec review before planning.
**ADRs:** amends **ADR-024** (Deployment Substrate / Helm Packaging); references ADR-009 (pluggable infra adapters — Langfuse-OTel observability) + ADR-020 (observability surfaces). Closes the parked **Langfuse-OTLP enablement** follow-up.

## Context

Sprint 14B-Z1b decomposed into four sub-slices: **Z1b-a** external access (MERGED), **Z1b-b** external secrets (MERGED), **Z1b-c — the OTLP exporter protocol primitive + Langfuse chart wiring** (this; the **first kernel-touching Z1b slice**), **Z1b-d** AKS bring-up (the live cloud exercise).

**The gap (recon, from source 2026-06-18).** Trace spans flow: gateway → `LangfuseOtelAdapter.emit_trace` (`db/adapters/langfuse_otel_adapter.py`) creates an OTel span on the **process-global `TracerProvider`** (set by `observability/otel.py:configure_tracing`, consumed at `portal/api/app.py:440`) → `BatchSpanProcessor` → **gRPC `OTLPSpanExporter`** → `otel_exporter_endpoint`. Two facts make Langfuse OTLP ingestion impossible today:
1. `observability/otel.py:36` imports **only** the gRPC exporter, and `_build_otlp_exporter` threads `endpoint`/`insecure`/mTLS-`credentials` but **no headers**. The `otel_exporter_endpoint` Field itself says "OTLP **gRPC** endpoint".
2. The `LangfuseOtelAdapter` only **health-checks** + **pings** Langfuse (`/api/public/health`, `/api/public/ingestion`) — it never exports spans there. So there is **no path** that sends spans to Langfuse's OTLP/HTTP ingestion endpoint (`{langfuse_host}/api/public/otel/v1/traces`), which requires **HTTP + Basic-auth** (`Authorization: Basic base64(public:secret)`), not gRPC.

**Recon truths that shape the spec:**
- **`observability/otel.py` + `core/config.py` are OFF the CC gate** (the gate file only mentions them in comments) → **CC stays 131**; a real code change with real tests, but no gate module moves.
- **No new dependency.** The HTTP OTLP exporter is **already importable in the venv** — the `opentelemetry-exporter-otlp` umbrella (already in `pyproject.toml`) pulls both the grpc and http exporters. The http `OTLPSpanExporter.__init__` takes `endpoint, certificate_file, client_key_file, client_certificate_file, headers, timeout, compression, session`.
- **`Settings`**: `env_prefix="COGNIC_"`, `case_sensitive=False`, **no `env_nested_delimiter`** → a `dict` field parses from a **JSON-string** env var (`COGNIC_OTEL_EXPORTER_HEADERS={"Authorization":"Basic …"}`).
- **Chart env planes**: the ConfigMap (`envFrom: configMapRef`) is the **non-secret** plane; the **Secret** is wired per-key via `env: secretKeyRef`.

## Goal

Give the kernel a **generic OTLP transport primitive** — export traces over `grpc` (today) OR `http` with arbitrary headers — so any HTTP OTLP backend (Langfuse, Grafana, Honeycomb, a collector gateway) works with **no kernel special-casing**. Wire it through the Helm chart (values + ConfigMap + a secret-safe header passthrough) so an operator can make Langfuse OTLP/HTTP ingestion turnkey, with the Langfuse-specific URL/auth conventions living in the **chart/runbook**, not the kernel.

## Non-goals (guards — user-locked)

- **The kernel stays Langfuse-AGNOSTIC.** `observability/otel.py` knows `grpc`/`http` + headers; it does NOT know Langfuse URL conventions or Basic-auth derivation. Those live in the chart/runbook. (CLAUDE.md OS/pack boundary — Langfuse is one bundled backend, not the only one.)
- **No new dependency** (the http exporter is already resolved via the otlp umbrella).
- **`otel_exporter_insecure` stays gRPC-only** — HTTP transport security is the endpoint URL scheme (`https://` vs `http://`).
- **The Z1b-b ESO `ExternalSecret` 2-key contract is UNTOUCHED.** The sensitive Basic-auth header rides an OPTIONAL operator-provided extra secret key, never the fixed 2-entry ESO template.
- **CC stays 131** (`otel.py` + `core/config.py` are off the per-file coverage gate); no migration. **But `core/config.py` is under the AGENTS.md `core/` stop-rule** ("Anything in `core/`") — so T1's config edit gets the same **halt-before-commit human scrutiny + focused config tests** as any `core/` change, even though the gate count does not move. (`observability/otel.py` is off-gate and not in `core/`, but T1 edits both in one task, so the whole task carries that scrutiny.)
- **Not live-exercised in-session.** The real-Langfuse ingestion proof is env-gated (the Gateway-Observability Z2 pattern); the chart's otel render is validated by snapshot/kubeconform only. The live cloud exercise is Z1b-d.

## Design

### 1. Kernel — the generic OTLP primitive

**`core/config.py`** — two additive, backward-compatible Settings:
- `otel_exporter_protocol: Literal["grpc", "http"] = "grpc"` (back-compat default).
- `otel_exporter_headers: dict[str, str] = Field(default_factory=dict, ...)` — generic OTLP headers (parsed from the `COGNIC_OTEL_EXPORTER_HEADERS` JSON env var); carries e.g. `{"Authorization": "Basic <base64>"}`. Uses **`default_factory=dict`** (NOT a `= {}` mutable default), matching the local `Settings` style (`embedding_extra_headers`, `llm_model_id_map`).

**`observability/otel.py`** — `_build_otlp_exporter(settings)` branches on `settings.otel_exporter_protocol`:
- **`grpc`** (default): the EXISTING path — gRPC `OTLPSpanExporter(endpoint, insecure, credentials=<mTLS from cert/CA bytes>)` — PLUS `headers=settings.otel_exporter_headers` (the gRPC exporter accepts headers too).
- **`http`**: the http `OTLPSpanExporter` (`opentelemetry.exporter.otlp.proto.http.trace_exporter`) with `endpoint` + `headers=settings.otel_exporter_headers` + **file-based TLS** — the SAME mTLS-triple settings map to the http exporter's `certificate_file` (CA) / `client_certificate_file` / `client_key_file` kwargs. **`insecure` is NOT passed** (http security = the endpoint URL scheme).

Shape (illustrative — the plan gives the exact body):

```python
def _build_otlp_exporter(settings: Settings) -> SpanExporter:
    if settings.otel_exporter_protocol == "http":
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter as HTTPExporter,
        )
        kwargs: dict[str, object] = {"endpoint": settings.otel_exporter_endpoint}
        if settings.otel_exporter_headers:
            kwargs["headers"] = dict(settings.otel_exporter_headers)
        if settings.otel_exporter_ca_cert_path:
            kwargs["certificate_file"] = str(settings.otel_exporter_ca_cert_path)
        if settings.otel_exporter_client_cert_path:
            kwargs["client_certificate_file"] = str(settings.otel_exporter_client_cert_path)
        if settings.otel_exporter_client_key_path:
            kwargs["client_key_file"] = str(settings.otel_exporter_client_key_path)
        return HTTPExporter(**kwargs)  # type: ignore[arg-type]
    # grpc (default) — the existing path, plus headers
    ...  # endpoint + insecure + credentials (mTLS) + headers
```

The function's return annotation widens from the concrete gRPC `OTLPSpanExporter` to the OTel `SpanExporter` base (both grpc + http exporters are `SpanExporter` subclasses). `_build_processor` is otherwise unchanged — still gated on `otel_exporter_endpoint` being set → `BatchSpanProcessor(_build_otlp_exporter(settings))`.

**Tests** (`tests/unit/test_otel.py`): keep the 6 gRPC cases; ADD http-path cases — `protocol="http"` installs the http `OTLPSpanExporter`; `otel_exporter_headers` are threaded; the mTLS file paths map to the http TLS kwargs; `insecure` is NOT passed on the http path; the default (`grpc`) path is unchanged.

### 2. Chart — modest wiring, gated on `endpoint` (default render UNCHANGED)

The chart's otel exporter config is **gated on `otel.exporter.endpoint` being set** (default empty) — mirroring the kernel (`_build_processor` only exports when an endpoint is set). So the **default render and the 5 existing snapshots are byte-UNCHANGED**; the otel keys appear only when an endpoint is configured (the `otel-http` scenario).

**`values.yaml`:**
```yaml
otel:
  exporter:
    endpoint: ""              # COGNIC_OTEL_EXPORTER_ENDPOINT; when set, traces export (else no-op/console)
    protocol: grpc            # grpc | http
    insecure: false           # gRPC-only; HTTP security is the endpoint URL scheme
    headersSecretKey: ""      # optional: a key in the operator's Secret holding COGNIC_OTEL_EXPORTER_HEADERS (e.g. the Langfuse Basic-auth JSON)
```

**`templates/configmap.yaml`** — a `{{- if .Values.otel.exporter.endpoint }}` block, **non-secret only**:
```yaml
  {{- if .Values.otel.exporter.endpoint }}
  COGNIC_OTEL_EXPORTER_ENDPOINT: {{ .Values.otel.exporter.endpoint | quote }}
  COGNIC_OTEL_EXPORTER_PROTOCOL: {{ .Values.otel.exporter.protocol | quote }}
  COGNIC_OTEL_EXPORTER_INSECURE: {{ .Values.otel.exporter.insecure | quote }}
  {{- end }}
```

**`templates/deployment.yaml`** — a conditional, secret-safe header env (the sensitive Basic-auth JSON NEVER enters the ConfigMap):
```yaml
            {{- if .Values.otel.exporter.headersSecretKey }}
            - name: COGNIC_OTEL_EXPORTER_HEADERS
              valueFrom:
                secretKeyRef:
                  name: {{ include "agentos.secretName" . }}
                  key: {{ .Values.otel.exporter.headersSecretKey }}
            {{- end }}
```
The header rides the Secret via this optional passthrough — leaving the Z1b-b ESO 2-key contract untouched (the operator adds the header key to the operator-owned Secret referenced by `secrets.existingSecret`, or provides it through a separate ExternalSecret).

**`values.schema.json`:** add the `otel` block shape — `exporter.endpoint` (string), `exporter.protocol` (enum `["grpc","http"]`), `exporter.insecure` (bool), `exporter.headersSecretKey` (string).

### 3. The Langfuse turnkey wiring (chart/runbook, NOT kernel)

The runbook documents the operator path:
```text
otel.exporter.protocol: http
otel.exporter.endpoint: {langfuse_host}/api/public/otel/v1/traces
otel.exporter.headersSecretKey: COGNIC_OTEL_EXPORTER_HEADERS
# …and in your Secret: COGNIC_OTEL_EXPORTER_HEADERS = {"Authorization":"Basic <base64(public:secret)>"}
```
Two secret patterns documented: (a) `secrets.existingSecret` points at an operator-owned Secret containing the two bootstrap keys plus `COGNIC_OTEL_EXPORTER_HEADERS`; (b) ESO operators create a separate `ExternalSecret` or extend their own outside the chart's fixed 2-key template. `secrets.create=true` remains smoke/dev bootstrap-only and is **not** compatible with `headersSecretKey` unless the chart explicitly grows a future dev-only header value.

### 4. CI gate — a 6th scenario (no CRD change)

The Z1b-b five scenarios become **six** (+ `otel-http`): an overlay setting `otel.exporter.endpoint` + `protocol: http` + `headersSecretKey`. **The overlay MUST use `secrets.create: false` + `secrets.existingSecret: <name>`** (NOT the base `secrets.create:true`): a chart-created Secret renders only the 2 bootstrap keys, so a `headersSecretKey` reference would point at a **missing** `COGNIC_OTEL_EXPORTER_HEADERS` key — kubeconform passes (it does not validate secret-key existence) but the pod fails at runtime. With `existingSecret` mode the chart renders no Secret and the Deployment references the operator-owned Secret for all keys incl. the header (which the operator must populate — documented in the runbook), preserving the secret-safe production boundary. The new scenario captures the otel ConfigMap keys + the Deployment header `secretKeyRef` env. **The 5 existing snapshots are UNCHANGED** (default-off). `pytest` `_SCENARIOS` 5→6; the CI `helm-chart` loop 5→6. **No kubeconform CRD change** — the otel render is core kinds only (ConfigMap + Deployment), so the existing `-skip Route` scope is unchanged.

### 5. Live proof (env-gated)

A `COGNIC_RUN_LANGFUSE_OTEL=1`-gated integration test that configures the http exporter against a real Langfuse (host + keys), emits a span, and asserts ingestion — the Gateway-Observability **Z2 pattern** (fail-loud when opted in, skip by default). NOT always-on CI.

### 6. Docs & posture

- **ADR-024** gains a `## Sprint 14B-Z1b-c amendment` (amend-by-addition): the generic OTLP protocol primitive, the headers-for-both contract, the http-reuses-the-mTLS-triple-as-files / insecure-is-grpc-only decisions, the chart's endpoint-gated wiring + the secret-safe header passthrough, and the 6th scenario.
- **AS_BUILT** Pillar-5 + forward-item-7's Z1b sub-item updated (Z1b-c DONE; Z1b-d forward) — **both surfaces** (the Z1b-a/Z1b-b lesson); **AGENTS.md** note.
- The `docs/operator-runbooks/helm-chart-production-install.md` gains an **"OTLP exporter (gRPC/HTTP) + Langfuse OTLP ingestion"** section.
- **Posture:** CC stays **131**; no migration; no new on-gate module. The `src/` change is `otel.py` + `core/config.py` (off-gate); the new always-on Python is the snapshot param + the otel http unit tests (the live proof is env-gated).

## Tasks (high-level; the plan expands each)

- **T1** — kernel: `core/config.py` Settings (`otel_exporter_protocol` + `otel_exporter_headers` via `default_factory=dict`) + `observability/otel.py` protocol-selectable exporter + `tests/unit/test_otel.py` http cases + the env-gated `COGNIC_RUN_LANGFUSE_OTEL` live-proof test. Verify the gRPC path is unchanged + the http path installs the http exporter with headers. **`core/config.py` is a `core/` stop-rule edit** — halt-before-commit human scrutiny + focused config tests for the two new Settings (default, JSON-env parse, the `Literal` enum).
- **T2** — chart: the `values.yaml` `otel` block + the endpoint-gated `configmap.yaml` keys + the conditional `deployment.yaml` header `secretKeyRef` + the `values.schema.json` extension + the 6th `otel-http` overlay + the committed snapshot + the pytest param (5→6). Verify the default render + the 5 existing snapshots are UNCHANGED.
- **T3** — CI: extend the `helm-chart` job loops to 6 scenarios on both lanes (no CRD-schema change).
- **T4** — docs: ADR-024 amendment + AS_BUILT (both surfaces) / AGENTS + the runbook OTLP-exporter section.
- **T5** — closeout: full gate (ruff/format/mypy + full suite + the 131-module gate on fresh `--cov-branch`; the six-scenario helm gate green) + confirm CC stays 131 (no gate module moved).

## Posture

CC count stays **131**; no migration; no new on-gate module (`otel.py` + `core/config.py` are off-gate). Z1b-c is the kernel-OTLP-transport-primitive + chart-wiring slice; **Z1b-d** (AKS bring-up — the live cloud / live-ESO / live-observability exercise) is the remaining Z1b sub-slice.
