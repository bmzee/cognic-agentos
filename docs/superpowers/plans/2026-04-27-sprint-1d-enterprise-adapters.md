# Sprint 1D — Enterprise Adapters (Oracle + Dynatrace + OpenAI-compat embedding) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship three bundled enterprise adapters per ADR-009 (Oracle relational, Dynatrace observability, OpenAI-compat embedding for vLLM / SGLang / cloud) plus the opt-in compose overlays (`docker-compose.oracle.yml`, `docker-compose.vllm.yml`) and the operator guide (`INFERENCE-BACKENDS.md`) so banks running on enterprise stacks get first-class support, not plugin-pack-only.

**Architecture:** Each new adapter follows the Sprint-1C contract pattern (PEP-544 protocol conformance, lazy-init with `bundled_registry.register(...)` on import, `_BUNDLED_ADAPTER_OPTIONAL_DEPS` allowlist entry for kernel-image resilience, factory-side per-driver-arg helper). The `OracleAdapter` mirrors `PostgresAdapter`'s `SQLAlchemy[asyncio]` shape with `oracle+oracledb` driver. The `DynatraceAdapter` mirrors `LangfuseOtelAdapter`'s OTel-bridged emit + HTTP health probe pattern, plus a Dynatrace Metric Ingest line-protocol POST for native custom metrics. The `OpenAICompatEmbeddingAdapter` mirrors `OllamaEmbeddingAdapter`'s httpx shape against the standard OpenAI `/v1/embeddings` schema, but records a `provider_label` (vllm / sglang / openai / azure_oai / bedrock / cohere) on every emission for audit clarity per ADR-007.

**Tech Stack:** Python 3.12 / uv. SQLAlchemy[asyncio] 2.0 + `python-oracledb` 2.5+ thin-mode async (no Oracle client install required). httpx (Sprint 1B carryover) for Dynatrace + OpenAI-compat HTTP. OpenTelemetry (Sprint 1B carryover) for in-process trace emission to the Dynatrace OTLP ingest. Docker compose overlays for Oracle XE 21c (`gvenzl/oracle-xe:21-slim`) + single-GPU vLLM (`vllm/vllm-openai`). respx for HTTP-mock tests; `unittest.mock.patch` for SQLAlchemy engine mocking; `@pytest.mark.oracle` for the integration job that opts into the live overlay.

---

## Context

Sprint 1C (squash-merged at `40ed26a` via PR #1) shipped the adapter protocol layer + five default-bundled reference adapters (Postgres / Qdrant / Vault / Ollama / Langfuse-OTel). Sprint 1D extends the bundled set with the three enterprise variants ADR-009 calls out: Oracle for banks already on Oracle databases, Dynatrace for banks already on Dynatrace observability, and OpenAI-compat for production GPU-cluster embedding (vLLM / SGLang) — all of which are common enterprise realities Cognic must serve without forcing a plugin-pack install.

The Sprint 1C contracts make this straightforward: the new adapters self-register into `bundled_registry` on import; `load_bundled_adapters()` already iterates the allowlist (we just add three entries); the factory pattern accepts new per-driver-arg helpers; the existing `Adapters` dataclass + `/readyz` roll-up need no changes. The risk concentrations are infra-side: Oracle XE is a 3 GB image with 2 GB RAM ask, only opt-in via overlay; vLLM compose needs GPU runtime, CI runs without; Dynatrace API tokens come from operator-side Vault wiring that Sprint 10 will fully automate.

**Operating-mode + stop-rule check:**

- Most of Sprint 1D is **autonomous low-risk build mode** — adapter modules, registry / factory extensions, compose overlays, operator-guide doc, CI workflow extension. None of these touch the AGENTS.md critical-controls list.
- **Task 2 — `core/config.py` extension — gets a stop-for-review gate.** AGENTS.md §"Stop rules" says "Stop for human review when touching: Anything in `core/`". Same rule that applied at Sprint 1C T2; same halt-then-resume cadence. Executor commits T2 then halts for `yes` / `go` before starting T3.
- No `core-controls-engineer` / `/critical-module-mode` invocation required because the touched core/ surface (config) is settings-only, but the stop rule is honoured nonetheless.

**Sprint 1C carryovers brought into Sprint 1D (non-negotiable):**

- All adapter Python packages live in `[project.optional-dependencies] adapters` extras (NOT in `[project] dependencies`) so the kernel image stays slim. `oracledb>=2.5` joins the existing list.
- Image budgets gated in CI: kernel ≤120 MiB (currently ~102 MiB / 18 MiB headroom), default-adapters ≤220 MiB (currently ~198 MiB / 22 MiB headroom). `oracledb` is small (~5 MiB) but will eat into headroom; `opentelemetry-exporter-otlp-proto-http` is already installed (Sprint 1B). Re-measure after T1 sync; if default-adapters approaches 220 MiB, re-trim or escalate to a doctrine-amendment commit.
- `/readyz` key contract is `relational` / `observability` (long form, matches `Adapters` field names + `AdapterKind` literal). Exit-criteria text in BUILD_PLAN already aligned during Sprint 1C T16.
- Adapter modules auto-register to `bundled_registry` on import; `load_bundled_adapters()` allowlist entries needed.
- Production-grade rule: real runtime path; no silent no-ops; raise `NotImplementedError` for deferred work (e.g. Oracle `run_migrations` like Postgres).
- Tests use `respx` for httpx mocking; `unittest.mock.patch` for SQLAlchemy engines; new `@pytest.mark.oracle` marker for integration tests against the compose overlay.
- Compose Langfuse pin: `langfuse/langfuse:2` (single-container). Sprint 1D should NOT bump to v3 — stays out of scope.
- LiteLLM is a non-readiness-gated dev sidecar in Sprint 1C; full `/health` wiring is Sprint 3 territory; Sprint 1D leaves LiteLLM alone.
- No new MemoryAdapter (still ADR-019 / Sprint 11.5 territory).

**Schedule risk**: BUILD_PLAN.md schedule-risk table flags Sprint 1D at 2-3.5 wu (Oracle alone is ~1.5 wu). If execution overruns Day 2, the plan is structured so a split into 1D-Oracle (T3) + 1D-Observability (T4) + 1D-Embedding (T5) is straightforward — each adapter's tasks are self-contained.

**Production-grade rule:** every adapter's main runtime path is real (`oracledb` async / httpx + Dynatrace API / httpx + OpenAI-compat). In-memory variants under `tests/support/adapter_fixtures.py` are not extended (no in-memory Oracle / Dynatrace / openai_compat variants) — tests mock at the library boundary instead.

---

## File Structure

**Created:**

| Path | Responsibility |
|---|---|
| `src/cognic_agentos/db/adapters/oracle_adapter.py` | `OracleAdapter` — RelationalAdapter via SQLAlchemy[asyncio] + python-oracledb thin-mode async. Constructor refuses empty/None URL; `connect`/`session`/`close` mirror PostgresAdapter shape. `run_migrations` raises `NotImplementedError` (Sprint 2 hook); `health_check` runs `SELECT 1 FROM dual`. Auto-registers under `bundled_registry` as `("relational", "oracle")`. |
| `src/cognic_agentos/db/adapters/dynatrace_adapter.py` | `DynatraceAdapter` — ObservabilityAdapter for Dynatrace tenants. `emit_trace` creates an in-process OTel span (Sprint 1B OTel pipeline handles OTLP export to Dynatrace ingest when env-configured). `emit_metric` POSTs to Dynatrace `/api/v2/metrics/ingest` using line-protocol shape. `flush` is a non-raising best-effort. `health_check` GETs `/api/v2/metrics/query?metricSelector=builtin:host.cpu.usage&pageSize=1` with `Authorization: Api-Token <token>`; non-200 → `unreachable`. Auto-registers as `("observability", "dynatrace")`. |
| `src/cognic_agentos/db/adapters/openai_compat_embedding_adapter.py` | `OpenAICompatEmbeddingAdapter` — EmbeddingAdapter against any OpenAI-compatible `/v1/embeddings` endpoint. Constructor takes `base_url`, `model`, `dimensions`, `provider_label`, optional `api_key` + `api_key_header` (default `Authorization`; uses `Bearer <key>` when header is `Authorization`, raw `<key>` otherwise — for Azure `api-key` shape), optional `extra_headers` dict (for Azure `api-version`, custom proxy headers, etc.). `embed` POSTs `{"input": [...], "model": "...", "encoding_format": "float"}` with the configured auth + extra headers, parses `{"data": [{"embedding": [...], "index": ...}]}` (sorted by `index` defensively). `dimensions` + `provider_label` properties. `health_check` GETs `/v1/models` with the same auth headers; non-200 → `unreachable`. Audit emission of `provider_label` lands with Sprint 2 `core/audit` wiring (Sprint 1D ships storage + plumbing only — see BUILD_PLAN amendment). Covers vLLM/SGLang (no auth), OpenAI/Cohere (Bearer), Azure-OpenAI / Bedrock when fronted by an OpenAI-compat proxy (api-key header + extra_headers). Auto-registers as `("embedding", "openai_compat")`. |
| `src/cognic_agentos/db/migrations/__init__.py` | Empty package init. |
| `src/cognic_agentos/db/migrations/oracle/.gitkeep` | Reserves `db/migrations/oracle/` for Sprint 2 Alembic migrations (Oracle dialect). |
| `infra/dev/docker-compose.oracle.yml` | Opt-in compose overlay. Single service: `gvenzl/oracle-xe:21-slim`. Activated via `docker compose -f docker-compose.yml -f docker-compose.oracle.yml up -d`. Most devs run Postgres locally; Oracle compose only when testing the Oracle adapter or running `@pytest.mark.oracle`. |
| `infra/dev/docker-compose.vllm.yml` | Opt-in compose overlay for a single-GPU vLLM node (`vllm/vllm-openai:v0.6.6` — intentionally conservative pin; operators bump to a current stable after testing against their CUDA driver). nvidia runtime; CI runs without; only GPU machines activate. |
| `docs/INFERENCE-BACKENDS.md` | Operator guide: when to pick Ollama (dev) vs vLLM (prod, fast inference) vs SGLang (prod, throughput-optimised) vs cloud (OpenAI/Azure/Bedrock). Deployment topology examples. References ADR-009 §"LLM serving" for the LiteLLM tier-alias scheme. |
| `tests/unit/db/test_oracle_adapter.py` | Protocol conformance via `unittest.mock.patch` on `sqlalchemy.ext.asyncio.create_async_engine`; integration test against the live overlay marked `@pytest.mark.oracle`. |
| `tests/unit/db/test_dynatrace_adapter.py` | respx-mocked HTTP probes — health check OK / unreachable / 5xx; emit_metric body shape (line protocol); emit_trace no-raise; flush no-raise; protocol conformance. |
| `tests/unit/db/test_openai_compat_embedding_adapter.py` | respx-mocked HTTP — embed body shape (OpenAI v1 schema); response parsing yields N×D float lists; provider_label storage; health_check via /v1/models; constructor refusal of empty base_url; protocol conformance. |

**Modified:**

| Path | Change |
|---|---|
| `pyproject.toml` | Append `oracledb>=2.5` to `[project.optional-dependencies] adapters`. No other dep additions (httpx + opentelemetry already in core; respx already in dev). |
| `uv.lock` | Regenerated. |
| `src/cognic_agentos/core/config.py` | Add Dynatrace settings group (`dynatrace_tenant_url`, `dynatrace_api_token`); add OpenAI-compat embedding settings (`embed_provider_label`). Oracle uses the existing `database_url` field with the `oracle+oracledb://...` SQLAlchemy URL shape — no Oracle-specific URL field needed. |
| `src/cognic_agentos/db/adapters/__init__.py` | Extend `_BUNDLED_ADAPTER_OPTIONAL_DEPS` with three new entries: oracle (allowlist `{oracledb, sqlalchemy}`), dynatrace (empty — only httpx + opentelemetry, both core), openai_compat_embedding (empty — only httpx). |
| `src/cognic_agentos/db/adapters/factory.py` | Extend `_relational_args` (new branch for `oracle` returning `(database_url,)`); extend `_observability_args` (new branch for `dynatrace` returning `(tenant_url, api_token)`); extend `_embedding_args` (new branch for `openai_compat` returning `(base_url, model, dimensions, provider_label)`). |
| `tests/unit/db/test_adapter_factory.py` | Extend `TestPerDriverArgs` with three new test methods covering the Oracle / Dynatrace / openai_compat branches. |
| `.github/workflows/python.yml` | Add a third CI job `oracle-integration` that brings up `docker-compose.yml + docker-compose.oracle.yml` and runs `uv run pytest -m oracle -v`. Default `lint + test` job continues to run with the marker excluded (default pytest behaviour for skipped markers). |
| `pyproject.toml` (markers) | Register the new `oracle` pytest marker so `--strict-markers` doesn't reject it. |
| `.env.example` | Append Oracle / Dynatrace / openai_compat env stubs. |

---

## Tasks

### Task 1: Branch + dependency setup

**Files:**
- Stage and commit: `docs/superpowers/plans/2026-04-27-sprint-1d-enterprise-adapters.md` + `docs/BUILD_PLAN.md` (amendments)
- Modify: `pyproject.toml`
- Modify: `uv.lock` (regenerated)
- Modify: `.env.example`

- [ ] **Step 1.0: Commit the plan + BUILD_PLAN amendments to `main` so the working tree is clean for preflight**

The plan document and the small Sprint-1D BUILD_PLAN amendments are tracked artifacts; until they're committed, the preflight clean-tree check would fail. Commit them on `main` first as a `chore(plan)` checkpoint (Sprint-1C T1 precedent), THEN branch.

```bash
git add docs/superpowers/plans/2026-04-27-sprint-1d-enterprise-adapters.md \
        docs/BUILD_PLAN.md
git commit -m "chore(plan): sprint 1d enterprise-adapters plan + BUILD_PLAN amendments"
```

Expected: one new commit on `main`. The BUILD_PLAN amendments clarify Oracle URL handling (existing `database_url` covers all SQLAlchemy `oracle+oracledb://` variants), Dynatrace settings (token via direct env in 1D + reserved `_vault_path` setting for Sprint-10 runtime resolution), OpenAI-compat auth surface (api_key + api_key_header + extra_headers + reserved vault_path), provider_label storage-only-in-1D + audit-emission-in-Sprint-2, and CI strategy (unit tests for all drivers + live Oracle XE integration job; Dynatrace + openai_compat live-stack verification is operator-side).

- [ ] **Step 1.1: Verify safe starting state**

```bash
git status --short                           # MUST be empty
git rev-parse --abbrev-ref HEAD              # MUST be `main`
git fetch origin main --quiet
git merge-base --is-ancestor origin/main HEAD \
  && echo "ok: local main is at or ahead of origin/main" \
  || echo "warn: local main is BEHIND origin/main; pull before proceeding"
```

Expected: clean tree; current branch `main`; ancestry probe prints `ok`. Abort if any check fails.

- [ ] **Step 1.2: Create feature branch**

```bash
git switch -c feat/sprint-1d-enterprise-adapters
```

Expected: `Switched to a new branch 'feat/sprint-1d-enterprise-adapters'`.

- [ ] **Step 1.3: Extend `pyproject.toml`**

Add to the `adapters` extras group (after `langfuse>=3.0`):

```toml
    # Enterprise relational (Sprint 1D, per ADR-009)
    "oracledb>=2.5",
```

Add the `oracle` pytest marker to `[tool.pytest.ini_options].markers` (alongside the existing `integration` marker). The marker is for **discoverability** (so `pytest -m oracle` selects them); actual skipping is enforced per-test via `@pytest.mark.skipif(not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"), reason=...)` so default `pytest -v` invocations do NOT execute live-DB tests. (Pytest markers do not auto-skip; the `--strict-markers` option only validates that markers are *registered*, not that they're filtered.)

```toml
markers = [
    "integration: integration tests requiring external services",
    "oracle: tests requiring the live Oracle XE compose overlay (env-gated via COGNIC_RUN_ORACLE_INTEGRATION=1)",
]
```

- [ ] **Step 1.4: Lock + sync**

```bash
uv lock
uv sync --all-extras
```

Expected: `uv.lock` updates with `oracledb` + its small transitive closure; `uv sync` reports the new package installed.

- [ ] **Step 1.5: Verify Sprint 1C baseline still green**

```bash
uv run pytest -v
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
```

Expected: 193 tests pass; lint/format/mypy clean.

- [ ] **Step 1.6: Append adapter env stubs to `.env.example`**

Append at end of file:

```bash

# ----- Sprint 1D — Enterprise adapters -----
# Oracle (uses the same DATABASE_URL field with oracle+oracledb:// scheme):
# COGNIC_DB_DRIVER=oracle
# COGNIC_DATABASE_URL=oracle+oracledb://cognic:cognic_dev_only@localhost:1521/?service_name=XEPDB1

# Dynatrace observability:
# COGNIC_OBS_DRIVER=dynatrace
# COGNIC_DYNATRACE_TENANT_URL=https://abc12345.live.dynatrace.com
# COGNIC_DYNATRACE_API_TOKEN=dt0c01.YOUR_API_TOKEN_HERE  # dev-only direct env; prod sources via Vault (Sprint 10)
# COGNIC_DYNATRACE_API_TOKEN_VAULT_PATH=secret/dynatrace/cognic  # reserved; Sprint 10 wires runtime resolution
# Required Dynatrace API token scopes: metrics.read (health probe) + metrics.ingest (emit_metric).

# OpenAI-compat embedding (vLLM / SGLang / OpenAI / Cohere / Azure-OAI-via-shim / Bedrock-via-shim):
# COGNIC_EMBED_DRIVER=openai_compat
# COGNIC_EMBEDDING_BASE_URL=http://vllm:8000   # or http://sglang:30000, https://api.openai.com, etc.
# COGNIC_EMBEDDING_MODEL=BAAI/bge-large-en-v1.5
# COGNIC_EMBEDDING_DIMENSIONS=1024
# COGNIC_EMBED_PROVIDER_LABEL=vllm  # one of: vllm | sglang | openai | azure_oai | bedrock | cohere | openai_compat
# COGNIC_EMBEDDING_API_KEY=                    # leave unset for vLLM/SGLang local; "sk-..." for OpenAI; raw key for Azure
# COGNIC_EMBEDDING_API_KEY_HEADER=Authorization  # default; set to "api-key" for Azure-OpenAI proxies (raw, no Bearer prefix)
# COGNIC_EMBEDDING_API_KEY_VAULT_PATH=         # reserved; Sprint 10 wires runtime resolution
# COGNIC_EMBEDDING_EXTRA_HEADERS={}            # JSON dict; e.g. '{"api-version": "2024-02-15-preview"}' for Azure
```

- [ ] **Step 1.7: Commit**

```bash
git add pyproject.toml uv.lock .env.example
git commit -m "chore(sprint-1d): add oracledb dep + enterprise-adapter env stubs"
```

---

### Task 2: Extend `core/config.py` with Dynatrace + OpenAI-compat settings

Oracle uses the existing `database_url` field with the `oracle+oracledb://...` SQLAlchemy URL shape — no new Oracle-specific URL field needed. Dynatrace + OpenAI-compat each get a small settings group following the Sprint 1C pattern.

**Files:**
- Modify: `src/cognic_agentos/core/config.py`
- Modify: `tests/unit/test_config.py`

- [ ] **Step 2.1: Write the failing test**

Append a new class to `tests/unit/test_config.py` (after `TestAdapterSettings`):

```python
class TestEnterpriseAdapterSettings:
    """Sprint 1D enterprise adapter settings — Dynatrace + OpenAI-compat."""

    def test_dynatrace_defaults_are_none(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        s = build_settings_without_env_file()

        assert s.dynatrace_tenant_url is None
        assert s.dynatrace_api_token is None

    def test_dynatrace_settings_load_from_env(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        monkeypatch.setenv(
            "COGNIC_DYNATRACE_TENANT_URL", "https://abc12345.live.dynatrace.com"
        )
        monkeypatch.setenv("COGNIC_DYNATRACE_API_TOKEN", "dt0c01.test-token")
        monkeypatch.setenv(
            "COGNIC_DYNATRACE_API_TOKEN_VAULT_PATH", "secret/dynatrace/cognic"
        )

        s = build_settings_without_env_file()
        assert s.dynatrace_tenant_url == "https://abc12345.live.dynatrace.com"
        assert s.dynatrace_api_token == "dt0c01.test-token"
        assert s.dynatrace_api_token_vault_path == "secret/dynatrace/cognic"

    def test_dynatrace_api_token_vault_path_default_none(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Reserved field for Sprint 10 runtime Vault resolution; Sprint 1D
        does not consume this — adapter takes the resolved token directly."""

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        s = build_settings_without_env_file()
        assert s.dynatrace_api_token_vault_path is None

    def test_embed_provider_label_default(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Default is ``openai_compat`` so misconfigured deployments
        emit a label that's clearly the no-op placeholder rather than
        misattributing to a specific backend."""

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        s = build_settings_without_env_file()

        assert s.embed_provider_label == "openai_compat"

    @pytest.mark.parametrize(
        "label",
        ["vllm", "sglang", "openai", "azure_oai", "bedrock", "cohere", "openai_compat"],
    )
    def test_embed_provider_label_accepts_known_values(
        self,
        label: str,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Known values flow through; unknown values are accepted at config
        layer (factory + adapter handle classification, not config —
        consistent with Sprint 1C's str-typed driver fields rationale)."""

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        monkeypatch.setenv("COGNIC_EMBED_PROVIDER_LABEL", label)

        s = build_settings_without_env_file()
        assert s.embed_provider_label == label

    def test_embed_provider_label_unknown_value_accepted(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Mirroring the str-typed driver-field rationale: accept unknown
        labels at the config layer so future providers don't require a
        config-schema bump."""

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        monkeypatch.setenv("COGNIC_EMBED_PROVIDER_LABEL", "future_provider")

        s = build_settings_without_env_file()
        assert s.embed_provider_label == "future_provider"

    def test_openai_compat_auth_defaults(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Defaults: no API key (vLLM/SGLang no-auth path); header name
        defaults to Authorization (the OpenAI Bearer convention)."""

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        s = build_settings_without_env_file()

        assert s.embedding_api_key is None
        assert s.embedding_api_key_header == "Authorization"
        assert s.embedding_api_key_vault_path is None
        assert s.embedding_extra_headers == {}

    def test_openai_compat_auth_loads_from_env(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        monkeypatch.setenv("COGNIC_EMBEDDING_API_KEY", "sk-test-openai-key")
        monkeypatch.setenv("COGNIC_EMBEDDING_API_KEY_HEADER", "Authorization")
        monkeypatch.setenv(
            "COGNIC_EMBEDDING_API_KEY_VAULT_PATH", "secret/openai/embedding"
        )
        monkeypatch.setenv(
            "COGNIC_EMBEDDING_EXTRA_HEADERS",
            '{"api-version": "2024-02-15-preview"}',
        )

        s = build_settings_without_env_file()
        assert s.embedding_api_key == "sk-test-openai-key"
        assert s.embedding_api_key_header == "Authorization"
        assert s.embedding_api_key_vault_path == "secret/openai/embedding"
        assert s.embedding_extra_headers == {"api-version": "2024-02-15-preview"}

    def test_openai_compat_auth_azure_shape(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Azure OpenAI proxies use ``api-key: <key>`` instead of
        ``Authorization: Bearer <key>``. The header-name override covers
        that shape without an Azure-specific adapter."""

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        monkeypatch.setenv("COGNIC_EMBEDDING_API_KEY", "azure-key-value")
        monkeypatch.setenv("COGNIC_EMBEDDING_API_KEY_HEADER", "api-key")

        s = build_settings_without_env_file()
        assert s.embedding_api_key == "azure-key-value"
        assert s.embedding_api_key_header == "api-key"
```

- [ ] **Step 2.2: Run the test, expect failure**

```bash
uv run pytest tests/unit/test_config.py::TestEnterpriseAdapterSettings -v
```

Expected: 14 failures (dynatrace defaults + dynatrace env-load + provider-label-default + 7 parametrised known values + provider-label unknown-accepted + openai_compat auth defaults + openai_compat auth env-load + openai_compat Azure shape).

- [ ] **Step 2.3: Add Dynatrace + OpenAI-compat settings to `Settings`**

In `src/cognic_agentos/core/config.py`, insert after the existing `obs_driver` block (and before `# --- Build metadata ---`):

```python
    # --- Sprint 1D enterprise-adapter settings ----------------------
    # Dynatrace observability: tenant URL + API token + reserved
    # vault-path field. Sprint 1D takes the API token via direct env
    # (or operator-side secret-mount); native runtime Vault resolution
    # of `dynatrace_api_token_vault_path` lands in Sprint 10 alongside
    # Vault credential leasing.
    dynatrace_tenant_url: str | None = Field(
        default=None,
        description="Dynatrace tenant URL (e.g. https://abc12345.live.dynatrace.com).",
    )
    dynatrace_api_token: str | None = Field(
        default=None,
        description=(
            "Dynatrace API token (header form: Api-Token <value>). "
            "Dev-only when set in source; prod sources via Vault (Sprint 10)."
        ),
    )
    dynatrace_api_token_vault_path: str | None = Field(
        default=None,
        description=(
            "Reserved Vault path for the Dynatrace API token. "
            "Sprint 1D does NOT consume this — adapter takes the resolved "
            "token directly via ``dynatrace_api_token``. Sprint 10 wires "
            "runtime Vault resolution from this path."
        ),
    )

    # OpenAI-compat embedding: provider_label declares which backend the
    # configured base_url actually points at. Recorded on every audit
    # emission per ADR-007 — Sprint 1D ships storage; Sprint 2 wires
    # actual audit emission alongside core/audit.
    embed_provider_label: str = Field(
        default="openai_compat",
        description=(
            "Audit label for OpenAI-compat embedding backend. "
            "Known values: vllm, sglang, openai, azure_oai, bedrock, cohere, openai_compat. "
            "Unknown values accepted at config layer (str-typed) — the adapter forwards "
            "the label verbatim to audit emissions."
        ),
    )

    # OpenAI-compat embedding auth surface. Default = no auth (vLLM /
    # SGLang local). Set ``embedding_api_key`` for cloud providers; the
    # ``embedding_api_key_header`` toggles between ``Authorization`` (with
    # implicit ``Bearer `` prefix — OpenAI/Cohere) and a custom header
    # name (e.g. ``api-key`` for Azure OpenAI proxies). ``extra_headers``
    # carries provider-specific quirks like Azure's ``api-version``.
    embedding_api_key: str | None = Field(
        default=None,
        description=(
            "OpenAI-compat embedding API key. None = no-auth (vLLM/SGLang local). "
            "Dev-only when set in source; prod sources via Vault (Sprint 10)."
        ),
    )
    embedding_api_key_header: str = Field(
        default="Authorization",
        description=(
            "Header name to send the embedding API key under. Defaults to "
            "``Authorization`` (adapter prefixes value with ``Bearer ``). "
            "Set to ``api-key`` for Azure OpenAI proxies (raw value, no prefix)."
        ),
    )
    embedding_api_key_vault_path: str | None = Field(
        default=None,
        description=(
            "Reserved Vault path for the embedding API key. "
            "Sprint 1D does NOT consume this — adapter takes the resolved "
            "key directly via ``embedding_api_key``. Sprint 10 wires "
            "runtime Vault resolution from this path."
        ),
    )
    embedding_extra_headers: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Optional extra headers to send on every /v1/embeddings + "
            "/v1/models request. Common uses: Azure ``api-version``, "
            "custom proxy auth tokens, observability correlation IDs. "
            "Env-var form is JSON-encoded."
        ),
    )
```

- [ ] **Step 2.4: Run the test, expect pass**

```bash
uv run pytest tests/unit/test_config.py::TestEnterpriseAdapterSettings -v
uv run mypy src tests
```

Expected: all 11 new tests pass; mypy clean.

- [ ] **Step 2.5: Re-run discipline tests**

```bash
uv run pytest tests/unit/architecture/ -v
uv run pytest -v
```

Expected: green; total tests now ~204 (193 + 11 new).

- [ ] **Step 2.6: Format + commit**

```bash
uv run ruff format src/cognic_agentos/core/config.py tests/unit/test_config.py
uv run ruff check . && uv run ruff format --check .
git add src/cognic_agentos/core/config.py tests/unit/test_config.py
git commit -m "feat(sprint-1d): add Dynatrace + openai_compat-embedding settings to core/config"
```

- [ ] **Step 2.7: STOP for human review (AGENTS.md `core/` stop rule)**

Per AGENTS.md §"Stop rules" — "Stop for human review when touching: **Anything in `core/`**". Surface to the user:

- the diff against `main` (`git diff main..HEAD -- src/cognic_agentos/core/config.py tests/unit/test_config.py`)
- the test result (`uv run pytest tests/unit/test_config.py -v`)
- the discipline-test confirmation (`uv run pytest tests/unit/architecture/ -v`)

Wait for explicit `yes` / `go` before starting Task 3.

---

### Task 3: OracleAdapter (SQLAlchemy + python-oracledb async)

`OracleAdapter` mirrors `PostgresAdapter`'s shape: lazy `connect()` builds an `AsyncEngine` against the SQLAlchemy URL; `session()` returns an `AsyncSession`; `run_migrations` raises `NotImplementedError` (Sprint 2 hook); `health_check` runs `SELECT 1 FROM dual` (Oracle's no-table-required SELECT). Tests mock `sqlalchemy.ext.asyncio.create_async_engine` to verify URL construction + the SELECT statement, and gate live-Oracle assertions behind `@pytest.mark.oracle`.

**Files:**
- Create: `src/cognic_agentos/db/adapters/oracle_adapter.py`
- Create: `src/cognic_agentos/db/migrations/__init__.py`
- Create: `src/cognic_agentos/db/migrations/oracle/.gitkeep`
- Create: `tests/unit/db/test_oracle_adapter.py`

- [ ] **Step 3.1: Write the failing test**

Create `tests/unit/db/test_oracle_adapter.py`:

```python
"""OracleAdapter — SQLAlchemy[asyncio] + python-oracledb async.

Unit tests mock the SQLAlchemy engine boundary so they never need a live
Oracle instance. The integration test (at the bottom) opts INTO the
``docker-compose.oracle.yml`` overlay via ``@pytest.mark.skipif`` gated on
``COGNIC_RUN_ORACLE_INTEGRATION=1``; the CI ``oracle-integration`` job
sets the env var. Default ``pytest`` invocations skip the integration
class entirely (markers alone do NOT auto-skip — see Sprint 1D plan
review note).
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cognic_agentos.db.adapters import bundled_registry
from cognic_agentos.db.adapters import protocols as P
from cognic_agentos.db.adapters.oracle_adapter import OracleAdapter

ORACLE_URL = "oracle+oracledb://cognic:cognic_dev_only@localhost:1521/?service_name=XEPDB1"


class TestRegistration:
    def test_oracle_registered_under_bundled(self) -> None:
        assert bundled_registry.has("relational", "oracle")
        assert bundled_registry.resolve("relational", "oracle") is OracleAdapter


class TestConstruction:
    def test_constructor_refuses_empty_url(self) -> None:
        with pytest.raises(ValueError, match="database_url"):
            OracleAdapter(None)
        with pytest.raises(ValueError, match="database_url"):
            OracleAdapter("")


class TestLifecycle:
    async def test_connect_uses_oracle_async_drivername(self) -> None:
        """``create_async_engine`` should be called with the same URL the
        operator configured. We assert URL pass-through rather than
        normalising the driver-name in adapter code (the SQLAlchemy URL
        is the source of truth)."""

        with patch(
            "cognic_agentos.db.adapters.oracle_adapter.create_async_engine"
        ) as ce:
            ce.return_value = MagicMock()
            a = OracleAdapter(ORACLE_URL)
            await a.connect()
            ce.assert_called_once()
            assert ce.call_args[0][0] == ORACLE_URL
            assert ce.call_args[1]["echo"] is False

    async def test_unreachable_before_connect(self) -> None:
        a = OracleAdapter(ORACLE_URL)
        h = await a.health_check()
        assert h.status == "unreachable"
        assert h.driver == "oracle"

    async def test_health_check_runs_select_1_from_dual(self) -> None:
        """Oracle's no-table-required SELECT is ``SELECT 1 FROM dual``;
        Postgres uses ``SELECT 1``. The dialect difference is the only
        place this adapter diverges from PostgresAdapter at the SQL
        layer."""

        from sqlalchemy import text

        with patch(
            "cognic_agentos.db.adapters.oracle_adapter.create_async_engine"
        ) as ce:
            mock_engine = MagicMock()
            mock_conn = AsyncMock()
            mock_engine.connect.return_value.__aenter__.return_value = mock_conn
            mock_engine.connect.return_value.__aexit__.return_value = None
            mock_engine.dispose = AsyncMock()
            ce.return_value = mock_engine

            a = OracleAdapter(ORACLE_URL)
            await a.connect()
            h = await a.health_check()

            assert h.status == "ok"
            assert h.driver == "oracle"
            assert h.latency_ms is not None
            # The exact text() comparison is tricky because text() returns
            # a clause element; we check the rendered SQL via .text on the
            # passed argument.
            call_args = mock_conn.execute.call_args
            executed = call_args[0][0]
            rendered = str(executed)
            assert "SELECT 1 FROM dual" in rendered

    async def test_close_disposes_engine(self) -> None:
        with patch(
            "cognic_agentos.db.adapters.oracle_adapter.create_async_engine"
        ) as ce:
            mock_engine = MagicMock()
            mock_engine.dispose = AsyncMock()
            ce.return_value = mock_engine

            a = OracleAdapter(ORACLE_URL)
            await a.connect()
            await a.close()
            mock_engine.dispose.assert_awaited_once()

            h = await a.health_check()
            assert h.status == "unreachable"


class TestRunMigrationsRaises:
    """Production-grade rule: production adapters never silently no-op.
    Alembic invocation lands in Sprint 2 alongside core/ schema work.
    Same shape as PostgresAdapter."""

    async def test_run_migrations_not_implemented(self) -> None:
        a = OracleAdapter(ORACLE_URL)
        with pytest.raises(NotImplementedError, match="Sprint 2"):
            await a.run_migrations("db/migrations/oracle")


class TestSatisfiesProtocol:
    def test_protocol_conformance(self) -> None:
        a = OracleAdapter(ORACLE_URL)
        assert isinstance(a, P.RelationalAdapter)


# --- Integration test (live Oracle XE compose overlay) ---------------

@pytest.mark.oracle
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"),
    reason="live Oracle XE integration; opt in via COGNIC_RUN_ORACLE_INTEGRATION=1 + compose overlay up",
)
class TestOracleLiveIntegration:
    """Activated only when:
      1. The compose overlay is up:
           docker compose -f infra/dev/docker-compose.yml \\
                          -f infra/dev/docker-compose.oracle.yml up -d
      2. The env-gate is set:
           export COGNIC_RUN_ORACLE_INTEGRATION=1

    The CI ``oracle-integration`` job sets both. Default ``pytest`` runs
    skip via ``skipif`` (the marker alone does NOT auto-skip; pytest's
    ``--strict-markers`` only validates that markers are *registered*).
    """

    async def test_health_check_against_live_oracle(self) -> None:
        a = OracleAdapter(ORACLE_URL)
        await a.connect()
        h = await a.health_check()
        assert h.status == "ok"
        assert h.driver == "oracle"
        assert h.latency_ms is not None
        await a.close()
```

- [ ] **Step 3.2: Run the test, expect failure**

```bash
uv run pytest tests/unit/db/test_oracle_adapter.py -v
```

Expected: `cannot import name 'OracleAdapter'`.

- [ ] **Step 3.3: Create the adapter**

Create `src/cognic_agentos/db/migrations/__init__.py` (empty). Create `src/cognic_agentos/db/migrations/oracle/.gitkeep` (empty).

Create `src/cognic_agentos/db/adapters/oracle_adapter.py`:

```python
"""OracleAdapter — RelationalAdapter via SQLAlchemy[asyncio] + python-oracledb.

Driver name: ``oracle``. Auto-registers into ``bundled_registry`` on import.

Production runtime path uses python-oracledb thin-mode async (no Oracle
client install required) via SQLAlchemy's ``oracle+oracledb`` driver.
Mirrors PostgresAdapter's shape; the only Oracle-specific divergence is
the ``SELECT 1 FROM dual`` health probe (Oracle has no implicit
no-table-required SELECT).

Per CLAUDE.md production-grade rule: ``run_migrations`` RAISES
``NotImplementedError`` rather than silently no-op'ing. Alembic-driven
migration invocation lands in Sprint 2 alongside ``core/`` schema work
(see ADR-009 §"Migration policy"). Oracle migration files will live in
``db/migrations/oracle/`` (directory pre-created in this sprint).
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from cognic_agentos.db.adapters.protocols import AdapterHealth
from cognic_agentos.db.adapters.registry import bundled_registry


class OracleAdapter:
    driver = "oracle"

    def __init__(self, url: str | None) -> None:
        if not url:
            raise ValueError("OracleAdapter requires database_url; got empty/None")
        self._url = url
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker[Any] | None = None
        self._closed = False

    async def connect(self) -> None:
        self._engine = create_async_engine(self._url, echo=False, future=True)
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)
        self._closed = False

    def session(self) -> Any:
        if self._session_factory is None:
            raise RuntimeError("connect() must be awaited first")
        return self._session_factory()

    async def run_migrations(self, dir: str) -> None:
        # Per CLAUDE.md production-grade rule: production code paths never
        # silently no-op. Alembic invocation lands in Sprint 2 alongside
        # core/ schema work; until then this method fails loudly so a
        # caller cannot accidentally believe migrations ran. See ADR-009
        # §"Migration policy".
        raise NotImplementedError(
            "OracleAdapter.run_migrations is wired in Sprint 2 alongside "
            "core/ Alembic migrations (ADR-009 §'Migration policy'). "
            "Sprint 1D ships the protocol-method shape only; "
            "db/migrations/oracle/ is pre-reserved for the Oracle-dialect "
            "migration set."
        )

    async def close(self) -> None:
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
        self._closed = True

    async def health_check(self) -> AdapterHealth:
        if self._closed or self._engine is None:
            return AdapterHealth(status="unreachable", driver=self.driver, detail="not connected")
        start = time.perf_counter()
        try:
            async with self._engine.connect() as conn:
                await conn.execute(text("SELECT 1 FROM dual"))
        except Exception as exc:
            return AdapterHealth(
                status="unreachable",
                driver=self.driver,
                detail=type(exc).__name__,
            )
        return AdapterHealth(
            status="ok",
            driver=self.driver,
            latency_ms=(time.perf_counter() - start) * 1000.0,
        )


bundled_registry.register("relational", "oracle", OracleAdapter)
```

- [ ] **Step 3.4: Add the new module to the bundled-loader allowlist**

In `src/cognic_agentos/db/adapters/__init__.py`, extend `_BUNDLED_ADAPTER_OPTIONAL_DEPS`:

```python
_BUNDLED_ADAPTER_OPTIONAL_DEPS: dict[str, frozenset[str]] = {
    "cognic_agentos.db.adapters.postgres_adapter": frozenset({"sqlalchemy", "asyncpg"}),
    "cognic_agentos.db.adapters.qdrant_adapter": frozenset({"qdrant_client"}),
    "cognic_agentos.db.adapters.vault_adapter": frozenset({"hvac"}),
    # Ollama adapter only depends on httpx (always present); no kernel-image misses.
    "cognic_agentos.db.adapters.ollama_embedding_adapter": frozenset(),
    "cognic_agentos.db.adapters.langfuse_otel_adapter": frozenset({"langfuse"}),
    # Sprint 1D enterprise adapters
    "cognic_agentos.db.adapters.oracle_adapter": frozenset({"sqlalchemy", "oracledb"}),
}
```

- [ ] **Step 3.5: Run the test, expect pass (integration class self-skips via skipif)**

```bash
uv run pytest tests/unit/db/test_oracle_adapter.py -v
uv run mypy src tests
```

Expected: 7 unit tests pass; the `TestOracleLiveIntegration` class reports `SKIPPED` (env-gate `COGNIC_RUN_ORACLE_INTEGRATION` not set). mypy clean.

To run the integration tests locally:
```bash
docker compose -f infra/dev/docker-compose.yml \
               -f infra/dev/docker-compose.oracle.yml up -d
COGNIC_RUN_ORACLE_INTEGRATION=1 uv run pytest -m oracle -v
```

- [ ] **Step 3.6: Format + sweep**

```bash
uv run ruff format src/cognic_agentos/db/adapters/oracle_adapter.py tests/unit/db/test_oracle_adapter.py
uv run ruff check . && uv run ruff format --check .
uv run pytest -v
```

Expected: all green; suite size grows to ~211 (204 from T2 + 7 unit + 1 skipped integration).

- [ ] **Step 3.7: Commit**

```bash
git add src/cognic_agentos/db/adapters/oracle_adapter.py \
        src/cognic_agentos/db/adapters/__init__.py \
        src/cognic_agentos/db/migrations \
        tests/unit/db/test_oracle_adapter.py
git commit -m "feat(sprint-1d): OracleAdapter via SQLAlchemy + python-oracledb async"
```

---

### Task 4: DynatraceAdapter (OTel-bridged + Metric Ingest API)

Two-path observability sink per ADR-009: (a) trace export rides the Sprint 1B OTel pipeline (Dynatrace OTLP ingest is configured via the existing `OTEL_EXPORTER_OTLP_ENDPOINT` env vars; the adapter just creates spans), (b) metric emission goes through Dynatrace's native Metric Ingest API for structured custom metrics with Dynatrace-specific dimensions. Health probe hits `/api/v2/metrics/query?metricSelector=builtin:host.cpu.usage&pageSize=1` with `Authorization: Api-Token <value>`.

**Files:**
- Create: `src/cognic_agentos/db/adapters/dynatrace_adapter.py`
- Create: `tests/unit/db/test_dynatrace_adapter.py`

- [ ] **Step 4.1: Write the failing test**

```python
"""DynatraceAdapter — OTel-bridged trace emission + Dynatrace Metric
Ingest API for native custom metrics + HTTP health probe."""

from __future__ import annotations

import respx
from httpx import ConnectError, Response

from cognic_agentos.db.adapters import bundled_registry
from cognic_agentos.db.adapters import protocols as P
from cognic_agentos.db.adapters.dynatrace_adapter import DynatraceAdapter

TENANT = "https://abc12345.live.dynatrace.com"
TOKEN = "dt0c01.test-token"


class TestRegistration:
    def test_dynatrace_registered_under_bundled(self) -> None:
        assert bundled_registry.has("observability", "dynatrace")
        assert bundled_registry.resolve("observability", "dynatrace") is DynatraceAdapter


class TestConstruction:
    def test_constructor_refuses_empty_tenant_url(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="dynatrace_tenant_url"):
            DynatraceAdapter(None, api_token=TOKEN)
        with pytest.raises(ValueError, match="dynatrace_tenant_url"):
            DynatraceAdapter("", api_token=TOKEN)

    def test_constructor_refuses_empty_token(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="dynatrace_api_token"):
            DynatraceAdapter(TENANT, api_token=None)
        with pytest.raises(ValueError, match="dynatrace_api_token"):
            DynatraceAdapter(TENANT, api_token="")


class TestHealth:
    @respx.mock
    async def test_health_ok(self) -> None:
        respx.get(f"{TENANT}/api/v2/metrics/query?metricSelector=builtin:host.cpu.usage&pageSize=1").mock(
            return_value=Response(200, json={"version": "1.301.0"})
        )
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        h = await a.health_check()
        assert h.status == "ok"
        assert h.driver == "dynatrace"
        assert h.latency_ms is not None

    @respx.mock
    async def test_health_unreachable_on_connect_error(self) -> None:
        respx.get(f"{TENANT}/api/v2/metrics/query?metricSelector=builtin:host.cpu.usage&pageSize=1").mock(side_effect=ConnectError("nope"))
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        h = await a.health_check()
        assert h.status == "unreachable"

    @respx.mock
    async def test_health_unreachable_on_401(self) -> None:
        """Bad / expired API token → 401; surface as unreachable so
        operators see the auth failure in /readyz."""

        respx.get(f"{TENANT}/api/v2/metrics/query?metricSelector=builtin:host.cpu.usage&pageSize=1").mock(return_value=Response(401))
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        h = await a.health_check()
        assert h.status == "unreachable"

    @respx.mock
    async def test_health_sends_api_token_header(self) -> None:
        """Dynatrace API expects ``Authorization: Api-Token <value>`` —
        not ``Bearer``. Verify the adapter sends the right shape."""

        route = respx.get(f"{TENANT}/api/v2/metrics/query?metricSelector=builtin:host.cpu.usage&pageSize=1").mock(
            return_value=Response(200, json={})
        )
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        await a.health_check()
        assert route.called
        sent = route.calls.last.request
        assert sent.headers["authorization"] == f"Api-Token {TOKEN}"


class TestEmissions:
    async def test_emit_trace_no_raise(self) -> None:
        """Trace emission rides Sprint 1B's OTel pipeline (configured via
        OTEL_EXPORTER_OTLP_ENDPOINT to point at Dynatrace's OTLP ingest).
        The adapter creates spans; OTel exports."""

        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        await a.emit_trace("test_span", {"k": 1, "k2": "v"})

    @respx.mock
    async def test_emit_metric_posts_line_protocol(self) -> None:
        """Dynatrace Metric Ingest line-protocol shape:
        ``<metric.name>,<dim1>=<v1>,<dim2>=<v2> <value> <ts_ms>``.
        ``ts`` is optional (server uses ingest time)."""

        route = respx.post(f"{TENANT}/api/v2/metrics/ingest").mock(
            return_value=Response(202)
        )
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        await a.emit_metric("agentos.test.gauge", 42.0, {"adapter": "dynatrace"})

        assert route.called
        sent = route.calls.last.request
        body = sent.content.decode("utf-8")
        # Line protocol: metric.name + dimensions + value
        assert body.startswith("agentos.test.gauge")
        assert "adapter=dynatrace" in body
        assert " 42.0" in body or " 42" in body
        # Header: text/plain for line protocol, NOT application/json
        assert sent.headers["content-type"] == "text/plain"
        assert sent.headers["authorization"] == f"Api-Token {TOKEN}"

    @respx.mock
    async def test_emit_metric_no_raise_on_outage(self) -> None:
        """Observability outages must NOT raise into the request path;
        same rule as LangfuseOtelAdapter.flush()."""

        respx.post(f"{TENANT}/api/v2/metrics/ingest").mock(
            side_effect=ConnectError("nope")
        )
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        # Must not raise
        await a.emit_metric("agentos.test.gauge", 1.0, {})

    @respx.mock
    async def test_flush_no_raise(self) -> None:
        """flush is a non-raising best-effort liveness ping."""

        respx.get(f"{TENANT}/api/v2/metrics/query?metricSelector=builtin:host.cpu.usage&pageSize=1").mock(side_effect=ConnectError("nope"))
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        await a.flush()


class TestSatisfiesProtocol:
    def test_protocol_conformance(self) -> None:
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        assert isinstance(a, P.ObservabilityAdapter)
```

- [ ] **Step 4.2: Run the test, expect failure**

```bash
uv run pytest tests/unit/db/test_dynatrace_adapter.py -v
```

Expected: `cannot import name 'DynatraceAdapter'`.

- [ ] **Step 4.3: Create the adapter**

```python
"""DynatraceAdapter — OTel-bridged observability sink + Dynatrace Metric
Ingest API for native custom metrics + HTTP health probe.

Driver name: ``dynatrace``. Auto-registers into ``bundled_registry`` on import.

**Sprint 1D scope:**

- ``emit_trace`` creates an in-process OpenTelemetry span. Trace export
  to Dynatrace's OTLP ingest is configured at the OTel-pipeline level
  (Sprint 1B ``observability/otel.py`` reads
  ``COGNIC_OTEL_EXPORTER_ENDPOINT``); the adapter does not duplicate
  that wiring.
- ``emit_metric`` POSTs Dynatrace Metric Ingest line protocol to
  ``/api/v2/metrics/ingest``. Non-raising on outage so observability
  failures never propagate into the request path.
- ``flush`` is a non-raising best-effort liveness ping.
- ``health_check`` GETs ``/api/v2/metrics/query?metricSelector=builtin:host.cpu.usage&pageSize=1``
  with the ``Authorization: Api-Token <value>`` header Dynatrace expects
  (note: ``Api-Token``, not ``Bearer``). The metrics-query endpoint
  validates BOTH connectivity AND token scope — a 200 proves the token
  has the ``metrics.read`` scope and the tenant URL is reachable; a 401
  proves the token is bad; any non-200 → ``unreachable``.

**Required Dynatrace API token scopes** (operator must grant when
provisioning the token in the Dynatrace UI):
  - ``metrics.read`` — for the ``health_check`` probe
  - ``metrics.ingest`` — for ``emit_metric`` POST to ``/api/v2/metrics/ingest``
  - (no ``traces.write`` needed — trace export rides the Sprint 1B OTel
    pipeline configured separately via ``OTEL_EXPORTER_OTLP_ENDPOINT``)

Per BUILD_PLAN Sprint 1D exit criterion: ``COGNIC_OBS_DRIVER=dynatrace``
+ Vault-stored API token → ``/readyz`` shows
``observability: {driver: dynatrace, status: ok}``. Native runtime Vault
resolution lands with Sprint 10 (Vault credential leasing); Sprint 1D
takes the token via direct env or operator-side secret-mount.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx
from opentelemetry import trace

from cognic_agentos.db.adapters.protocols import AdapterHealth
from cognic_agentos.db.adapters.registry import bundled_registry

logger = logging.getLogger(__name__)


class DynatraceAdapter:
    driver = "dynatrace"

    def __init__(self, tenant_url: str | None, api_token: str | None) -> None:
        if not tenant_url:
            raise ValueError(
                "DynatraceAdapter requires dynatrace_tenant_url; got empty/None"
            )
        if not api_token:
            raise ValueError(
                "DynatraceAdapter requires dynatrace_api_token; got empty/None"
            )
        self._tenant = tenant_url.rstrip("/")
        self._token = api_token
        self._tracer = trace.get_tracer("cognic_agentos.observability.dynatrace")

    def _headers(self, content_type: str = "application/json") -> dict[str, str]:
        return {
            "Authorization": f"Api-Token {self._token}",
            "Content-Type": content_type,
        }

    async def emit_trace(self, name: str, attributes: dict[str, Any]) -> None:
        # OTel trace emit is in-process and never raises on Dynatrace outage.
        with self._tracer.start_as_current_span(name) as span:
            for k, v in attributes.items():
                if isinstance(v, str | bool | int | float):
                    span.set_attribute(k, v)
                else:
                    span.set_attribute(k, str(v))

    async def emit_metric(
        self, name: str, value: float, attributes: dict[str, Any]
    ) -> None:
        # Dynatrace Metric Ingest line protocol:
        #   <metric.name>,<dim1>=<v1>,<dim2>=<v2> <value>
        dim_parts = [f"{k}={v}" for k, v in attributes.items()]
        dim_block = "," + ",".join(dim_parts) if dim_parts else ""
        line = f"{name}{dim_block} {value}"

        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                await client.post(
                    f"{self._tenant}/api/v2/metrics/ingest",
                    headers=self._headers(content_type="text/plain"),
                    content=line.encode("utf-8"),
                )
        except Exception as exc:
            # Observability outages must NOT raise into the request path.
            logger.warning("dynatrace metric emit failed: %s", exc)

    async def flush(self) -> None:
        # Best-effort liveness ping. Same non-raising contract as
        # LangfuseOtelAdapter.flush() — observability outages never
        # propagate as runtime errors.
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                await client.get(
                    f"{self._tenant}/api/v2/metrics/query?metricSelector=builtin:host.cpu.usage&pageSize=1",
                    headers=self._headers(),
                )
        except Exception as exc:
            logger.warning("dynatrace flush ping failed: %s", exc)

    async def health_check(self) -> AdapterHealth:
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(
                    f"{self._tenant}/api/v2/metrics/query?metricSelector=builtin:host.cpu.usage&pageSize=1",
                    headers=self._headers(),
                )
                resp.raise_for_status()
        except Exception as exc:
            return AdapterHealth(
                status="unreachable",
                driver=self.driver,
                detail=type(exc).__name__,
            )
        return AdapterHealth(
            status="ok",
            driver=self.driver,
            latency_ms=(time.perf_counter() - start) * 1000.0,
        )


bundled_registry.register("observability", "dynatrace", DynatraceAdapter)
```

- [ ] **Step 4.4: Add the module to the bundled-loader allowlist**

In `src/cognic_agentos/db/adapters/__init__.py`, append to `_BUNDLED_ADAPTER_OPTIONAL_DEPS`:

```python
    # Dynatrace adapter only depends on httpx + opentelemetry (both core); no kernel-image misses.
    "cognic_agentos.db.adapters.dynatrace_adapter": frozenset(),
```

- [ ] **Step 4.5: Run + format + commit**

```bash
uv run pytest tests/unit/db/test_dynatrace_adapter.py -v
uv run ruff format src/cognic_agentos/db/adapters/dynatrace_adapter.py tests/unit/db/test_dynatrace_adapter.py
uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/db/adapters/dynatrace_adapter.py \
        src/cognic_agentos/db/adapters/__init__.py \
        tests/unit/db/test_dynatrace_adapter.py
git commit -m "feat(sprint-1d): DynatraceAdapter (OTel-bridged + Metric Ingest line protocol)"
```

Expected: ~10 new tests pass; suite ~221.

---

### Task 5: OpenAICompatEmbeddingAdapter (vLLM / SGLang / OpenAI / Azure / Bedrock-via-shim)

EmbeddingAdapter against any OpenAI-compatible `/v1/embeddings` endpoint. Records `provider_label` for audit clarity. Mirrors `OllamaEmbeddingAdapter`'s httpx shape but speaks the OpenAI v1 schema.

**Files:**
- Create: `src/cognic_agentos/db/adapters/openai_compat_embedding_adapter.py`
- Create: `tests/unit/db/test_openai_compat_embedding_adapter.py`

- [ ] **Step 5.1: Write the failing test**

```python
"""OpenAICompatEmbeddingAdapter — speaks the OpenAI /v1/embeddings
schema; covers vLLM / SGLang (no auth), OpenAI / Cohere (Bearer auth),
Azure-OpenAI / Bedrock when fronted by an OpenAI-compat proxy
(api-key + extra_headers)."""

from __future__ import annotations

import json

import respx
from httpx import ConnectError, Response

from cognic_agentos.db.adapters import bundled_registry
from cognic_agentos.db.adapters import protocols as P
from cognic_agentos.db.adapters.openai_compat_embedding_adapter import (
    OpenAICompatEmbeddingAdapter,
)

BASE = "http://vllm.test:8000"
MODEL = "BAAI/bge-large-en-v1.5"


def _adapter(**overrides: object) -> OpenAICompatEmbeddingAdapter:
    """Helper: build an adapter with sensible vLLM-no-auth defaults."""

    kwargs: dict[str, object] = dict(
        base_url=BASE,
        model=MODEL,
        dimensions=4,
        provider_label="vllm",
        api_key=None,
        api_key_header="Authorization",
        extra_headers={},
    )
    kwargs.update(overrides)
    return OpenAICompatEmbeddingAdapter(**kwargs)  # type: ignore[arg-type]


class TestRegistration:
    def test_openai_compat_registered_under_bundled(self) -> None:
        assert bundled_registry.has("embedding", "openai_compat")
        assert (
            bundled_registry.resolve("embedding", "openai_compat")
            is OpenAICompatEmbeddingAdapter
        )


class TestConstruction:
    def test_constructor_refuses_empty_base_url(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="embedding_base_url"):
            _adapter(base_url=None)
        with pytest.raises(ValueError, match="embedding_base_url"):
            _adapter(base_url="")

    def test_provider_label_property(self) -> None:
        assert _adapter(provider_label="vllm").provider_label == "vllm"

    def test_dimensions_property(self) -> None:
        assert _adapter(dimensions=1024).dimensions == 1024


class TestEmbedNoAuth:
    """vLLM / SGLang local stacks expose /v1/embeddings without auth.
    No Authorization header should be sent when api_key is None."""

    @respx.mock
    async def test_embed_no_auth_header_when_api_key_none(self) -> None:
        route = respx.post(f"{BASE}/v1/embeddings").mock(
            return_value=Response(
                200,
                json={
                    "data": [{"embedding": [0.1, 0.2, 0.3, 0.4], "index": 0}],
                    "model": MODEL,
                    "object": "list",
                },
            )
        )
        a = _adapter(api_key=None)
        v = await a.embed(["foo"])
        assert len(v) == 1

        sent = route.calls.last.request
        # Must NOT have sent any auth header
        assert "authorization" not in {h.lower() for h in sent.headers.keys()}
        assert "api-key" not in {h.lower() for h in sent.headers.keys()}

    @respx.mock
    async def test_embed_posts_openai_v1_schema(self) -> None:
        """OpenAI v1 schema: ``POST /v1/embeddings`` with body
        ``{"input": [...], "model": "...", "encoding_format": "float"}``."""

        route = respx.post(f"{BASE}/v1/embeddings").mock(
            return_value=Response(
                200,
                json={
                    "data": [
                        {"embedding": [0.1, 0.2, 0.3, 0.4], "index": 0},
                        {"embedding": [0.5, 0.6, 0.7, 0.8], "index": 1},
                    ],
                    "model": MODEL,
                    "object": "list",
                    "usage": {"prompt_tokens": 4, "total_tokens": 4},
                },
            )
        )
        a = _adapter()
        v = await a.embed(["foo", "bar"])
        assert len(v) == 2
        assert v[0] == [0.1, 0.2, 0.3, 0.4]
        assert v[1] == [0.5, 0.6, 0.7, 0.8]

        sent = route.calls.last.request
        body = json.loads(sent.content)
        assert body["input"] == ["foo", "bar"]
        assert body["model"] == MODEL
        assert body["encoding_format"] == "float"

    @respx.mock
    async def test_embed_preserves_index_order(self) -> None:
        """OpenAI's response order matches request order via the ``index``
        field; the adapter sorts by index defensively in case providers
        respond out-of-order."""

        respx.post(f"{BASE}/v1/embeddings").mock(
            return_value=Response(
                200,
                json={
                    "data": [
                        {"embedding": [0.5, 0.6], "index": 1},
                        {"embedding": [0.1, 0.2], "index": 0},
                    ],
                    "model": MODEL,
                    "object": "list",
                },
            )
        )
        a = _adapter(provider_label="sglang", dimensions=2)
        v = await a.embed(["a", "b"])
        assert v[0] == [0.1, 0.2]
        assert v[1] == [0.5, 0.6]


class TestEmbedValidation:
    """Defensive validation: response-count + embedding-shape checks
    catch out-of-spec providers before mis-aligned rows poison
    downstream retrieval / index state."""

    @respx.mock
    async def test_embed_raises_on_response_count_mismatch(self) -> None:
        """Provider returns fewer rows than requested → fail loud."""

        import pytest

        respx.post(f"{BASE}/v1/embeddings").mock(
            return_value=Response(
                200,
                json={
                    "data": [
                        # Requested 2 inputs, only 1 row returned
                        {"embedding": [0.1, 0.2, 0.3, 0.4], "index": 0},
                    ],
                    "model": MODEL,
                    "object": "list",
                },
            )
        )
        a = _adapter()
        with pytest.raises(ValueError, match="response shape mismatch"):
            await a.embed(["foo", "bar"])

    @respx.mock
    async def test_embed_raises_on_wrong_dimensions(self) -> None:
        """Provider returns a row with dim != adapter.dimensions →
        operator misconfiguration; fail loud."""

        import pytest

        respx.post(f"{BASE}/v1/embeddings").mock(
            return_value=Response(
                200,
                json={
                    "data": [
                        # adapter dimensions=4 but provider returned 8
                        {
                            "embedding": [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8],
                            "index": 0,
                        },
                    ],
                    "model": MODEL,
                    "object": "list",
                },
            )
        )
        a = _adapter(dimensions=4)
        with pytest.raises(ValueError, match="dim=8.*dimensions=4"):
            await a.embed(["foo"])

    @respx.mock
    async def test_embed_raises_on_non_list_embedding(self) -> None:
        """Provider returns malformed row → fail loud rather than
        silently producing garbage."""

        import pytest

        respx.post(f"{BASE}/v1/embeddings").mock(
            return_value=Response(
                200,
                json={
                    "data": [{"embedding": "not-a-list", "index": 0}],
                    "model": MODEL,
                    "object": "list",
                },
            )
        )
        a = _adapter()
        with pytest.raises(ValueError, match="not a list"):
            await a.embed(["foo"])


class TestEmbedBearerAuth:
    """OpenAI / Cohere / vLLM-with-auth-token: ``Authorization: Bearer <key>``."""

    @respx.mock
    async def test_embed_sends_bearer_authorization(self) -> None:
        route = respx.post(f"{BASE}/v1/embeddings").mock(
            return_value=Response(
                200,
                json={
                    "data": [{"embedding": [0.1, 0.2, 0.3, 0.4], "index": 0}],
                    "model": MODEL,
                    "object": "list",
                },
            )
        )
        a = _adapter(api_key="sk-test-openai-key", api_key_header="Authorization")
        await a.embed(["foo"])

        sent = route.calls.last.request
        assert sent.headers["authorization"] == "Bearer sk-test-openai-key"


class TestEmbedAzureApiKeyAuth:
    """Azure-OpenAI proxy convention: ``api-key: <key>`` header (raw, no prefix)
    + custom api-version query/header carried via extra_headers."""

    @respx.mock
    async def test_embed_sends_api_key_header_raw(self) -> None:
        route = respx.post(f"{BASE}/v1/embeddings").mock(
            return_value=Response(
                200,
                json={
                    "data": [{"embedding": [0.1, 0.2, 0.3, 0.4], "index": 0}],
                    "model": MODEL,
                    "object": "list",
                },
            )
        )
        a = _adapter(
            api_key="azure-key-value",
            api_key_header="api-key",
            extra_headers={"api-version": "2024-02-15-preview"},
        )
        await a.embed(["foo"])

        sent = route.calls.last.request
        # Raw key value (no Bearer prefix)
        assert sent.headers["api-key"] == "azure-key-value"
        assert "authorization" not in {h.lower() for h in sent.headers.keys()}
        # extra_headers carried through
        assert sent.headers["api-version"] == "2024-02-15-preview"


class TestHealth:
    @respx.mock
    async def test_health_ok_via_v1_models(self) -> None:
        """Standard OpenAI-compat liveness path is GET /v1/models."""

        respx.get(f"{BASE}/v1/models").mock(
            return_value=Response(
                200, json={"object": "list", "data": [{"id": MODEL}]}
            )
        )
        a = _adapter(dimensions=1024)
        h = await a.health_check()
        assert h.status == "ok"
        assert h.driver == "openai_compat"
        assert h.latency_ms is not None

    @respx.mock
    async def test_health_uses_same_auth_headers_as_embed(self) -> None:
        """The /v1/models probe must validate the same auth path that
        embed() uses, otherwise health_check could falsely report ``ok``
        on misconfigured tokens."""

        route = respx.get(f"{BASE}/v1/models").mock(
            return_value=Response(200, json={"object": "list", "data": []})
        )
        a = _adapter(api_key="sk-bearer", api_key_header="Authorization")
        await a.health_check()

        sent = route.calls.last.request
        assert sent.headers["authorization"] == "Bearer sk-bearer"

    @respx.mock
    async def test_health_unreachable_on_connect_error(self) -> None:
        respx.get(f"{BASE}/v1/models").mock(side_effect=ConnectError("nope"))
        a = _adapter()
        h = await a.health_check()
        assert h.status == "unreachable"

    @respx.mock
    async def test_health_unreachable_on_401(self) -> None:
        """Bad/expired API key → 401; surface as unreachable so operators
        see the auth failure in /readyz rather than getting silent embed
        failures later."""

        respx.get(f"{BASE}/v1/models").mock(return_value=Response(401))
        a = _adapter(api_key="sk-stale")
        h = await a.health_check()
        assert h.status == "unreachable"


class TestSatisfiesProtocol:
    def test_protocol_conformance(self) -> None:
        a = _adapter(dimensions=1024)
        assert isinstance(a, P.EmbeddingAdapter)
```

- [ ] **Step 5.2: Run the test, expect failure**

```bash
uv run pytest tests/unit/db/test_openai_compat_embedding_adapter.py -v
```

Expected: `cannot import name 'OpenAICompatEmbeddingAdapter'`.

- [ ] **Step 5.3: Create the adapter**

```python
"""OpenAICompatEmbeddingAdapter — EmbeddingAdapter against any
OpenAI-compatible /v1/embeddings endpoint.

Driver name: ``openai_compat``. Auto-registers into ``bundled_registry``
on import.

Per ADR-009 this adapter is the production embedding default for banks
running vLLM/SGLang (no auth), OpenAI/Cohere (Bearer), or Azure-OpenAI
/ Bedrock when fronted by an OpenAI-compat proxy (api-key + extra
headers). Direct Azure-OpenAI URL shape requires a separate Azure-
specific adapter (deferred — see Sprint 1D plan + BUILD_PLAN amendment).

Auth surface:
- ``api_key`` is None → no auth header sent (vLLM/SGLang local default).
- ``api_key_header == "Authorization"`` → ``Authorization: Bearer <key>``
  (OpenAI / Cohere / vLLM-with-auth convention).
- Any other ``api_key_header`` value → ``<header>: <key>`` raw, no
  prefix (e.g. ``api-key`` for Azure-OpenAI proxies).
- ``extra_headers`` carries provider-specific quirks (e.g. Azure's
  ``api-version`` header) and is sent on every /v1/embeddings + /v1/models
  request, including health probes.

The ``provider_label`` is exposed as a property; per-embed audit
emission of the label lands with Sprint 2 ``core/audit`` wiring (Sprint
1D ships storage + plumbing only — see BUILD_PLAN amendment).
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from cognic_agentos.db.adapters.protocols import AdapterHealth
from cognic_agentos.db.adapters.registry import bundled_registry


class OpenAICompatEmbeddingAdapter:
    driver = "openai_compat"

    def __init__(
        self,
        base_url: str | None,
        model: str,
        dimensions: int,
        provider_label: str,
        api_key: str | None = None,
        api_key_header: str = "Authorization",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        if not base_url:
            raise ValueError(
                "OpenAICompatEmbeddingAdapter requires embedding_base_url; got empty/None"
            )
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._dimensions = dimensions
        self._provider_label = provider_label
        self._api_key = api_key
        self._api_key_header = api_key_header
        self._extra_headers = dict(extra_headers or {})

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = dict(self._extra_headers)
        if self._api_key:
            if self._api_key_header == "Authorization":
                # OpenAI / Cohere / vLLM-with-auth convention
                h["Authorization"] = f"Bearer {self._api_key}"
            else:
                # Azure-OpenAI proxy convention: raw key under custom header
                h[self._api_key_header] = self._api_key
        return h

    async def embed(self, texts: list[str]) -> list[list[float]]:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._base_url}/v1/embeddings",
                headers=self._headers(),
                json={
                    "input": texts,
                    "model": self._model,
                    "encoding_format": "float",
                },
            )
            resp.raise_for_status()
            body = resp.json()
        data: list[dict[str, Any]] = body.get("data", [])

        # Validation: response count must match request count. Out-of-spec
        # providers that drop or duplicate rows would otherwise silently
        # mis-align downstream consumers (e.g. retrieval upserts).
        if len(data) != len(texts):
            raise ValueError(
                f"OpenAI-compat embedding response shape mismatch: requested "
                f"{len(texts)} input(s), got {len(data)} row(s) from "
                f"{self._provider_label!r}"
            )

        # Defensively sort by ``index`` so providers that respond out of
        # order (rare, but spec-permitted) still yield request-order rows.
        data_sorted = sorted(data, key=lambda d: int(d.get("index", 0)))

        out: list[list[float]] = []
        for i, d in enumerate(data_sorted):
            embedding = d.get("embedding")
            # Validation: embedding must be a list of numerics with the
            # adapter's declared dimensionality. A wrong-dim response is
            # almost always a model misconfiguration (operator pointed
            # the adapter at a different model than declared) — fail
            # loudly so retrieval doesn't poison its index with garbage
            # rows.
            if not isinstance(embedding, list):
                raise ValueError(
                    f"OpenAI-compat embedding row {i} from "
                    f"{self._provider_label!r} is not a list: "
                    f"got {type(embedding).__name__}"
                )
            if len(embedding) != self._dimensions:
                raise ValueError(
                    f"OpenAI-compat embedding row {i} from "
                    f"{self._provider_label!r} has dim={len(embedding)}, "
                    f"adapter declared dimensions={self._dimensions}. "
                    f"Likely misconfigured: COGNIC_EMBEDDING_DIMENSIONS "
                    f"must match the deployed model's actual output dim."
                )
            out.append([float(x) for x in embedding])
        return out

    @property
    def dimensions(self) -> int:
        return self._dimensions

    @property
    def provider_label(self) -> str:
        return self._provider_label

    async def health_check(self) -> AdapterHealth:
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(
                    f"{self._base_url}/v1/models",
                    headers=self._headers(),
                )
                resp.raise_for_status()
        except Exception as exc:
            return AdapterHealth(
                status="unreachable",
                driver=self.driver,
                detail=type(exc).__name__,
            )
        return AdapterHealth(
            status="ok",
            driver=self.driver,
            latency_ms=(time.perf_counter() - start) * 1000.0,
        )


bundled_registry.register("embedding", "openai_compat", OpenAICompatEmbeddingAdapter)
```

- [ ] **Step 5.4: Add the module to the bundled-loader allowlist**

In `src/cognic_agentos/db/adapters/__init__.py`, append to `_BUNDLED_ADAPTER_OPTIONAL_DEPS`:

```python
    # OpenAI-compat embedding only depends on httpx (always present); no kernel-image misses.
    "cognic_agentos.db.adapters.openai_compat_embedding_adapter": frozenset(),
```

- [ ] **Step 5.5: Run + format + commit**

```bash
uv run pytest tests/unit/db/test_openai_compat_embedding_adapter.py -v
uv run ruff format src/cognic_agentos/db/adapters/openai_compat_embedding_adapter.py \
                   tests/unit/db/test_openai_compat_embedding_adapter.py
uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/db/adapters/openai_compat_embedding_adapter.py \
        src/cognic_agentos/db/adapters/__init__.py \
        tests/unit/db/test_openai_compat_embedding_adapter.py
git commit -m "feat(sprint-1d): OpenAICompatEmbeddingAdapter (vLLM/SGLang/OpenAI/Azure/Bedrock-shim)"
```

Expected: ~10 new tests pass; suite ~231.

---

### Task 6: Factory per-driver-arg helpers + bundled-registry verification

Extend `factory.py` with per-driver-arg branches for the three new drivers, and extend `tests/unit/db/test_adapter_factory.py::TestPerDriverArgs` with corresponding tests. Also extend `test_bundled_registry_lists_real_drivers` to include the three new modules.

**Files:**
- Modify: `src/cognic_agentos/db/adapters/factory.py`
- Modify: `tests/unit/db/test_adapter_factory.py`

- [ ] **Step 6.1: Extend `factory.py` per-driver-arg helpers**

In `src/cognic_agentos/db/adapters/factory.py`:

```python
def _relational_args(s: Settings) -> tuple[Any, ...]:
    if s.db_driver == "memory":
        return ()
    if s.db_driver == "postgres":
        return (s.database_url,)
    if s.db_driver == "oracle":
        return (s.database_url,)
    return ()  # plugin packs may take additional args via their own helper


def _embedding_args(s: Settings) -> tuple[Any, ...]:
    if s.embed_driver == "memory":
        return ()
    if s.embed_driver == "ollama":
        return (s.embedding_base_url, s.embedding_model, s.embedding_dimensions)
    if s.embed_driver == "openai_compat":
        return (
            s.embedding_base_url,
            s.embedding_model,
            s.embedding_dimensions,
            s.embed_provider_label,
            s.embedding_api_key,
            s.embedding_api_key_header,
            s.embedding_extra_headers,
        )
    return ()


def _observability_args(s: Settings) -> tuple[Any, ...]:
    if s.obs_driver == "memory":
        return ()
    if s.obs_driver == "langfuse_otel":
        return (s.langfuse_host, s.langfuse_public_key, s.langfuse_secret_key)
    if s.obs_driver == "dynatrace":
        return (s.dynatrace_tenant_url, s.dynatrace_api_token)
    return ()
```

- [ ] **Step 6.2: Extend `test_adapter_factory.py::TestPerDriverArgs`**

Append to the `TestPerDriverArgs` class:

```python
    def test_relational_oracle_args(self, base_settings: Any) -> None:
        from cognic_agentos.db.adapters.factory import _relational_args

        s = base_settings.model_copy(
            update={
                "db_driver": "oracle",
                "database_url": "oracle+oracledb://u:p@h:1521/?service_name=XEPDB1",
            }
        )
        assert _relational_args(s) == ("oracle+oracledb://u:p@h:1521/?service_name=XEPDB1",)

    def test_observability_dynatrace_args(self, base_settings: Any) -> None:
        from cognic_agentos.db.adapters.factory import _observability_args

        s = base_settings.model_copy(
            update={
                "obs_driver": "dynatrace",
                "dynatrace_tenant_url": "https://abc.live.dynatrace.com",
                "dynatrace_api_token": "dt0c01.tok",
            }
        )
        assert _observability_args(s) == (
            "https://abc.live.dynatrace.com",
            "dt0c01.tok",
        )

    def test_embedding_openai_compat_args(self, base_settings: Any) -> None:
        from cognic_agentos.db.adapters.factory import _embedding_args

        s = base_settings.model_copy(
            update={
                "embed_driver": "openai_compat",
                "embedding_base_url": "http://vllm:8000",
                "embedding_model": "BAAI/bge-large-en-v1.5",
                "embedding_dimensions": 1024,
                "embed_provider_label": "vllm",
                "embedding_api_key": "sk-test",
                "embedding_api_key_header": "Authorization",
                "embedding_extra_headers": {"x-trace": "abc"},
            }
        )
        assert _embedding_args(s) == (
            "http://vllm:8000",
            "BAAI/bge-large-en-v1.5",
            1024,
            "vllm",
            "sk-test",
            "Authorization",
            {"x-trace": "abc"},
        )
```

- [ ] **Step 6.3a: Update Sprint-1C "unknown driver" tests to use truly-unknown driver names**

The Sprint 1C `TestPerDriverArgs` class included three tests verifying that unknown drivers return empty tuples — using `mssql` (relational), `chroma` (vector), `aws` (secret), `openai_compat` (embed), and `dynatrace` (obs) as the "unknown" placeholders. **Two of those — `openai_compat` and `dynatrace` — become bundled drivers in Sprint 1D**, so the existing tests would now assert wrong behaviour. Update them to use names that are NOT bundled in either sprint.

In `tests/unit/db/test_adapter_factory.py`:

```python
    def test_embedding_unknown_returns_empty(self, base_settings: Any) -> None:
        """Use a placeholder name that's truly not bundled (Sprint 1D
        added openai_compat to bundled). ``cohere_native`` represents a
        future Cohere-native (non-OpenAI-shape) plugin pack."""

        from cognic_agentos.db.adapters.factory import _embedding_args

        s = base_settings.model_copy(update={"embed_driver": "cohere_native"})
        assert _embedding_args(s) == ()

    def test_observability_unknown_returns_empty(self, base_settings: Any) -> None:
        """Use a placeholder name that's truly not bundled (Sprint 1D
        added dynatrace to bundled). ``splunk`` is a future plugin-pack
        candidate per ADR-009."""

        from cognic_agentos.db.adapters.factory import _observability_args

        s = base_settings.model_copy(update={"obs_driver": "splunk"})
        assert _observability_args(s) == ()
```

Apply via `Edit` against the existing methods (they currently use `openai_compat` and `dynatrace` as the "unknown" names — Sprint 1D makes both known).

- [ ] **Step 6.3: Extend `test_bundled_registry_lists_real_drivers`**

In `test_adapter_factory.py`, find the existing `test_bundled_registry_lists_real_drivers` method and extend the iteration tuple + assertions:

```python
    def test_bundled_registry_lists_real_drivers(self) -> None:
        """``load_bundled_adapters()`` registers all eight Sprint-1C+1D
        drivers in the test env (--all-extras so every module loads)."""

        from cognic_agentos.db.adapters import load_bundled_adapters

        results = load_bundled_adapters()
        for module_name in (
            "cognic_agentos.db.adapters.postgres_adapter",
            "cognic_agentos.db.adapters.qdrant_adapter",
            "cognic_agentos.db.adapters.vault_adapter",
            "cognic_agentos.db.adapters.ollama_embedding_adapter",
            "cognic_agentos.db.adapters.langfuse_otel_adapter",
            # Sprint 1D
            "cognic_agentos.db.adapters.oracle_adapter",
            "cognic_agentos.db.adapters.dynatrace_adapter",
            "cognic_agentos.db.adapters.openai_compat_embedding_adapter",
        ):
            assert results[module_name] == "loaded", (
                f"{module_name} should load in the test env: {results[module_name]}"
            )

        # Sprint 1C drivers
        assert bundled_registry.has("relational", "postgres")
        assert bundled_registry.has("vector", "qdrant")
        assert bundled_registry.has("secret", "vault")
        assert bundled_registry.has("embedding", "ollama")
        assert bundled_registry.has("observability", "langfuse_otel")
        # Sprint 1D drivers
        assert bundled_registry.has("relational", "oracle")
        assert bundled_registry.has("observability", "dynatrace")
        assert bundled_registry.has("embedding", "openai_compat")
```

- [ ] **Step 6.4: Run + format + commit**

```bash
uv run pytest tests/unit/db/test_adapter_factory.py -v
uv run ruff format src/cognic_agentos/db/adapters/factory.py tests/unit/db/test_adapter_factory.py
uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/db/adapters/factory.py tests/unit/db/test_adapter_factory.py
git commit -m "feat(sprint-1d): factory per-driver-arg helpers for oracle/dynatrace/openai_compat"
```

Expected: 3 new TestPerDriverArgs tests + 3 new bundled-registry assertions; suite ~234.

---

### Task 7: docker-compose.oracle.yml overlay

Opt-in compose overlay activated via `docker compose -f docker-compose.yml -f docker-compose.oracle.yml up -d`. `gvenzl/oracle-xe:21-slim` is the standard community image (Oracle's own images are huge; gvenzl is the compose-friendly community build).

**Files:**
- Create: `infra/dev/docker-compose.oracle.yml`

- [ ] **Step 7.1: Create the overlay**

```yaml
# Cognic AgentOS — Oracle XE 21c compose overlay (Sprint 1D opt-in).
#
# Activated via:
#   docker compose -f infra/dev/docker-compose.yml \
#                  -f infra/dev/docker-compose.oracle.yml up -d
#
# Most devs run Postgres locally; Oracle is opt-in only when testing the
# Oracle adapter or running `pytest -m oracle`.
#
# gvenzl/oracle-xe is the standard community image — Oracle's own images
# are licensed + huge. The :21-slim variant is ~2 GB compressed, ~3 GB
# unpacked, and needs ~2 GB RAM. First-boot takes ~3-5 minutes while the
# database initialises; subsequent boots are <30s once the volume is
# populated.

services:
  oracle:
    image: gvenzl/oracle-xe:21-slim
    container_name: cognic-agentos-oracle
    environment:
      ORACLE_PASSWORD: cognic_dev_only  # NEVER used outside dev
      APP_USER: cognic
      APP_USER_PASSWORD: cognic_dev_only
    ports:
      - "${COGNIC_ORACLE_PORT:-1521}:1521"
    volumes:
      - oracle-data:/opt/oracle/oradata
    healthcheck:
      # gvenzl ships a /opt/oracle/healthcheck.sh that checks SQL*Plus
      # connectivity. ~3-5 minutes on first boot before it returns 0.
      test: ["CMD", "/opt/oracle/healthcheck.sh"]
      interval: 10s
      timeout: 5s
      retries: 60          # generous for first-boot init
      start_period: 60s    # don't probe for 60s after start

volumes:
  oracle-data:
```

- [ ] **Step 7.2: Validate**

```bash
docker compose -f infra/dev/docker-compose.yml \
               -f infra/dev/docker-compose.oracle.yml \
               config --quiet && echo "compose+overlay valid"
```

Expected: validates clean.

- [ ] **Step 7.3: Commit**

```bash
git add infra/dev/docker-compose.oracle.yml
git commit -m "feat(sprint-1d): docker-compose.oracle.yml overlay (Oracle XE 21c, opt-in)"
```

---

### Task 8: docker-compose.vllm.yml overlay

Opt-in single-GPU vLLM node. CI runs without; only GPU machines activate.

**Files:**
- Create: `infra/dev/docker-compose.vllm.yml`

- [ ] **Step 8.1: Create the overlay**

```yaml
# Cognic AgentOS — vLLM GPU compose overlay (Sprint 1D opt-in).
#
# Activated via:
#   docker compose -f infra/dev/docker-compose.yml \
#                  -f infra/dev/docker-compose.vllm.yml up -d
#
# Requires:
#   - NVIDIA Container Toolkit installed on the host
#   - At least one CUDA-capable GPU
#
# CI runs without this overlay (CI has no GPU). Local GPU machines + bank
# staging environments use this to validate the openai_compat embedding
# path against a real vLLM instance.

services:
  vllm:
    # Pin: avoid `latest` so a vLLM upstream-image change can't silently
    # break the overlay between local-dev sessions. v0.6.6 is an
    # **intentionally conservative** pin used as a known-shape baseline
    # for the dev-stack contract (the OpenAI-compat /v1/embeddings +
    # /v1/models endpoints have been stable since v0.5.x). Operators
    # productionising on real GPU hardware should bump to a current
    # stable (recent vLLM releases are tracked at
    # https://github.com/vllm-project/vllm/releases) and re-verify
    # against their CUDA driver before locking the production pin.
    image: vllm/vllm-openai:v0.6.6
    container_name: cognic-agentos-vllm
    runtime: nvidia
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
    environment:
      # Pick a small embedding model by default; operators override to
      # match their cluster's GPU memory. Defaults are dev-friendly only.
      VLLM_SERVED_MODEL: ${VLLM_SERVED_MODEL:-BAAI/bge-large-en-v1.5}
    command: ["--model", "${VLLM_SERVED_MODEL:-BAAI/bge-large-en-v1.5}"]
    ports:
      - "${COGNIC_VLLM_PORT:-8000}:8000"
    healthcheck:
      # vLLM serves the OpenAI-compat /v1/models endpoint as soon as the
      # model loads. The image is python-slim and DOES ship `python` so
      # we use a tiny urllib probe rather than wget.
      test:
        - "CMD-SHELL"
        - "python -c 'import urllib.request,sys; sys.exit(0 if urllib.request.urlopen(\"http://localhost:8000/v1/models\",timeout=2).status==200 else 1)'"
      interval: 15s
      timeout: 5s
      retries: 20
      start_period: 60s    # model load is slow on first boot
```

- [ ] **Step 8.2: Validate**

```bash
docker compose -f infra/dev/docker-compose.yml \
               -f infra/dev/docker-compose.vllm.yml \
               config --quiet && echo "compose+vllm overlay valid"
```

Expected: validates clean. (Live `up` requires GPU; CI does not run.)

- [ ] **Step 8.3: Commit**

```bash
git add infra/dev/docker-compose.vllm.yml
git commit -m "feat(sprint-1d): docker-compose.vllm.yml overlay (single-GPU, opt-in)"
```

---

### Task 9: docs/INFERENCE-BACKENDS.md operator guide

Operator-facing guide for picking between Ollama / vLLM / SGLang / cloud. Not architecture doctrine — that lives in ADR-009 — but practical deployment guidance.

**Files:**
- Create: `docs/INFERENCE-BACKENDS.md`

- [ ] **Step 9.1: Create the doc**

```markdown
# Inference Backends — Operator Guide

> **Status:** Sprint 1D operator reference (2026-04-27). Companion to
> [`ADR-009`](adrs/ADR-009-pluggable-infrastructure-adapters.md) §"LLM serving"
> + [`infra/litellm/config.yaml`](../infra/litellm/config.yaml).

Cognic AgentOS speaks LLM inference through LiteLLM tier aliases
(`cognic-tier1-*` / `cognic-tier2-*`); the alias resolves to one of the
backends below. Embedding inference goes through one of the bundled
`EmbeddingAdapter` implementations. This guide helps operators choose
the right backend per deployment.

## TL;DR

| Use case | Inference (chat) | Embedding | Notes |
|---|---|---|---|
| **Local dev / laptop** | Ollama (`cognic-tier{1,2}-dev`) | Ollama (`embed_driver=ollama`) | Single-process; no GPU required; fits a Mac M-series. |
| **Single-GPU staging** | vLLM (`cognic-tier{1,2}-vllm`) | OpenAI-compat (`embed_driver=openai_compat`, `provider_label=vllm`) | One GPU per node; vLLM is the simplest production stack. |
| **Multi-GPU production** | SGLang (`cognic-tier{1,2}-sglang`) | OpenAI-compat (`provider_label=sglang`) | SGLang is throughput-optimised on long-context workloads. |
| **Cloud-only deployment** | LiteLLM cloud aliases | OpenAI-compat (`provider_label=openai`/`azure_oai`/`bedrock`) | Requires `ALLOW_EXTERNAL_LLM=true` cloud-policy override (per ADR-007 provider-honesty). |

## Decision matrix

### Picking inference

| Criterion | Ollama | vLLM | SGLang | Cloud |
|---|---|---|---|---|
| GPU required | No | Yes | Yes | No (network out) |
| Throughput | Low | High | Highest | Variable |
| Long-context (>32K) | Slow | Good | Best | Provider-dependent |
| Streaming | Yes | Yes | Yes | Yes |
| Self-hosted / sovereign | Yes | Yes | Yes | **No** |
| Cognic dev parity | Strongest | Strong | Strong | Drift risk |
| Cost (per 1M tokens, 2026 averages) | $0 (HW only) | $0 (HW only) | $0 (HW only) | $0.50–$15 |

### Picking embedding

| Criterion | Ollama | OpenAI-compat (vLLM) | OpenAI-compat (cloud) |
|---|---|---|---|
| GPU required | No | Yes | No |
| Throughput | Low | High | High |
| Audit `provider_label` | `ollama` | `vllm` | `openai`, `azure_oai`, `bedrock`, `cohere` |
| Multilingual coverage | Good (Qwen3-Embedding) | Model-dependent | Provider-dependent |
| Self-hosted | Yes | Yes | **No** |

## Deployment topologies

### Dev (Ollama, no GPU)

`infra/dev/docker-compose.yml` brings up Ollama-on-host (`COGNIC_EMBEDDING_BASE_URL=http://localhost:11434`); set
`COGNIC_EMBED_DRIVER=ollama` and `COGNIC_TIER1_MODEL=cognic-tier1-dev`. Best for laptop work, demos, and CI without GPU runners.

### Single-GPU staging (vLLM)

Activate the vLLM compose overlay:

```bash
docker compose -f infra/dev/docker-compose.yml \
               -f infra/dev/docker-compose.vllm.yml up -d
```

Set:

```bash
COGNIC_TIER1_MODEL=cognic-tier1-vllm
VLLM_BASE_URL=http://vllm:8000
COGNIC_TIER1_VLLM_MODEL=Qwen/Qwen3-8B-Instruct  # or whatever fits the GPU

COGNIC_EMBED_DRIVER=openai_compat
COGNIC_EMBEDDING_BASE_URL=http://vllm:8000
COGNIC_EMBEDDING_MODEL=BAAI/bge-large-en-v1.5
COGNIC_EMBED_PROVIDER_LABEL=vllm
```

### Multi-GPU production (SGLang)

SGLang is preferred when throughput per GPU matters (e.g. Tier-1 banks
running >100K agent invocations / day). Topology mirrors vLLM but with
SGLang's runtime + a model-shard configuration matching the cluster's
GPU count.

```bash
COGNIC_TIER1_MODEL=cognic-tier1-sglang
SGLANG_BASE_URL=http://sglang.internal:30000
COGNIC_TIER1_SGLANG_MODEL=Qwen/Qwen3-32B-Instruct

COGNIC_EMBED_DRIVER=openai_compat
COGNIC_EMBEDDING_BASE_URL=http://sglang-embed.internal:30000
COGNIC_EMBED_PROVIDER_LABEL=sglang
```

### Cloud (OpenAI / Azure / Bedrock)

Requires the cloud-policy override per ADR-007 (`ALLOW_EXTERNAL_LLM=true`).
The provider-honesty endpoint will surface the active backend; banks
reviewing routing reality see `provider_label=openai|azure_oai|bedrock`
in the audit trail.

```bash
# Example: OpenAI cloud
COGNIC_TIER1_MODEL=cognic-tier1-cloud-openai  # see infra/litellm/config.yaml
COGNIC_EMBED_DRIVER=openai_compat
COGNIC_EMBEDDING_BASE_URL=https://api.openai.com
COGNIC_EMBEDDING_MODEL=text-embedding-3-large
COGNIC_EMBED_PROVIDER_LABEL=openai
OPENAI_API_KEY=...                            # via Vault in prod
```

## Audit + governance notes

- **Provider honesty (per ADR-007).** Every embedding emission records
  `provider_label`. The full Langfuse trace lifecycle wires in Sprint
  2/3; Sprint 1D's adapter holds the label for the audit-event integration
  to consume. Cloud routing requires `ALLOW_EXTERNAL_LLM=true`; the
  policy gate is enforced in the LLM gateway (Sprint 3).
- **Self-hosted-first.** Bank-grade deployments default to vLLM/SGLang;
  cloud is opt-in per tenant. Provider audit (Sprint 7B portal) shows
  which backend served which call.
- **Tier promotion.** Tier 1 = primary inference; Tier 2 = fallback
  (cheaper/smaller model when Tier 1 is unavailable or budget-capped).
  Both tiers can independently target Ollama/vLLM/SGLang/cloud.

## References

- [ADR-009 §"LLM serving"](adrs/ADR-009-pluggable-infrastructure-adapters.md) — adapter contract + LiteLLM tier-alias scheme
- [ADR-007 — Provider honesty](adrs/ADR-007-provider-honesty.md) — cloud-policy + audit surface
- [`infra/litellm/config.yaml`](../infra/litellm/config.yaml) — concrete tier-alias definitions
- [`infra/dev/docker-compose.vllm.yml`](../infra/dev/docker-compose.vllm.yml) — single-GPU vLLM overlay
- vLLM docs: https://docs.vllm.ai
- SGLang docs: https://github.com/sgl-project/sglang
```

- [ ] **Step 9.2: Commit**

```bash
git add docs/INFERENCE-BACKENDS.md
git commit -m "docs(sprint-1d): operator guide for Ollama / vLLM / SGLang / cloud"
```

---

### Task 10: CI workflow extension — `oracle-integration` job

Add a third CI job that runs `pytest -m oracle` against the live Oracle XE overlay. Default `lint + test` job continues to filter the marker out (pytest's `--strict-markers` config now registers `oracle` as a known marker; the default invocation does not select it).

**Files:**
- Modify: `.github/workflows/python.yml`

- [ ] **Step 10.1: Extend the workflow**

Append after the `image-size-budget` job:

```yaml
  oracle-integration:
    # Sprint 1D: live Oracle XE compose overlay + pytest -m oracle. Runs
    # on PR + main; failure blocks merge. Standard lint/test job filters
    # the `oracle` marker out (default pytest behaviour for un-selected
    # markers); this job is the only place those tests execute.
    name: oracle integration (live XE overlay)
    runs-on: ubuntu-latest
    timeout-minutes: 25  # Oracle XE first-boot is slow

    steps:
      - name: Checkout
        uses: actions/checkout@v6

      - name: Install uv
        uses: astral-sh/setup-uv@v7
        with:
          version: "0.5.29"
          enable-cache: true

      - name: Read .python-version
        id: python-version
        run: echo "version=$(cat .python-version)" >> "$GITHUB_OUTPUT"

      - name: Set up Python
        uses: actions/setup-python@v6
        with:
          python-version: ${{ steps.python-version.outputs.version }}

      - name: uv sync (frozen + all extras)
        run: uv sync --frozen --all-extras

      - name: Bring up Oracle XE overlay
        run: |
          docker compose -f infra/dev/docker-compose.yml \
                         -f infra/dev/docker-compose.oracle.yml \
                         up -d oracle

      - name: Wait for Oracle XE healthy
        run: |
          set -euo pipefail
          # First-boot can take ~3-5 minutes; gvenzl healthcheck reports
          # healthy as soon as SQL*Plus accepts connections.
          for i in $(seq 1 60); do
            status=$(docker inspect cognic-agentos-oracle --format='{{.State.Health.Status}}')
            echo "[${i}/60] oracle health: ${status}"
            if [ "${status}" = "healthy" ]; then exit 0; fi
            sleep 10
          done
          echo "::error::Oracle XE did not reach healthy state in 10 minutes"
          docker compose -f infra/dev/docker-compose.yml \
                         -f infra/dev/docker-compose.oracle.yml logs oracle
          exit 1

      - name: Run @pytest.mark.oracle tests
        env:
          # COGNIC_RUN_ORACLE_INTEGRATION is the env-gate the test
          # uses via @pytest.mark.skipif. Without this set the live
          # tests self-skip even when -m oracle selects them.
          COGNIC_RUN_ORACLE_INTEGRATION: "1"
          COGNIC_DB_DRIVER: oracle
          COGNIC_DATABASE_URL: oracle+oracledb://cognic:cognic_dev_only@localhost:1521/?service_name=XEPDB1
        run: uv run pytest -m oracle -v

      - name: Tear down overlay
        if: always()
        run: |
          docker compose -f infra/dev/docker-compose.yml \
                         -f infra/dev/docker-compose.oracle.yml \
                         down -v
```

- [ ] **Step 10.2: Validate locally**

The CI yaml itself isn't directly testable on the developer machine (it
runs on GitHub Actions infrastructure), but the underlying commands are.
Smoke-test the local path:

```bash
docker compose -f infra/dev/docker-compose.yml \
               -f infra/dev/docker-compose.oracle.yml \
               config --quiet && echo "yaml valid"

# Optional: spin up locally to catch issues before pushing
# docker compose -f infra/dev/docker-compose.yml \
#                -f infra/dev/docker-compose.oracle.yml up -d oracle
# (wait for healthy ~3-5 min)
# COGNIC_DATABASE_URL='oracle+oracledb://cognic:cognic_dev_only@localhost:1521/?service_name=XEPDB1' \
#   uv run pytest -m oracle -v
# docker compose -f infra/dev/docker-compose.yml \
#                -f infra/dev/docker-compose.oracle.yml down -v
```

Expected: yaml valid; (optional) live Oracle test passes.

- [ ] **Step 10.3: Commit**

```bash
git add .github/workflows/python.yml
git commit -m "ci(sprint-1d): add oracle-integration job (live Oracle XE overlay)"
```

---

### Task 11: READY FOR GATE — final sweep + handoff

**Files:**
- Verify suite end-to-end
- Inspect commits
- Compose YAML smoke

- [ ] **Step 11.1: Full local CI sweep**

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
uv run pytest -v --cov=cognic_agentos --cov-report=term-missing
```

Expected: all green; coverage ≥80% global; new adapter modules ≥80%.

- [ ] **Step 11.2: Compose smoke (default profile only)**

```bash
docker compose -f infra/dev/docker-compose.yml config --quiet
docker compose -f infra/dev/docker-compose.yml \
               -f infra/dev/docker-compose.oracle.yml \
               config --quiet
docker compose -f infra/dev/docker-compose.yml \
               -f infra/dev/docker-compose.vllm.yml \
               config --quiet
```

Expected: all three configs valid.

- [ ] **Step 11.3: Inspect the sprint commit log**

```bash
git log --oneline main..HEAD
```

Expected: 9-11 conventional commits, one per task (T1, T2, T3, T4, T5, T6, T7, T8, T9, T10).

- [ ] **Step 11.4: Verify dep-floor headroom on default-adapters image**

```bash
docker build -f infra/agentos/Dockerfile --target default-adapters \
             --build-arg PACKAGE_VERSION=ci -t cognic-agentos:adapters-1d-test .
docker image inspect cognic-agentos:adapters-1d-test --format='{{.Size}}' \
  | awk '{ printf "default-adapters: %d MiB / 220 MiB\n", $1 / 1024 / 1024 }'
```

Expected: ≤220 MiB. If it pushes to ≥215 MiB, flag at READY-FOR-GATE — Sprint 1E (Sprint 2 prep) may need to escalate the budget again or the Oracle/Dynatrace deps need a closer look.

- [ ] **Step 11.5: Hand off**

Handoff summary to the user:

- Branch `feat/sprint-1d-enterprise-adapters`
- N commits, all CI gates locally green
- Suite size grew from 193 → ~234 (+~41 from the three adapters + factory extensions + config tests + integration test scaffolding)
- Default-adapters image size + headroom against 220 MiB ceiling
- Compose overlay validation status
- Outstanding flags (e.g. if image budget headroom is tight)

Do NOT push, merge, or open a PR. Per the per-action authorization rule + AGENTS.md sprint discipline, the user holds those decisions explicitly.

---

## Self-Review

**Spec coverage check:** Every BUILD_PLAN.md:155-178 deliverable maps to a task:

- pyproject.toml extension (oracledb dep + oracle marker) → Task 1
- core/config.py extension (Dynatrace + openai_compat settings) → Task 2
- db/adapters/oracle_adapter.py → Task 3
- db/adapters/dynatrace_adapter.py → Task 4
- db/adapters/openai_compat_embedding_adapter.py → Task 5
- factory + bundled-loader extensions → Task 6
- db/migrations/oracle/ scaffold → Task 3
- infra/dev/docker-compose.oracle.yml → Task 7
- infra/dev/docker-compose.vllm.yml → Task 8
- docs/INFERENCE-BACKENDS.md → Task 9
- tests/unit/db/test_oracle_adapter.py → Task 3
- tests/unit/db/test_dynatrace_adapter.py → Task 4
- tests/unit/db/test_openai_compat_embedding_adapter.py → Task 5
- CI matrix oracle job → Task 10

**LiteLLM config extension** — BUILD_PLAN line 166 lists `infra/litellm/config.yaml` extension for Phase 2 production aliases. **Sprint 1C T14 already shipped these aliases** (`cognic-tier1-vllm`, `cognic-tier2-vllm`, `cognic-tier1-sglang`, `cognic-tier2-sglang`), so Sprint 1D doesn't need to touch the file. Verified at `/Users/bmz/development/cognic-agentos/infra/litellm/config.yaml`.

Every BUILD_PLAN exit criterion has a verification step in Tasks 3-5 (the unit-mocked path) + Task 10 (the CI Oracle integration path). The Dynatrace + openai_compat live-stack verification is operator-side (vLLM needs GPU; Dynatrace tenant needs an account) — same operator-deferred pattern Sprint 1C established for compose live-up.

**Placeholder scan:** no TBD / TODO / "fill in details" / "similar to" placeholders. Every code-changing step shows the code in full. Three adapter test snippets each contain full test code; the per-driver-arg extensions show full helper bodies.

**Type consistency:** `OracleAdapter` constructor signature matches `PostgresAdapter`'s (single positional `url`); `DynatraceAdapter` constructor signature is `(tenant_url, api_token)` consistent with the factory's tuple in `_observability_args`; `OpenAICompatEmbeddingAdapter` constructor signature is `(base_url, model, dimensions, provider_label, api_key=None, api_key_header="Authorization", extra_headers=None)` matching the factory's 7-tuple in `_embedding_args`. All three drivers register with the long-form `AdapterKind` keys (`relational`, `observability`, `embedding`) — no `db`/`obs` shorthand. `_BUNDLED_ADAPTER_OPTIONAL_DEPS` keys use the canonical `cognic_agentos.db.adapters.<module>` FQMN.

---

## Patch log (post-review)

Round 1 (six review blockers + workspace state — applied 2026-04-27):

- a: Added Step 1.0 — commit the plan + a small BUILD_PLAN amendment to `main` BEFORE branching, so the preflight clean-tree check passes (Sprint-1C T1 precedent). The amendment clarifies Oracle URL handling, Dynatrace + OpenAI-compat auth surface, provider_label audit deferral to Sprint 2, and CI-strategy language.
- b: Replaced the Oracle pytest-marker auto-skip assumption with `@pytest.mark.skipif(not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"), ...)`. Pytest markers do NOT auto-skip; `--strict-markers` only validates registration. The CI `oracle-integration` job sets `COGNIC_RUN_ORACLE_INTEGRATION=1`; default `pytest` runs self-skip.
- c: Extended `OpenAICompatEmbeddingAdapter` with real auth: `api_key` + `api_key_header` (default `Authorization` with implicit `Bearer ` prefix; raw key for `api-key` and other custom headers — covers Azure-OpenAI proxy shape) + `extra_headers` (Azure `api-version`, custom proxy headers) + reserved `embedding_api_key_vault_path` setting (Sprint 10 wires runtime resolution). Tests now cover three auth modes: vLLM no-auth, OpenAI Bearer, Azure api-key + extra_headers. `_embedding_args` factory helper grows from a 4-tuple to a 7-tuple.
- d: Replaced Dynatrace health endpoint `/api/v2/cluster` (not a documented health path) with `/api/v2/metrics/query?metricSelector=builtin:host.cpu.usage&pageSize=1` — token-validating (requires `metrics.read` scope) and reachability-validating in one probe. Module docstring documents required token scopes (`metrics.read` for health, `metrics.ingest` for the Metric Ingest API per Dynatrace docs — initial Round-2 wording said `metrics.write`; corrected in Round-3).
- e: Fixed stale Sprint-1C `TestPerDriverArgs` "unknown driver" tests in Step 6.3a — `openai_compat` and `dynatrace` were used as "unknown" placeholders in Sprint 1C tests; Sprint 1D makes them bundled drivers, so the tests would now assert wrong behaviour. Updated to use `cohere_native` (embed) and `splunk` (obs) which remain genuinely-unbundled per ADR-009 alternative-adapter list.
- f: Pinned `vllm/vllm-openai:v0.6.6` (was `latest`) so vLLM upstream-image changes don't silently break the overlay. Operators bump the pin alongside CUDA-capability changes.
- g: Added reserved `dynatrace_api_token_vault_path` and `embedding_api_key_vault_path` settings in Task 2 — fields exist now so Sprint 10 runtime Vault resolution doesn't need a config-schema bump; Sprint 1D adapters take resolved tokens directly via the non-vault fields.

BUILD_PLAN amendments committed alongside the plan in Step 1.0:
- L162 (`core/config.py extension`): Oracle URL clarification + Dynatrace + OpenAI-compat auth-surface listing.
- L165 (`openai_compat_embedding_adapter`): provider_label storage in 1D / audit emission deferred to Sprint 2; Azure direct-URL adapter deferred.
- L178 (CI matrix): replaced cross-product matrix language with the actual Sprint-1D strategy (unit tests for all drivers + Oracle integration job + operator-side dynatrace/openai_compat live verification).

Round 3 (five Round-2 review followups — applied 2026-04-27, post-T2 stop-gate):

- α: CI `oracle-integration` job now sets `COGNIC_RUN_ORACLE_INTEGRATION: "1"` in the env block (Round-2 added the skipif gate but the workflow snippet missed the env var, so live tests would have been collected by `-m oracle` and immediately self-skipped).
- β: BUILD_PLAN exit criterion + test-deliverable wording (L175 + L180) stopped claiming audit emission for Sprint 1D — corrected to match the L165 deliverable text. Sprint 1D ships storage; Sprint 2 emits.
- γ: Dynatrace Metric Ingest scope `metrics.write` → `metrics.ingest` per Dynatrace docs. Updated in plan adapter docstring, plan tests, plan patch log (Round-2 entry annotated with the correction), AND `.env.example` (Sprint 1D T1 had committed `metrics.write` in the operator-facing scope list).
- δ: vLLM file-structure table previously said `vllm/vllm-openai:latest`; updated to match the overlay snippet's `v0.6.6` pin. The `current stable` claim in the overlay's pin comment was rewritten as `intentionally conservative pin` with a note pointing operators at the upstream releases page for production bumps.
- ε: Stale "Expected: 5 failures" in Step 2.2 → "Expected: 14 failures" with the breakdown matching the actual `TestEnterpriseAdapterSettings` test count.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-27-sprint-1d-enterprise-adapters.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using superpowers:executing-plans, batch execution with checkpoints.

Which approach?
