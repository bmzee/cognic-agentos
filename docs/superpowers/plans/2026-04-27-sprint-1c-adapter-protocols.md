# Sprint 1C — Adapter Protocols + Reference Adapters Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the adapter protocol layer per ADR-009 and ship five default-bundled reference adapters (Postgres, Qdrant, Vault, Ollama, Langfuse-OTel) plus in-memory test adapters, factory, registry, `/readyz` extension, 7-service docker-compose, LiteLLM tier config, and the kernel/default-adapters image split required by `BUILD_PLAN.md` cross-cutting principles.

**Architecture:** Six PEP-544 `Protocol` interfaces live in `db/adapters/protocols.py`. Bundled adapters self-register into an `AdapterRegistry`. A `build_adapters(settings)` factory reads `core/config.py` driver settings, instantiates the configured set, and exposes them to the FastAPI lifespan. `/readyz` calls `health_check()` on each registered adapter and reports per-driver status; 503 when any reports non-`ok`. The Docker image is split: `cognic-agentos-kernel` (server + observability only, ≤120 MiB) stays minimal; `cognic-agentos-default-adapters` (kernel + Postgres/Qdrant/Vault/Ollama/Langfuse-OTel deps, ≤180 MiB) carries the bundled-adapter weight. Both budgets are CI-gated.

**Tech Stack:** Python 3.12 / uv. SQLAlchemy[asyncio] 2.1 + asyncpg + pgvector. qdrant-client (`":memory:"` mode for tests). hvac (Vault). httpx (Sprint 1B carryover) for Ollama HTTP. OpenTelemetry (Sprint 1B carryover) for in-process span emission. **langfuse v3 — Sprint 1C scope is HTTP health probe + dep on the package; full Langfuse SDK trace lifecycle (parent-child generations linked to agent invocations, scorers, prompt/response capture) ships with Sprint 2/3 alongside `core/decision_history` + the LLM gateway**, where the trace context actually exists. aiosqlite for the in-memory relational fixture. respx for HTTP mocking in tests. Docker multi-stage + docker-compose.

---

## Context

Sprint 1A bootstrapped FastAPI + healthz + version + image-size-budget CI gate at 120 MiB. Sprint 1B added the observability stack (JSON logs, OTel + TLS, Prometheus, internal-only `/readyz`). Sprint 1C is the first sprint that introduces external dependencies. From day 1 it splits the Docker image because the bundled-adapter dep set will exceed the 120 MiB kernel ceiling (memory: ≈18 MiB headroom remaining at end of 1B).

Per ADR-009 §"Implementation phases" — Sprint 1 ships protocol definitions + Postgres + Qdrant + Vault + Ollama + Langfuse-OTel adapters + factory + memory adapters for tests. Sprint 1D adds Oracle/Dynatrace/OpenAI-compat. Sprint 4 wires alternative adapter packs through the trust gate.

**Operating-mode + stop-rule check:**

- Most of Sprint 1C is **autonomous low-risk build mode** — adapter modules, registry, factory, `tests/support/` fixtures, docker-compose, LiteLLM presets, Dockerfile split, CI image-budget extension. None of these touch the AGENTS.md critical-controls list (audit / decision_history / guardrails / approval / policy / emergency / plugin_registry / trust_gate / supply_chain / mcp_authz / a2a_authz / sandbox / subagent / memory / llm-gateway / data_governance / models).

- **Task 2 — `core/config.py` extension — gets a stop-for-review gate.** AGENTS.md §"Stop rules" says **"Stop for human review when touching: Anything in `core/`"**. Even though the change is settings-only (driver fields + per-driver paths) and not a governance primitive, the rule is "anything in core/." Executor halts after Task 2's commit and surfaces the diff to the user before T3 begins. The user's explicit `yes`/`go` advances past T2; otherwise the loop pauses there.

- **Task 12 — `portal/api/app.py` lifespan + `/readyz` extension** is portal-surface work, not core/, so it does NOT trigger the core stop rule. Standard TDD + per-task review at READY FOR GATE applies.

- No `core-controls-engineer` / `/critical-module-mode` invocation is required because the touched core/ surface (config) is settings-only, but the stop rule is honoured nonetheless.

**Memory governance is OUT OF SCOPE for Sprint 1C.** Per ADR-009 the Sprint-1C protocol surface is exactly: `RelationalAdapter`, `VectorAdapter`, `SecretAdapter`, `EmbeddingAdapter`, `ObjectStoreAdapter`, `ObservabilityAdapter`. `MemoryAdapter` is an ADR-019 concern that ships with Sprint 11.5 alongside `core/memory/`. The `AdapterRegistry` does not constrain its set of `kind` strings, so Sprint 11.5 can add `"memory"` without a structural migration — but the protocol class itself, the `MemoryRecordId` type, and any `Adapters.memory` slot all wait for Sprint 11.5.

**Production-grade rule:** every adapter's main runtime path is real (asyncpg / qdrant-client / hvac / httpx / OpenTelemetry + Langfuse HTTP health probe). In-memory variants live ONLY under `tests/support/adapter_fixtures.py` and are imported only from test modules; production code paths never fall back to them. (Full Langfuse SDK integration is out of scope for Sprint 1C — see ADR-007 alignment notes; Sprint 2/3 wires the real SDK alongside `core/decision_history` + the LLM gateway.)

---

## File Structure

**Created:**

| Path | Responsibility |
|---|---|
| `src/cognic_agentos/db/__init__.py` | empty package init |
| `src/cognic_agentos/db/adapters/__init__.py` | re-exports public API: protocol classes + `build_adapters` + `AdapterRegistry` + `AdapterNotInstalled` |
| `src/cognic_agentos/db/adapters/protocols.py` | six `Protocol` interfaces per ADR-009 (Relational, Vector, Secret, Embedding, ObjectStore [declared only — actual impl in Sprint 8], Observability). Memory governance is Sprint 11.5 / ADR-019 — do **not** declare a MemoryAdapter protocol here. |
| `src/cognic_agentos/db/adapters/registry.py` | `AdapterRegistry` mapping (kind, driver_name) → adapter class; bundled auto-register; `AdapterNotInstalled` exception |
| `src/cognic_agentos/db/adapters/factory.py` | `build_adapters(settings) -> Adapters` (typed dataclass); raises `AdapterNotInstalled` on miss |
| `tests/support/__init__.py` | empty package init so `tests.support.*` is importable from test modules |
| `tests/support/adapter_fixtures.py` | in-memory test impls (aiosqlite for relational; in-process dicts for the rest). Lives under `tests/` per AGENTS.md "test-only mocks/fixtures … in clearly separated test paths" rule. Production source path **never** ships these. |
| `src/cognic_agentos/db/adapters/postgres_adapter.py` | `PostgresAdapter` via SQLAlchemy[asyncio] + asyncpg |
| `src/cognic_agentos/db/adapters/qdrant_adapter.py` | `QdrantAdapter` via `AsyncQdrantClient` |
| `src/cognic_agentos/db/adapters/vault_adapter.py` | `VaultAdapter` via hvac (sync client wrapped with `asyncio.to_thread`) |
| `src/cognic_agentos/db/adapters/ollama_embedding_adapter.py` | `OllamaEmbeddingAdapter` via httpx async |
| `src/cognic_agentos/db/adapters/langfuse_otel_adapter.py` | `LangfuseOtelAdapter` (Langfuse v3 + OTel emit/flush) |
| `infra/litellm/config.yaml` | tier-aliased model routing presets |
| `tests/unit/db/__init__.py` | package init |
| `tests/unit/db/test_adapter_protocols.py` | structural conformance for the six ADR-009 protocols + ObjectStore declared-only |
| `tests/unit/db/test_adapter_factory.py` | `build_adapters(settings)` returns typed container; unknown driver → `AdapterNotInstalled` |
| `tests/unit/db/test_memory_adapters.py` | each in-memory adapter satisfies its protocol contract |
| `tests/unit/db/test_postgres_adapter.py` | health_check + open/close lifecycle (aiosqlite-backed test URL) |
| `tests/unit/db/test_qdrant_adapter.py` | ensure_collection + upsert/search round-trip via `:memory:` mode |
| `tests/unit/db/test_vault_adapter.py` | read/write/lease/revoke via respx-mocked HTTP |
| `tests/unit/db/test_ollama_embedding_adapter.py` | embed shape + health_check + graceful degrade |
| `tests/unit/db/test_langfuse_otel_adapter.py` | graceful degrade when host unreachable; flush idempotent |

**Modified:**

| Path | Change |
|---|---|
| `pyproject.toml` | add adapter deps + test deps |
| `uv.lock` | regenerated by `uv lock` |
| `src/cognic_agentos/core/config.py` | add five adapter settings groups + driver fields |
| `src/cognic_agentos/portal/api/app.py` | `lifespan` opens adapters at startup, closes at shutdown; `/readyz` extended to call `adapter.health_check()` per registered adapter |
| `tests/unit/test_readyz.py` | extend with adapter-status assertions |
| `infra/dev/docker-compose.yml` | extend from 1-service placeholder to 7-service stack |
| `infra/agentos/Dockerfile` | split: `kernel` target unchanged; new `default-adapters` target adds adapter deps |
| `.github/workflows/python.yml` | extend `image-size-budget` job to also build + measure `default-adapters` target ≤180 MiB |
| `.env.example` | adapter env-var examples |

---

## Tasks

### Task 1: Branch + dependency setup

**Files:**
- Stage and commit: `docs/superpowers/plans/2026-04-27-sprint-1c-adapter-protocols.md`
- Modify: `pyproject.toml`
- Modify: `uv.lock` (regenerated)
- Modify: `.env.example`

- [ ] **Step 1.0: Commit the plan file to `main` so the working tree is clean for preflight**

The plan document itself is a tracked artifact; until it's committed, the preflight clean-tree check below would fail on `?? docs/superpowers/`. Commit it on `main` first as a `chore(plan)` checkpoint, THEN branch.

```bash
git add docs/superpowers/plans/2026-04-27-sprint-1c-adapter-protocols.md
git commit -m "chore(plan): sprint 1c adapter-protocols implementation plan"
```

Expected: one new commit on `main` with message above. No other files staged.

- [ ] **Step 1.1: Verify safe starting state**

Hard-coded commit hashes in preflight checks rot quickly (the local `main` may legitimately be ahead of `origin/main` between sessions). Use property-level probes instead:

```bash
git status --short                           # MUST be empty (clean tree)
git rev-parse --abbrev-ref HEAD              # MUST be `main`
git fetch origin main --quiet
git merge-base --is-ancestor origin/main HEAD \
  && echo "ok: local main is at or ahead of origin/main" \
  || echo "warn: local main is BEHIND origin/main; pull before proceeding"
```

Expected: empty `git status`; current branch `main`; ancestry probe prints `ok: ...`. Abort and ask the user if any of those three checks fail.

- [ ] **Step 1.2: Create feature branch**

```bash
git switch -c feat/sprint-1c-adapter-protocols
```

Expected: `Switched to a new branch 'feat/sprint-1c-adapter-protocols'`.

- [ ] **Step 1.3: Extend `pyproject.toml` with `adapters` extras + dev test deps**

Adapter packages live in a NEW `adapters` optional-dependencies group from day one — NOT in `[project] dependencies`. The kernel image build (`uv sync --frozen --no-dev` without `--extra adapters`) excludes them, keeping the kernel ≤120 MiB. The default-adapters image (Task 15) opts in via `--extra adapters`. Tests get them via `--all-extras` (already in CI's `uv sync --frozen --all-extras`).

This avoids the lockfile churn of "deps in main → moved to extras later in the sprint."

Edit `pyproject.toml`:

1. **Do NOT touch `[project] dependencies`.** Leave the Sprint 1A/1B deps as-is.

2. **Add a new `adapters` group** under `[project.optional-dependencies]` (alongside the existing `dev`):

```toml
adapters = [
    # Persistence (Sprint 1C, per ADR-009)
    "sqlalchemy[asyncio]>=2.1",
    "alembic>=1.16",
    "asyncpg>=0.31",
    "pgvector>=0.4",
    "qdrant-client>=1.18",
    "redis>=5.3",
    # Secrets (Sprint 1C, per ADR-009)
    "hvac>=2.4",
    "cryptography>=45",
    # Observability adapter (Sprint 1C, per ADR-009)
    "langfuse>=3.0",
]
```

3. **Append test deps** to BOTH `[project.optional-dependencies] dev` AND `[tool.uv] dev-dependencies` (keep them in sync — Sprint 1A established the duplication):

```toml
    "aiosqlite>=0.20",
    "respx>=0.22",
```

- [ ] **Step 1.4: Lock + sync (with all extras so tests can import adapter deps)**

```bash
uv lock
uv sync --all-extras
```

Expected: `uv.lock` updates with the `adapters` extras + their transitive closure (asyncpg, qdrant-client, hvac, langfuse, etc.); `uv sync --all-extras` reports them installed. After this, `import asyncpg` etc. works in dev/test paths but the kernel image (no `--extra adapters` at build time) won't carry them.

- [ ] **Step 1.5: Verify Sprint 1B baseline still green**

```bash
uv run pytest -v
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
```

Expected: all 63 Sprint 1B tests pass; lint/format/mypy clean. New deps must not break the existing suite.

- [ ] **Step 1.6: Append adapter env-var stubs to `.env.example`**

Append to end of file:

```bash

# ----- Sprint 1C — Adapter drivers -----
# Driver names map to bundled adapters in cognic_agentos.db.adapters.registry.
# Setting an unknown driver causes startup to fail fast with AdapterNotInstalled.

# Relational
COGNIC_DB_DRIVER=postgres
COGNIC_DATABASE_URL=postgresql+asyncpg://cognic:cognic_dev_only@localhost:5432/cognic_agentos

# Vector
COGNIC_VECTOR_DRIVER=qdrant
COGNIC_QDRANT_URL=http://localhost:6333
COGNIC_QDRANT_COLLECTION=cognic_default

# Secrets
COGNIC_SECRET_DRIVER=vault
COGNIC_VAULT_ADDR=http://localhost:8200
COGNIC_VAULT_TOKEN=dev-only-root
COGNIC_VAULT_NAMESPACE=

# Embedding
COGNIC_EMBED_DRIVER=ollama
COGNIC_EMBEDDING_MODEL=qwen3-embedding:8b
COGNIC_EMBEDDING_BASE_URL=http://localhost:11434
COGNIC_EMBEDDING_DIMENSIONS=1024

# Observability
COGNIC_OBS_DRIVER=langfuse_otel
COGNIC_LANGFUSE_HOST=http://localhost:3000
COGNIC_LANGFUSE_PUBLIC_KEY=pk-lf-dev
COGNIC_LANGFUSE_SECRET_KEY=sk-lf-dev
```

- [ ] **Step 1.7: Commit**

```bash
git add pyproject.toml uv.lock .env.example
git commit -m "chore(sprint-1c): add adapter deps + env stubs (bootstrap)"
```

---

### Task 2: Extend `core/config.py` with adapter settings groups

Settings keep the existing single-class pattern (Sprint 1A/1B style with grouped `# --- … ---` comment blocks). Driver fields are typed `str` (not `Literal`) so unknown drivers reach the factory and fail with a precise `AdapterNotInstalled` error rather than a Pydantic validation error.

**Files:**
- Modify: `src/cognic_agentos/core/config.py`
- Test: `tests/unit/test_config.py`

- [ ] **Step 2.1: Write the failing test**

Append to `tests/unit/test_config.py`:

```python
class TestAdapterSettings:
    """Sprint 1C adapter settings — driver names + per-driver fields."""

    def test_default_drivers(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Defaults match the bundled adapter set per ADR-009."""

        # Strip any user .env so we measure class defaults
        monkeypatch.chdir("/tmp")
        get_settings.cache_clear()
        s = build_settings_without_env_file()

        assert s.db_driver == "postgres"
        assert s.vector_driver == "qdrant"
        assert s.secret_driver == "vault"
        assert s.embed_driver == "ollama"
        assert s.obs_driver == "langfuse_otel"

    def test_driver_fields_typed_as_strings(self) -> None:
        """Driver names are plain str; unknown values are surfaced by the factory,
        not by Pydantic. This lets ``COGNIC_DB_DRIVER=mssql`` reach
        ``AdapterNotInstalled`` with a precise message instead of a validation
        error that lists allowed values (which would leak the bundled-adapter
        list into config-error UX)."""

        from cognic_agentos.core.config import Settings

        fields = Settings.model_fields
        for name in ("db_driver", "vector_driver", "secret_driver",
                     "embed_driver", "obs_driver"):
            assert fields[name].annotation is str

    def test_adapter_urls_load_from_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("COGNIC_DATABASE_URL", "postgresql+asyncpg://u:p@h/db")
        monkeypatch.setenv("COGNIC_QDRANT_URL", "http://qdrant:6333")
        monkeypatch.setenv("COGNIC_VAULT_ADDR", "http://vault:8200")
        monkeypatch.setenv("COGNIC_EMBEDDING_MODEL", "test-embed:1b")
        monkeypatch.setenv("COGNIC_EMBEDDING_DIMENSIONS", "512")
        monkeypatch.setenv("COGNIC_LANGFUSE_HOST", "http://lf:3000")
        get_settings.cache_clear()

        s = build_settings_without_env_file()
        assert s.database_url == "postgresql+asyncpg://u:p@h/db"
        assert s.qdrant_url == "http://qdrant:6333"
        assert s.vault_addr == "http://vault:8200"
        assert s.embedding_model == "test-embed:1b"
        assert s.embedding_dimensions == 512
        assert s.langfuse_host == "http://lf:3000"

    def test_unknown_driver_value_accepted_at_config_layer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``mssql`` is a planned plugin pack (per ADR-009 alternative adapters);
        config must not refuse it. The factory, not config, surfaces the miss."""

        monkeypatch.setenv("COGNIC_DB_DRIVER", "mssql")
        get_settings.cache_clear()
        s = build_settings_without_env_file()
        assert s.db_driver == "mssql"
```

The `pytest`/`get_settings`/`build_settings_without_env_file` imports already exist at the top of `test_config.py` from Sprint 1B — re-use them.

- [ ] **Step 2.2: Run the test, expect failure**

```bash
uv run pytest tests/unit/test_config.py::TestAdapterSettings -v
```

Expected: 4 failures with `AttributeError: 'Settings' object has no attribute 'db_driver'`.

- [ ] **Step 2.3: Add adapter settings to `Settings`**

In `src/cognic_agentos/core/config.py`, insert after the existing `# --- Observability (Sprint 1B) ---` block and before `# --- Build metadata ---`:

```python
    # --- Adapters (Sprint 1C, per ADR-009) ---------------------------
    # Drivers are plain ``str`` so unknown values flow to the factory's
    # ``AdapterNotInstalled`` error path. The bundled set lives in
    # ``cognic_agentos.db.adapters.registry``; alternative drivers install
    # as plugin packs (per ADR-002) and self-register on import.

    db_driver: str = Field(
        default="postgres",
        description="Relational adapter driver. Bundled: postgres. Plugin packs: oracle (Sprint 1D), mssql, mysql.",
    )
    database_url: str | None = Field(
        default=None,
        description="SQLAlchemy URL (e.g. postgresql+asyncpg://user:pass@host:5432/db).",
    )

    vector_driver: str = Field(
        default="qdrant",
        description="Vector adapter driver. Bundled: qdrant. Plugin packs: chroma, weaviate, pgvector, milvus.",
    )
    qdrant_url: str | None = Field(
        default=None,
        description="Qdrant HTTP endpoint (e.g. http://qdrant:6333).",
    )
    qdrant_collection: str = Field(
        default="cognic_default",
        description="Default Qdrant collection name for upsert/search.",
    )

    secret_driver: str = Field(
        default="vault",
        description="Secrets adapter driver. Bundled: vault. Plugin packs: aws, azure, cyberark.",
    )
    vault_addr: str | None = Field(
        default=None,
        description="Vault address (e.g. http://vault:8200).",
    )
    vault_token: str | None = Field(
        default=None,
        description="Vault token. Dev-only when set in source; prod uses Kubernetes auth.",
    )
    vault_namespace: str | None = Field(
        default=None,
        description="Vault Enterprise namespace (None = default namespace).",
    )

    embed_driver: str = Field(
        default="ollama",
        description="Embedding adapter driver. Bundled (dev): ollama. Bundled (prod, Sprint 1D): openai_compat.",
    )
    embedding_model: str = Field(
        default="qwen3-embedding:8b",
        description="Embedding model identifier (Ollama model tag or OpenAI-compat model name).",
    )
    embedding_base_url: str | None = Field(
        default=None,
        description="Embedding service HTTP endpoint (e.g. http://ollama:11434).",
    )
    embedding_dimensions: int = Field(
        default=1024,
        ge=1,
        description="Vector dimensions emitted by the embedding model. Operators set per model.",
    )

    obs_driver: str = Field(
        default="langfuse_otel",
        description="Observability adapter driver. Bundled: langfuse_otel. Bundled (Sprint 1D): dynatrace. Plugin packs: splunk, datadog, newrelic.",
    )
    langfuse_host: str | None = Field(
        default=None,
        description="Langfuse host (e.g. http://langfuse:3000).",
    )
    langfuse_public_key: str | None = Field(
        default=None,
        description="Langfuse public API key.",
    )
    langfuse_secret_key: str | None = Field(
        default=None,
        description="Langfuse secret API key. Dev-only when set in source; prod uses Vault.",
    )
```

- [ ] **Step 2.4: Run the test, expect pass**

```bash
uv run pytest tests/unit/test_config.py::TestAdapterSettings -v
uv run mypy src tests
```

Expected: 4 passes; mypy clean.

- [ ] **Step 2.5: Re-run the no-env-specific-values discipline test**

```bash
uv run pytest tests/unit/architecture/test_no_env_specific_values_in_source.py -v
```

Expected: passes. (Adapter settings are declared inside `Settings`; no operational values leaked to other modules.)

- [ ] **Step 2.6: Commit**

```bash
git add src/cognic_agentos/core/config.py tests/unit/test_config.py
git commit -m "feat(sprint-1c): add adapter settings groups to core/config (ADR-009)"
```

- [ ] **Step 2.7: STOP for human review (AGENTS.md `core/` stop rule)**

Per AGENTS.md §"Stop rules" — "Stop for human review when touching: **Anything in `core/`**". Even though this change is settings-only (no governance primitive), the rule applies.

After the commit lands, surface to the user:

- the diff against `main` (`git diff main..HEAD -- src/cognic_agentos/core/config.py tests/unit/test_config.py`)
- the test result (`uv run pytest tests/unit/test_config.py -v`)
- the discipline-test confirmation (`uv run pytest tests/unit/architecture/test_no_env_specific_values_in_source.py -v`)

Wait for explicit `yes` / `go` before starting Task 3. If the user requests changes, apply them inside Task 2 (additional commits on the same branch are fine), then re-surface.

---

### Task 3: Adapter protocols (the contracts)

Defines the six PEP-544 `Protocol` interfaces — these ARE the contract bundled adapters and plugin-pack adapters implement.

**Files:**
- Create: `src/cognic_agentos/db/__init__.py`
- Create: `src/cognic_agentos/db/adapters/__init__.py`
- Create: `src/cognic_agentos/db/adapters/protocols.py`
- Create: `tests/unit/db/__init__.py`
- Create: `tests/unit/db/test_adapter_protocols.py`

- [ ] **Step 3.1: Write the failing test**

Create `tests/unit/db/__init__.py` (empty).

Create `tests/unit/db/test_adapter_protocols.py`:

```python
"""Sprint 1C — adapter protocol structural conformance tests.

These tests assert that every ADR-009 protocol exposes the declared
methods with the right async/sync flavour. ``ObjectStoreAdapter`` is
declared-only here (impl ships with Sprint 8 + evidence-pack export);
memory governance (ADR-019) lands in Sprint 11.5 and is not part of this
sprint's protocol surface."""

from __future__ import annotations

from typing import get_type_hints

import pytest

from cognic_agentos.db.adapters import protocols as P


class TestProtocolShape:
    def test_relational_methods(self) -> None:
        for name in ("connect", "session", "run_migrations", "close", "health_check"):
            assert hasattr(P.RelationalAdapter, name), f"missing {name}"

    def test_vector_methods(self) -> None:
        for name in ("ensure_collection", "upsert", "search", "delete", "health_check"):
            assert hasattr(P.VectorAdapter, name), f"missing {name}"

    def test_secret_methods(self) -> None:
        for name in ("read", "write", "lease", "revoke", "health_check"):
            assert hasattr(P.SecretAdapter, name), f"missing {name}"

    def test_embedding_methods(self) -> None:
        for name in ("embed", "dimensions", "health_check"):
            assert hasattr(P.EmbeddingAdapter, name), f"missing {name}"

    def test_object_store_methods(self) -> None:
        for name in ("put", "get", "delete", "presign", "health_check"):
            assert hasattr(P.ObjectStoreAdapter, name), f"missing {name}"

    def test_observability_methods(self) -> None:
        for name in ("emit_trace", "emit_metric", "flush", "health_check"):
            assert hasattr(P.ObservabilityAdapter, name), f"missing {name}"

class TestImplementsProtocol:
    """A minimal concrete class satisfying the protocol's method shape
    must pass ``isinstance(obj, Protocol)`` at runtime (Protocols are
    decorated with ``@runtime_checkable``)."""

    def test_relational_runtime_check(self) -> None:
        class FakeRelational:
            async def connect(self) -> None: ...
            def session(self) -> object: ...
            async def run_migrations(self, dir: str) -> None: ...
            async def close(self) -> None: ...
            async def health_check(self) -> P.AdapterHealth: ...

        assert isinstance(FakeRelational(), P.RelationalAdapter)

    def test_vector_runtime_check(self) -> None:
        class FakeVector:
            async def ensure_collection(
                self, name: str, dim: int, metric: str = "cosine"
            ) -> None: ...
            async def upsert(self, items: list[P.VectorItem]) -> None: ...
            async def search(
                self, vector: list[float], k: int = 10,
                filter: dict[str, object] | None = None,
            ) -> list[P.VectorHit]: ...
            async def delete(self, ids: list[str]) -> None: ...
            async def health_check(self) -> P.AdapterHealth: ...

        assert isinstance(FakeVector(), P.VectorAdapter)


class TestAdapterHealth:
    def test_health_dataclass_fields(self) -> None:
        h = P.AdapterHealth(status="ok", driver="x", detail=None, latency_ms=1.2)
        assert h.status == "ok"
        assert h.driver == "x"
        assert h.detail is None
        assert h.latency_ms == 1.2

    @pytest.mark.parametrize("bad", ["healthy", "OK", "", "ready"])
    def test_status_must_be_canonical(self, bad: str) -> None:
        # status is a Literal; allowed = {"ok", "degraded", "unreachable"}
        with pytest.raises((ValueError, TypeError)):
            P.AdapterHealth(status=bad, driver="x")  # type: ignore[arg-type]
```

- [ ] **Step 3.2: Run the test, expect failure**

```bash
uv run pytest tests/unit/db/test_adapter_protocols.py -v
```

Expected: `ModuleNotFoundError: No module named 'cognic_agentos.db'`.

- [ ] **Step 3.3: Create the package + protocol module**

Create `src/cognic_agentos/db/__init__.py`:

```python
"""Persistence + adapter sub-package.

Per ADR-009, AgentOS reaches every external system through a typed
``Protocol`` interface declared in ``cognic_agentos.db.adapters.protocols``.
Bundled adapters live alongside the protocols; alternative adapters
install as plugin packs (per ADR-002).
"""
```

Create `src/cognic_agentos/db/adapters/__init__.py`:

```python
"""Adapter package — protocols, bundled implementations, registry, factory.

The public API (Sprint 1C):

- :class:`protocols.RelationalAdapter`, :class:`VectorAdapter`,
  :class:`SecretAdapter`, :class:`EmbeddingAdapter`,
  :class:`ObjectStoreAdapter`, :class:`ObservabilityAdapter` — the six
  ADR-009 typed contracts. (``MemoryAdapter`` ships with Sprint 11.5
  per ADR-019.)
- :class:`registry.AdapterRegistry`, :exc:`registry.AdapterNotInstalled`.
- :func:`factory.build_adapters` — reads ``Settings``, returns ``Adapters``.
- :func:`load_bundled_adapters` — explicit loader the lifespan invokes at
  startup. Imports each bundled adapter module so its registration side-
  effect runs. Missing optional deps (kernel image deliberately omits the
  ``adapters`` extras) are skipped silently — the configured driver will
  surface via ``AdapterNotInstalled`` at factory time, which is the
  intended fail-fast path.
"""

import importlib
import logging

from cognic_agentos.db.adapters import protocols
from cognic_agentos.db.adapters.factory import Adapters, build_adapters
from cognic_agentos.db.adapters.registry import (
    AdapterNotInstalled,
    AdapterRegistry,
    bundled_registry,
)

logger = logging.getLogger(__name__)

# The five bundled-adapter modules Sprint 1C ships. Each module performs a
# `bundled_registry.register(kind, driver_name, cls)` call at import time;
# `load_bundled_adapters()` triggers those side-effects in a single,
# audit-able call site.
#
# The value side of this map is the **allowlist of top-level packages whose
# absence is legitimate in the kernel image** (which omits the `adapters`
# optional-dep group). Any other ImportError — typo inside the module, a
# transitive dep that the adapter module itself imports unexpectedly, broken
# package post-install — re-raises so operators see real bugs immediately.
# Empty frozenset means "this adapter has no kernel-image-acceptable misses,
# so any ImportError is a bug."
_BUNDLED_ADAPTER_OPTIONAL_DEPS: dict[str, frozenset[str]] = {
    "cognic_agentos.db.adapters.postgres_adapter": frozenset({"sqlalchemy", "asyncpg"}),
    "cognic_agentos.db.adapters.qdrant_adapter": frozenset({"qdrant_client"}),
    "cognic_agentos.db.adapters.vault_adapter": frozenset({"hvac"}),
    # Ollama adapter only depends on httpx (always present); no kernel-image misses.
    "cognic_agentos.db.adapters.ollama_embedding_adapter": frozenset(),
    "cognic_agentos.db.adapters.langfuse_otel_adapter": frozenset({"langfuse"}),
}


def load_bundled_adapters() -> dict[str, str]:
    """Import each bundled adapter module so its driver registers.

    On ``ImportError``, inspect ``.name`` (PEP 451) — if the missing
    top-level package is on the adapter's optional-deps allowlist, log
    + skip (kernel image legitimately lacks it). Otherwise re-raise so
    real bugs are not silently buried.

    Returns a diagnostic map ``{module_name: 'loaded' | 'skipped: <reason>'}``.
    Configured-but-missing drivers later surface via ``AdapterNotInstalled``
    from the factory.
    """

    results: dict[str, str] = {}
    for fqmn in _BUNDLED_ADAPTER_OPTIONAL_DEPS:
        try:
            importlib.import_module(fqmn)
            results[fqmn] = "loaded"
        except ImportError as exc:
            missing_module = (exc.name or "").split(".")[0]
            allowlist = _BUNDLED_ADAPTER_OPTIONAL_DEPS[fqmn]
            if missing_module and missing_module in allowlist:
                results[fqmn] = (
                    f"skipped: optional dep {missing_module!r} not installed"
                )
                logger.info(
                    "bundled adapter %s skipped: optional dep %r absent (kernel image)",
                    fqmn, missing_module,
                )
            else:
                # Real bug — typo, broken package, missing internal symbol.
                # Do not bury it.
                logger.error(
                    "bundled adapter %s failed to load with unexpected ImportError "
                    "(missing module=%r, allowlist=%s): %s",
                    fqmn, missing_module, sorted(allowlist), exc,
                )
                raise
    return results


__all__ = [
    "Adapters",
    "AdapterNotInstalled",
    "AdapterRegistry",
    "build_adapters",
    "bundled_registry",
    "load_bundled_adapters",
    "protocols",
]
```

Create `src/cognic_agentos/db/adapters/protocols.py`:

```python
"""Adapter protocols — the typed contracts every bundled or plugin adapter implements.

Per ADR-009. PEP-544 ``Protocol`` is used so adapters do NOT need to
inherit from a base class; structural conformance is enough. Each protocol
is decorated with ``@runtime_checkable`` so the test suite (and the
factory) can verify a registered class actually satisfies its declared
shape at registration time.

Async/sync flavour rule: every IO-bound method is ``async``. Pure-getter
methods (e.g. ``EmbeddingAdapter.dimensions``) are synchronous.

``ObjectStoreAdapter`` is declared-only in Sprint 1C — Sprint 8 ships the
S3/MinIO impl alongside evidence-pack export. Declaring it here lets the
rest of the codebase reference the type immediately and avoids a churn
migration later.

Memory governance (``MemoryAdapter`` per ADR-019) is **not** declared in
this sprint — it ships with Sprint 11.5 alongside ``core/memory/``. The
registry's ``kind`` field is unconstrained, so Sprint 11.5 can add
``"memory"`` without modifying this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable

AdapterStatus = Literal["ok", "degraded", "unreachable"]


@dataclass(frozen=True, slots=True)
class AdapterHealth:
    """Standardised return shape for every ``health_check()``.

    ``status`` is the boolean signal /readyz collapses across adapters
    (``ok`` → 200; anything else → 503). ``driver`` lets the operator
    see exactly which bundled or plugin driver answered. ``detail`` is a
    free-form string for diagnostic noise (e.g. error class). ``latency_ms``
    is the elapsed health-probe wall-time so dashboards can chart adapter
    responsiveness.
    """

    status: AdapterStatus
    driver: str
    detail: str | None = None
    latency_ms: float | None = None

    def __post_init__(self) -> None:
        if self.status not in ("ok", "degraded", "unreachable"):
            raise ValueError(
                f"AdapterHealth.status must be ok|degraded|unreachable; got {self.status!r}"
            )


# --- Vector helpers ----------------------------------------------------

@dataclass(frozen=True, slots=True)
class VectorItem:
    """A single point to upsert into a vector collection."""

    id: str
    vector: list[float]
    payload: dict[str, Any]


@dataclass(frozen=True, slots=True)
class VectorHit:
    """A single search result."""

    id: str
    score: float
    payload: dict[str, Any]


# --- Secret helpers ----------------------------------------------------

@dataclass(frozen=True, slots=True)
class SecretLease:
    """Result of ``SecretAdapter.lease()``."""

    lease_id: str
    ttl_s: int
    value: dict[str, Any]


# --- Protocols ---------------------------------------------------------


@runtime_checkable
class RelationalAdapter(Protocol):
    """RDBMS adapter — Sprint 1C ships postgres; Sprint 1D adds oracle."""

    async def connect(self) -> None: ...
    def session(self) -> Any: ...
    async def run_migrations(self, dir: str) -> None: ...
    async def close(self) -> None: ...
    async def health_check(self) -> AdapterHealth: ...


@runtime_checkable
class VectorAdapter(Protocol):
    """Vector store — Sprint 1C ships qdrant."""

    async def ensure_collection(
        self, name: str, dim: int, metric: str = "cosine"
    ) -> None: ...
    async def upsert(self, items: list[VectorItem]) -> None: ...
    async def search(
        self,
        vector: list[float],
        k: int = 10,
        filter: dict[str, Any] | None = None,
    ) -> list[VectorHit]: ...
    async def delete(self, ids: list[str]) -> None: ...
    async def health_check(self) -> AdapterHealth: ...


@runtime_checkable
class SecretAdapter(Protocol):
    """Secrets manager — Sprint 1C ships vault."""

    async def read(self, path: str) -> dict[str, Any]: ...
    async def write(self, path: str, value: dict[str, Any]) -> None: ...
    async def lease(self, path: str, ttl_s: int) -> SecretLease: ...
    async def revoke(self, lease_id: str) -> None: ...
    async def health_check(self) -> AdapterHealth: ...


@runtime_checkable
class EmbeddingAdapter(Protocol):
    """Embedding provider — Sprint 1C ships ollama (dev); Sprint 1D adds openai_compat (prod)."""

    async def embed(self, texts: list[str]) -> list[list[float]]: ...
    @property
    def dimensions(self) -> int: ...
    async def health_check(self) -> AdapterHealth: ...


@runtime_checkable
class ObjectStoreAdapter(Protocol):
    """Object storage — DECLARED ONLY in Sprint 1C; Sprint 8 ships the S3/MinIO impl
    alongside evidence-pack export."""

    async def put(self, bucket: str, key: str, body: bytes) -> None: ...
    async def get(self, bucket: str, key: str) -> bytes: ...
    async def delete(self, bucket: str, key: str) -> None: ...
    async def presign(self, bucket: str, key: str, ttl_s: int) -> str: ...
    async def health_check(self) -> AdapterHealth: ...


@runtime_checkable
class ObservabilityAdapter(Protocol):
    """Observability sink — Sprint 1C ships langfuse_otel (Langfuse v3 + OTel)."""

    async def emit_trace(self, name: str, attributes: dict[str, Any]) -> None: ...
    async def emit_metric(self, name: str, value: float, attributes: dict[str, Any]) -> None: ...
    async def flush(self) -> None: ...
    async def health_check(self) -> AdapterHealth: ...
```

- [ ] **Step 3.4: Run the test, expect pass**

```bash
uv run pytest tests/unit/db/test_adapter_protocols.py -v
uv run mypy src tests
```

Expected: all conformance tests pass; mypy clean. (The `__init__.py` import chain will fail because `factory` and `registry` don't exist yet — fix in Task 4 by **deferring** that import until both modules exist. **For now, comment out the factory/registry imports in `db/adapters/__init__.py` and uncomment in Task 5.**)

- [ ] **Step 3.5: Defer factory/registry imports**

In `src/cognic_agentos/db/adapters/__init__.py`, replace the contents with the protocol-only form for now:

```python
"""Adapter package — protocols + (Task 5) registry/factory.

After Task 5 lands, this re-exports the registry + factory too.
"""

from cognic_agentos.db.adapters import protocols

__all__ = ["protocols"]
```

- [ ] **Step 3.6: Re-run the test**

```bash
uv run pytest tests/unit/db/ -v
uv run mypy src tests
```

Expected: green.

- [ ] **Step 3.7: Commit**

```bash
git add src/cognic_agentos/db tests/unit/db
git commit -m "feat(sprint-1c): adapter protocols (ADR-009 contracts)"
```

---

### Task 4: In-memory test adapters (under `tests/support/`)

These are test-only fixtures: an aiosqlite-backed `InMemoryRelationalAdapter` (so `test_postgres_adapter.py` can drive the SQLAlchemy machinery without a live Postgres) and dict-backed implementations for vector/secret/embedding/observability.

Per AGENTS.md production-grade rule + "Test-only mocks, fixtures, and demo-safe sample data are allowed only under clearly separated test/demo paths," these live under **`tests/support/`**, NOT in `src/cognic_agentos/`. The production source tree never ships them; the bundled-adapter registry never references them; tests construct them explicitly or register them through a test-local `AdapterRegistry`.

**Files:**
- Create: `tests/support/__init__.py` (empty)
- Create: `tests/support/adapter_fixtures.py`
- Create: `tests/unit/db/test_memory_adapters.py`

- [ ] **Step 4.1: Write the failing test**

Create `tests/unit/db/test_memory_adapters.py`:

```python
"""In-memory adapters — used by tests, never registered as default drivers.

Lives under ``tests/`` per AGENTS.md test-fixture-placement rule."""

from __future__ import annotations

from cognic_agentos.db.adapters import protocols as P
from tests.support.adapter_fixtures import (
    InMemoryEmbeddingAdapter,
    InMemoryObservabilityAdapter,
    InMemoryRelationalAdapter,
    InMemorySecretAdapter,
    InMemoryVectorAdapter,
)


class TestInMemoryRelational:
    async def test_lifecycle(self) -> None:
        a = InMemoryRelationalAdapter()
        await a.connect()
        h = await a.health_check()
        assert h.status == "ok"
        assert h.driver == "memory"
        await a.close()
        h2 = await a.health_check()
        assert h2.status == "unreachable"

    async def test_satisfies_protocol(self) -> None:
        assert isinstance(InMemoryRelationalAdapter(), P.RelationalAdapter)


class TestInMemoryVector:
    async def test_upsert_and_search(self) -> None:
        a = InMemoryVectorAdapter()
        await a.ensure_collection("c", dim=3)
        await a.upsert(
            [
                P.VectorItem(id="1", vector=[1.0, 0.0, 0.0], payload={"k": "a"}),
                P.VectorItem(id="2", vector=[0.0, 1.0, 0.0], payload={"k": "b"}),
            ]
        )
        hits = await a.search([1.0, 0.0, 0.0], k=2)
        assert len(hits) == 2
        assert hits[0].id == "1"  # exact match wins on cosine

    async def test_delete(self) -> None:
        a = InMemoryVectorAdapter()
        await a.ensure_collection("c", dim=2)
        await a.upsert([P.VectorItem(id="1", vector=[1.0, 0.0], payload={})])
        await a.delete(["1"])
        hits = await a.search([1.0, 0.0])
        assert hits == []

    async def test_satisfies_protocol(self) -> None:
        assert isinstance(InMemoryVectorAdapter(), P.VectorAdapter)


class TestInMemorySecret:
    async def test_round_trip(self) -> None:
        a = InMemorySecretAdapter()
        await a.write("p/q", {"k": "v"})
        assert await a.read("p/q") == {"k": "v"}

    async def test_lease_and_revoke(self) -> None:
        a = InMemorySecretAdapter()
        await a.write("p/q", {"k": "v"})
        lease = await a.lease("p/q", ttl_s=60)
        assert lease.value == {"k": "v"}
        assert lease.ttl_s == 60
        await a.revoke(lease.lease_id)

    async def test_satisfies_protocol(self) -> None:
        assert isinstance(InMemorySecretAdapter(), P.SecretAdapter)


class TestInMemoryEmbedding:
    async def test_deterministic_shape(self) -> None:
        a = InMemoryEmbeddingAdapter(dimensions=8)
        v = await a.embed(["hello", "world"])
        assert len(v) == 2
        assert all(len(row) == 8 for row in v)

    def test_dimensions_property(self) -> None:
        assert InMemoryEmbeddingAdapter(dimensions=4).dimensions == 4

    async def test_satisfies_protocol(self) -> None:
        assert isinstance(InMemoryEmbeddingAdapter(), P.EmbeddingAdapter)


class TestInMemoryObservability:
    async def test_records_emissions(self) -> None:
        a = InMemoryObservabilityAdapter()
        await a.emit_trace("t", {"k": 1})
        await a.emit_metric("m", 1.0, {})
        await a.flush()
        assert len(a.traces) == 1
        assert len(a.metrics) == 1

    async def test_satisfies_protocol(self) -> None:
        assert isinstance(InMemoryObservabilityAdapter(), P.ObservabilityAdapter)
```

- [ ] **Step 4.2: Run the test, expect failure**

```bash
uv run pytest tests/unit/db/test_memory_adapters.py -v
```

Expected: import error — `cannot import name 'InMemoryRelationalAdapter'`.

- [ ] **Step 4.3: Create `tests/support/__init__.py` (empty) and `tests/support/adapter_fixtures.py`**

`tests/support/__init__.py` is an empty file. The fixtures themselves go in `tests/support/adapter_fixtures.py`:

```python
"""In-memory adapter implementations — TEST FIXTURES ONLY.

Lives under ``tests/support/`` per AGENTS.md "test-only mocks, fixtures,
and demo-safe sample data are allowed only under clearly separated
test/demo paths." Never wired as a default driver; the bundled registry
uses the real adapters (postgres / qdrant / vault / ollama / langfuse_otel).

The relational variant uses ``aiosqlite`` so SQLAlchemy machinery can
exercise the adapter contract without a live Postgres. The other variants
are dict-backed.
"""

from __future__ import annotations

import asyncio
import math
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from cognic_agentos.db.adapters.protocols import (
    AdapterHealth,
    SecretLease,
    VectorHit,
    VectorItem,
)


class InMemoryRelationalAdapter:
    """SQLite-backed relational adapter for tests.

    Driver name: ``memory``. Database URL fixed to in-memory SQLite.
    """

    driver = "memory"

    def __init__(self) -> None:
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker[Any] | None = None
        self._closed = False

    async def connect(self) -> None:
        self._engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            echo=False,
            future=True,
        )
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)
        self._closed = False

    def session(self) -> Any:
        if self._session_factory is None:
            raise RuntimeError("connect() must be awaited first")
        return self._session_factory()

    async def run_migrations(self, dir: str) -> None:
        # Tests don't need real migrations; presence of method satisfies protocol.
        return None

    async def close(self) -> None:
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
        self._closed = True

    async def health_check(self) -> AdapterHealth:
        if self._closed or self._engine is None:
            return AdapterHealth(status="unreachable", driver=self.driver, detail="closed")
        return AdapterHealth(status="ok", driver=self.driver, latency_ms=0.0)


class InMemoryVectorAdapter:
    driver = "memory"

    def __init__(self) -> None:
        self._collections: dict[str, list[VectorItem]] = {}

    async def ensure_collection(self, name: str, dim: int, metric: str = "cosine") -> None:
        self._collections.setdefault(name, [])

    async def upsert(self, items: list[VectorItem]) -> None:
        # Single default collection for test convenience
        col = self._collections.setdefault("default", [])
        existing_ids = {it.id for it in col}
        for it in items:
            if it.id in existing_ids:
                col[:] = [c for c in col if c.id != it.id]
        col.extend(items)

    async def search(
        self,
        vector: list[float],
        k: int = 10,
        filter: dict[str, Any] | None = None,
    ) -> list[VectorHit]:
        if filter is not None:
            raise NotImplementedError(
                "InMemoryVectorAdapter.search filter is deferred to Sprint 11.5 "
                "+ ADR-017 — same fail-loud rule as the bundled Qdrant adapter."
            )
        col = self._collections.get("default", [])
        scored = [(self._cosine(vector, it.vector), it) for it in col]
        scored.sort(key=lambda x: x[0], reverse=True)
        return [
            VectorHit(id=it.id, score=score, payload=it.payload)
            for score, it in scored[:k]
        ]

    async def delete(self, ids: list[str]) -> None:
        for col in self._collections.values():
            col[:] = [it for it in col if it.id not in ids]

    async def health_check(self) -> AdapterHealth:
        return AdapterHealth(status="ok", driver=self.driver, latency_ms=0.0)

    @staticmethod
    def _cosine(a: list[float], b: list[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b, strict=True))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(x * x for x in b))
        if na == 0 or nb == 0:
            return 0.0
        return dot / (na * nb)


class InMemorySecretAdapter:
    driver = "memory"

    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}
        self._leases: dict[str, str] = {}

    async def read(self, path: str) -> dict[str, Any]:
        if path not in self._store:
            raise KeyError(path)
        return dict(self._store[path])

    async def write(self, path: str, value: dict[str, Any]) -> None:
        self._store[path] = dict(value)

    async def lease(self, path: str, ttl_s: int) -> SecretLease:
        lease_id = uuid.uuid4().hex
        self._leases[lease_id] = path
        return SecretLease(lease_id=lease_id, ttl_s=ttl_s, value=dict(self._store[path]))

    async def revoke(self, lease_id: str) -> None:
        self._leases.pop(lease_id, None)

    async def health_check(self) -> AdapterHealth:
        return AdapterHealth(status="ok", driver=self.driver, latency_ms=0.0)


class InMemoryEmbeddingAdapter:
    driver = "memory"

    def __init__(self, dimensions: int = 8) -> None:
        self._dimensions = dimensions

    async def embed(self, texts: list[str]) -> list[list[float]]:
        # Deterministic pseudo-embedding: hash → float per dim.
        out: list[list[float]] = []
        for t in texts:
            seed = abs(hash(t)) or 1
            row = [
                ((seed >> (i * 3)) & 0xFFFF) / 0xFFFF
                for i in range(self._dimensions)
            ]
            out.append(row)
        return out

    @property
    def dimensions(self) -> int:
        return self._dimensions

    async def health_check(self) -> AdapterHealth:
        return AdapterHealth(status="ok", driver=self.driver, latency_ms=0.0)


class InMemoryObservabilityAdapter:
    driver = "memory"

    def __init__(self) -> None:
        self.traces: list[tuple[str, dict[str, Any]]] = []
        self.metrics: list[tuple[str, float, dict[str, Any]]] = []
        self._flushed = 0

    async def emit_trace(self, name: str, attributes: dict[str, Any]) -> None:
        self.traces.append((name, dict(attributes)))

    async def emit_metric(
        self, name: str, value: float, attributes: dict[str, Any]
    ) -> None:
        self.metrics.append((name, value, dict(attributes)))

    async def flush(self) -> None:
        # Exercise async flush boundary; idempotent.
        await asyncio.sleep(0)
        self._flushed += 1

    async def health_check(self) -> AdapterHealth:
        return AdapterHealth(status="ok", driver=self.driver, latency_ms=0.0)
```

- [ ] **Step 4.4: Run the test, expect pass**

```bash
uv run pytest tests/unit/db/test_memory_adapters.py -v
uv run mypy src tests
```

Expected: 11 passes; mypy clean.

- [ ] **Step 4.5: Commit**

```bash
git add tests/support/__init__.py tests/support/adapter_fixtures.py tests/unit/db/test_memory_adapters.py
git commit -m "feat(sprint-1c): in-memory test adapters under tests/support/ (aiosqlite + dict-backed)"
```

---

### Task 5: Registry + Factory

The registry maps `(kind, driver_name)` → adapter class. Bundled adapters auto-register on import. The factory reads `Settings`, looks each driver up, instantiates, returns a typed `Adapters` container.

**Files:**
- Create: `src/cognic_agentos/db/adapters/registry.py`
- Create: `src/cognic_agentos/db/adapters/factory.py`
- Modify: `src/cognic_agentos/db/adapters/__init__.py` (un-defer the imports)
- Create: `tests/unit/db/test_adapter_factory.py`

- [ ] **Step 5.1: Write the failing test**

Create `tests/unit/db/test_adapter_factory.py`:

```python
"""Sprint 1C — adapter registry + factory.

Exit criterion: ``COGNIC_DB_DRIVER=mssql`` (a planned plugin pack, not bundled
in Sprint 1C) raises ``AdapterNotInstalled`` at startup with the kind +
driver name in the message — no silent fallback.
"""

from __future__ import annotations

from typing import Any

import pytest

from cognic_agentos.db.adapters import (
    AdapterNotInstalled,
    AdapterRegistry,
    build_adapters,
    bundled_registry,
    protocols as P,
)
from tests.support.adapter_fixtures import (
    InMemoryEmbeddingAdapter,
    InMemoryObservabilityAdapter,
    InMemoryRelationalAdapter,
    InMemorySecretAdapter,
    InMemoryVectorAdapter,
)


def _memory_settings() -> Any:
    """Build a Settings-like with all drivers set to 'memory'."""

    from cognic_agentos.core.config import build_settings_without_env_file

    s = build_settings_without_env_file().model_copy(
        update={
            "db_driver": "memory",
            "vector_driver": "memory",
            "secret_driver": "memory",
            "embed_driver": "memory",
            "obs_driver": "memory",
            "database_url": None,
            "qdrant_url": None,
            "vault_addr": None,
            "embedding_base_url": None,
            "langfuse_host": None,
        }
    )
    return s


def _memory_registry() -> AdapterRegistry:
    """A fresh registry with only the in-memory test impls."""

    r = AdapterRegistry()
    r.register("relational", "memory", InMemoryRelationalAdapter)
    r.register("vector", "memory", InMemoryVectorAdapter)
    r.register("secret", "memory", InMemorySecretAdapter)
    r.register("embedding", "memory", InMemoryEmbeddingAdapter)
    r.register("observability", "memory", InMemoryObservabilityAdapter)
    return r


class TestRegistry:
    def test_register_and_resolve(self) -> None:
        r = AdapterRegistry()
        r.register("relational", "x", InMemoryRelationalAdapter)
        assert r.resolve("relational", "x") is InMemoryRelationalAdapter

    def test_unknown_driver_raises(self) -> None:
        r = AdapterRegistry()
        with pytest.raises(AdapterNotInstalled) as exc:
            r.resolve("relational", "mssql")
        assert "mssql" in str(exc.value)
        assert "relational" in str(exc.value)

    def test_bundled_registry_lists_real_drivers(self) -> None:
        """``load_bundled_adapters()`` registers the five Sprint-1C drivers
        in any image where their optional deps are installed (test env =
        ``--all-extras`` so every module loads cleanly)."""

        from cognic_agentos.db.adapters import load_bundled_adapters

        results = load_bundled_adapters()
        for module_name in (
            "cognic_agentos.db.adapters.postgres_adapter",
            "cognic_agentos.db.adapters.qdrant_adapter",
            "cognic_agentos.db.adapters.vault_adapter",
            "cognic_agentos.db.adapters.ollama_embedding_adapter",
            "cognic_agentos.db.adapters.langfuse_otel_adapter",
        ):
            assert results[module_name] == "loaded", (
                f"{module_name} should load in the test env: {results[module_name]}"
            )

        assert bundled_registry.has("relational", "postgres")
        assert bundled_registry.has("vector", "qdrant")
        assert bundled_registry.has("secret", "vault")
        assert bundled_registry.has("embedding", "ollama")
        assert bundled_registry.has("observability", "langfuse_otel")

    def test_load_bundled_adapters_kernel_resilience(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Simulate kernel-image behaviour: one bundled module's optional
        dep is missing. ``ModuleNotFoundError.name`` matches the loader's
        per-adapter allowlist, so the loader logs + skips and the rest
        continue. ``ModuleNotFoundError`` is the standard library subclass
        of ``ImportError`` Python raises when a top-level package is absent,
        and it carries the missing module's name in ``.name``."""

        import importlib as _importlib

        from cognic_agentos.db.adapters import load_bundled_adapters

        real_import = _importlib.import_module

        def fake_import(name: str, package: object = None) -> object:
            if name == "cognic_agentos.db.adapters.qdrant_adapter":
                # Simulate "qdrant_client not installed" — name= is the PEP-451
                # attribute the loader inspects against its allowlist.
                raise ModuleNotFoundError(
                    "No module named 'qdrant_client'", name="qdrant_client"
                )
            return real_import(name, package)

        monkeypatch.setattr(_importlib, "import_module", fake_import)

        # Allowlisted miss → log + skip, no exception.
        results = load_bundled_adapters()

        assert "skipped" in results["cognic_agentos.db.adapters.qdrant_adapter"]
        assert "qdrant_client" in results["cognic_agentos.db.adapters.qdrant_adapter"]
        # Other modules still load
        assert results["cognic_agentos.db.adapters.postgres_adapter"] == "loaded"

    def test_load_bundled_adapters_reraises_unexpected_import_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When the missing module is NOT on the adapter's allowlist (e.g.
        a typo bug inside the adapter's own code or an unexpected transitive
        miss), the loader must re-raise so the bug is visible — never bury
        it as 'skipped'."""

        import importlib as _importlib

        from cognic_agentos.db.adapters import load_bundled_adapters

        real_import = _importlib.import_module

        def fake_import(name: str, package: object = None) -> object:
            if name == "cognic_agentos.db.adapters.qdrant_adapter":
                # qdrant_client IS allowlisted; "definitely_a_typo" is NOT.
                raise ModuleNotFoundError(
                    "No module named 'definitely_a_typo'",
                    name="definitely_a_typo",
                )
            return real_import(name, package)

        monkeypatch.setattr(_importlib, "import_module", fake_import)

        with pytest.raises(ModuleNotFoundError, match="definitely_a_typo"):
            load_bundled_adapters()


class TestFactory:
    async def test_build_with_memory_drivers(self) -> None:
        s = _memory_settings()
        adapters = build_adapters(s, registry=_memory_registry())

        assert isinstance(adapters.relational, P.RelationalAdapter)
        assert isinstance(adapters.vector, P.VectorAdapter)
        assert isinstance(adapters.secret, P.SecretAdapter)
        assert isinstance(adapters.embedding, P.EmbeddingAdapter)
        assert isinstance(adapters.observability, P.ObservabilityAdapter)

        # ObjectStore remains unset in Sprint 1C (Sprint 8 fills it).
        # MemoryAdapter is ADR-019 / Sprint 11.5 — no slot in this sprint.
        assert adapters.object_store is None
        assert not hasattr(adapters, "memory")

    async def test_unknown_driver_fails_fast(self) -> None:
        s = _memory_settings().model_copy(update={"db_driver": "mssql"})
        with pytest.raises(AdapterNotInstalled) as exc:
            build_adapters(s, registry=_memory_registry())
        assert "mssql" in str(exc.value)
        assert "relational" in str(exc.value)

    async def test_open_close_lifecycle(self) -> None:
        s = _memory_settings()
        adapters = build_adapters(s, registry=_memory_registry())

        await adapters.open_all()
        for name in ("relational", "vector", "secret", "embedding", "observability"):
            adapter = getattr(adapters, name)
            h = await adapter.health_check()
            assert h.status == "ok", f"{name} not ok: {h}"

        await adapters.close_all()
        # Relational adapter flips to unreachable after close
        h = await adapters.relational.health_check()
        assert h.status == "unreachable"
```

- [ ] **Step 5.2: Run the test, expect failure**

```bash
uv run pytest tests/unit/db/test_adapter_factory.py -v
```

Expected: import errors — `cannot import name 'AdapterRegistry'` etc.

- [ ] **Step 5.3: Create `registry.py`**

```python
"""Adapter registry — maps (kind, driver_name) → adapter class.

Bundled adapter modules call ``bundled_registry.register(...)`` at import
time so a plain ``import cognic_agentos.db.adapters`` populates the
default driver set before the factory runs.

Plugin-pack adapters (per ADR-002) discover via Python entry points in
Sprint 4 and register into a per-process ``AdapterRegistry`` the host
constructs from ``bundled_registry`` plus discovered packs.
"""

from __future__ import annotations

from typing import Literal

from cognic_agentos.db.adapters import protocols as P

# Sprint 1C's known kinds. The registry itself does NOT enforce this set —
# Sprint 11.5 adds "memory" alongside ADR-019 without modifying this module
# (the AdapterKind alias is convenience typing for Sprint 1C consumers).
AdapterKind = Literal[
    "relational", "vector", "secret", "embedding", "object_store", "observability"
]

# The PEP-544 protocol classes exposed alongside each kind — used by tests
# (and Sprint 4 plugin host) to verify registered classes structurally
# satisfy the declared shape.
PROTOCOL_FOR_KIND: dict[str, type] = {
    "relational": P.RelationalAdapter,
    "vector": P.VectorAdapter,
    "secret": P.SecretAdapter,
    "embedding": P.EmbeddingAdapter,
    "object_store": P.ObjectStoreAdapter,
    "observability": P.ObservabilityAdapter,
}


class AdapterNotInstalled(Exception):
    """Raised when ``Settings`` declares a driver that no registered class
    serves. The factory surfaces this at startup so misconfigurations
    fail fast — no silent fallback is permitted (per ADR-009).
    """

    def __init__(self, kind: str, driver: str) -> None:
        super().__init__(
            f"adapter not installed: kind={kind} driver={driver!r}. "
            "Bundled drivers register at import time; alternative drivers "
            "must be installed as plugin packs (see ADR-002, ADR-009)."
        )
        self.kind = kind
        self.driver = driver


class AdapterRegistry:
    """Mapping from ``(kind, driver_name)`` → adapter class.

    The class is responsible for instantiation; the factory owns the
    instantiation parameters (passed via ``Settings``).
    """

    def __init__(self) -> None:
        self._reg: dict[tuple[str, str], type] = {}

    def register(self, kind: str, driver: str, cls: type) -> None:
        self._reg[(kind, driver)] = cls

    def resolve(self, kind: str, driver: str) -> type:
        try:
            return self._reg[(kind, driver)]
        except KeyError as exc:
            raise AdapterNotInstalled(kind, driver) from exc

    def has(self, kind: str, driver: str) -> bool:
        return (kind, driver) in self._reg

    def kinds(self) -> set[str]:
        return {k for (k, _) in self._reg}


# Process-wide bundled registry. Bundled adapter modules mutate this on import.
bundled_registry = AdapterRegistry()
```

- [ ] **Step 5.4: Create `factory.py`**

```python
"""Adapter factory — builds the ``Adapters`` container from ``Settings``.

The factory is the only place ``Settings`` field names cross into the
adapter layer. Adapter constructors take a small typed config they can
read from settings via small per-driver helper functions kept here to
avoid scattering settings access across adapter modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cognic_agentos.core.config import Settings
from cognic_agentos.db.adapters import protocols as P
from cognic_agentos.db.adapters.registry import AdapterRegistry, bundled_registry


@dataclass(slots=True)
class Adapters:
    """Typed container exposed to the FastAPI lifespan + harness.

    ``object_store`` ships in Sprint 8 (alongside evidence-pack export).
    ``None`` in Sprint 1C — the slot exists so Sprint 8 does not require a
    structural migration. Memory governance (Sprint 11.5 / ADR-019) is
    handled outside this dataclass; that sprint introduces both the
    protocol AND the slot at the same time."""

    relational: P.RelationalAdapter
    vector: P.VectorAdapter
    secret: P.SecretAdapter
    embedding: P.EmbeddingAdapter
    observability: P.ObservabilityAdapter
    object_store: P.ObjectStoreAdapter | None = None
    _all: list[Any] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        self._all = [
            self.relational,
            self.vector,
            self.secret,
            self.embedding,
            self.observability,
        ]

    async def open_all(self) -> None:
        """Open every adapter that has a ``connect()``. Idempotent for
        adapters whose constructor already established the connection
        (e.g. dict-backed memory variants)."""

        for a in self._all:
            connect = getattr(a, "connect", None)
            if callable(connect):
                await connect()

    async def close_all(self) -> None:
        """Close in reverse-open order. Errors are swallowed per-adapter
        and surfaced via the next ``/readyz`` probe."""

        for a in reversed(self._all):
            close = getattr(a, "close", None)
            if callable(close):
                try:
                    await close()
                except Exception:
                    # Logging happens at the lifespan boundary; here we
                    # never let one adapter's shutdown error prevent the
                    # others from cleaning up.
                    pass


def build_adapters(
    settings: Settings,
    *,
    registry: AdapterRegistry | None = None,
) -> Adapters:
    """Read driver names from ``settings``, instantiate each adapter, return ``Adapters``.

    Raises :exc:`AdapterNotInstalled` when a configured driver isn't registered.
    """

    reg = registry or bundled_registry

    relational_cls = reg.resolve("relational", settings.db_driver)
    vector_cls = reg.resolve("vector", settings.vector_driver)
    secret_cls = reg.resolve("secret", settings.secret_driver)
    embedding_cls = reg.resolve("embedding", settings.embed_driver)
    observability_cls = reg.resolve("observability", settings.obs_driver)

    return Adapters(
        relational=relational_cls(*_relational_args(settings)),
        vector=vector_cls(*_vector_args(settings)),
        secret=secret_cls(*_secret_args(settings)),
        embedding=embedding_cls(*_embedding_args(settings)),
        observability=observability_cls(*_observability_args(settings)),
    )


# --- per-driver constructor argument helpers --------------------------------
# Each helper returns the positional args the bundled adapter expects.
# Keeping them here means adding a new driver doesn't touch the factory's
# core logic — the pattern is consistent: registered class + helper.

def _relational_args(s: Settings) -> tuple[Any, ...]:
    if s.db_driver == "memory":
        return ()
    if s.db_driver == "postgres":
        return (s.database_url,)
    return ()  # plugin packs may take additional args; their wrapper handles


def _vector_args(s: Settings) -> tuple[Any, ...]:
    if s.vector_driver == "memory":
        return ()
    if s.vector_driver == "qdrant":
        return (s.qdrant_url, s.qdrant_collection)
    return ()


def _secret_args(s: Settings) -> tuple[Any, ...]:
    if s.secret_driver == "memory":
        return ()
    if s.secret_driver == "vault":
        return (s.vault_addr, s.vault_token, s.vault_namespace)
    return ()


def _embedding_args(s: Settings) -> tuple[Any, ...]:
    if s.embed_driver == "memory":
        return ()
    if s.embed_driver == "ollama":
        return (s.embedding_base_url, s.embedding_model, s.embedding_dimensions)
    return ()


def _observability_args(s: Settings) -> tuple[Any, ...]:
    if s.obs_driver == "memory":
        return ()
    if s.obs_driver == "langfuse_otel":
        return (s.langfuse_host, s.langfuse_public_key, s.langfuse_secret_key)
    return ()
```

- [ ] **Step 5.5: Restore the `__init__.py` re-exports**

In `src/cognic_agentos/db/adapters/__init__.py`:

```python
"""Adapter package — protocols, bundled implementations, registry, factory.

The public API:

- :mod:`protocols` — typed contracts (RelationalAdapter, VectorAdapter, etc.)
- :class:`Adapters`, :func:`build_adapters` — typed container + factory
- :class:`AdapterRegistry`, :exc:`AdapterNotInstalled`, :data:`bundled_registry`
"""

from cognic_agentos.db.adapters import protocols
from cognic_agentos.db.adapters.factory import Adapters, build_adapters
from cognic_agentos.db.adapters.registry import (
    AdapterNotInstalled,
    AdapterRegistry,
    bundled_registry,
)

__all__ = [
    "Adapters",
    "AdapterNotInstalled",
    "AdapterRegistry",
    "build_adapters",
    "bundled_registry",
    "protocols",
]
```

- [ ] **Step 5.6: Run the test, expect pass (with the noqa imports)**

```bash
uv run pytest tests/unit/db/test_adapter_factory.py -v
```

Expected: registry tests pass; the `bundled_registry_lists_real_drivers` test fails because Tasks 6-10 haven't created the real adapter modules yet. **Mark that test as `@pytest.mark.skip(reason="enabled in Task 11 wrap")` for now**, or accept the xfail until Task 11. We choose: skip.

In `test_adapter_factory.py`, change the test to:

```python
    @pytest.mark.skip(reason="real bundled adapters land in Tasks 6-10; enabled in Task 11")
    def test_bundled_registry_lists_real_drivers(self) -> None:
        ...
```

Re-run:

```bash
uv run pytest tests/unit/db/ -v
uv run mypy src tests
```

Expected: green; one test skipped.

- [ ] **Step 5.7: Commit**

```bash
git add src/cognic_agentos/db/adapters/registry.py src/cognic_agentos/db/adapters/factory.py src/cognic_agentos/db/adapters/__init__.py tests/unit/db/test_adapter_factory.py
git commit -m "feat(sprint-1c): adapter registry + factory + Adapters container"
```

---

### Task 6: Postgres adapter

Real adapter via SQLAlchemy[asyncio] + asyncpg. Tests use an aiosqlite URL so SQLAlchemy machinery exercises but no Postgres process is required.

**Files:**
- Create: `src/cognic_agentos/db/adapters/postgres_adapter.py`
- Create: `tests/unit/db/test_postgres_adapter.py`

- [ ] **Step 6.1: Write the failing test**

Create `tests/unit/db/test_postgres_adapter.py`:

```python
"""PostgresAdapter — uses aiosqlite URL for tests so SQLAlchemy machinery
exercises without a live Postgres process.

Per BUILD_PLAN exit criterion this sprint covers `health_check` + lifecycle
only; full integration tests come with Sprint 1C compose stack."""

from __future__ import annotations

from cognic_agentos.db.adapters import bundled_registry, protocols as P
from cognic_agentos.db.adapters.postgres_adapter import PostgresAdapter


class TestRegistration:
    def test_postgres_registered_under_bundled(self) -> None:
        # Importing the module registers it
        assert bundled_registry.has("relational", "postgres")
        assert bundled_registry.resolve("relational", "postgres") is PostgresAdapter


class TestLifecycle:
    async def test_health_then_close(self) -> None:
        # aiosqlite URL — exercises SQLAlchemy async engine without Postgres
        a = PostgresAdapter("sqlite+aiosqlite:///:memory:")
        await a.connect()
        h = await a.health_check()
        assert h.status == "ok"
        assert h.driver == "postgres"
        assert h.latency_ms is not None
        await a.close()
        h2 = await a.health_check()
        assert h2.status == "unreachable"

    async def test_unreachable_on_bad_url(self) -> None:
        # No engine yet — connect() never called
        a = PostgresAdapter("postgresql+asyncpg://no:no@127.0.0.1:1/x")
        h = await a.health_check()
        assert h.status == "unreachable"


class TestSatisfiesProtocol:
    def test_protocol_conformance(self) -> None:
        a = PostgresAdapter("sqlite+aiosqlite:///:memory:")
        assert isinstance(a, P.RelationalAdapter)
```

- [ ] **Step 6.2: Run the test, expect failure**

```bash
uv run pytest tests/unit/db/test_postgres_adapter.py -v
```

Expected: `cannot import name 'PostgresAdapter'`.

- [ ] **Step 6.3: Create the adapter**

Create `src/cognic_agentos/db/adapters/postgres_adapter.py`:

```python
"""PostgresAdapter — RelationalAdapter via SQLAlchemy[asyncio] + asyncpg.

Driver name: ``postgres``. Auto-registers into ``bundled_registry`` on import.

Production runtime path is real (asyncpg). Tests use ``sqlite+aiosqlite:///:memory:``
to exercise SQLAlchemy machinery without a live Postgres process — the
adapter does not branch on URL shape; SQLAlchemy picks the right driver.
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from cognic_agentos.db.adapters.protocols import AdapterHealth
from cognic_agentos.db.adapters.registry import bundled_registry


class PostgresAdapter:
    driver = "postgres"

    def __init__(self, url: str | None) -> None:
        if not url:
            raise ValueError("PostgresAdapter requires database_url; got empty/None")
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
        # silently no-op. Alembic-driven migration invocation lands in
        # Sprint 2 alongside core/ schema work; until then this method
        # fails loudly so a caller cannot accidentally believe migrations
        # ran. See ADR-009 §"Migration policy".
        raise NotImplementedError(
            "PostgresAdapter.run_migrations is wired in Sprint 2 alongside "
            "core/ Alembic migrations (ADR-009 §'Migration policy'). "
            "Sprint 1C ships the protocol-method shape only."
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
                await conn.execute(text("SELECT 1"))
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


bundled_registry.register("relational", "postgres", PostgresAdapter)
```

- [ ] **Step 6.4: Run the test, expect pass**

```bash
uv run pytest tests/unit/db/test_postgres_adapter.py -v
uv run mypy src tests
```

Expected: green.

- [ ] **Step 6.5: Commit**

```bash
git add src/cognic_agentos/db/adapters/postgres_adapter.py tests/unit/db/test_postgres_adapter.py
git commit -m "feat(sprint-1c): PostgresAdapter via SQLAlchemy + asyncpg"
```

---

### Task 7: Qdrant adapter

Real adapter via `AsyncQdrantClient`. Tests use the client's `:memory:` mode (qdrant-client supports an in-process embedded mode for tests).

**Files:**
- Create: `src/cognic_agentos/db/adapters/qdrant_adapter.py`
- Create: `tests/unit/db/test_qdrant_adapter.py`

- [ ] **Step 7.1: Write the failing test**

```python
"""QdrantAdapter — exercises ``AsyncQdrantClient(":memory:")`` in tests."""

from __future__ import annotations

import pytest

from cognic_agentos.db.adapters import bundled_registry, protocols as P
from cognic_agentos.db.adapters.qdrant_adapter import QdrantAdapter


class TestRegistration:
    def test_qdrant_registered_under_bundled(self) -> None:
        assert bundled_registry.has("vector", "qdrant")
        assert bundled_registry.resolve("vector", "qdrant") is QdrantAdapter


class TestRoundTrip:
    async def test_ensure_upsert_search(self) -> None:
        a = QdrantAdapter(url=":memory:", collection="test_col")
        await a.connect()
        await a.ensure_collection("test_col", dim=4)
        await a.upsert(
            [
                P.VectorItem(id="1", vector=[1.0, 0.0, 0.0, 0.0], payload={"k": "a"}),
                P.VectorItem(id="2", vector=[0.0, 1.0, 0.0, 0.0], payload={"k": "b"}),
            ]
        )
        hits = await a.search([1.0, 0.0, 0.0, 0.0], k=2)
        assert len(hits) == 2
        assert hits[0].id == "1"
        await a.close()

    async def test_health_check(self) -> None:
        a = QdrantAdapter(url=":memory:", collection="test_col")
        await a.connect()
        h = await a.health_check()
        assert h.status == "ok"
        assert h.driver == "qdrant"
        await a.close()

    async def test_filter_argument_rejected(self) -> None:
        """Sprint 1C deliberately fails loud on non-None filter — translation
        to qdrant.Filter shape lands with Sprint 11.5 + ADR-017."""

        a = QdrantAdapter(url=":memory:", collection="test_col")
        await a.connect()
        await a.ensure_collection("test_col", dim=2)
        with pytest.raises(NotImplementedError, match="filter translation"):
            await a.search([1.0, 0.0], k=1, filter={"k": "a"})
        await a.close()


class TestSatisfiesProtocol:
    def test_protocol_conformance(self) -> None:
        a = QdrantAdapter(url=":memory:", collection="x")
        assert isinstance(a, P.VectorAdapter)
```

- [ ] **Step 7.2: Create `qdrant_adapter.py`**

```python
"""QdrantAdapter — VectorAdapter via qdrant-client (async).

Driver name: ``qdrant``. Auto-registers into ``bundled_registry`` on import.

The ``url`` parameter accepts both ``http://host:6333`` (real server) and
``:memory:`` (qdrant-client embedded mode used in tests).
"""

from __future__ import annotations

import time
from typing import Any
from uuid import UUID, uuid4, uuid5, NAMESPACE_OID

from qdrant_client import AsyncQdrantClient
from qdrant_client.http import models as qmodels

from cognic_agentos.db.adapters.protocols import (
    AdapterHealth,
    VectorHit,
    VectorItem,
)
from cognic_agentos.db.adapters.registry import bundled_registry


def _to_qdrant_id(s: str) -> str:
    """Qdrant accepts UUID or unsigned int IDs; we accept str ids and map
    to a deterministic UUID5 so callers can use natural keys."""

    try:
        return str(UUID(s))
    except ValueError:
        return str(uuid5(NAMESPACE_OID, s))


class QdrantAdapter:
    driver = "qdrant"

    def __init__(self, url: str | None, collection: str) -> None:
        if not url:
            raise ValueError("QdrantAdapter requires qdrant_url; got empty/None")
        self._url = url
        self._default_collection = collection
        self._client: AsyncQdrantClient | None = None

    async def connect(self) -> None:
        # ``location`` is the unified parameter on AsyncQdrantClient that
        # accepts URLs, file paths, or ``:memory:``.
        self._client = AsyncQdrantClient(location=self._url)

    async def ensure_collection(
        self, name: str, dim: int, metric: str = "cosine"
    ) -> None:
        if self._client is None:
            await self.connect()
        assert self._client is not None
        existing = await self._client.get_collections()
        if any(c.name == name for c in existing.collections):
            return
        await self._client.create_collection(
            collection_name=name,
            vectors_config=qmodels.VectorParams(
                size=dim,
                distance=qmodels.Distance.COSINE if metric == "cosine" else qmodels.Distance.EUCLID,
            ),
        )

    async def upsert(self, items: list[VectorItem]) -> None:
        if self._client is None:
            await self.connect()
        assert self._client is not None
        points = [
            qmodels.PointStruct(
                id=_to_qdrant_id(it.id),
                vector=it.vector,
                payload={**it.payload, "_natural_id": it.id},
            )
            for it in items
        ]
        await self._client.upsert(
            collection_name=self._default_collection,
            points=points,
        )

    async def search(
        self,
        vector: list[float],
        k: int = 10,
        filter: dict[str, Any] | None = None,
    ) -> list[VectorHit]:
        if filter is not None:
            # Sprint 1C deliberately refuses to silently drop a filter we
            # cannot translate. Filter shape (data-class / purpose / tenant)
            # is the responsibility of Sprint 11.5 + ADR-017 governance work
            # — that sprint introduces the typed filter vocabulary and the
            # qdrant.Filter translator. Until then, fail loudly so callers
            # cannot believe their predicate ran.
            raise NotImplementedError(
                "QdrantAdapter.search filter translation is deferred to "
                "Sprint 11.5 + ADR-017 (data-governance filtering). "
                "Sprint 1C accepts filter=None only."
            )
        if self._client is None:
            await self.connect()
        assert self._client is not None
        hits = await self._client.search(
            collection_name=self._default_collection,
            query_vector=vector,
            limit=k,
        )
        out: list[VectorHit] = []
        for h in hits:
            payload = dict(h.payload or {})
            natural = payload.pop("_natural_id", str(h.id))
            out.append(VectorHit(id=natural, score=float(h.score), payload=payload))
        return out

    async def delete(self, ids: list[str]) -> None:
        if self._client is None:
            await self.connect()
        assert self._client is not None
        await self._client.delete(
            collection_name=self._default_collection,
            points_selector=qmodels.PointIdsList(points=[_to_qdrant_id(i) for i in ids]),
        )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None

    async def health_check(self) -> AdapterHealth:
        if self._client is None:
            return AdapterHealth(status="unreachable", driver=self.driver, detail="not connected")
        start = time.perf_counter()
        try:
            await self._client.get_collections()
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


bundled_registry.register("vector", "qdrant", QdrantAdapter)
```

- [ ] **Step 7.3: Run + commit**

```bash
uv run pytest tests/unit/db/test_qdrant_adapter.py -v
uv run mypy src tests
git add src/cognic_agentos/db/adapters/qdrant_adapter.py tests/unit/db/test_qdrant_adapter.py
git commit -m "feat(sprint-1c): QdrantAdapter via AsyncQdrantClient"
```

---

### Task 8: Vault adapter

Per BUILD_PLAN deliverable + ADR-009: `db/adapters/vault_adapter.py` implements `SecretAdapter` **via hvac** (the standard Python Vault client). hvac is synchronous, so blocking calls are wrapped with `asyncio.to_thread` to keep the FastAPI event loop cooperative. Tests mock `hvac.Client` at the module boundary via `unittest.mock.patch` (respx is not used here because hvac talks to Vault over `requests`, not httpx).

**Files:**
- Create: `src/cognic_agentos/db/adapters/vault_adapter.py`
- Create: `tests/unit/db/test_vault_adapter.py`

- [ ] **Step 8.1: Write the failing test**

```python
"""VaultAdapter — hvac.Client mocked at the module boundary.

We patch ``hvac.Client`` (not the underlying transport) so the test stays
agnostic to whether hvac uses ``requests``, ``urllib3``, or future async
backends. This is the intended hvac unit-test pattern."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cognic_agentos.db.adapters import bundled_registry, protocols as P
from cognic_agentos.db.adapters.vault_adapter import VaultAdapter

VAULT_ADDR = "http://vault.test:8200"


def _client_with(read=None, write=None, sys=None) -> MagicMock:
    """Build a MagicMock hvac.Client with optional read/write/sys behaviours."""

    mock = MagicMock()
    if read is not None:
        mock.read.return_value = read
    if write is not None:
        mock.write.return_value = write
    if sys is not None:
        mock.sys = sys
    return mock


class TestRegistration:
    def test_vault_registered_under_bundled(self) -> None:
        assert bundled_registry.has("secret", "vault")
        assert bundled_registry.resolve("secret", "vault") is VaultAdapter


class TestReadWrite:
    async def test_read_kv_v2(self) -> None:
        # KV v2 nests under data/data
        with patch("cognic_agentos.db.adapters.vault_adapter.hvac.Client") as cls:
            cls.return_value = _client_with(read={"data": {"data": {"k": "v"}}})
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            assert await a.read("secret/data/p/q") == {"k": "v"}
            cls.return_value.read.assert_called_once_with("secret/data/p/q")

    async def test_read_kv_v1(self) -> None:
        # KV v1 returns flat under data
        with patch("cognic_agentos.db.adapters.vault_adapter.hvac.Client") as cls:
            cls.return_value = _client_with(read={"data": {"k": "v"}})
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            assert await a.read("secret/p/q") == {"k": "v"}

    async def test_read_missing_raises(self) -> None:
        with patch("cognic_agentos.db.adapters.vault_adapter.hvac.Client") as cls:
            cls.return_value = _client_with(read=None)
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            with pytest.raises(KeyError):
                await a.read("secret/data/missing")

    async def test_write(self) -> None:
        with patch("cognic_agentos.db.adapters.vault_adapter.hvac.Client") as cls:
            mock_client = MagicMock()
            cls.return_value = mock_client
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            await a.write("secret/data/p/q", {"k": "v"})
            mock_client.write.assert_called_once_with("secret/data/p/q", k="v")


class TestLeaseRevoke:
    async def test_lease(self) -> None:
        with patch("cognic_agentos.db.adapters.vault_adapter.hvac.Client") as cls:
            cls.return_value = _client_with(
                read={
                    "lease_id": "abc-lease",
                    "lease_duration": 60,
                    "data": {"username": "u", "password": "p"},
                }
            )
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            lease = await a.lease("database/creds/test", ttl_s=60)
            assert lease.lease_id == "abc-lease"
            assert lease.ttl_s == 60
            assert lease.value == {"username": "u", "password": "p"}

    async def test_revoke(self) -> None:
        with patch("cognic_agentos.db.adapters.vault_adapter.hvac.Client") as cls:
            mock_client = MagicMock()
            cls.return_value = mock_client
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            await a.revoke("abc-lease")
            mock_client.sys.revoke_lease.assert_called_once_with(lease_id="abc-lease")


class TestHealth:
    async def test_health_ok(self) -> None:
        with patch("cognic_agentos.db.adapters.vault_adapter.hvac.Client") as cls:
            mock_client = MagicMock()
            mock_client.sys.read_health_status.return_value = {
                "initialized": True,
                "sealed": False,
            }
            cls.return_value = mock_client
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            h = await a.health_check()
            assert h.status == "ok"
            assert h.driver == "vault"

    async def test_health_unreachable_when_sealed(self) -> None:
        with patch("cognic_agentos.db.adapters.vault_adapter.hvac.Client") as cls:
            mock_client = MagicMock()
            mock_client.sys.read_health_status.return_value = {
                "initialized": True,
                "sealed": True,
            }
            cls.return_value = mock_client
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            h = await a.health_check()
            assert h.status == "unreachable"
            assert h.detail is not None and "sealed" in h.detail.lower()

    async def test_health_unreachable_on_connect_error(self) -> None:
        with patch("cognic_agentos.db.adapters.vault_adapter.hvac.Client") as cls:
            mock_client = MagicMock()
            mock_client.sys.read_health_status.side_effect = ConnectionError("nope")
            cls.return_value = mock_client
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            h = await a.health_check()
            assert h.status == "unreachable"


class TestSatisfiesProtocol:
    def test_protocol_conformance(self) -> None:
        a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
        assert isinstance(a, P.SecretAdapter)
```

- [ ] **Step 8.2: Create `vault_adapter.py`**

```python
"""VaultAdapter — SecretAdapter via hvac (per ADR-009 + BUILD_PLAN).

Driver name: ``vault``. Auto-registers into ``bundled_registry`` on import.

hvac is the standard Python client for HashiCorp Vault. It is synchronous,
so every blocking call is wrapped with ``asyncio.to_thread`` to keep the
FastAPI event loop cooperative. The hvac.Client instance is created lazily
on first use so adapter construction remains side-effect-free (the
constructor never opens a network connection).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import hvac

from cognic_agentos.db.adapters.protocols import AdapterHealth, SecretLease
from cognic_agentos.db.adapters.registry import bundled_registry


class VaultAdapter:
    driver = "vault"

    def __init__(
        self,
        addr: str | None,
        token: str | None,
        namespace: str | None,
    ) -> None:
        if not addr:
            raise ValueError("VaultAdapter requires vault_addr; got empty/None")
        self._addr = addr.rstrip("/")
        self._token = token
        self._namespace = namespace
        self._client: hvac.Client | None = None

    def _ensure_client(self) -> hvac.Client:
        if self._client is None:
            self._client = hvac.Client(
                url=self._addr,
                token=self._token,
                namespace=self._namespace,
            )
        return self._client

    async def read(self, path: str) -> dict[str, Any]:
        def _read() -> dict[str, Any]:
            client = self._ensure_client()
            resp = client.read(path)
            if resp is None:
                raise KeyError(path)
            data = resp.get("data", {})
            # KV v2 nests under data/data; KV v1 returns under data
            if isinstance(data, dict) and "data" in data and isinstance(data["data"], dict):
                return dict(data["data"])
            return dict(data)

        return await asyncio.to_thread(_read)

    async def write(self, path: str, value: dict[str, Any]) -> None:
        def _write() -> None:
            client = self._ensure_client()
            client.write(path, **value)

        await asyncio.to_thread(_write)

    async def lease(self, path: str, ttl_s: int) -> SecretLease:
        def _lease() -> SecretLease:
            client = self._ensure_client()
            resp = client.read(path)
            if resp is None:
                raise KeyError(path)
            return SecretLease(
                lease_id=resp.get("lease_id", ""),
                ttl_s=int(resp.get("lease_duration", ttl_s)),
                value=dict(resp.get("data", {})),
            )

        return await asyncio.to_thread(_lease)

    async def revoke(self, lease_id: str) -> None:
        def _revoke() -> None:
            client = self._ensure_client()
            client.sys.revoke_lease(lease_id=lease_id)

        await asyncio.to_thread(_revoke)

    async def health_check(self) -> AdapterHealth:
        start = time.perf_counter()

        def _probe() -> dict[str, Any]:
            client = self._ensure_client()
            return dict(client.sys.read_health_status(method="GET") or {})

        try:
            status = await asyncio.to_thread(_probe)
        except Exception as exc:
            return AdapterHealth(
                status="unreachable",
                driver=self.driver,
                detail=type(exc).__name__,
            )

        if not status.get("initialized", False):
            return AdapterHealth(
                status="unreachable",
                driver=self.driver,
                detail="vault not initialized",
            )
        if status.get("sealed", True):
            return AdapterHealth(
                status="unreachable",
                driver=self.driver,
                detail="vault sealed",
            )
        return AdapterHealth(
            status="ok",
            driver=self.driver,
            latency_ms=(time.perf_counter() - start) * 1000.0,
        )


bundled_registry.register("secret", "vault", VaultAdapter)
```

- [ ] **Step 8.3: Run + commit**

```bash
uv run pytest tests/unit/db/test_vault_adapter.py -v
uv run mypy src tests
git add src/cognic_agentos/db/adapters/vault_adapter.py tests/unit/db/test_vault_adapter.py
git commit -m "feat(sprint-1c): VaultAdapter via hvac (asyncio.to_thread wrap)"
```

---

### Task 9: Ollama embedding adapter

Real adapter via httpx against Ollama's `/api/embed`. Tests mock via respx.

**Files:**
- Create: `src/cognic_agentos/db/adapters/ollama_embedding_adapter.py`
- Create: `tests/unit/db/test_ollama_embedding_adapter.py`

- [ ] **Step 9.1: Write the failing test**

```python
"""OllamaEmbeddingAdapter — embed() shape + health_check + graceful degrade."""

from __future__ import annotations

import respx
from httpx import ConnectError, Response

from cognic_agentos.db.adapters import bundled_registry, protocols as P
from cognic_agentos.db.adapters.ollama_embedding_adapter import OllamaEmbeddingAdapter


BASE = "http://ollama.test:11434"


class TestRegistration:
    def test_ollama_registered_under_bundled(self) -> None:
        assert bundled_registry.has("embedding", "ollama")
        assert bundled_registry.resolve("embedding", "ollama") is OllamaEmbeddingAdapter


class TestEmbed:
    @respx.mock
    async def test_embed_returns_vectors(self) -> None:
        respx.post(f"{BASE}/api/embed").mock(
            return_value=Response(
                200,
                json={"embeddings": [[0.1, 0.2, 0.3, 0.4], [0.5, 0.6, 0.7, 0.8]]},
            )
        )
        a = OllamaEmbeddingAdapter(BASE, model="qwen3-embedding:8b", dimensions=4)
        v = await a.embed(["a", "b"])
        assert len(v) == 2
        assert len(v[0]) == 4

    def test_dimensions_property(self) -> None:
        a = OllamaEmbeddingAdapter(BASE, model="x", dimensions=512)
        assert a.dimensions == 512


class TestHealth:
    @respx.mock
    async def test_health_ok(self) -> None:
        respx.get(f"{BASE}/api/tags").mock(
            return_value=Response(200, json={"models": []})
        )
        a = OllamaEmbeddingAdapter(BASE, model="x", dimensions=8)
        h = await a.health_check()
        assert h.status == "ok"
        assert h.driver == "ollama"

    @respx.mock
    async def test_health_unreachable(self) -> None:
        respx.get(f"{BASE}/api/tags").mock(side_effect=ConnectError("nope"))
        a = OllamaEmbeddingAdapter(BASE, model="x", dimensions=8)
        h = await a.health_check()
        assert h.status == "unreachable"


class TestSatisfiesProtocol:
    def test_protocol_conformance(self) -> None:
        a = OllamaEmbeddingAdapter(BASE, model="x", dimensions=8)
        assert isinstance(a, P.EmbeddingAdapter)
```

- [ ] **Step 9.2: Create `ollama_embedding_adapter.py`**

```python
"""OllamaEmbeddingAdapter — EmbeddingAdapter via Ollama HTTP.

Driver name: ``ollama``. Auto-registers into ``bundled_registry`` on import.

Per ADR-009 this adapter is **dev-only** for production deployment —
production banks set ``embed_driver=openai_compat`` against vLLM/SGLang
in Sprint 1D. The Ollama adapter exists to make local dev workable
without a GPU cluster.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from cognic_agentos.db.adapters.protocols import AdapterHealth
from cognic_agentos.db.adapters.registry import bundled_registry


class OllamaEmbeddingAdapter:
    driver = "ollama"

    def __init__(
        self,
        base_url: str | None,
        model: str,
        dimensions: int,
    ) -> None:
        if not base_url:
            raise ValueError("OllamaEmbeddingAdapter requires embedding_base_url; got empty/None")
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._dimensions = dimensions

    async def embed(self, texts: list[str]) -> list[list[float]]:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._base_url}/api/embed",
                json={"model": self._model, "input": texts},
            )
            resp.raise_for_status()
            body = resp.json()
        return [list(row) for row in body.get("embeddings", [])]

    @property
    def dimensions(self) -> int:
        return self._dimensions

    async def health_check(self) -> AdapterHealth:
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"{self._base_url}/api/tags")
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


bundled_registry.register("embedding", "ollama", OllamaEmbeddingAdapter)
```

- [ ] **Step 9.3: Run + commit**

```bash
uv run pytest tests/unit/db/test_ollama_embedding_adapter.py -v
uv run mypy src tests
git add src/cognic_agentos/db/adapters/ollama_embedding_adapter.py tests/unit/db/test_ollama_embedding_adapter.py
git commit -m "feat(sprint-1c): OllamaEmbeddingAdapter (dev embedding default)"
```

---

### Task 10: Langfuse-OTel observability adapter

Combines Langfuse v3 client + OpenTelemetry. Tests assert graceful degrade when Langfuse host is unreachable (per BUILD_PLAN exit criterion).

**Files:**
- Create: `src/cognic_agentos/db/adapters/langfuse_otel_adapter.py`
- Create: `tests/unit/db/test_langfuse_otel_adapter.py`

- [ ] **Step 10.1: Write the failing test**

```python
"""LangfuseOtelAdapter — graceful degrade when host unreachable; flush idempotent."""

from __future__ import annotations

import respx
from httpx import ConnectError, Response

from cognic_agentos.db.adapters import bundled_registry, protocols as P
from cognic_agentos.db.adapters.langfuse_otel_adapter import LangfuseOtelAdapter


HOST = "http://langfuse.test:3000"


class TestRegistration:
    def test_langfuse_otel_registered_under_bundled(self) -> None:
        assert bundled_registry.has("observability", "langfuse_otel")
        assert (
            bundled_registry.resolve("observability", "langfuse_otel")
            is LangfuseOtelAdapter
        )


class TestHealth:
    @respx.mock
    async def test_health_ok_when_langfuse_reachable(self) -> None:
        respx.get(f"{HOST}/api/public/health").mock(
            return_value=Response(200, json={"status": "OK"})
        )
        a = LangfuseOtelAdapter(HOST, public_key="pk", secret_key="sk")
        h = await a.health_check()
        assert h.status == "ok"
        assert h.driver == "langfuse_otel"

    @respx.mock
    async def test_health_unreachable_when_host_down(self) -> None:
        """Per BUILD_PLAN Sprint 1C exit criterion (line ~151): stopping
        the Langfuse container makes /readyz return **503** with
        ``obs: {driver: langfuse_otel, status: unreachable}``. Restart →
        /readyz flips back to 200.

        That criterion is binding for Sprint 1C. ``health_check()`` therefore
        returns ``unreachable`` (not ``degraded``) on host outage so the
        /readyz roll-up collapses to 503 as specified. Any future
        ``degraded``-but-still-ready semantics for observability outages
        require an explicit BUILD_PLAN amendment first.
        """

        respx.get(f"{HOST}/api/public/health").mock(side_effect=ConnectError("nope"))
        a = LangfuseOtelAdapter(HOST, public_key="pk", secret_key="sk")
        h = await a.health_check()
        assert h.status == "unreachable"


class TestEmissions:
    @respx.mock
    async def test_emit_and_flush_no_raise(self) -> None:
        # Even if the host is down, emit/flush must not raise — observability
        # outages must not propagate as runtime errors.
        respx.post(f"{HOST}/api/public/ingestion").mock(side_effect=ConnectError("nope"))
        a = LangfuseOtelAdapter(HOST, public_key="pk", secret_key="sk")
        await a.emit_trace("t", {"k": 1})
        await a.emit_metric("m", 1.0, {})
        await a.flush()  # idempotent + non-raising


class TestSatisfiesProtocol:
    def test_protocol_conformance(self) -> None:
        a = LangfuseOtelAdapter(HOST, public_key="pk", secret_key="sk")
        assert isinstance(a, P.ObservabilityAdapter)
```

- [ ] **Step 10.2: Create `langfuse_otel_adapter.py`**

```python
"""LangfuseOtelAdapter — OTel-bridged observability sink with a Langfuse health probe.

Driver name: ``langfuse_otel``. Auto-registers into ``bundled_registry`` on import.

**Sprint 1C scope (deliberately thin):**

- ``emit_trace`` creates an OpenTelemetry span with the supplied
  attributes. The Sprint 1B OTel pipeline (configured in
  ``cognic_agentos.observability.otel``) handles export.
- ``emit_metric`` is logged at debug level — full metric pipeline ships
  in Sprint 2 alongside ``core/audit``.
- ``flush`` posts an empty ingestion batch to Langfuse as a liveness
  ping; non-raising.
- ``health_check`` does an HTTP GET against ``/api/public/health`` so
  the /readyz roll-up surfaces Langfuse outages.

**Out of scope (Sprint 2/3 work):** real Langfuse SDK trace lifecycle —
parent-child generation records linked to agent invocations, prompt /
response capture, custom scorers, ``workflow_trace_id`` propagation. Those
require ``core/decision_history`` and the LLM gateway, which Sprint 1C
does not ship. This adapter therefore satisfies the ObservabilityAdapter
**contract** without claiming a full Langfuse trace integration.

Per BUILD_PLAN Sprint 1C exit criterion: stopping the Langfuse container
makes /readyz return 503 with ``obs: {driver: langfuse_otel, status:
unreachable}``. ``health_check()`` returns ``unreachable`` on host outage
so the /readyz roll-up collapses to 503 exactly as spec'd.

emit/flush remain non-raising — losing individual traces is acceptable
runtime behaviour; a sustained outage surfaces via the next /readyz probe,
not via exceptions in the request path.
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


class LangfuseOtelAdapter:
    driver = "langfuse_otel"

    def __init__(
        self,
        host: str | None,
        public_key: str | None,
        secret_key: str | None,
    ) -> None:
        if not host:
            raise ValueError("LangfuseOtelAdapter requires langfuse_host; got empty/None")
        self._host = host.rstrip("/")
        self._public_key = public_key
        self._secret_key = secret_key
        self._tracer = trace.get_tracer("cognic_agentos.observability")

    async def emit_trace(self, name: str, attributes: dict[str, Any]) -> None:
        # OTel trace emit is in-process and never raises on Langfuse outage.
        with self._tracer.start_as_current_span(name) as span:
            for k, v in attributes.items():
                # OTel span attributes are str|bool|int|float|sequence
                if isinstance(v, (str, bool, int, float)):
                    span.set_attribute(k, v)
                else:
                    span.set_attribute(k, str(v))

    async def emit_metric(
        self, name: str, value: float, attributes: dict[str, Any]
    ) -> None:
        # Sprint 1C ships metric emission as a debug-log fallback;
        # full metric pipeline lands in Sprint 2 alongside core/audit.
        logger.debug("metric %s=%s %s", name, value, attributes)

    async def flush(self) -> None:
        # Best-effort. Exceptions are swallowed and logged.
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                await client.post(
                    f"{self._host}/api/public/ingestion",
                    json={"batch": []},
                    auth=httpx.BasicAuth(self._public_key or "", self._secret_key or ""),
                )
        except Exception as exc:
            logger.warning("langfuse flush failed: %s", exc)

    async def health_check(self) -> AdapterHealth:
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"{self._host}/api/public/health")
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


bundled_registry.register("observability", "langfuse_otel", LangfuseOtelAdapter)
```

- [ ] **Step 10.3: Run + commit**

```bash
uv run pytest tests/unit/db/test_langfuse_otel_adapter.py -v
uv run mypy src tests
git add src/cognic_agentos/db/adapters/langfuse_otel_adapter.py tests/unit/db/test_langfuse_otel_adapter.py
git commit -m "feat(sprint-1c): LangfuseOtelAdapter (unreachable on host down → /readyz 503)"
```

---

### Task 11: Re-enable bundled-registry test + sweep

Now that all five real adapters exist, un-skip the bundled registry test and run the full suite to confirm every adapter auto-registers.

**Files:**
- Modify: `tests/unit/db/test_adapter_factory.py`

- [ ] **Step 11.1: Remove the skip marker**

In `tests/unit/db/test_adapter_factory.py`, remove the `@pytest.mark.skip(...)` line above `test_bundled_registry_lists_real_drivers`.

- [ ] **Step 11.2: Run the full adapter suite**

```bash
uv run pytest tests/unit/db/ -v
uv run mypy src tests
uv run ruff check .
uv run ruff format --check .
```

Expected: all green, no skips.

- [ ] **Step 11.3: Commit**

```bash
git add tests/unit/db/test_adapter_factory.py
git commit -m "test(sprint-1c): re-enable bundled-registry verification"
```

---

### Task 12: Lifespan + `/readyz` adapter integration

Replace the synthetic `_readiness_components` with real per-adapter health probes. Wire `Adapters.open_all()` / `close_all()` into the FastAPI lifespan.

**Files:**
- Modify: `src/cognic_agentos/portal/api/app.py`
- Modify: `tests/unit/test_readyz.py`

- [ ] **Step 12.1: Write the failing test**

Append to `tests/unit/test_readyz.py`:

```python
class TestReadyzWithAdapters:
    """Sprint 1C — /readyz now reports per-adapter status.

    The factory is invoked with an in-memory registry so the test does not
    require a live Postgres / Qdrant / Vault / Ollama / Langfuse process.
    """

    @pytest.fixture
    def memory_app(self, monkeypatch: pytest.MonkeyPatch) -> FastAPI:
        from cognic_agentos.db.adapters import AdapterRegistry
        from tests.support.adapter_fixtures import (
            InMemoryEmbeddingAdapter,
            InMemoryObservabilityAdapter,
            InMemoryRelationalAdapter,
            InMemorySecretAdapter,
            InMemoryVectorAdapter,
        )
        from cognic_agentos.core.config import build_settings_without_env_file
        from cognic_agentos.portal.api.app import create_app

        reg = AdapterRegistry()
        reg.register("relational", "memory", InMemoryRelationalAdapter)
        reg.register("vector", "memory", InMemoryVectorAdapter)
        reg.register("secret", "memory", InMemorySecretAdapter)
        reg.register("embedding", "memory", InMemoryEmbeddingAdapter)
        reg.register("observability", "memory", InMemoryObservabilityAdapter)

        settings = build_settings_without_env_file().model_copy(
            update={
                "db_driver": "memory",
                "vector_driver": "memory",
                "secret_driver": "memory",
                "embed_driver": "memory",
                "obs_driver": "memory",
            }
        )

        return create_app(settings=settings, adapter_registry=reg)

    def test_readyz_reports_per_adapter(self, memory_app: FastAPI) -> None:
        with TestClient(memory_app) as client:
            resp = client.get("/api/v1/readyz")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ready"] is True
        comps = body["components"]
        for name in ("relational", "vector", "secret", "embedding", "observability"):
            assert comps[name]["driver"] == "memory"
            assert comps[name]["status"] == "ok"

    def test_readyz_503_when_adapter_unreachable(
        self, memory_app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Force the relational adapter to report unreachable by closing it
        from cognic_agentos.db.adapters.protocols import AdapterHealth

        async def fake_health() -> AdapterHealth:
            return AdapterHealth(status="unreachable", driver="memory", detail="forced")

        with TestClient(memory_app) as client:
            # Replace the adapter's health_check at runtime
            adapters = memory_app.state.adapters
            monkeypatch.setattr(adapters.relational, "health_check", fake_health)
            resp = client.get("/api/v1/readyz")
        assert resp.status_code == 503
        body = resp.json()
        assert body["ready"] is False
        assert body["components"]["relational"]["status"] == "unreachable"
```

- [ ] **Step 12.2: Run the test, expect failure**

```bash
uv run pytest tests/unit/test_readyz.py::TestReadyzWithAdapters -v
```

Expected: `TypeError: create_app() got unexpected keyword argument 'adapter_registry'`.

- [ ] **Step 12.3: Extend `create_app` + lifespan + `/readyz`**

In `src/cognic_agentos/portal/api/app.py`:

```python
"""FastAPI application factory.

[existing docstring unchanged through Sprint 1B description]

Sprint 1C extension:
- ``lifespan`` opens adapters at startup, closes at shutdown.
- ``/readyz`` calls ``adapter.health_check()`` per registered adapter
  and reports per-driver status. Any adapter reporting non-``ok``
  collapses the response to 503.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator

from cognic_agentos import __version__
from cognic_agentos.core.config import Settings, get_settings
from cognic_agentos.db.adapters import (
    Adapters,
    AdapterRegistry,
    build_adapters,
    bundled_registry,
    load_bundled_adapters,
)
from cognic_agentos.observability import (
    configure_logging,
    configure_tracing,
    install_access_log_middleware,
    install_cors_middleware,
    install_otel_instrumentation,
    install_request_id_middleware,
    silence_uvicorn_access_log,
)


def _build_router(settings: Settings) -> APIRouter:
    router = APIRouter(prefix=settings.api_prefix)

    @router.get("/healthz", tags=["probes"], summary="Liveness probe")
    async def healthz() -> dict[str, Any]:
        return {"alive": True, "version": __version__}

    @router.get("/readyz", tags=["probes"], summary="Readiness probe")
    async def readyz(request: Request) -> JSONResponse:
        """Per-adapter health roll-up.

        Per Sprint 1C: each registered adapter contributes a
        ``components[<kind>] = {driver, status, ...}`` entry. ``ready``
        is the AND of every component being ``ok``.
        """

        adapters: Adapters | None = getattr(request.app.state, "adapters", None)
        components: dict[str, dict[str, Any]] = {
            "settings": {"status": "ok"},
            "logging": {"status": "ok"},
            "tracing": {"status": "ok"},
        }

        if adapters is not None:
            kinds: list[tuple[str, Any]] = [
                ("relational", adapters.relational),
                ("vector", adapters.vector),
                ("secret", adapters.secret),
                ("embedding", adapters.embedding),
                ("observability", adapters.observability),
            ]
            for kind, adapter in kinds:
                health = await adapter.health_check()
                comp: dict[str, Any] = {
                    "driver": health.driver,
                    "status": health.status,
                }
                if health.detail is not None:
                    comp["detail"] = health.detail
                if health.latency_ms is not None:
                    comp["latency_ms"] = round(health.latency_ms, 2)
                components[kind] = comp

        ready = all(comp.get("status") == "ok" for comp in components.values())
        body: dict[str, Any] = {
            "ready": ready,
            "runtime_profile": settings.runtime_profile,
            "components": components,
        }
        return JSONResponse(content=body, status_code=200 if ready else 503)

    @router.get("/version", tags=["probes"], summary="Build metadata")
    async def version() -> dict[str, Any]:
        return {
            "version": __version__,
            "build_sha": settings.build_sha,
            "build_time": settings.build_time,
            "python_version": settings.python_version,
            "platform": settings.platform_string,
            "runtime_profile": settings.runtime_profile,
        }

    return router


def create_app(
    settings: Settings | None = None,
    *,
    adapter_registry: AdapterRegistry | None = None,
) -> FastAPI:
    """Build and return the FastAPI application.

    Sprint 1C: adapters are constructed at startup via ``build_adapters``
    using the supplied ``adapter_registry`` (default: process-wide
    ``bundled_registry``). The factory's ``Adapters`` container is
    attached to ``app.state.adapters`` so route handlers can reach it.
    """

    settings = settings or get_settings()
    configure_logging(settings)
    silence_uvicorn_access_log()
    configure_tracing(settings)

    api_prefix = settings.api_prefix
    registry = adapter_registry or bundled_registry

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Trigger bundled-adapter registration side-effects. In the
        # default-adapters image this loads all five drivers; in the kernel
        # image (no `adapters` extras installed) every module ImportErrors
        # quietly and any configured driver fails fast at build_adapters().
        load_bundled_adapters()
        adapters = build_adapters(settings, registry=registry)
        await adapters.open_all()
        app.state.adapters = adapters
        try:
            yield
        finally:
            await adapters.close_all()
            app.state.adapters = None

    app = FastAPI(
        title="Cognic AgentOS",
        version=__version__,
        description=(
            "Bank-grade governance kernel + runtime + protocol layer for agent plugin packs."
        ),
        docs_url=None,
        redoc_url=None,
        openapi_url=f"{api_prefix}/openapi.json",
        lifespan=lifespan,
    )

    install_access_log_middleware(app)
    install_cors_middleware(app, settings)
    install_otel_instrumentation(app)
    install_request_id_middleware(app)

    app.include_router(_build_router(settings))

    Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        should_respect_env_var=False,
        excluded_handlers=[f"{api_prefix}{settings.prometheus_metrics_path}"],
    ).instrument(app).expose(
        app,
        endpoint=f"{api_prefix}{settings.prometheus_metrics_path}",
        include_in_schema=False,
    )

    return app
```

- [ ] **Step 12.4: Run all tests**

```bash
uv run pytest -v
uv run mypy src tests
```

Expected: all tests pass (Sprint 1B `test_readyz` cases + new Sprint 1C cases).

If `test_readyz` Sprint 1B cases fail because the existing fixtures didn't supply a registry, fix by setting `adapter_registry` to a memory-backed one OR by setting all driver fields to `memory` in the test settings. The simplest fix: route the existing Sprint 1B tests through `create_app(settings, adapter_registry=memory_registry())` via a shared `tests/conftest.py` fixture.

Add `tests/conftest.py` if not present:

```python
"""Shared test fixtures."""

from __future__ import annotations

import pytest

from cognic_agentos.core.config import Settings, build_settings_without_env_file
from cognic_agentos.db.adapters import AdapterRegistry
from tests.support.adapter_fixtures import (
    InMemoryEmbeddingAdapter,
    InMemoryObservabilityAdapter,
    InMemoryRelationalAdapter,
    InMemorySecretAdapter,
    InMemoryVectorAdapter,
)


@pytest.fixture
def memory_registry() -> AdapterRegistry:
    r = AdapterRegistry()
    r.register("relational", "memory", InMemoryRelationalAdapter)
    r.register("vector", "memory", InMemoryVectorAdapter)
    r.register("secret", "memory", InMemorySecretAdapter)
    r.register("embedding", "memory", InMemoryEmbeddingAdapter)
    r.register("observability", "memory", InMemoryObservabilityAdapter)
    return r


@pytest.fixture
def memory_settings() -> Settings:
    return build_settings_without_env_file().model_copy(
        update={
            "db_driver": "memory",
            "vector_driver": "memory",
            "secret_driver": "memory",
            "embed_driver": "memory",
            "obs_driver": "memory",
        }
    )
```

Update existing Sprint 1B tests that call `create_app()` to use these fixtures.

- [ ] **Step 12.5: Commit**

```bash
git add src/cognic_agentos/portal/api/app.py tests/unit/test_readyz.py tests/conftest.py
git commit -m "feat(sprint-1c): adapter lifespan + per-adapter /readyz roll-up"
```

---

### Task 13: docker-compose 7-service extension

Per BUILD_PLAN exit criterion: `docker compose -f infra/dev/docker-compose.yml up -d` brings up 7 services healthy in ≤30s. **Treat this as integration-risk work, not routine wiring.** Three of the seven services have known fragility:

- **Langfuse v3** — moving release; image tag `langfuse/langfuse:3` may pin to a build that needs different env vars (e.g. `LANGFUSE_INIT_*`, `CLICKHOUSE_*` if v3 splits its analytics store) than this plan's bare-minimum envs assume. Verify the running Langfuse version's required env shape before claiming "healthy in 30s."
- **Temporal `auto-setup` image** — Postgres-bootstrap race on cold start. The healthcheck command `tctl ... cluster health` may not be present in slimmer Temporal variants. Be ready to swap to `temporalio/admin-tools` for the healthcheck or relax the probe.
- **LiteLLM config validation** — `--config /app/config.yaml` is strict; a single env-var typo (e.g. `${VLLM_BASE_URL}` unset in dev) breaks startup. The Task-14 config keeps the dev aliases env-var-free; verify the prod aliases reference variables LiteLLM tolerates being unset.

**Mitigation if any service is brittle on this machine:** put non-essential-for-/readyz services behind `profiles:` so the default `up` brings only the four readiness-critical ones (Postgres, Qdrant, Vault, Langfuse — Langfuse is required because Sprint 1C's exit criterion explicitly tests its outage path through /readyz). LiteLLM, Redis, Temporal can be `profiles: [llm]` / `profiles: [cache]` / `profiles: [workflow]` and brought up with `--profile llm` etc. **Do this only if the default profile fails to come up healthy in two consecutive attempts** — don't profile-gate preemptively.

**Image version verification first:** before applying the compose file below, run `docker pull` against each pinned image tag locally; if any pull fails or the image's known-good config has changed, halt and consult the user before substituting a different tag.

**Files:**
- Modify: `infra/dev/docker-compose.yml`

- [ ] **Step 13.1: Replace `infra/dev/docker-compose.yml`**

```yaml
# Cognic AgentOS — local development compose stack.
#
# Sprint 1C: 7 services (Postgres, Qdrant, Redis, Vault, LiteLLM, Langfuse,
# Temporal). All ports env-driven via ${VAR:-default} so an operator can
# avoid host-port collisions without editing the file.

name: cognic-agentos-dev

services:
  postgres:
    image: postgres:16-alpine
    container_name: cognic-agentos-postgres
    environment:
      POSTGRES_DB: cognic_agentos
      POSTGRES_USER: cognic
      POSTGRES_PASSWORD: cognic_dev_only  # NEVER used outside dev
    ports:
      - "${COGNIC_POSTGRES_PORT:-5432}:5432"
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U cognic -d cognic_agentos"]
      interval: 5s
      timeout: 3s
      retries: 10

  qdrant:
    image: qdrant/qdrant:v1.18.1
    container_name: cognic-agentos-qdrant
    ports:
      - "${COGNIC_QDRANT_HTTP_PORT:-6333}:6333"
      - "${COGNIC_QDRANT_GRPC_PORT:-6334}:6334"
    volumes:
      - qdrant-data:/qdrant/storage
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:6333/readyz"]
      interval: 5s
      timeout: 3s
      retries: 10

  redis:
    image: redis:8-alpine
    container_name: cognic-agentos-redis
    ports:
      - "${COGNIC_REDIS_PORT:-6379}:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 10

  vault:
    image: hashicorp/vault:1.21
    container_name: cognic-agentos-vault
    cap_add:
      - IPC_LOCK
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: dev-only-root
      VAULT_DEV_LISTEN_ADDRESS: 0.0.0.0:8200
    ports:
      - "${COGNIC_VAULT_PORT:-8200}:8200"
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:8200/v1/sys/health"]
      interval: 5s
      timeout: 3s
      retries: 10

  litellm:
    image: ghcr.io/berriai/litellm:main-stable
    container_name: cognic-agentos-litellm
    command: ["--config", "/app/config.yaml", "--port", "4000"]
    volumes:
      - ../litellm/config.yaml:/app/config.yaml:ro
    environment:
      LITELLM_MASTER_KEY: dev-only-litellm
    ports:
      - "${COGNIC_LITELLM_PORT:-4000}:4000"
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:4000/health"]
      interval: 10s
      timeout: 5s
      retries: 5

  langfuse:
    image: langfuse/langfuse:3
    container_name: cognic-agentos-langfuse
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DATABASE_URL: postgresql://cognic:cognic_dev_only@postgres:5432/cognic_agentos
      NEXTAUTH_SECRET: dev-only-nextauth
      SALT: dev-only-salt
      NEXTAUTH_URL: http://localhost:${COGNIC_LANGFUSE_PORT:-3000}
      TELEMETRY_ENABLED: "false"
    ports:
      - "${COGNIC_LANGFUSE_PORT:-3000}:3000"
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:3000/api/public/health"]
      interval: 10s
      timeout: 5s
      retries: 10

  temporal:
    image: temporalio/auto-setup:1.27
    container_name: cognic-agentos-temporal
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DB: postgres12
      DB_PORT: "5432"
      POSTGRES_USER: cognic
      POSTGRES_PWD: cognic_dev_only
      POSTGRES_SEEDS: postgres
    ports:
      - "${COGNIC_TEMPORAL_PORT:-7233}:7233"
    healthcheck:
      test: ["CMD", "tctl", "--ad", "127.0.0.1:7233", "cluster", "health"]
      interval: 10s
      timeout: 5s
      retries: 12

volumes:
  postgres-data:
  qdrant-data:
```

- [ ] **Step 13.2: Local smoke**

```bash
docker compose -f infra/dev/docker-compose.yml config --quiet
```

Expected: no output (compose file parses cleanly).

```bash
docker compose -f infra/dev/docker-compose.yml up -d
docker compose -f infra/dev/docker-compose.yml ps
```

Expected: all 7 services Up. After ~20-30s `curl http://localhost:6333/readyz` returns 200, `curl http://localhost:8200/v1/sys/health` returns 200, etc.

If any service fails to come up: stop, debug, fix the compose entry, re-run. Don't `down -v` casually — the local user may have cached state from a different repo.

```bash
docker compose -f infra/dev/docker-compose.yml down
```

- [ ] **Step 13.3: Commit**

```bash
git add infra/dev/docker-compose.yml
git commit -m "feat(sprint-1c): docker-compose extends to 7 services (postgres+qdrant+redis+vault+litellm+langfuse+temporal)"
```

---

### Task 14: LiteLLM tier config

**Files:**
- Create: `infra/litellm/config.yaml`

- [ ] **Step 14.1: Create the file**

```yaml
# Cognic AgentOS — LiteLLM router presets (Sprint 1C).
#
# Production banks set COGNIC_TIER1_MODEL / COGNIC_TIER2_MODEL to one of
# the alias names below. Per ADR-009 §"LLM serving" the alias resolves
# through LiteLLM to the bank's actual inference endpoint. AgentOS code
# never references upstream model checkpoints directly — only aliases.

model_list:
  # --- Dev: Ollama local --------------------------------------------------
  - model_name: cognic-tier1-dev
    litellm_params:
      model: ollama/qwen3:8b
      api_base: ${OLLAMA_BASE_URL:-http://ollama:11434}

  - model_name: cognic-tier2-dev
    litellm_params:
      model: ollama/qwen3:32b
      api_base: ${OLLAMA_BASE_URL:-http://ollama:11434}

  # --- Production: vLLM (Sprint 1D wires the OpenAI-compat adapter) -------
  - model_name: cognic-tier1-vllm
    litellm_params:
      model: openai/${COGNIC_TIER1_VLLM_MODEL}
      api_base: ${VLLM_BASE_URL}
      api_key: ${VLLM_API_KEY}

  - model_name: cognic-tier2-vllm
    litellm_params:
      model: openai/${COGNIC_TIER2_VLLM_MODEL}
      api_base: ${VLLM_BASE_URL}
      api_key: ${VLLM_API_KEY}

  # --- Production: SGLang -------------------------------------------------
  - model_name: cognic-tier1-sglang
    litellm_params:
      model: openai/${COGNIC_TIER1_SGLANG_MODEL}
      api_base: ${SGLANG_BASE_URL}
      api_key: ${SGLANG_API_KEY}

  - model_name: cognic-tier2-sglang
    litellm_params:
      model: openai/${COGNIC_TIER2_SGLANG_MODEL}
      api_base: ${SGLANG_BASE_URL}
      api_key: ${SGLANG_API_KEY}

litellm_settings:
  drop_params: true
  set_verbose: false

general_settings:
  master_key: ${LITELLM_MASTER_KEY}
```

- [ ] **Step 14.2: Commit**

```bash
git add infra/litellm/config.yaml
git commit -m "feat(sprint-1c): LiteLLM tier-aliased model routing presets"
```

---

### Task 15: Dockerfile split + image-size-budget for default-adapters

Per BUILD_PLAN cross-cutting commitment: kernel ≤120 MiB, default-adapters ≤180 MiB, both gated in CI.

**Files:**
- Modify: `infra/agentos/Dockerfile`
- Modify: `.github/workflows/python.yml`

- [ ] **Step 15.1: Extend `Dockerfile` with a `default-adapters` build target**

The existing `runtime` stage stays as-is for the kernel image. Add a NEW final stage `default-adapters` that adds the adapter dep set on top.

The simplest split: pass a build-arg `INSTALL_ADAPTERS=0|1` to the `builder` stage so `uv sync` includes the adapter deps when set, and rename the runtime stage:

Append to `infra/agentos/Dockerfile` (after the existing `runtime` stage):

```dockerfile

# ---------- default-adapters --------------------------------------------------
# This image extends the kernel with the Sprint 1C bundled adapter Python
# packages (sqlalchemy[asyncio]/asyncpg/pgvector/qdrant-client/redis/hvac/
# cryptography/langfuse). Deployed when the bank's tenant uses the bundled
# default driver set; banks running plugin-pack adapters use the kernel image
# and install adapters via pip into a sidecar volume per Sprint 4.

FROM python:${PYTHON_VERSION}-alpine AS default-adapters-builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /build
RUN apk add --no-cache ca-certificates curl build-base
ADD https://astral.sh/uv/0.5.29/install.sh /uv-install.sh
RUN sh /uv-install.sh && rm /uv-install.sh
ENV PATH="/root/.local/bin:${PATH}"
COPY pyproject.toml uv.lock README.md ./
COPY src ./src

# --no-dev keeps test deps (pytest, ruff, etc.) out of the runtime image.
# --extra adapters explicitly opts INTO the [project.optional-dependencies]
# adapters group so asyncpg/qdrant-client/hvac/langfuse etc. land in the
# venv. Without this flag the default-adapters image would be byte-identical
# to the kernel image and break the runtime contract for default drivers.
RUN uv sync --frozen --no-dev --no-editable --extra adapters \
 && find /opt/venv -depth \( -type d -name __pycache__ -o -type d -name tests -o -type d -name test \) -exec rm -rf {} + \
 && find /opt/venv -name "*.dist-info" -exec sh -c 'rm -rf "$1"/RECORD "$1"/WHEEL "$1"/METADATA.bak' _ {} \;

FROM python:${PYTHON_VERSION}-alpine AS default-adapters

ARG BUILD_SHA=dev
ARG BUILD_TIME=unknown
ARG PACKAGE_VERSION=0.0.1

LABEL org.opencontainers.image.title="cognic-agentos-default-adapters" \
      org.opencontainers.image.description="Cognic AgentOS kernel + bundled default adapters (Postgres/Qdrant/Vault/Ollama/Langfuse-OTel)" \
      org.opencontainers.image.vendor="Cognic" \
      org.opencontainers.image.source="https://github.com/bmzee/cognic-agentos" \
      org.opencontainers.image.version="${PACKAGE_VERSION}" \
      org.opencontainers.image.revision="${BUILD_SHA}" \
      org.opencontainers.image.created="${BUILD_TIME}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    COGNIC_HOST=0.0.0.0 \
    COGNIC_PORT=8000 \
    COGNIC_API_PREFIX=/api/v1 \
    COGNIC_RUNTIME_PROFILE=prod \
    COGNIC_BUILD_SHA="${BUILD_SHA}" \
    COGNIC_BUILD_TIME="${BUILD_TIME}"

RUN addgroup -S -g 10001 cognic \
 && adduser -S -u 10001 -G cognic -h /home/cognic -s /sbin/nologin cognic

COPY --from=default-adapters-builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=root:cognic src ./src
COPY --chown=root:cognic pyproject.toml README.md ./

USER cognic
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,os,sys; \
url='http://127.0.0.1:'+os.environ.get('COGNIC_PORT','8000')+os.environ.get('COGNIC_API_PREFIX','/api/v1')+'/healthz'; \
sys.exit(0 if urllib.request.urlopen(url, timeout=3).status==200 else 1)"

CMD ["sh", "-c", "exec uvicorn cognic_agentos.portal.api.app:create_app --factory --host \"$COGNIC_HOST\" --port \"$COGNIC_PORT\""]
```

**Note on the dep boundary (no churn — already in place from Task 1):** adapter Python packages live in `[project.optional-dependencies] adapters`, NOT in `[project] dependencies`. The kernel image's `uv sync --frozen --no-dev --no-editable` therefore picks up only the Sprint 1A/1B server + observability deps and stays well under 120 MiB. The default-adapters builder explicitly adds `--extra adapters` (see `default-adapters-builder` stage above) to pull the persistence/secret/observability packages into its venv.

No `pyproject.toml` edit is required at this step — the dependency packaging shape was set correctly in Task 1.3.

- [ ] **Step 15.2: Re-lock + verify dev install still gets adapter deps**

```bash
uv lock
uv sync --all-extras
uv run pytest -v
```

Expected: green (the `dev` extras OR `--all-extras` still pulls adapter deps for tests).

- [ ] **Step 15.3: Local Docker build of both targets**

```bash
docker build -f infra/agentos/Dockerfile --target runtime -t cognic-agentos:kernel-test .
docker build -f infra/agentos/Dockerfile --target default-adapters -t cognic-agentos:adapters-test .
docker image inspect cognic-agentos:kernel-test --format='{{.Size}}' | awk '{ printf "kernel: %d MiB\n", $1 / 1024 / 1024 }'
docker image inspect cognic-agentos:adapters-test --format='{{.Size}}' | awk '{ printf "adapters: %d MiB\n", $1 / 1024 / 1024 }'
```

Expected: `kernel ≤120 MiB`, `adapters ≤180 MiB`.

If kernel exceeds 120: investigate which dep leaked in (probably a transitive dep accidentally included). Fix in pyproject before continuing.
If adapters exceeds 180: investigate; the most likely culprit is grpc/protobuf wheels brought in by qdrant-client. Adapt the budget or trim deps as needed.

- [ ] **Step 15.4: Extend the CI image-size-budget job**

Replace the `image-size-budget` job in `.github/workflows/python.yml` with two-target form:

```yaml
  image-size-budget:
    # Sprint 1C: image is split. Kernel ≤120 MiB; default-adapters ≤180 MiB.
    name: image size budget (kernel ≤120 / default-adapters ≤180 MiB)
    runs-on: ubuntu-latest
    timeout-minutes: 15

    steps:
      - name: Checkout
        uses: actions/checkout@v6

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v4

      - name: Build kernel image
        run: |
          docker build \
            -f infra/agentos/Dockerfile \
            --target runtime \
            --build-arg BUILD_SHA=${{ github.sha }} \
            --build-arg PACKAGE_VERSION=ci \
            -t cognic-agentos:kernel-ci \
            .

      - name: Enforce kernel image budget (≤120 MiB)
        run: |
          set -euo pipefail
          BUDGET_MIB=120
          size_bytes=$(docker image inspect cognic-agentos:kernel-ci --format='{{.Size}}')
          size_mib=$(( size_bytes / 1024 / 1024 ))
          echo "Kernel image: ${size_mib} MiB (budget ${BUDGET_MIB} MiB)"
          if [ "${size_mib}" -gt "${BUDGET_MIB}" ]; then
            echo "::error::Kernel image ${size_mib} MiB exceeds ${BUDGET_MIB} MiB"
            exit 1
          fi
          echo "::notice::Kernel image ${size_mib} MiB OK"

      - name: Build default-adapters image
        run: |
          docker build \
            -f infra/agentos/Dockerfile \
            --target default-adapters \
            --build-arg BUILD_SHA=${{ github.sha }} \
            --build-arg PACKAGE_VERSION=ci \
            -t cognic-agentos:adapters-ci \
            .

      - name: Enforce default-adapters image budget (≤180 MiB)
        run: |
          set -euo pipefail
          BUDGET_MIB=180
          size_bytes=$(docker image inspect cognic-agentos:adapters-ci --format='{{.Size}}')
          size_mib=$(( size_bytes / 1024 / 1024 ))
          echo "default-adapters image: ${size_mib} MiB (budget ${BUDGET_MIB} MiB)"
          if [ "${size_mib}" -gt "${BUDGET_MIB}" ]; then
            echo "::error::default-adapters image ${size_mib} MiB exceeds ${BUDGET_MIB} MiB"
            exit 1
          fi
          echo "::notice::default-adapters image ${size_mib} MiB OK"
```

- [ ] **Step 15.5: Commit**

```bash
git add pyproject.toml uv.lock infra/agentos/Dockerfile .github/workflows/python.yml
git commit -m "build(sprint-1c): split kernel + default-adapters images; budgets 120/180 MiB"
```

---

### Task 16: READY FOR GATE — final sweep + sprint summary

**Files:**
- Verify the suite end-to-end
- Compose stack smoke
- Inspect commits

- [ ] **Step 16.1: Full local CI sweep**

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
uv run pytest -v --cov=cognic_agentos --cov-report=term-missing
```

Expected: all green; coverage ≥80% global; new adapter modules ≥80%.

- [ ] **Step 16.2: Compose smoke + /readyz exit verification**

```bash
docker compose -f infra/dev/docker-compose.yml up -d
sleep 30
docker compose -f infra/dev/docker-compose.yml ps --format json | jq -r '.[] | "\(.Name): \(.Health)"'
```

Expected: every service healthy.

In another shell, run AgentOS pointed at the compose stack:

```bash
COGNIC_DATABASE_URL='postgresql+asyncpg://cognic:cognic_dev_only@localhost:5432/cognic_agentos' \
COGNIC_QDRANT_URL='http://localhost:6333' \
COGNIC_VAULT_ADDR='http://localhost:8200' \
COGNIC_VAULT_TOKEN='dev-only-root' \
COGNIC_EMBEDDING_BASE_URL='http://localhost:11434' \
COGNIC_LANGFUSE_HOST='http://localhost:3000' \
COGNIC_LANGFUSE_PUBLIC_KEY='dev' COGNIC_LANGFUSE_SECRET_KEY='dev' \
uv run uvicorn cognic_agentos.portal.api.app:create_app --factory --port 8000 &

sleep 3
curl -s http://localhost:8000/api/v1/readyz | jq .
```

Expected: 200 + per-adapter `status=ok` (Postgres / Qdrant / Vault all reachable).

If Ollama is not running locally: `embedding` reports unreachable → /readyz returns 503. That is the correct behaviour. To verify the negative-path Langfuse exit criterion: stop Langfuse (`docker compose stop langfuse`) and re-curl: `obs.status` flips to `unreachable` and /readyz returns 503 (per BUILD_PLAN Sprint 1C exit). Restart Langfuse → `obs.status` returns to `ok` and /readyz flips back to 200.

Stop AgentOS (`fg`, then `Ctrl-C`). Stop the compose stack:

```bash
docker compose -f infra/dev/docker-compose.yml down
```

- [ ] **Step 16.3: Inspect the sprint commit log**

```bash
git log --oneline main..HEAD
```

Expected: 14-15 conventional commits, one per task. No "WIP" or "fixup" commits.

- [ ] **Step 16.4: Summarise the sprint state for hand-off**

Hand the user a concise status:

- branch `feat/sprint-1c-adapter-protocols`
- N commits, all CI gates locally green
- Suite size grew from 63 → ~95 (≈18 new tests per BUILD_PLAN exit + ~14 protocol/factory/readyz/conftest assertions)
- Both Docker images measured locally; sizes vs budgets
- Compose stack: all 7 services healthy
- Negative-path verifications: AdapterNotInstalled on `mssql`; Langfuse-down → /readyz 503 with `obs.status: unreachable`; Postgres-down → /readyz 503

Do NOT push, merge, or open a PR. Per the per-action authorization rule and AGENTS.md sprint discipline, the user holds those decisions explicitly.

---

## Self-Review

**Spec coverage check:** Every BUILD_PLAN.md:105-153 deliverable maps to a task:
- pyproject `adapters` extras + dev test deps → Task 1
- core/config.py adapter settings → Task 2
- db/__init__.py + db/adapters/__init__.py → Task 3
- db/adapters/protocols.py (six ADR-009 protocols; ObjectStore declared-only; MemoryAdapter explicitly deferred to Sprint 11.5) → Task 3
- db/adapters/postgres_adapter.py → Task 6
- db/adapters/qdrant_adapter.py → Task 7
- db/adapters/vault_adapter.py (hvac, per ADR-009) → Task 8
- db/adapters/ollama_embedding_adapter.py → Task 9
- db/adapters/langfuse_otel_adapter.py (`unreachable` on host outage so /readyz collapses to 503 per BUILD_PLAN exit) → Task 10
- tests/support/adapter_fixtures.py (test fixtures only — relocated out of src/ per AGENTS.md) → Task 4
- db/adapters/factory.py → Task 5
- db/adapters/registry.py → Task 5
- infra/dev/docker-compose.yml extension (7 services, with image-version verification + profile-gating fallback) → Task 13
- infra/litellm/config.yaml → Task 14
- portal/api/app.py extension → Task 12
- All 8 specified test files → Tasks 3, 4, 5, 6, 7, 8, 9, 10
- BUILD_PLAN cross-cutting "image-budget split from day 1" → packaging set up in Task 1; image build + CI gate in Task 15

Every BUILD_PLAN exit criterion has a verification step in Task 16.

**Placeholder scan:** no TBD / TODO / "fill in details" / "similar to" placeholders. Every code-changing step shows the code in full.

**Type consistency:** `Adapters` dataclass field names (`relational/vector/secret/embedding/observability/object_store`) are consistent across factory, lifespan, and `/readyz` route. `AdapterHealth` fields (`status/driver/detail/latency_ms`) are consistent across all five real adapters. `VectorItem`/`VectorHit` types used by both protocols and the in-memory + Qdrant impls. No MemoryAdapter slot in this sprint — Sprint 11.5 introduces both the protocol AND the slot together.

**Patch log (post-review 2026-04-27):**

Round 1 (six doctrine conflicts):
- A: Replaced hard-coded commit-hash guard with property-level preflight (clean tree + branch name + ancestry probe)
- B: Langfuse-OTel `health_check` returns `unreachable` (not `degraded`) on host outage per BUILD_PLAN Sprint 1C exit
- C: Adapter packages live in `[project.optional-dependencies] adapters` from Task 1 onward — no Task-15 dep movement, no lockfile churn
- D: Vault adapter uses hvac wrapped via `asyncio.to_thread` (per ADR-009 + BUILD_PLAN); tests mock `hvac.Client` via `unittest.mock.patch`, not respx
- E: `MemoryAdapter` removed from Sprint 1C entirely — protocol class, `MemoryRecordId`, registry kind entry, `Adapters.memory` slot, and conformance test all deferred to Sprint 11.5 / ADR-019 (registry remains extensible — no structural migration needed)
- F: Task 13 flags Langfuse v3 / Temporal auto-setup / LiteLLM config as integration-risk; verify image versions before apply; profile-gate non-readiness-critical services if the default-profile up fails twice

Round 2 (eight implementation traps):
- 1: Step 1.0 added — commit the plan to `main` as `chore(plan)` BEFORE the preflight clean-tree check, so the untracked plan file does not break Step 1.1
- 2: `default-adapters-builder` Dockerfile stage now runs `uv sync --frozen --no-dev --no-editable --extra adapters` (was missing `--extra adapters`); stale comment at the install line replaced
- 3: `db/adapters/__init__.py` adds `load_bundled_adapters()` — explicit loader the lifespan invokes at startup so `bundled_registry` is populated when `build_adapters()` runs (was empty in production runtime path)
- 4: `load_bundled_adapters()` catches per-module `ImportError` so the kernel image (no `--extra adapters`) safely calls it without crashing; configured-but-missing drivers still surface via `AdapterNotInstalled`. Test added: `test_load_bundled_adapters_kernel_resilience`
- 5: In-memory test adapters relocated from `src/cognic_agentos/db/adapters/memory_adapters.py` to `tests/support/adapter_fixtures.py` per AGENTS.md "test-only fixtures … in clearly separated test paths" rule. Production source path no longer ships them. All test imports updated.
- 6: `PostgresAdapter.run_migrations()` now raises `NotImplementedError` citing Sprint 2 + ADR-009 §"Migration policy" (was a silent no-op — violated CLAUDE.md production-grade rule)
- 7: `QdrantAdapter.search()` and `InMemoryVectorAdapter.search()` raise `NotImplementedError` on non-None `filter` (was silently dropping the argument). Filter translation deferred to Sprint 11.5 + ADR-017 governance work. Negative-path test added.
- 8: `LangfuseOtelAdapter` module docstring + plan-header Tech-Stack line narrowed to honest Sprint 1C scope (OTel-bridged sink + HTTP health probe). Full Langfuse SDK trace lifecycle deferred to Sprint 2/3 alongside `core/decision_history` + LLM gateway.

Round 3 (five lint / hygiene / safety hardening fixes):
- a: Three stale `from cognic_agentos.db.adapters.memory_adapters import …` import sites (test_adapter_factory.py, test_readyz.py memory_app fixture, conftest.py) updated to `from tests.support.adapter_fixtures import …`. Round-2 fixture relocation is now consistent across all consumers.
- b: Task 4 step heading + module docstring updated — "Create `memory_adapters.py`" → "Create `tests/support/__init__.py` (empty) and `tests/support/adapter_fixtures.py`". Production-grade-rule paragraph in Context updated to reference the test path.
- c: Removed unused `import pytest` from test_postgres_adapter, test_ollama_embedding_adapter, test_langfuse_otel_adapter snippets (no `pytest.*` usage in those blocks → ruff F401). Removed unused `from unittest.mock import patch` from test_adapter_factory.py snippet (the new kernel-resilience tests use the built-in `monkeypatch` fixture, not unittest.mock).
- d: `load_bundled_adapters()` narrowed `ImportError` handling: introduced `_BUNDLED_ADAPTER_OPTIONAL_DEPS` map of `{module → allowlisted top-level packages}`, inspect `ImportError.name` (PEP 451) to decide skip-or-reraise. Allowlisted misses skip silently with a log; anything else (typos in adapter modules, broken transitive deps, missing internal symbols) re-raises so real bugs surface. Empty allowlist for the Ollama adapter (httpx is always present) means any ImportError from that module is a bug.
- e: Added `test_load_bundled_adapters_reraises_unexpected_import_error` to verify the narrowed handling propagates non-allowlisted ImportError. Updated existing `test_load_bundled_adapters_kernel_resilience` to use `ModuleNotFoundError(..., name=...)` so the loader's `.name` introspection matches the simulated path.

Round 4 (three precision fixes):
- i: Operating-mode header rewritten — Sprint 1C as a whole stays autonomous low-risk, BUT Task 2 (`core/config.py`) now carries an explicit stop-for-review gate (Step 2.7) per AGENTS.md "Stop for human review when touching: Anything in `core/`". Executor commits T2 then halts for `yes`/`go` before starting T3.
- ii: Production-grade-rule line corrected — Langfuse runtime path described as "OpenTelemetry + Langfuse HTTP health probe" (the actual Sprint 1C scope), not "langfuse SDK" (which won't be wired until Sprint 2/3 alongside core/decision_history + LLM gateway).
- iii: Removed unused `import pytest` from the `test_memory_adapters.py` snippet (no `pytest.*` references in that block; ruff F401 would have failed at execution).

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-27-sprint-1c-adapter-protocols.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using superpowers:executing-plans, batch execution with checkpoints.

Which approach?
