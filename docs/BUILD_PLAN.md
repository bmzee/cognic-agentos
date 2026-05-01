# Cognic AgentOS — Build Plan

> Sprint-level plan for the 4 phases in [`ROADMAP.md`](ROADMAP.md). Each sprint is a shippable unit. **Approve sprint-by-sprint** — I will not start Sprint N until you say go.

**Estimating unit:** one "work-unit" ≈ one focused day. Solo-engineer + Claude-Code throughput. Sprints range 2-5 work-units.

**Cadence:** approve → execute → green checkpoint → next sprint. No batching across phases.

---

## Phase 1 — Foundation (Sprints 1A-1D, 2, 3, ~12 work-units)

Sprint 1 is split into four focused sub-sprints for a clean bootstrap. Each ships a green checkpoint before the next begins.

### Production-grade principles (apply across all Phase-1 sprints)

- **No environment-specific operational values in source.** Ports, URLs, hostnames, timeouts, log levels, CORS origins, retry counts, model identifiers — all come from `core/config.py` Pydantic Settings. **Constants are fine.** Route names (`/api/v1/healthz`), protocol names (`mcp`, `a2a`), package metadata, and reasonable in-code defaults inside `Settings` class declarations are not "hardcoding." The discipline test (`test_no_env_specific_values_in_source.py`) targets operational-config drift only.
- **Adapter protocols, not concrete classes** (per ADR-009) — every external system is reached through a `Protocol` interface. Postgres / Qdrant / Vault land in Sprint 1C; Oracle / Dynatrace / OpenAI-compat embedding land in Sprint 1D; alternative adapters install as plugin packs in Phase 2+.
- **Reproducible dependency locking** — `uv.lock` committed; CI runs `uv sync` (consumes lock, does NOT resolve latest). Scheduled weekly `dep-upgrade.yml` opens a PR with `uv lock --upgrade` diff; lands only after CI is green on the new lock.
- **Probe separation** — `/healthz` is **liveness** (Sprint 1A; never depends on external systems). `/readyz` is **readiness** (Sprint 1B/1C; per-component status, returns 503 when any critical component is unreachable).
- **Structured logging from request 1** — JSON logs with `request_id` + OTel `trace_id` + `span_id` (Sprint 1B). Langfuse-side trace correlation rides the OTel pipeline (Langfuse-OTel adapter, Sprint 1C); per-event `langfuse_trace_id` joining lands with `core/audit` + the LLM gateway (Sprint 2/3).
- **Three-layer observability** — Prometheus `/metrics` (Sprint 1B), OpenTelemetry traces (Sprint 1B), Langfuse via observability adapter (Sprint 1C).
- **OpenAPI schema exposed** at `/api/v1/openapi.json` (Sprint 1B).
- **CORS allow-list-only** — no `*` wildcards.
- **Graceful shutdown** — lifespan hooks close DB pools, Temporal client, Vault leases, Langfuse client (flushes pending events) in dependency-correct order.
- **Append-only governance tables** *(Sprint 2 onward)* — the runtime DB role used by AgentOS at runtime holds `INSERT, SELECT` only on `audit_event` + `decision_history`, and `INSERT, SELECT, UPDATE` on `governance_chain_heads` (the chain-head row is the only legitimately-mutated state in the governance tier). UPDATE / DELETE on the evidence tables are NOT granted to the runtime role. This is **schema-design doctrine, not just code discipline** — `tests/integration/db/test_runtime_role_is_append_only.py` is the production-grade canary that the operator runbook for governance-table GRANTs has been applied. A separate `agentos_evidence_admin` role holds DELETE on the evidence tables for retention enforcement (Phase 3.3 evidence-pack export). Without the runbook applied, the runtime is using superuser credentials and the chain is INSERT-only by code discipline only — explicitly NOT acceptable for `COGNIC_RUNTIME_PROFILE=prod`.
- **Image-size budget** — pre-1C, the single Docker image carries server + observability only and ships under a **120 MiB** ceiling, enforced by a CI job (`image-size-budget`) that fails the build if the kernel image grows past it. When Sprint 1C lands its adapter dependencies, the image is split into:
  - `cognic-agentos-kernel` — server + observability + harness only; **≤120 MiB**.
  - `cognic-agentos-default-adapters` — kernel + Postgres / Qdrant / Vault / Ollama / Langfuse-OTel reference adapters; **≤220 MiB** budget. *(Originally specified at ≤180 MiB pre-build; raised to 220 MiB during Sprint 1C T15 because measured size landed at ~198 MiB — driven by numpy ~50 MiB transitive of qdrant-client + pgvector, grpc ~18 MiB, cryptography ~13 MiB, sqlalchemy ~12 MiB, uvloop ~12 MiB. None have removable bloat. Aggressive prune saved only ~2 MiB. 220 MiB gives ~10% headroom over measured.)*
  Heavy / enterprise-only adapters (Oracle, Dynatrace, vLLM/SGLang from Sprint 1D) install as opt-in extras or build into a separate `cognic-agentos-enterprise` image variant. The kernel image keeps the bank-grade slim default; ops teams pull the variant they need.

### Sprint 1A — Bootstrap *(1.5 work-units)*

**Goal:** the repo is git-initialised, the package is importable, FastAPI boots with the absolute minimum routes, the image builds, the architecture-discipline test runs in CI.

**Deliverables:**

- `pyproject.toml` — distribution `cognic-agentos` v0.0.1; minimum-version declarations targeting April-2026 current releases (full dep list in Sprint 1B/1C as those subsystems land):
  - Web: `fastapi>=0.116`, `uvicorn[standard]>=0.35`, `httpx>=0.28` *(floor was 0.29 in the original draft; lowered to match the latest stable on PyPI at the time of Sprint 1A — 0.29 was pre-release-only. Bump back when upstream ships 0.29 stable.)*
  - Settings: `pydantic>=2.11`, `pydantic-settings>=2.8`, `pyyaml>=6.0.2`
  - Dev: `pytest>=8.4`, `pytest-asyncio>=1.0`, `pytest-cov>=6.1`, `ruff>=0.9`, `mypy>=1.14`, `types-PyYAML`
- `uv.lock` — committed; CI uses `uv sync` (consumes lock; does NOT resolve latest)
- `.python-version` — pinned to current Python 3.12.x
- `src/cognic_agentos/__init__.py` — `__version__` from package metadata
- `src/cognic_agentos/core/__init__.py`, `core/config.py` — minimal Pydantic Settings (server fields only: `port`, `host`, `api_prefix`, `runtime_profile`, `log_level`, build metadata). Other settings groups added in 1B/1C.
- `src/cognic_agentos/portal/api/app.py` — `create_app()` factory; **two routes only**:
  - `GET {api_prefix}/healthz` — **liveness probe** (per Kubernetes convention). Returns `{"alive": true, "version": "..."}` if the process is responsive. Does NOT check dependencies. Always 200 unless the app itself is hanging.
  - `GET {api_prefix}/version` — build metadata (sha, time, version, runtime profile, python version)
- `infra/agentos/Dockerfile` — multi-stage Python builder → slim runtime; multi-arch labels; non-root user; HEALTHCHECK on `/healthz`
- `infra/dev/docker-compose.yml` — **placeholder** with one service (Postgres only) so the compose file exists for 1C to extend. Other services added in 1C/1D.
- `.env.example` — initial Sprint-1A settings (server + profile only)
- `.gitignore`, `.dockerignore`
- `.github/workflows/python.yml` — `ci` job: uv sync → ruff lint → ruff format-check → pytest
- `tests/__init__.py`, `tests/unit/__init__.py`, `tests/unit/architecture/__init__.py`
- `tests/unit/architecture/test_no_pack_imports.py` — discipline gate per ADR-001/002 (compile-time check; no pack-namespace imports in OS source)
- `tests/unit/test_healthz.py` — TestClient hits `/healthz`; asserts shape
- `tests/unit/test_version.py` — asserts `/version` shape

**Exit criteria:**
- `uv sync` reproduces the locked dependency set (no resolution drift)
- `uv run uvicorn cognic_agentos.portal.api.app:create_app --factory --port 8000` boots in ≤2s
- `curl /api/v1/healthz` returns `{"alive": true, "version": "..."}`
- `curl /api/v1/version` returns build metadata
- `uv run pytest -v` is green (3 tests: architecture-discipline + healthz + version)
- `uv run ruff check .` and `uv run ruff format --check .` clean
- `docker build -f infra/agentos/Dockerfile .` succeeds in ≤90s; image ≤120 MB (smaller without observability/adapter deps)
- `git init` on `main`; doctrine baseline + Sprint 1A scaffold commits land; Sprint 1A merges into `main` via a feature branch (one merge bubble per sprint). Exact commit count is not pinned — the original "one commit" wording was a pre-baseline simplification.
- Sanity check: deliberately add `from cognic_agent_test import X` → architecture test fails; revert.

### Sprint 1B — Observability stack *(1.5 work-units)*

**Goal:** the production-grade observability stack — structured logging, request IDs, OpenTelemetry, Prometheus metrics, OpenAPI export, `/readyz` endpoint. Still no external dependencies (those land in 1C).

**Deliverables:**

- `pyproject.toml` extension — observability deps:
  - OpenTelemetry: `opentelemetry-api>=1.28`, `opentelemetry-sdk>=1.28`, `opentelemetry-instrumentation-fastapi>=0.49`, `opentelemetry-exporter-otlp>=1.28`
  - Prometheus: `prometheus-client>=0.25`, `prometheus-fastapi-instrumentator>=7.1` *(prometheus-client floor was 0.26 in the original draft; lowered to match latest stable on PyPI at Sprint 1B time — 0.26 was not yet released. Bump back when upstream ships 0.26 stable.)*
  - Logging: `python-json-logger>=3.2`
- `core/config.py` extension — observability settings group: `log_format` (json/text), `otel_exporter_endpoint`, `prometheus_metrics_path`, `cors_allowed_origins` (list, no `*`)
- `src/cognic_agentos/observability/__init__.py`, `observability/logging.py` — JSON logger setup; `request_id` + OTel `trace_id` bound to log context
- `observability/middleware.py` — request-id middleware (UUID gen + `X-Request-Id` echo); OpenTelemetry FastAPI instrumentor; CORS middleware (allow-list-only, refuses `*`)
- `observability/otel.py` — OTel tracer setup; OTLP exporter when endpoint set, console exporter in dev when unset
- `portal/api/app.py` extension —
  - mounts the three middlewares
  - mounts Prometheus instrumentator → `{api_prefix}/metrics`
  - adds `GET {api_prefix}/openapi.json` (auto-generated)
  - adds `GET {api_prefix}/readyz` — **readiness probe** (per Kubernetes convention). Returns 200 + per-component status if all critical components are ready; 503 otherwise. **Sprint 1B reports only on internal readiness** (process started, middleware mounted); external dependency probes are added in 1C as adapters land.
- `tests/unit/test_request_id.py` — middleware echoes `X-Request-Id`; generates UUID if absent
- `tests/unit/test_logging.py` — JSON log line includes `request_id` + `trace_id` fields
- `tests/unit/test_otel.py` — tracer exports to OTLP when set; console fallback in dev
- `tests/unit/test_metrics.py` — `/metrics` returns Prometheus-format with `http_requests_total`
- `tests/unit/test_openapi.py` — `/openapi.json` valid OpenAPI 3 spec
- `tests/unit/test_readyz.py` — `/readyz` returns shape `{"ready": bool, "components": {...}}`; 503 when a component is not ready
- `tests/unit/test_config.py` — settings load without `.env`; env-var override; CORS rejects `*`
- `tests/unit/architecture/test_no_env_specific_values_in_source.py` — refined discipline gate (per principles section above): targets ports/URLs/hosts/timeouts in non-config source; allows constants, route names, protocol names, defaults inside `Settings`

**Exit criteria:**
- All Sprint 1A tests still green; new tests bring suite to ~10
- `/readyz` returns `{"ready": true, "components": {...}}`
- `/metrics` scrapeable
- `/openapi.json` validates against OpenAPI 3 schema
- JSON log line during a request shows `request_id` + `trace_id` populated
- `test_no_env_specific_values_in_source.py` flags a deliberately-introduced `port = 8000` in `app.py`; allows `API_PREFIX = "/api/v1"` constant in `config.py`

### Sprint 1C — Adapter protocols + reference (default) adapters *(2 work-units)*

**Goal:** establish the adapter protocol layer (per ADR-009) and ship the three default-bundled reference adapters: Postgres, Qdrant, Vault. `/readyz` now probes adapter health.

**Deliverables:**

- `pyproject.toml` extension — persistence + secrets + embedding deps:
  - Persistence: `sqlalchemy[asyncio]>=2.1`, `alembic>=1.16`, `asyncpg>=0.31`, `pgvector>=0.4`, `qdrant-client>=1.18`, `redis>=5.3`
  - Secrets: `hvac>=2.4`, `cryptography>=45`
- `core/config.py` extension — adapter-settings groups:
  - `db_driver` (default `postgres`), `database_url`
  - `vector_driver` (default `qdrant`), `qdrant_url`, `qdrant_collection`
  - `secret_driver` (default `vault`), `vault_addr`, `vault_token`, `vault_namespace`
  - `embed_driver` (default `ollama`), `embedding_model`, `embedding_base_url`, `embedding_dimensions`
  - `obs_driver` (default `langfuse_otel`), `langfuse_host`, `langfuse_public_key`, `langfuse_secret_key`
- `src/cognic_agentos/db/__init__.py`, `db/adapters/__init__.py`
- `db/adapters/protocols.py` — six `Protocol` (PEP 544) interfaces:
  - `RelationalAdapter` — `connect`, `session`, `run_migrations(dir)`, `close`, `health_check`
  - `VectorAdapter` — `ensure_collection`, `upsert`, `search`, `delete`, `health_check`
  - `SecretAdapter` — `read`, `write`, `lease(path, ttl_s)`, `revoke`, `health_check`
  - `EmbeddingAdapter` — `embed(texts)`, `dimensions`, `health_check`
  - `ObjectStoreAdapter` — protocol declared; impl in Sprint 8
  - `ObservabilityAdapter` — `emit_trace`, `emit_metric`, `flush`, `health_check`
- `db/adapters/postgres_adapter.py` — `RelationalAdapter` via SQLAlchemy + asyncpg
- `db/adapters/qdrant_adapter.py` — `VectorAdapter` via qdrant-client
- `db/adapters/vault_adapter.py` — `SecretAdapter` via hvac
- `db/adapters/ollama_embedding_adapter.py` — `EmbeddingAdapter` over Ollama HTTP (dev only — production uses Sprint 1D's OpenAI-compat adapter)
- `db/adapters/langfuse_otel_adapter.py` — `ObservabilityAdapter` (Langfuse + OTel). HTTP shape compatible with both Langfuse v2 and v3. Sprint 1C dev compose pins `langfuse/langfuse:2` (single-container); v3 needs Clickhouse + Redis + S3 + worker, deferred to a future overlay.
- `db/adapters/memory_adapters.py` — in-memory implementations for tests (Postgres+SQLite-fallback for relational; in-memory dict for others)
- `db/adapters/factory.py` — `build_adapters(settings) -> Adapters` reads drivers, looks up bundled adapter; fails fast on unknown
- `db/adapters/registry.py` — `AdapterRegistry`; bundled auto-register; plugin-pack registration wired in Sprint 4
- `infra/dev/docker-compose.yml` extension — adds Postgres, Qdrant, Redis, Vault, LiteLLM, Langfuse, Temporal (now 7 services). Port mappings env-driven via `${VAR:-default}` syntax.
- `infra/litellm/config.yaml` — tier-aliased model routing; Ollama for dev; vLLM/SGLang/cloud aliases declared (env-var-driven)
- `portal/api/app.py` extension — `/readyz` now invokes `adapter.health_check()` on each registered adapter; reports per-driver status `{relational: {driver: postgres, status: ok}, vector: {driver: qdrant, status: ok}, secret: {driver: vault, status: ok}, embedding: {driver: ollama, status: ok}, observability: {driver: langfuse_otel, status: ok}}`. Component keys mirror the `Adapters` dataclass field names + `AdapterKind` literal so operators see a consistent kind→driver mapping. Lifespan opens adapters at startup, closes at shutdown.
- `tests/unit/db/__init__.py`
- `tests/unit/db/test_adapter_protocols.py`
- `tests/unit/db/test_adapter_factory.py`
- `tests/unit/db/test_memory_adapters.py`
- `tests/unit/db/test_postgres_adapter.py` — health_check + lifecycle
- `tests/unit/db/test_qdrant_adapter.py` — ensure_collection + upsert/search round-trip
- `tests/unit/db/test_vault_adapter.py` — read/write/lease/revoke
- `tests/unit/db/test_langfuse_otel_adapter.py` — graceful degrade when host unreachable

**Exit criteria:**
- `docker compose -f infra/dev/docker-compose.yml up -d` brings up 7 services, all healthy in ≤30s
- `/readyz` returns 200 + per-adapter status when all reachable
- Stop the Langfuse container → `/readyz` returns 503 + `observability: {driver: langfuse_otel, status: unreachable}`. Restart → `/readyz` flips back to 200.
- Setting `COGNIC_DB_DRIVER=mssql` → startup fails fast with `AdapterNotInstalled` (no silent fallback)
- `uv run pytest -v` green (~18 tests total at this point)

### Sprint 1D — Enterprise adapters (Oracle + Dynatrace + OpenAI-compat embedding) *(2 work-units)*

**Goal:** banks running on enterprise stacks (Oracle for RDBMS, Dynatrace for observability, vLLM/SGLang for production embedding) get bundled support, not plugin-pack-only.

**Deliverables:**

- `pyproject.toml` extension — `oracledb>=2.5`
- `core/config.py` extension:
  - **Oracle**: uses the existing `database_url` field; the SQLAlchemy `oracle+oracledb://...` URL shape covers basic XE, Oracle Cloud Autonomous DB (wallet-path embedded in URL), and TNS-aliased descriptors. Bank-deployment variants requiring Pydantic-typed connection-descriptor fields (e.g. wallet path as a separate setting) wait until a real bank deployment needs them.
  - **Dynatrace**: `dynatrace_tenant_url` + `dynatrace_api_token` + reserved `dynatrace_api_token_vault_path` (Sprint 10 wires runtime Vault resolution). OTLP trace export uses the existing Sprint 1B `OTEL_EXPORTER_OTLP_ENDPOINT` plumbing (operator points it at the Dynatrace OTLP ingest URL); no new OTLP-specific Sprint-1D setting.
  - **OpenAI-compat embedding**: `embedding_api_key` (the resolved key), `embedding_api_key_header` (default `Authorization`; `api-key` for Azure OpenAI proxies), reserved `embedding_api_key_vault_path` (Sprint 10), `embedding_extra_headers` (dict — for Azure `api-version` etc.), `embed_provider_label` (one of: vllm/sglang/openai/azure_oai/bedrock/cohere/openai_compat — for audit clarity).
- `db/adapters/oracle_adapter.py` — `RelationalAdapter` via SQLAlchemy + python-oracledb async; migration directory `db/migrations/oracle/`
- `db/adapters/dynatrace_adapter.py` — `ObservabilityAdapter` for Dynatrace tenants. Two paths: (a) OTLP export to Dynatrace ingest endpoint with API token from Vault, (b) Dynatrace Metric Ingest API for native custom-metric publishing.
- `db/adapters/openai_compat_embedding_adapter.py` — `EmbeddingAdapter` against any OpenAI-compatible `/v1/embeddings` endpoint. Sends optional `Authorization: Bearer <key>` (default) or `<custom-header>: <key>` (e.g. Azure `api-key`) plus operator-supplied extra headers. Stores `provider_label` as an adapter property; per-embed audit-event emission of the label lands with Sprint 2 `core/audit` wiring (Sprint 1D ships the storage + plumbing only). Covers vLLM, SGLang, OpenAI, Cohere (OpenAI shape), and Azure-OpenAI / Bedrock when fronted by an OpenAI-compat proxy. Direct Azure-OpenAI URL shape (`/openai/deployments/<name>/embeddings?api-version=...`) requires a separate Azure-specific adapter (deferred — Sprint 1D supports Azure via OpenAI-compat-proxy only).
- `infra/litellm/config.yaml` extension — Phase 2 production aliases: `cognic-tier1-vllm` (`VLLM_BASE_URL`), `cognic-tier1-sglang` (`SGLANG_BASE_URL`), plus tier-2 equivalents
- `infra/dev/docker-compose.oracle.yml` — opt-in compose overlay (Oracle XE 21c, ~3 GB image, ~2 GB RAM). Activated via `docker compose -f docker-compose.yml -f docker-compose.oracle.yml up -d`. Most devs run Postgres locally; Oracle compose only when testing the Oracle adapter.
- `infra/dev/docker-compose.vllm.yml` — opt-in compose overlay for a single-GPU vLLM node (CI runs without; only GPU machines activate)
- `docs/INFERENCE-BACKENDS.md` — operator guide: when to pick Ollama vs vLLM vs SGLang vs cloud; deployment topology examples
- `tests/unit/db/test_oracle_adapter.py` — protocol conformance via mock + integration test against Oracle XE marked `@pytest.mark.oracle` (CI matrix has an "oracle" job that brings up the overlay)
- `tests/unit/db/test_dynatrace_adapter.py` — OTLP path uses configured ingest endpoint + API token; metric ingest API emits Dynatrace-shape metric lines
- `tests/unit/db/test_openai_compat_embedding_adapter.py` — vLLM-shape and SGLang-shape mock servers; `provider_label` is exposed as an adapter property (Sprint 1D storage-only); per-embed audit-event emission lands with Sprint 2 `core/audit` wiring

**Exit criteria:**
- `COGNIC_DB_DRIVER=oracle` + Oracle compose overlay → `/readyz` shows `relational: {driver: oracle, status: ok}`
- `COGNIC_OBS_DRIVER=dynatrace` + API token resolved by operator (env or secret-mount in Sprint 1D; native runtime Vault resolution lands in Sprint 10) → `/readyz` shows `observability: {driver: dynatrace, status: ok}`
- `COGNIC_EMBED_DRIVER=openai_compat` + `EMBED_BASE_URL` + `EMBED_PROVIDER_LABEL=vllm` → adapter embeds; `adapter.provider_label == "vllm"` (storage-only in Sprint 1D). Per-embed audit-event emission of the label lands with Sprint 2 `core/audit` wiring; the Sprint 1D contract is the storage + factory plumbing, not the audit-event side.
- `uv run pytest -v` green (CI runs unit tests for all bundled drivers — postgres / qdrant / vault / ollama / langfuse_otel / oracle / dynatrace / openai_compat — without external dependencies; the `oracle-integration` job exercises the live Oracle XE compose overlay via env-gated `@pytest.mark.skipif(not COGNIC_RUN_ORACLE_INTEGRATION)` tests; dynatrace + openai_compat live-stack verification is operator-side, not CI, since Dynatrace requires a real tenant + API token and openai_compat live verification needs either a GPU-resident vLLM or external API keys).


### Sprint 2 — Core governance primitives — chain-of-custody foundation *(2 work-units)*

**Scope split** (vs. the original BUILD_PLAN-2025 single-sprint shape, see Sprint 2.5 below): three critical-controls modules at ≥95% coverage + Postgres+Oracle migration parity could not realistically fit in 3 wu alongside three additional governance modules. The split lands the chain-of-custody foundation cleanly, then layers operational primitives on top in Sprint 2.5.

**Goal:** the kernel's tamper-evident substrate — audit, decision history with hash chain, schema vocabulary, and the Alembic baseline that retires `OracleAdapter.run_migrations` / `PostgresAdapter.run_migrations` `NotImplementedError` reservations from Phase 1.

**Deliverables:**
- `core/schemas.py` — `CognicAction`, `ComplianceVerdict`, `FieldStatus` enums + `FieldMeta` frozen dataclass
- `core/canonical.py` — `canonical_bytes(obj)` + `hash_record(canonical, prev_hash)` (single source of truth for canonical form). Round-2..4 review hardenings: NaN/Infinity dict-key bypass closed, naive datetimes rejected, tuples rejected (collide with lists in JSON), non-string Enum values rejected, non-finite Decimals rejected
- `core/audit.py` — `AuditStore.append(event)` (INSERT-only, fail-loud, hash-chained via `governance_chain_heads` lock-row). Payload normalised through canonical-form round-trip at method boundary; chain-head UPDATE is compare-and-set verified
- `core/decision_history.py` — `DecisionHistoryStore.append(record)` returning `(record_id, hash)`. Same shape as `AuditStore` plus an `actor_id` field on `DecisionRecord`: merged into the normalised payload before hashing/storage with strict equality enforcement against any pre-existing `payload['actor_id']` and `str | None` runtime type-checking on both paths (raw payload + dataclass field)
- `core/chain_verifier.py` — `ChainVerifier(engine, chain_id)` with `walk()` + `verify_record(record_id)` returning typed `TamperReport`. Five `BreakKind` values: `hash_mismatch`, `sequence_gap`, `prev_hash_mismatch`, `head_mismatch` (catches `governance_chain_heads` row tamper; walk() locks the head row with `SELECT ... FOR UPDATE` for snapshot safety against concurrent appenders), `record_not_found`. NULL passthrough on `iso_controls` + `payload` (no coercion that would mask DBA-side NULL tamper)
- `db/engine.py` — async SQLAlchemy engine + session factory
- `db/types.py` — dialect-portable governance column types: `chain_hash_column_type()` (Postgres BYTEA / Oracle RAW(32) / SQLite BLOB) + `GovernanceJSON` `TypeDecorator` (Postgres + SQLite native JSON / Oracle CLOB-with-app-side-serialisation; bridges SQLAlchemy 2.0.49's missing `oracle.JSON` type)
- Alembic baseline + initial migration `0001_initial_governance_schema.py` — `governance_chain_heads`, `audit_event`, `decision_history` (single migration set; dialect-portable via SQLAlchemy types). `audit_event` (not `audit`) avoids Oracle's reserved `AUDIT` identifier; `sequence` is application-assigned (no `Identity()` — would double-source vs the chain-head FOR UPDATE lock)
- `tools/check_critical_coverage.py` — per-file coverage gate (≥95% line + ≥90% branch on each of the four critical-controls modules); replaces a combined `--cov-fail-under=95` shape that masks an under-covered file behind a well-covered sibling
- `docs/operator-runbooks/governance-tables-grants.md` — Postgres + Oracle GRANT snippets for runtime + evidence-admin roles. Two pinned Oracle paths for the unqualified-table-resolution problem (private synonyms via `CREATE ANY SYNONYM` OR `CREATE SYNONYM` per-user, OR per-session `ALTER SESSION SET CURRENT_SCHEMA`)

**Tests:**
- `test_canonical.py` — golden-hash tests (NaN/Inf rejection; datetime / UUID / bytes round-trip; dict-key sort)
- `test_audit.py` + `test_decision_history.py` — unit-level append + chain-head update against in-memory SQLite
- `test_chain_verifier.py` — tamper detection (mutation, deletion, prev_hash corruption, sequence gap, empty chain, single record)
- `test_alembic_migrations.py` — upgrade → downgrade → upgrade round-trip on Postgres + Oracle
- `test_concurrent_append.py` — 50 concurrent appends serialise via `governance_chain_heads` `SELECT ... FOR UPDATE`; parametrised on Postgres + Oracle
- `test_runtime_role_is_append_only.py` — runtime role denied UPDATE/DELETE; positive canary drives `AuditStore.append()` through the runtime-role DSN

**Exit criteria:**
- Hash chain tamper-evident (verifier raises on mutated row, deleted row, corrupted prev_hash, AND mutated `governance_chain_heads` row)
- Append serialises correctly under concurrent load on real Postgres + Oracle (no duplicate sequences, no duplicate hashes); `walk()` snapshot-safe against concurrent appenders via the same `SELECT ... FOR UPDATE` primitive
- Critical-controls modules at ≥95% line + ≥90% branch coverage, enforced per-file (not a combined target) via `tools/check_critical_coverage.py` in the `lint + test` CI job
- Operator runbook applied: runtime role provably append-only on both Postgres + Oracle (positive canary drives `AuditStore.append()` through the runtime-role DSN, not just SELECT)
- Both `OracleAdapter.run_migrations` and `PostgresAdapter.run_migrations` real (no `NotImplementedError`); `db/migrations/env.py` honours pre-set `sqlalchemy.url` (programmatic adapter invocation) before falling back to `Settings.database_url` (CLI invocation)
- Suite grows from 264 (Phase 1 close) to ~470 (≈+200 across 11 implementation tasks); coverage stays ≥93% global
- New `postgres-integration` CI job mirrors the `oracle-integration` shape; both run live-DB tests against compose services
- No ADR changes (implements ADR-001 / ADR-006 / ADR-009 hooks)

### Sprint 2.5 — Operational governance primitives *(1 work-unit)*

**Goal:** the operational primitives that consume Sprint 2's chain-of-custody foundation. Carved out of the original Sprint 2 in the 2026-04-28 doctrine amendment so each critical-controls module gets the pair-engineering attention it needs.

**Deliverables:**
- `core/sla.py` — SLA timer primitive (deadline computation, breach detection)
- `core/escalation.py` — escalation lifecycle state machine; transitions emit hash-chained events into `decision_history`
- `core/guardrails.py` — pluggable input/output filter pipeline (PII, injection — initial filters regex-based; ML filters Wave 2)
- `core/decision_history.append_with_precondition[T]` — additive primitive on the Sprint-2 critical-controls module: async caller-supplied validator runs INSIDE the chain-head FOR UPDATE transaction; T-typed return flows into a synchronous record_builder. Closes the TOCTOU window for state-machine validators (added in plan review; load-bearing for `core/escalation.transition`).

**Tests:**
- `test_sla.py` — deadline computation + breach detection
- `test_escalation.py` — lifecycle transitions emit hash-chained events
- `test_guardrails.py` — known-PII input blocked; clean input passes
- `tests/integration/db/test_sprint_2_5_chain_integration.py` — live PG + Oracle: escalation lifecycle + chain integrity (T8); deterministic `_PausingEscalationStore`-driven race proof for FOR UPDATE serialisation (T9, reviewer-mandated); guardrail-pipeline trip + audit chain integrity + PII privacy contract end-to-end (T10).

**Exit criteria:**
- All three operational primitives integrated with Sprint 2's audit / decision_history / chain_verifier
- Suite grows by ~25 tests; coverage stays ≥93% global

**Status:** **CLOSED on `feat/sprint-2.5-operational-primitives`** (2026-04-29). Suite grew from the Sprint-2 merge baseline (468 unit + 18 integration = 486) by **+191 unit + +6 integration** (vs the projected ~25); 96% global coverage. All seven critical-controls modules (Sprint 2 quartet + Sprint 2.5 triplet) pass per-file `≥95% line / ≥90% branch`. See [closeout note](closeouts/2026-04-29-sprint-2.5-operational-primitives.md). **12 commits (T1–T12)** atop the already-merged plan-of-record PR #7 (`4733b52` on `main`); branch READY-FOR-GATE awaiting push/PR/merge authorization.

### Sprint 3 — LLM gateway + provider-honesty *(2 work-units)*

**Goal:** every LLM call goes through one chokepoint with cloud-policy enforcement; `/system/effective-routing` exposes runtime reality (per ADR-007).

**Deliverables:**
- `llm/gateway.py` — `LLMGateway.completion(*, tier, messages, request_id, tenant_id)` with tier-alias resolution, pre-call cloud-policy enforcement, post-response policy recheck, drift detection, SLA classify, INPUT/OUTPUT guardrails, narrow connect-class httpx catch, strict-vs-best-effort ledger regimes per ADR-007 §"two layers"
- `llm/policy.py` — pure-functional `enforce_cloud_policy(resolved, settings, post_response)` over `(ResolvedUpstream, Settings)`; provenance-gap fail-closed gate (Round-4 P1)
- `llm/preflight.py` — `PreflightResolver.from_yaml` (lazy `${VAR}` substitution) + api_base-aware `_is_external` classifier + `reverse_lookup` tuple disambiguation; four-state provenance vocabulary (`resolved` / `unresolved` / `ambiguous` / `no_dispatch`)
- `llm/ledger.py` — `GatewayCallLedger.write_row` + `read_recent_calls`; persisted `upstream_api_base` + `provenance` so historical rows stay authoritative
- `llm/concurrency.py` — `ProfileRateLimiter` (queued + fail-fast modes; atomic per-profile lock)
- `src/cognic_agentos/db/migrations/versions/20260430_0002_gateway_call_ledger.py` — Alembic migration creating `gateway_call_ledger` (PG/Oracle dialect-portable; `sa.TIMESTAMP(timezone=True)` matches the `GATEWAY_LEDGER_TS_TYPE` convention)
- `core/config.py` extension — Sprint-3 LLM-gateway settings (`tier1_alias`, `tier2_alias`, `litellm_base_url`, `litellm_master_key`, `allow_external_llm`, `policy_mode`, `allowed_providers`, `llm_timeout_s`, `llm_concurrency_per_profile`, `llm_concurrency_mode`, `provider_honesty_ledger_window_minutes`, `llm_guardrail_scope`)
- `portal/api/system_routes.py` — new module hosting `GET /api/v1/system/policy` (intent surface; reflects current Settings) + `GET /api/v1/system/effective-routing` (authoritative outcome surface; reads `gateway_call_ledger` over the configured window; opportunistic Langfuse probe via `langfuse_available` flag — never fails closed per ADR-007)
- `infra/litellm/config.yaml` — four cloud aliases (`cognic-tier{1,2}-cloud-{openai,anthropic}`) so the cloud-policy denial path is exercisable end-to-end; `.env.example` documents the operator-facing env vars
- `tools/check_critical_coverage.py` — extended to enforce the LLM-gateway-shape quintet (`gateway`, `policy`, `preflight`, `ledger`, `concurrency`) at the same `(0.95 line, 0.90 branch)` floor as Sprint 2 + 2.5 modules; gate now covers 12 modules

**Tests:**
- `test_gateway_alias_resolution.py` — tier→LiteLLM-alias translation; `UnknownTierError` on unknown tier
- `test_gateway_policy.py` — pure decision-tree matrix (self-hosted ALLOW; external + flag off DENY; allow-list miss DENY; mode/flag mismatch DENY; provenance gap DENY unconditionally); audit-payload shape; policy-mode-vs-provider-family gap pinned as a tripwire
- `test_preflight_resolver.py` — lazy `${VAR}` substitution; api_base-aware classification (vLLM with private api_base classifies as self-hosted); `reverse_lookup` tuple disambiguation; round-trip against the real `infra/litellm/config.yaml` including the four cloud aliases (parametrized × 4); `cloud_alias_resolves_then_denies_under_default_policy` (parametrized × 4)
- `test_gateway_ledger.py` + `test_gateway_ledger_contract.py` — write-then-read; tz-aware round-trip; `outcome="ok"` happy path; `LedgerWriteFailed` on persistence failure (strict regime); window-filter
- `test_gateway_completion.py` — happy path (tier1 → ollama; ledger row written before return); pre-dispatch denial path (cloud + flag off → no LiteLLM call + audit + best-effort ledger); cloud-allowed pass-through
- `test_gateway_guardrails.py` — INPUT trip halts before dispatch; OUTPUT trip strict-ledgers before raise; four-mode scope matrix end-to-end (off / external_only / self_hosted_only / all) including external routes, output direction, single-direction-None overrides, and asymmetric-drift cases (input gates on preflight, output on actual)
- `test_gateway_sla.py` — breach emits `audit_event(sla.breach)` + does NOT raise; green is no-op
- `test_gateway_drift.py` — drift+actual-allowed; drift+actual-denied; external→external silent-drift caught post-response
- `test_gateway_post_dispatch_strict_discipline.py` — audit-failure-preserves-provenance for unresolved/ambiguous/drift events; malformed content path; one-call/one-ledger-row regression for JSON-decode + HTTP-status errors
- `test_gateway_httpx_dispatch_errors.py` — pre-dispatch connect-class vs post-dispatch dispatched-class taxonomy (parametrized 11 arms)
- `test_gateway_concurrency_ledger.py` — saturated limiter → `LLMConcurrencyExceeded` + best-effort ledger row outcome="concurrency_exhausted"
- `test_system_policy.py` — endpoint contract (5 tests); operator-vocabulary field naming; stable key set
- `test_effective_routing.py` — ledger-authoritative aggregation; window honoring; persisted-row pass-through; the four drift cases (resolved / unresolved / ambiguous / no_dispatch exclusion); Langfuse healthy / unreachable / raises (mutation-tested); no-ledger graceful empty; stable top-level key set
- `test_concurrency.py` — queued + fail-fast modes; atomic per-profile lock; fairness

**Exit criteria:**
- All five LLM critical-controls modules pass per-file `≥95% line / ≥90% branch`
- Gateway is the only path to LiteLLM in this repo; no `httpx.post` to a LiteLLM URL outside `llm/gateway.py`
- Pre-call cloud-policy DENIES external upstreams unless allow_external_llm=true AND provider on allow-list AND policy_mode != self_hosted
- Post-response drift detection emits `gateway.upstream_drift_detected` on any `actual_model_string != preflight.model_string`
- Post-response policy recheck on `actual_resolved` denies via `CloudPolicyViolationError(post_response=True)` when actual provider isn't allow-listed (closes external→external silent drift)
- `/api/v1/system/effective-routing` reads `gateway_call_ledger` as authoritative; PROFILE-chip drift detection filters to `provenance != "no_dispatch"`; never fails closed on missing data
- Suite grows by **+286 passing / +291 collected**; coverage stays ≥96% global

**Status:** **CLOSED on `feat/sprint-3-llm-gateway`** (2026-04-30). Sprint-2.5 merge baseline was 659 passed + 24 skipped = 683 collected; Sprint 3 ready state is 945 passed + 29 skipped = 974 collected — **delta +286 passed / +291 collected**; 96% global coverage. All twelve critical-controls modules (Sprint 2 quartet + Sprint 2.5 triplet + Sprint 3 LLM quintet) pass per-file `≥95% line / ≥90% branch`. See [closeout note](closeouts/2026-04-30-sprint-3-llm-gateway-and-provider-honesty.md). **15 commits** atop the merged plan-of-record (PR #9 / `8804088` on `main`): T1, T1-followup, T2, T3, T4, T5, T6 phase A, T6 phase B, T7, T11, fix(tz-aware-ledger-test), T8, T9, T10, T12 closeout. Branch READY-FOR-GATE awaiting push/PR/merge authorization.

**Phase 1 exit:** AgentOS boots, governs, audits. Zero plugins required. Cloud-policy enforcement provably works.

---

## Phase 2 — Protocol layer + SDK + Pack Lifecycle + UI Event-Stream (Sprints 4, 5, 6, 7A, 7B, ~14.5 work-units)

### Sprint 4 — Plugin registry + trust gate + supply-chain attestations + policy-engine seed *(3.5 work-units)*

**Goal:** AgentOS discovers installed packs via Python entry points, verifies the **full supply-chain attestation set** (cosign signature + SLSA L3+ provenance + in-toto layout + SBOM + vuln scan + license audit per ADR-016), enforces per-tenant allow-list (per ADR-002), and persists the **Sigstore bundle for 7-year retention** for examiner replay.

**Deliverables:**
- `protocol/plugin_registry.py` — `discover()` walking `cognic.tools` / `cognic.skills` / `cognic.agents` entry-point groups; `require(kind, name)` + `load(kind, name)` API
- `protocol/trust_gate.py` — cosign verification with **secure subprocess invocation**:
  - `subprocess.run([COSIGN_BIN, "verify", ...], shell=False, timeout=settings.cosign_verify_timeout_s, check=True, capture_output=True, text=True)` — explicit list-form args, never a shell-string
  - `COSIGN_BIN` resolved at startup via `shutil.which("cosign")` then frozen; Dockerfile pins the cosign binary and records its SHA256
  - Per-tenant trust root path read from Vault, canonicalised via `os.path.realpath()` and asserted to live under an operator-approved prefix; rejects path-traversal attempts
  - **No pack-controlled string ever flows into argv** — pack identity, version, and signature blob are validated against a strict regex before being passed; no environment variables passed through (subprocess uses an explicit minimal `env` dict)
  - Strict timeout (default 30s); SIGKILL on timeout; timeout itself is an audit event
  - Output parsed via cosign's JSON mode (`--output json`); never via shell pipe / regex on free-form stderr
  - Negative-path tests prove every input vector cannot smuggle an extra arg or shell metacharacter
- `protocol/supply_chain.py` (per ADR-016) — attestation verification pipeline with **two grades** matching ADR-016 §"Implementation phases":
  - **Mandatory in Wave 1 (refusal-grade)** — missing any of these → registration refused:
    - cosign signature (already enforced by trust gate above)
    - SBOM (CycloneDX or SPDX); SBOM digest pinned to the pack signature
    - Sigstore bundle persister — atomic write to `ObjectStoreAdapter` under `attestations/<pack_id>/<version>/bundle.sigstore` with **7-year minimum retention** policy enforced at adapter level
  - **Mandatory-but-grace-period in Wave 1 (`attestation_grade: partial` allowed)** — packs missing these register with `attestation_grade: partial`; banks can opt to refuse partial-grade via per-tenant Rego policy (per ADR-015):
    - SLSA L3+ provenance verifier (validates `buildType`, `builder.id`, `invocation.configSource`)
    - in-toto layout verifier (proves the build pipeline matches the declared layout)
    - Vulnerability scan gate (consumes Trivy/Grype JSON output; per-tenant Rego policy decides max-CVSS / max-EPSS / known-exploit thresholds)
    - License audit gate (per-tenant allow-list of OSI/SPDX identifiers; fails on disallowed copyleft for closed deployments)
  - Registry exposes `attestation_grade` per pack (`full` | `partial`) so tenants and reviewers see at a glance which packs cleared every gate vs which rode the grace period
- `protocol/reproducibility.py` — pack manifest declares a reproducibility manifest digest; Sprint 4 verifies the manifest's digest is signed but does NOT re-build the pack (rebuild is a Sprint 7B reviewer concern)
- **`core/policy/__init__.py`, `core/policy/engine.py` (minimal seed; expanded in Sprint 13.5)** — early Rego evaluator so Sprint 4's supply-chain grade decision and Sprint 11.5's memory enforcement do not block on Sprint 13.5. Scope of this seed:
  - Embeds the OPA Go binary (or `opa-wasm`) and exposes `policy.engine.evaluate(decision_point: str, input: dict) -> Decision` with cached compiled policies
  - Loads bundles from disk only (no hot-reload yet — that ships in 13.5); bundles read at startup; reload requires restart
  - Default bundles published in this sprint: `policies/_default/supply_chain.rego` (used by Sprint 4) — Sprint 11.5 adds `memory.rego` and `memory_purpose_matrix.rego`; Sprint 13.5 adds the rest (`packs.rego`, `models.rego`, `tools.rego`, `sandbox.rego`, `subagent.rego`, `lifecycle.rego`)
  - Audit: every evaluation emits `policy.decision_evaluated` event chain-linked to `decision_history` with bundle hash + rule-matched + outcome
  - Sprint 13.5 extends this evaluator with hot-reload, the rest of the default bundles, decision-trail API (`GET /api/v1/policy/decisions/{trace_id}`), and refactors all inline checks across Sprints 4/7B/8/9.5/11/11.5 to delegate
- `core/config.py` extension — `cognic_plugin_allowlist_path` (Vault path), `cognic_require_cosign` flag, `cognic_supply_chain_policy_bundle` (Rego bundle path; defaults to `policies/_default/supply_chain.rego`)
- `portal/api/app.py` — `GET /api/v1/system/plugins` (lists registered packs with identity + signature digest + attestation summary)
- `tests/fixtures/cognic_test_pack/` — installable Hatchling pack with entry point + full attestation set; distribution name (kebab-case) deliberately differs from entry-point alias (snake-case) so the T9/T10 distribution-name-vs-alias divergence is exercised end-to-end. Ships seven attestation files (SBOM / SLSA L3 / in-toto / vuln / license / cosign sig / Sigstore bundle); `tests/fixtures/_signing_kit/build_test_attestations.sh` is the idempotent regen + cosign-real arm
- `db/adapters/local_object_store_adapter.py` — production filesystem `ObjectStoreAdapter` per ADR-009 (atomic write, sha256-pinned content addressing, retention-window-active rejection of premature delete, path-traversal protection); used by T9 to persist Sigstore bundles under 7-year retention metadata
- `infra/agentos/Dockerfile` — default-adapters builder pins cosign v3.0.6 + OPA v1.16.1 (sha256-verified at build time, COPY'd into runtime stage); kernel image deliberately untouched. CI smoke runs `cosign version` + `opa version` inside the built image as cognic UID 10001
- `tools/check_critical_coverage.py` — extended to enforce the plugin-trust / supply-chain / policy quartet (`plugin_registry`, `trust_gate`, `supply_chain`, `core/policy/engine`) at the same `(0.95 line, 0.90 branch)` floor as Sprint 2/2.5/3; gate now covers 16 modules
- Documentation update: `docs/HOW-TO-WRITE-A-PACK.md` — pack-author entry point with manifest shape, AGNTCY/OASF identity matrix, mandatory-floor + grace-period attestation requirements, and Wave-1 escape-hatch recipes for the cosign / syft / grype generation that `agentos sign --bundle` (Sprint 7A) will eventually wrap

**Tests:**
- `test_plugin_registry.py` — discover finds the test pack
- `test_trust_gate.py` — unsigned pack → registration refused; signed-but-not-allowlisted → refused; signed + allow-listed → accepted
- `test_supply_chain_grade_full.py` — pack with full attestation set registers with `attestation_grade: full`
- `test_supply_chain_grade_partial.py` — pack missing SLSA / in-toto / vuln / license registers with `attestation_grade: partial` (NOT refused); registry exposes the grade
- `test_supply_chain_grade_partial_tenant_refuses.py` — same partial pack with tenant Rego policy `require_full = true` → refused at registration
- `test_supply_chain_mandatory_floor.py` — pack missing cosign OR SBOM OR Sigstore bundle → refused regardless of tenant policy (these are not grace-able)
- `test_supply_chain_slsa.py` — pack with valid SLSA L3 provenance recorded as full-grade; pack with L1/L2 provenance falls back to partial; tampered provenance refused (tampering is a hard fail, not a grace case)
- `test_supply_chain_intoto_layout.py` — pack matching declared layout marked full; mismatched layout falls back to partial
- `test_supply_chain_sbom.py` — SBOM digest must match pack signature; missing SBOM refused (SBOM is in the mandatory floor)
- `test_supply_chain_vuln_gate.py` — pack with critical CVE above tenant threshold refused if tenant requires full; pack with only low-severity CVEs accepted at full grade
- `test_supply_chain_license_audit.py` — pack with disallowed license refused if tenant requires full; pack with allow-listed licenses accepted at full grade
- `test_sigstore_bundle_retention.py` — bundle persisted to ObjectStoreAdapter under correct path; retention metadata applied; cannot be deleted within retention window
- `test_policy_engine_seed.py` — minimal evaluator loads `supply_chain.rego`; valid grade decision returns expected outcome; missing bundle → fail-closed refusal; every evaluation emits `policy.decision_evaluated` audit event
- `test_plugin_endpoint.py` — `/system/plugins` lists what's registered with attestation summary

**Exit criteria:**
- AgentOS startup logs `Discovered N packs (M registered, K rejected)` plus per-pack attestation outcomes
- Per-tenant allow-list enforces correctly
- A pack missing ANY of {cosign signature, SBOM, Sigstore bundle} is refused at registration regardless of tenant policy (the mandatory Wave 1 floor)
- A pack missing SLSA / in-toto / vuln-scan / license-audit registers with `attestation_grade: partial`; tenant Rego policy decides whether partial is acceptable (default policy: yes in Wave 1, with a deprecation warning surfaced in `/system/plugins`)
- Sigstore bundle is persisted to ObjectStoreAdapter and discoverable via `/system/plugins` for examiner replay
- `attestation_grade` (`full` | `partial`) is exposed per pack in `/system/plugins` and on the reviewer evidence panel
- Architecture-discipline test still green (registry doesn't import any pack at top-level)

**Status:** **CLOSED on `feat/sprint-4-plugin-registry-trust-gate`** (2026-05-01). Sprint-3 merge baseline measured at the Sprint-4 branch base (`cc0cb57`) was 945 passed + 29 skipped = 974 collected; Sprint 4 ready state is 1441 passed + 29 skipped = 1470 collected — **delta +496 passed / +496 collected** (vs the projected ~13 from the original deliverables list — actual ratio reflects the depth of plan-review-driven regression tests across T6/T7/T9/T10). 96% global coverage. All sixteen critical-controls modules (Sprint 2 quartet + Sprint 2.5 triplet + Sprint 3 LLM quintet + Sprint 4 plugin/trust/supply/policy quartet) pass per-file `≥95% line / ≥90% branch`. See [closeout note](closeouts/2026-05-01-sprint-4-plugin-registry-trust-gate.md). **17 commits** atop the merged plan-of-record (PR #12 / `a84ec85` on `main`): T1, T1-followup (env-prefix re-align), T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16 closeout. Branch READY-FOR-GATE awaiting push/PR/merge authorization.

### Sprint 5 — MCP host (Streamable HTTP first; STDIO restricted; OAuth/PRM authorization) *(3.5 work-units)*

**Goal:** AgentOS speaks MCP with **production-grade transport hardening** (per ADR-002 STDIO threat-model amendment + PROJECT_PLAN.md §5 line 71-72) and **OAuth + Protected Resource Metadata authorization** (per ADR-002 amendment + `docs/MCP-CONFORMANCE.md`). Streamable HTTP is the production default; STDIO is an opt-in escape hatch behind multiple gates; anonymous MCP is forbidden.

**MUST land before any MCP tool invocation code:**
- `docs/MCP-STDIO-THREAT-MODEL.md` — the threat model document. Catalogues the April-2026 supply-chain disclosures (OX Security et al). Codifies the four-gate STDIO restriction.
- `docs/MCP-CONFORMANCE.md` (already drafted) is the operator-facing reference for which capabilities are supported, restricted, or forbidden per wave.

**Deliverables:**
- `protocol/mcp_host.py` — `MCPHost` with `discover_servers()`, `list_tools()`, `call_tool(name, arguments)`. **Streamable HTTP transport is the default and first-implemented.**
- `protocol/mcp_transports.py` — pluggable transport layer:
  - `StreamableHTTPTransport` — production default. Pack manifest declares an HTTP endpoint; host opens session via streamable-HTTP MCP spec.
  - `StdioTransport` — **gated**. Refuses to launch unless ALL of:
    1. Pack ships a **signed static manifest** declaring command + arguments + env vars (verified at registration time)
    2. Launch command appears on a **per-tenant static command allow-list** (Vault path `secret/cognic/<tenant>/stdio-command-allowlist`)
    3. Launch occurs **inside a sandbox profile** (per ADR-004; depends on Sprint 8 sandbox primitive being available — until then, STDIO is hard-disabled in production profile)
    4. Environment variables are **bounded** — no `os.environ` passthrough; only the manifest's declared allow-list
  - **`audit.stdio_launch` event** emitted on every launch with pack identity + command + arguments + sandbox-id + outcome — chained into `decision_history`
- `protocol/mcp_authz.py` (per ADR-002 MCP Authorization amendment) — OAuth + PRM client per the MCP authorization spec:
  - **Resource-metadata discovery — three paths in priority order** (spec mandates all three):
    - **Primary**: `WWW-Authenticate: Bearer resource_metadata="..."` header on a 401 response — client follows the URL the server advertises
    - **Endpoint-specific well-known fallback**: when the 401 lacks `WWW-Authenticate`, client probes `<origin>/.well-known/oauth-protected-resource<endpoint-path>` first (for an MCP endpoint at `https://server.example/public/mcp`, the probe is `https://server.example/.well-known/oauth-protected-resource/public/mcp`). This is the spec's per-resource convention; supports multiple MCP servers under one origin with distinct PRMs.
    - **Root well-known fallback**: if endpoint-specific returns 404, client falls back to host-level `/.well-known/oauth-protected-resource`
    - All three paths produce the same PRM document; whichever returns first wins; client caches per `Cache-Control` directives
  - Per-tenant authorization-server allow-list read from Vault (`secret/cognic/<tenant>/mcp-as-allowlist`); refuses servers pointing to non-allow-listed AS
  - Token acquisition:
    - Minimum-scope tokens per pack manifest declaration
    - **RFC 8707 resource indicator** (`resource=<server URL>`) on every token request so tokens are bound to the specific MCP server
    - **Audience validation on every received token**: `aud` claim MUST match the MCP server's resource indicator; mismatched audience → token rejected, server treated as 401, fresh discovery + token request triggered
  - **Insufficient-scope step-up flow**: per the MCP authorization spec, runtime insufficient scope is signalled by **`403 Forbidden`** (not 401 — initial missing/invalid auth is 401, runtime under-scoped is 403). When the server returns `403` with `WWW-Authenticate: Bearer error="insufficient_scope", scope="<wider>"`, the client requests a fresh token covering the wider scope (subject to manifest declaration AND tenant policy permitting); the step-up is audit-logged with the prior scope set + the requested-additional scopes; if manifest does not declare the wider scope, the call fails closed with `mcp_step_up_unauthorised`. The 401-vs-403 distinction is what tells the client whether to discover-and-acquire vs step-up-existing-token.
  - Token cache + refresh; every refresh emits `audit.mcp_token_refresh` event chained into `decision_history` with AS issuer + scopes + client_id + resource indicator (no token contents)
  - Failed auth at registration → pack registration enters `proposed` state per ADR-002 (does NOT load until resolved)
  - **Anonymous MCP forbidden**: a server lacking both PRM and the API-key fallback declaration → registration refused
  - **API-key fallback** (Wave 1 only): manifest may declare `auth = "api-key"` with Vault path; deprecated in Wave 2
- `protocol/mcp_capabilities.py` — capability declaration validator (per `MCP-CONFORMANCE.md`):
  - **Resources are optional** — a pure tool-only MCP server with `resources_supported = false` is conformant; if `resources_supported = true` the server MUST implement list + read (subscribe optional)
  - **Sampling is default-deny per tenant + per pack** — pack must declare `sampling_supported = true` AND tenant Rego policy must explicitly permit AND model tier must be consistent with `ALLOW_EXTERNAL_LLM`; ANY missing element → sampling refused at every call. The default policy bundle (`policies/_default/sampling.rego`) returns `deny` until an operator overrides
  - Refuses pack manifests declaring `elicitation_modes = ["form"]` for any tool whose `data_classes` include `customer_pii` / `payment_action` / `regulator_communication` (per ADR-017)
  - Refuses `caching_strategy = "ttl"` for tools with the same restricted data classes (per ADR-017)
- `core/config.py` extension — `mcp_stdio_enabled` (default `false` in `prod` profile, `true` in `dev`); `mcp_stdio_command_allowlist_path`; `mcp_as_allowlist_path`; `mcp_oauth_token_cache_ttl_s`
- **Sandbox dependency hard-block**: STDIO transport refuses to register any pack until Sprint 8's sandbox primitive is available. Sprint 5 ships with `mcp_stdio_enabled` defaulting to `false` in **all** profiles. Sprint 8 flips the default for `dev` only after the sandbox is operational. **Production profile remains hard-disabled until both (a) sandbox primitive is operational AND (b) operator explicitly sets `mcp_stdio_enabled=true` plus the four-gate manifest.** This is enforced at config-load time: a `prod` profile with `mcp_stdio_enabled=true` AND no sandbox available → fail-fast at startup, not at first invocation.
- `core/audit.py` integration — every `call_tool` emits `audit.tool_invocation` with pack identity + tool name + `Mcp-Session-Id` + AS issuer + scopes + duration + outcome (chained per `MCP-CONFORMANCE.md` observability requirements)
- **Risk-tier transitional gate** (per ADR-014 Sprint 5 transitional rule + `MCP-CONFORMANCE.md`): `protocol/mcp_host.call_tool` reads the pack manifest's declared `risk_tier`. If the tier is anything other than `read_only` or `internal_write` AND the approval engine has not loaded (`core.approval` module not yet present in Sprint 5–13), the call is **refused** with error `tool_approval_engine_not_available` and an audit event is emitted. The high-risk pack still registers — only invocation is blocked. This rule is mechanical (not configurable) and is removed by Sprint 13.5 once `core/approval` ships.
- `tests/fixtures/cognic_test_tool_pack/` — fake MCP server (HTTP transport) publishing PRM + OAuth-protected
- Add `mcp` SDK to dependencies (pin to current released version)

**Tests:**
- `test_mcp_host_http.py` — open session to HTTP test pack, list tools, call tool, verify audit event chained
- `test_mcp_host_resilience.py` — pack process dies mid-call → host recovers + logs failure
- `test_mcp_oauth_prm_www_authenticate.py` — primary `WWW-Authenticate: Bearer resource_metadata="..."` discovery path: server 401s with header, client follows URL, fetches metadata, requests token
- `test_mcp_oauth_prm_endpoint_specific_fallback.py` — server 401 lacks `WWW-Authenticate`; client probes `/.well-known/oauth-protected-resource/<endpoint-path>` and finds PRM there; root well-known is NOT probed when endpoint-specific succeeds
- `test_mcp_oauth_prm_root_fallback.py` — endpoint-specific path returns 404; client falls back to `/.well-known/oauth-protected-resource` and parses PRM there
- `test_mcp_oauth_prm_path_priority.py` — when both endpoint-specific and root paths exist with conflicting PRMs, endpoint-specific wins (per spec priority order)
- `test_mcp_oauth_as_allowlist.py` — AS allow-list enforced; non-allow-listed AS → registration refused
- `test_mcp_oauth_token_minimum_scope.py` — tokens requested only for manifest-declared scopes; over-broad scope request refused
- `test_mcp_oauth_resource_indicator.py` — every token request includes RFC 8707 `resource=<server URL>`; tokens received without bound resource refused
- `test_mcp_oauth_audience_validation.py` — token with `aud` matching server resource accepted; token with mismatched `aud` rejected → fresh discovery + token request triggered; reuse of mismatched-audience token across servers blocked
- `test_mcp_oauth_step_up_scope.py` — server returns **`403 Forbidden`** `insufficient_scope` with wider scope advertised; manifest declares wider scope → step-up token requested + audit-logged; manifest does NOT declare → call fails with `mcp_step_up_unauthorised`. Negative-path: server returns `401 insufficient_scope` instead of 403 → client treats as discovery-required (NOT step-up); ensures the 401/403 dichotomy is honoured.
- `test_mcp_oauth_token_refresh_audit.py` — token refresh emits chained audit event with AS issuer + scopes + resource indicator; no token contents leaked
- `test_mcp_anonymous_refused.py` — server lacking PRM and API-key declaration → registration refused
- `test_mcp_api_key_fallback.py` — Wave 1 API-key fallback works; deprecation warning logged
- `test_mcp_capability_validator.py` — restricted-data-class + elicitation-form-mode → refused; restricted-data-class + ttl-cache → refused
- `test_mcp_resources_optional.py` — pure tool-only server (`resources_supported = false`) registers + invokes successfully
- `test_mcp_sampling_default_deny.py` — pack declaring `sampling_supported = true` but tenant policy missing → sampling refused at call; tenant policy permitting + pack declaring + tier consistent → sampling allowed; ANY missing element → refused
- `test_mcp_session_id_propagation.py` — `Mcp-Session-Id` flows from MCP envelope into `decision_history`
- `test_mcp_high_risk_tier_refused_pre_13_5.py` — pack declaring `risk_tier = "customer_data_read"` (or any tier above `internal_write`) registers successfully but every invocation is refused with `tool_approval_engine_not_available`; `read_only` and `internal_write` tier calls work; refusal is audit-logged with declared tier
- `test_mcp_stdio_disabled_in_prod.py` — production profile + `mcp_stdio_enabled=false` → any STDIO pack registration is refused
- `test_mcp_stdio_unsigned_manifest_refused.py` — STDIO pack with unsigned manifest → registration refused
- `test_mcp_stdio_command_not_allowlisted_refused.py` — STDIO pack with command not in tenant allow-list → registration refused
- `test_mcp_stdio_environment_isolation.py` — STDIO launch does NOT inherit `os.environ`; only manifest's declared env vars are visible
- `test_mcp_stdio_audit_event.py` — every STDIO launch produces a chained `audit.stdio_launch` event with full launch metadata
- `test_mcp_no_user_controlled_command.py` — **negative-path smoke**: deliberately attempt to inject a user-controlled command/argument through every reachable code path → refused at every entry point. This test is the canary for the threat model.
- Integration test using the HTTP test pack across the full lifecycle

**Exit criteria:**
- HTTP test pack registers + invokes successfully via MCP **with OAuth/PRM authorization**
- Production profile rejects any STDIO pack registration (default-secure)
- Production profile rejects any anonymous MCP server (default-secure)
- Dev profile allows STDIO pack only when all four gates pass
- `test_mcp_no_user_controlled_command.py` proves the threat-model boundary
- Audit event for every call (HTTP or STDIO) recorded with pack signature digest + AS issuer + scopes + `Mcp-Session-Id`
- MCP-spec compliance: a public reference MCP server (Anthropic's `everything` example) installs over HTTP and works
- Conformance matrix in `docs/MCP-CONFORMANCE.md` matches what the host actually enforces (test reads the matrix and verifies enforcement code)

### Sprint 6 — A2A endpoint (pinned to A2A 1.0 spec) + UI event-stream stub *(2 work-units)*

**Goal:** AgentOS speaks A2A inbound + outbound, **pinned to the released A2A 1.0 wire-spec with conformance fixtures** (per ADR-003 + `docs/A2A-CONFORMANCE.md`) — not a bespoke Python dict that resembles A2A. Wave 1 implements the **mandatory feature set** (Agent Cards, Tasks, Streaming, Artifacts, Capability negotiation, Cancellation, Error taxonomy); Wave 2 features (Push notifications, Multi-modal, Long-running task resumption) are explicitly out of scope. Agent-to-agent messages route to installed agent packs; chain-hashed audit linkage.

**Deliverables:**
- `protocol/a2a_endpoint.py` — `A2AEndpoint.handle(message)` with target resolution via plugin registry, parent_trace_id linkage, **task lifecycle state machine** (created → running → succeeded / failed / cancelled)
- `protocol/a2a_schema.py` — A2A 1.0 message envelope schema generated from the [official A2A 1.0 spec](https://a2a-protocol.org/dev/specification/) (NOT a Cognic-bespoke shape). **Source of truth: the spec's protobuf definitions** — `.proto` files are pulled into `protocol/a2a/proto/` and compiled to Python; JSON-schema bindings (also spec-published) are loaded into Pydantic and checked for parity against the protobuf-generated types. CI fails on drift between (a) our schema and upstream protobuf, OR (b) upstream protobuf and upstream JSON-schema binding.
- `protocol/a2a_version.py` — `A2A-Version` header parser + responder per spec; outbound calls always include `A2A-Version: 1.0`; inbound calls handle absent / matching / higher-minor / unsupported / malformed cases per `docs/A2A-CONFORMANCE.md`. **Per spec, an absent header is interpreted as version `0.3`** — AgentOS does not implement 0.3, so absent-header requests are rejected with `VersionNotSupportedError` + `Supported-A2A-Versions: 1.0` (no silent upgrade). Unsupported versions return `VersionNotSupportedError` with `Supported-A2A-Versions` header.
- `protocol/a2a_agent_cards.py` — Agent Card publisher AND verifier:
  - Card validation is **two-pass**: (a) **upstream A2A 1.0 schema** validation against the spec's `AgentCard` JSON-schema + protobuf source — the card must be a legitimate A2A 1.0 card; (b) **AgentOS bank-grade profile** validation — `provider`, `securitySchemes`, `securityRequirements`, `signatures`, and at least one `supportedInterfaces` entry are spec-optional but **AgentOS profile mandatory**. Capability flags (`AgentCapabilities` object) per spec: `streaming`, `pushNotifications`, `extensions`, `extendedAgentCard`. **Endpoint URLs live inside `supportedInterfaces[].url`, NOT at the AgentCard top level** (no top-level `url`). **No Cognic-specific identity fields in the card** — those (URN `agent_id`, `oasf_capability_set`, `verifiable_credentials_path`, etc.) live in the pack manifest's `[tool.cognic.identity]` block per ADR-002 amendment so any A2A 1.0 caller can consume the card without Cognic knowledge. Profile-violation errors return `agentos_profile_violation` with the specific mandatory field listed, distinct from upstream-schema failures so authors can diagnose without confusing the two layers.
  - **Spec well-known path: `/.well-known/agent-card.json` (singular, no per-id suffix)** — served on the agent's own origin (one origin per agent pack in Wave 1). For multi-agent discovery across an AgentOS deployment, the plugin registry exposes a Cognic catalog endpoint `GET /api/v1/system/agent-cards`; this is registry metadata, not the spec well-known path.
  - **Cards MUST be JWS-signed** (via the A2A 1.0 `signatures` field plus a detached JWS file); pack manifest declares `agent_card_jws_path` pointing at the detached JWS. The trust gate (Sprint 4) verifies the JWS signature against the same per-tenant trust root as the cosign signature on the pack itself — the same authority that signs the wheel signs the card. Card-signature verification is part of pack registration; an unsigned or invalid-signature card → registration refused.
  - **Outbound calls validate signed cards too** — when AgentOS dispatches A2A traffic to a remote agent (sub-agent or cross-pod call), it fetches the target's `/.well-known/agent-card.json`, verifies the JWS, and dispatches to the URL inside `supportedInterfaces[].url` (never a URL the caller supplied directly). Cards from non-allow-listed signers → call refused.
  - Card content is hash-chained into `decision_history` at pack registration; subsequent card mutations require the pack to re-register (no live card swaps without audit).
  - Schema drift: `protocol/a2a_schema.py` includes the upstream AgentCard schema; `test_a2a_schema_drift.py` fails CI if the AgentCard shape diverges from upstream protobuf or JSON-schema bindings.
- `protocol/a2a_streaming.py` — SSE streaming adapter for tasks declared `streaming = true` in their manifest; task-progress messages emitted to caller via Server-Sent Events
- `protocol/a2a_artifacts.py` — artifact reference generator: large outputs (PDFs, evidence packs, large JSON) are stored via `ObjectStoreAdapter` and returned by reference, not value; per-tenant artifact retention configurable
- `protocol/a2a_capability_negotiation.py` — `GET /api/v1/a2a/capabilities` endpoint per A2A 1.0; callers probe before dispatching tasks
- `protocol/a2a_cancellation.py` — `POST /api/v1/a2a/tasks/{id}/cancel`; in-flight task is cancelled; partial-state audit event emitted
- `protocol/a2a_errors.py` — full A2A 1.0 error taxonomy enum; every error response uses spec-defined codes (no Cognic-bespoke codes for spec-mapped failures)
- `protocol/a2a_authz.py` — per-tenant pinned-token authorization (Wave 1 default per `A2A-CONFORMANCE.md`); `Authorization: Bearer ...` required on every inbound A2A request; tokens rotated via Vault; mTLS deferred to Wave 2; VC deferred to Wave 3
- `portal/api/app.py` — `POST /api/v1/a2a` (inbound A2A receiver), task management endpoints (`GET /api/v1/a2a/tasks/{id}`, cancel, capabilities)
- `tests/fixtures/a2a-conformance/` — **A2A 1.0 conformance fixtures**: a curated set of valid + invalid messages from the official spec. Endpoint MUST accept all valid fixtures and reject all invalid ones.
- `docs/A2A-CONFORMANCE.md` (already drafted) is the operator-facing reference; Sprint 6 enforcement matches the matrix exactly.
- **`protocol/ui_events.py` (stub per ADR-020)** — typed event-emit hooks at the harness boundary so every audit event emitted in this sprint mirrors to a typed UI event in-process. No SSE endpoint yet (that ships in Sprint 7B). Wave 1 event taxonomy defined as Pydantic models so the schema is stable from day one even before any UI subscribes. Event families seeded in Sprint 6: `agent_run`, `tool_call`, `subagent`, `artifact`, `decision_audit`. Other families wired in their respective sprints.

**Tests:**
- `test_a2a_endpoint.py` — message addressed to test agent → routed → response returned
- `test_a2a_agent_cards.py` — every registered agent pack publishes a valid Agent Card; capability list discoverable
- `test_a2a_agent_card_spec_shape.py` — **two-pass validation**:
  - Pass 1 (upstream): card validates against the upstream A2A 1.0 AgentCard JSON-schema + protobuf; a card containing top-level `url` → fails (spec says URLs live in `supportedInterfaces[].url`); a card containing Cognic-specific identity fields (`agent_id`, `oasf_capability_set`, etc.) at the top level → fails (not in spec)
  - Pass 2 (AgentOS profile): card lacking `signatures` → fails with `agentos_profile_violation: signatures required` (spec-valid but profile-mandatory); same for missing `securitySchemes` / `securityRequirements` / `provider` / empty `supportedInterfaces`. Distinct error code from Pass 1 failures.
  - Card served at `/.well-known/agent-card.json` (NOT `/.well-known/agent-card.json/<id>`) per spec; multi-agent catalog accessible via `/api/v1/system/agent-cards` instead
- `test_a2a_agent_card_jws_required.py` — pack with unsigned card → registration refused; pack with valid JWS signature against tenant trust root → accepted; pack with JWS from non-allow-listed signer → refused
- `test_a2a_agent_card_outbound_verification.py` — outbound A2A call to remote agent: target's card fetched + JWS verified before request dispatch; tampered card → call refused with `agent_card_signature_invalid`
- `test_a2a_agent_card_chain_audit.py` — card content hash-chained into `decision_history` at registration; subsequent card mutation requires re-registration (no live swap)
- `test_a2a_streaming.py` — streaming task delivers progress events via SSE; final result terminates the stream
- `test_a2a_artifacts.py` — large output returned as artifact reference; reference resolvable via `ObjectStoreAdapter`; small payloads remain inline
- `test_a2a_capability_negotiation.py` — `/capabilities` lists exactly the capabilities the agent's manifest declared (no more, no less)
- `test_a2a_cancellation.py` — in-flight task cancelled; partial-state audit emitted; subsequent calls reject the cancelled task ID
- `test_a2a_error_taxonomy.py` — every spec-defined error path returns the spec's error code (not a Cognic-bespoke one)
- `test_a2a_chain_audit.py` — parent + 3 child messages → chain verifier returns full proof; `a2a.task_received` and `a2a.task_dispatched` events present
- `test_a2a_unknown_target.py` — target not registered → 501 with ADR-002 reference
- `test_a2a_anonymous_refused.py` — request without per-tenant token → refused with 401 (anonymous A2A forbidden per `A2A-CONFORMANCE.md`)
- `test_a2a_spec_conformance.py` — runs the conformance fixtures: every valid message accepted, every invalid message rejected with the spec-specified error
- `test_a2a_schema_drift.py` — diffs our `a2a_schema.py` against (a) upstream A2A 1.0 protobuf source, (b) upstream JSON-schema binding; fails CI if either has moved beyond our pinned version OR if the JSON-schema binding has diverged from protobuf
- `test_a2a_version_header.py` — inbound `A2A-Version: 1.0` accepted; **absent header is interpreted as `0.3` per spec and rejected with `VersionNotSupportedError` + `Supported-A2A-Versions: 1.0` response header** (NOT silently upgraded to 1.x); `0.x` rejected; `2.0` rejected with `VersionNotSupportedError` carrying `Supported-A2A-Versions` header; malformed header rejected with spec parse error
- `test_a2a_outbound_version.py` — every outbound call includes `A2A-Version: 1.0`
- `test_a2a_wave2_features_refused.py` — push-notification subscribe / multi-modal payload / long-running resumption requests are refused with explicit "Wave 2" error code (not silent-accept)

**Exit criteria:**
- A test agent pack receives messages via A2A 1.0 spec-compliant envelopes
- Every registered agent pack publishes a valid Agent Card; cards discoverable via plugin registry per ADR-002
- Streaming, artifacts, capability negotiation, cancellation, error taxonomy all enforce per `A2A-CONFORMANCE.md`
- Anonymous A2A is refused; every accepted call carries a per-tenant token
- Cross-agent decision history chain verifiable end-to-end
- All A2A 1.0 conformance fixtures pass
- Schema-drift test demonstrates we're pinned to a specific A2A spec version (currently 1.0); upstream changes require explicit version bump + re-validation
- Wave 2 features (push notifications, multi-modal, resumption) are refused with explicit error code, not silently accepted

### Sprint 7A — agentos-sdk + agentos-cli *(2 work-units)*

**Goal:** Cognic team, banks, and ecosystem authors can scaffold a new pack with one command (per ADR-008 Phase A).

**Deliverables:**
- `src/cognic_agentos/sdk/__init__.py` — public Python API
- `src/cognic_agentos/sdk/tool.py` — base classes for MCP tool implementations
- `src/cognic_agentos/sdk/skill.py` — composition helpers for skills (no LLM)
- `src/cognic_agentos/sdk/agent.py` — base class for A2A-speaking agents (subclasses inherit the harness contract)
- `src/cognic_agentos/sdk/testing.py` — pytest fixtures + assertions for pack tests
- `src/cognic_agentos/sdk/compliance.py` — ISO 42001 control-declaration helpers
- `src/cognic_agentos/cli/__init__.py` — `agentos-cli` entry point (registered as `project.scripts` in pyproject.toml)
- `src/cognic_agentos/cli/init.py` — `agentos init-tool|init-skill|init-agent <name>` scaffolders
- `src/cognic_agentos/cli/validate.py` — `agentos validate` (manifest check, schema validation, semver, declared permissions, sandbox policy, model tier, RBAC scopes, egress needs, AgentOS-version compatibility — per PROJECT_PLAN §8 deliverable 5). MUST also enforce:
  - **AGNTCY/OASF identity fields** (per ADR-002 amendment "Wave 1 identity-field strictness" matrix). Wave 1 tier breakdown:
    - **Mandatory**: `agent_id` (URN per AGNTCY/OASF naming), `display_name`, `provider_organization`, `provider_url`, `agent_card_url`, `agent_card_jws_path` (mandatory for agent packs; tool/skill packs skip it). Missing any of these → validate fails with explicit per-field error.
    - **Optional in Wave 1, mandatory in Wave 2**: `oasf_capability_set` from the OASF capability registry. Missing → warning logged, validate succeeds; the warning is reviewer-visible per Sprint 7B evidence panels.
    - **Optional / reserved (Wave 3 VC sprint flips it mandatory)**: `verifiable_credentials_path`. Missing → validate succeeds; if present, validator only checks that the path resolves to a file the cosign-signed wheel includes. Validator does NOT check VC format / signature / contents in Wave 1.
  - **A2A conformance declarations** (per `docs/A2A-CONFORMANCE.md` "What pack authors must declare"): `[tool.cognic.a2a]` block with `spec_version`, `agent_card_url`, `agent_card_jws_path` (mandatory for agent packs), `capabilities_supported`, `streaming`, `push_notification_config` (false in Wave 1), `artifacts_supported`, `auth_scheme`. Validates the declared values against the conformance matrix and confirms the JWS file exists + parses.
  - **MCP conformance declarations** (per `docs/MCP-CONFORMANCE.md`): `[tool.cognic.mcp]` block with `transport`, `auth`, `required_scopes`, `resources_supported`, `prompts_supported`, `sampling_supported`, `elicitation_modes`, `caching_strategy`, `caching_ttl_s`, `conformance_version`. Refuses Wave 2 features in a Wave 1 manifest; refuses caching of restricted data classes; refuses `elicitation_modes = ["form"]` for restricted data classes.
  - **Data-governance contract** (per ADR-017): `[tool.cognic.data_governance]` block with `data_classes`, `purpose`, `retention_policy`, `retention_max_window`, `egress_allow_list`, `dlp_pre_hooks`, `dlp_post_hooks`, `requires_consent`, `regulator_retention_required`. Refuses packs without a complete contract; cross-validates contract against MCP caching rules and tool risk tier.
  - **Risk-tier declaration** (per ADR-014): `[tool.cognic.runtime]` block with `risk_tier` (`read_only` | `internal_write` | `customer_data_read` | `customer_data_write` | `payment_action` | `regulator_communication` | `cross_tenant` | `high_risk_custom`). Validates that declared tier is consistent with declared data classes (e.g. a tool reading PII must declare at least `customer_data_read`).
  - **Supply-chain attestation declarations** (per ADR-016): `[tool.cognic.supply_chain]` block with `slsa_level`, `provenance_url`, `sbom_path`, `vuln_scan_report`, `license_audit_report`, `reproducibility_manifest`, `sigstore_bundle_path`. Validates required fields are present and points at locations the trust gate (Sprint 4) will verify.
- `src/cognic_agentos/cli/test_harness.py` — `agentos test-harness` runs pack against fixture-only AgentOS instance (per PROJECT_PLAN §8 deliverable 5: "local governance test harness")
- `src/cognic_agentos/cli/sign.py` — `agentos sign --key vault://...` (cosign wrapper)
- `src/cognic_agentos/cli/templates/` — starter templates for tool/skill/agent pack repos with CI, tests, SBOM generation, cosign signing (per PROJECT_PLAN §8 deliverable 4)
- `docs/HOW-TO-WRITE-A-PACK.md` — author tutorial (target: bank engineer)
- `docs/SDK-REFERENCE.md` — Python API reference
- `docs/PACK-MANIFEST-SPEC.md` — stable pack manifest format, versioning policy, compatibility matrix (per PROJECT_PLAN §8 deliverable 2)

**Tests:**
- `test_cli_init.py` — `agentos init-tool foo` produces valid pack tree
- `test_cli_validate.py` — invalid pack → validate fails with clear errors
- `test_cli_validate_agntcy_identity.py` — manifest missing **mandatory** Wave 1 identity fields (`agent_id`, `display_name`, `provider_organization`, `provider_url`, `agent_card_url`, `agent_card_jws_path` for agent packs) → validate fails with explicit per-field error; manifest missing only `oasf_capability_set` → validate succeeds with warning; manifest missing only `verifiable_credentials_path` → validate succeeds silently (Wave 3 reservation); manifest with `agent_card_jws_path` pointing at a non-existent file → validate fails
- `test_cli_validate_a2a_declarations.py` — manifest with Wave 2 A2A feature declared in Wave 1 → validate fails; manifest declarations must match `docs/A2A-CONFORMANCE.md` matrix
- `test_cli_validate_mcp_declarations.py` — manifest declaring caching of `customer_pii` → validate fails; declaring elicitation form-mode for restricted classes → validate fails
- `test_cli_validate_data_governance_contract.py` — manifest missing `[tool.cognic.data_governance]` → validate fails; contract inconsistent with risk tier → validate fails
- `test_cli_validate_risk_tier_consistency.py` — tool reading PII declared `read_only` → validate fails with clear remediation
- `test_cli_validate_supply_chain_attestations.py` — manifest missing supply-chain attestation paths → validate fails
- `test_cli_test_harness.py` — pack runs through fixture harness; conformance report generated
- `test_sdk_tool_base.py` — Tool base class enforces input/output schema declaration
- `test_sdk_agent_base.py` — Agent base class wires into the harness execute loop

**Exit criteria:**
- `agentos init-tool example-search` → working scaffold in <5s; scaffold ships a valid AGNTCY/OASF identity block + data-governance contract template (author fills in real values)
- `cd cognic-tool-example-search && agentos validate` → green
- `agentos test-harness` produces a conformance report including AGNTCY/OASF identity, A2A declarations, MCP declarations, data-governance contract, risk-tier consistency, supply-chain attestation completeness
- Three reference packs scaffolded under `examples/`: `cognic-tool-example-search`, `cognic-skill-example-kyc`, `cognic-agent-example-policyqa` — all carrying complete identity + governance + supply-chain declarations

### Sprint 7B — Bank pack lifecycle API + workflow + UI event-stream endpoints *(3.5 work-units)*

**Goal:** banks can manage the full pack lifecycle through portal APIs (per ADR-012 + PROJECT_PLAN §7-8). Not just CLI — a workflow with state machine, RBAC scopes, audit linkage, and evidence inspection.

**Deliverables:**

*Lifecycle state machine + storage:*
- `src/cognic_agentos/packs/__init__.py`, `packs/lifecycle.py` — state machine: `draft → submitted → under_review → approved (or rejected/withdrawn) → allow_listed → installed → disabled → revoked → uninstalled`
- `packs/storage.py` — Postgres-backed pack-record store (uses `RelationalAdapter`); schema includes manifest, signed-artefact digest, SBOM, conformance report, lifecycle history, RBAC-trail
- `db/migrations/001_packs_lifecycle.sql` (Postgres) and `db/migrations/oracle/001_packs_lifecycle.sql` (Oracle)

*Portal API endpoints:*
- Author surface: `POST /api/v1/packs/drafts`, `PUT /api/v1/packs/drafts/{id}`, `POST /api/v1/packs/drafts/{id}/submit`, `DELETE /api/v1/packs/drafts/{id}`
- Review surface: `GET /api/v1/packs?status=submitted`, `POST /api/v1/packs/{id}/claim`, `POST /api/v1/packs/{id}/approve`, `POST /api/v1/packs/{id}/reject`, `GET /api/v1/packs/{id}/evidence`
- Operator surface: `POST /api/v1/packs/{id}/allow-list`, `POST /api/v1/packs/{id}/install`, `POST /api/v1/packs/{id}/disable`, `POST /api/v1/packs/{id}/revoke`, `DELETE /api/v1/packs/{id}/install`
- Inspection: `GET /api/v1/packs`, `GET /api/v1/packs/{id}`, `GET /api/v1/packs/{id}/audit`, `GET /api/v1/packs/{id}/invocations`

*RBAC scopes (extends `portal/rbac/`):*
- `pack.submit`, `pack.withdraw` (author)
- `pack.review.claim`, `pack.review.approve`, `pack.review.reject` (reviewer)
- `pack.allow_list`, `pack.install`, `pack.disable`, `pack.revoke`, `pack.uninstall` (operator)
- `pack.audit.read`, `pack.invocation.read` (examiner)

*OWASP conformance integration:*
- `packs/conformance/__init__.py`, `packs/conformance/owasp_agentic.py` — OWASP Top 10 for Agentic Applications 2026 + Agentic Skills Top 10 checks (tool misuse, goal hijacking, identity abuse, prompt-injected skills, dependency poisoning, secret exfiltration, unsafe filesystem/network access)
- Run automatically as part of `submit` → if any check fails, submission attaches the failures and reviewer sees them in `evidence` view
- `packs/conformance/cli.py` — `agentos conformance` command for local runs (Sprint 7A SDK extension)

*Reviewer evidence panels (per ADR-017 + ADR-014 + ADR-016):*
- `packs/evidence/data_governance.py` — `GET /api/v1/packs/{id}/evidence/data-governance` returns the manifest's `[tool.cognic.data_governance]` contract (data classes, purpose, retention, egress allow-list, DLP hooks, consent requirement) plus diff against tenant policy; reviewer rejects if contract violates policy
- `packs/evidence/risk_tier.py` — `GET /api/v1/packs/{id}/evidence/risk-tier` returns declared risk tier, the approval flow this triggers per ADR-014 (single approval / 4-eyes / cross-tenant gate), and a reviewer-acknowledgement field
- `packs/evidence/supply_chain.py` — `GET /api/v1/packs/{id}/evidence/supply-chain` returns SLSA level, provenance verification result, SBOM contents, vuln-scan summary, license-audit result, Sigstore bundle pointer (with retention expiry date) per ADR-016
- `packs/evidence/conformance_matrix.py` — `GET /api/v1/packs/{id}/evidence/conformance` shows the manifest's declared MCP / A2A / AGNTCY-OASF declarations side-by-side with the conformance matrices in `MCP-CONFORMANCE.md` / `A2A-CONFORMANCE.md`

*Audit:*
- Every state transition emits a hash-chained `pack.lifecycle` event with from-state, to-state, actor identity, RBAC scope used, evidence pointer, ISO 42001 control tags
- Every reviewer panel access emits an audit event (examiner-traceable: "who looked at this pack's data-governance contract before approving")

*UI event-stream endpoints (per ADR-020):*
- `protocol/ui_events.py` extension — SSE endpoints `GET /api/v1/ui/runs/{run_id}/events`, `GET /api/v1/ui/tenants/{tenant_id}/events?families=...&since=evt_id`, `GET /api/v1/ui/events/since/{event_id}?run_id=...` (cursor-based catch-up from `decision_history`)
- `POST /api/v1/ui/actions` — frontend-initiated actions (`approve`, `deny`, `cancel_run`, `interrupt`, `resume`, `submit_elicitation`); typed payload; correlation event emitted on the stream within 200ms. **`submit_elicitation` is gated by the same MCP elicitation rules per ADR-020 §"submit_elicitation must obey MCP elicitation rules"**: mode parity with the originating server's manifest (URL-only in Wave 1 default), restricted data-class refusal even when form mode is enabled, Rego evaluation against `elicitation.rego`, audit linkage to the originating tool call.
- RBAC scopes: `ui.run_stream`, `ui.tenant_stream`, `ui.action.<class>` per action family
- Per-tenant connection caps + idle-timeout reaping
- Portable JSON schema published at `/.well-known/cognic-ui-events.json` so any UI in any language can implement the contract

**Tests:**
- `test_lifecycle_state_machine.py` — every valid transition succeeds; invalid transition raises with clear error
- `test_pack_submit.py` — author submits draft; conformance suite runs; evidence attached
- `test_pack_review_approve.py` — reviewer approves; audit event chained
- `test_pack_review_reject.py` — reviewer rejects with categorised reasons; pack returns to `rejected` state
- `test_pack_allow_list.py` — operator allow-lists approved pack on a tenant
- `test_pack_install_invoke.py` — installed pack discoverable via plugin registry; invocation routes through audit
- `test_pack_revoke_preserves_history.py` — revoked pack cannot be invoked; historical audit/evidence records remain queryable
- `test_pack_rbac.py` — author cannot approve own pack; operator cannot review; examiner cannot transition lifecycle
- `test_owasp_conformance.py` — sample malicious pack triggers expected OWASP-class failures
- `test_pack_audit_chain.py` — full draft → installed → revoked chain integrity verifies via Merkle proof
- `test_pack_evidence_data_governance.py` — reviewer fetches data-governance evidence; tenant-policy diff highlights violations; access emits audit event
- `test_pack_evidence_risk_tier.py` — reviewer sees risk tier + the approval flow it triggers; acknowledgement field required before approval
- `test_pack_evidence_supply_chain.py` — reviewer sees SLSA level, SBOM, vuln-scan, license-audit, Sigstore bundle retention date
- `test_pack_evidence_conformance.py` — reviewer sees declared MCP/A2A/AGNTCY-OASF declarations vs matrices; mismatches flagged
- `test_ui_events_sse_run_stream.py` — subscriber receives every event for a run in order; tenant-RBAC enforced
- `test_ui_events_reconnect_catchup.py` — disconnect + reconnect using cursor → no events lost; catch-up pulls from `decision_history`
- `test_ui_events_frontend_action.py` — `approve` action correlates within 200ms; RBAC scope enforced; unknown action class refused
- `test_ui_submit_elicitation_mode_parity.py` — originating server with `elicitation_modes = ["url"]` → form-payload submission refused with `elicitation_mode_not_permitted`; URL completion accepted
- `test_ui_submit_elicitation_data_class_refusal.py` — server with form-mode enabled BUT restricted data class (`customer_pii` / `payment_action` / `regulator_communication`) → form payload refused; Rego policy gate proven
- `test_ui_submit_elicitation_audit_linkage.py` — `elicitation.submission` event chain-linked to originating tool call; payload digest present, payload contents NOT logged
- `test_ui_events_schema_published.py` — `/.well-known/cognic-ui-events.json` returns the published schema; pinned to a version

**Exit criteria:**
- A pack moves through every state transition end-to-end
- RBAC denial of out-of-role transitions
- Revoked pack's invocation history remains queryable
- A bank engineer (simulated via test fixtures) can: submit → reviewer approves → operator installs → invoke → operator revokes — entirely via portal API, no AgentOS code change
- OWASP conformance runs automatically on submit; failures gate approval
- Reviewer cannot approve a pack without acknowledging the data-governance contract, risk tier, and supply-chain evidence panels (enforced server-side, not just UI)

**Phase 2 exit:** AgentOS hosts plugin packs, provides authoring tooling, AND drives the full bank-pack lifecycle through portal APIs. The PROJECT_PLAN §8 success criterion is met: "A bank engineering team can create its own signed tool pack, deterministic skill pack, and A2A-speaking agent pack; install them on AgentOS; and have them operate under the same governance controls as Cognic-authored packs."

---

## Phase 3 — Sandbox (with Resumable Sessions) + Compliance + Model Lifecycle (Sprints 8, 8.5, 9, 9.5, 10, ~10 work-units)

### Sprint 8 — Sandbox primitive *(3 work-units)*

**Goal:** ephemeral isolated execution per ADR-004; tools that touch untrusted code or external systems run in sandboxes.

**Deliverables:**
- `sandbox/__init__.py` — `SandboxBackend` protocol
- `sandbox/dind.py` — Docker-in-Docker reference implementation
- `sandbox/policy.py` — `SandboxPolicy` (CPU, memory, wall-time, egress allow-list, image digest)
- `sandbox/session.py` — `SandboxSession` lifecycle (create → exec → destroy)
- `core/audit.py` integration — sandbox lifecycle events recorded with policy + outcome
- `core/config.py` extension — per-tenant sandbox max policy

**Tests:**
- `test_sandbox_lifecycle.py` — create + exec + destroy works
- `test_sandbox_policy.py` — CPU cap enforced; memory cap enforced; wall-time enforced; egress denied to non-allow-listed host
- `test_sandbox_audit.py` — every lifecycle event hits the audit store
- `test_sandbox_image_pin.py` — wrong image digest → create refused

**Exit criteria:**
- Sandbox session creates in <500ms (P95)
- Resource caps prove-out (deliberate violation → caught + sandbox killed)
- Egress allow-list provably blocks non-listed hosts

### Sprint 8.5 — Resumable session API *(1 work-unit)*

**Goal:** add `checkpoint() / suspend() / wake()` to `SandboxSession` per ADR-004 amendment so long-running multi-step workflows survive harness restarts and operator pause/resume for compliance review. Required for Anthropic-Managed-Agents-style durable sessions before sub-agent work in Sprint 11.

**Deliverables:**
- `sandbox/session.py` extension — `async checkpoint(label: str) -> CheckpointId`, `async suspend()`, `await sandbox.wake(session_id) -> SandboxSession`
- `sandbox/checkpoint_store.py` — overlay-fs snapshot serialiser + env metadata + Vault lease references; persisted via `ObjectStoreAdapter` (introduced Sprint 1C)
- `sandbox/policy.py` extension — `checkpoint_retention_s: int` (default 24h, capped per tenant via `policy.yaml`); enforced by background reaper
- `core/audit.py` extension — `sandbox.checkpoint`, `sandbox.suspend`, `sandbox.wake` events hash-chained into `decision_history`; chain verifier walks suspend → wake transitions to prove no state forgery
- `core/config.py` extension — per-tenant max-checkpoint-age + max-checkpoints-per-session caps
- Reaper job — purges checkpoints past tenant retention; emits audit on purge

**Tests:**
- `test_sandbox_checkpoint.py` — `checkpoint() → suspend() → wake()` round-trip preserves filesystem deltas + env
- `test_sandbox_resume_after_restart.py` — wake works in a fresh process after harness restart
- `test_sandbox_checkpoint_audit_chain.py` — suspend/wake chain integrity verifies via Merkle proof
- `test_sandbox_checkpoint_retention.py` — retention cap enforced; reaper purges expired checkpoints; purge audited
- `test_sandbox_checkpoint_vault_lease_handling.py` — leases re-issued (not re-used) on wake; old lease revoked

**Exit criteria:**
- A sandbox can be suspended in process A and resumed in process B with identical filesystem + env
- Checkpoint round-trip ≤2s P95 for ≤100MB delta
- Audit chain across suspend/wake validates end-to-end
- Per-tenant retention enforced; over-retention attempts refused with clear error

### Sprint 9 — ISO 42001 control mapping *(2 work-units)*

**Goal:** every governance hook tags emitted events with applicable ISO 42001 control IDs; examiner-ready evidence-pack export (per ADR-006).

**Deliverables:**
- `compliance/iso42001/controls.py` — populated registry (initial 8 controls per ADR-006)
- `core/audit.py` extension — `append(event, iso_controls=())` accepts control tags
- `core/decision_history.py` extension — same pattern
- `compliance/iso42001/evidence_pack.py` — `export(period, scope)` returns a tarball: per-control coverage + raw evidence rows + Merkle root + signed manifest
- `portal/api/app.py` — `GET /api/v1/compliance/evidence-pack?from=...&to=...&scope=...`

**Tests:**
- `test_control_mapping.py` — every governance hook emits expected control tags
- `test_evidence_pack.py` — generate pack, validate Merkle root, validate signed manifest
- `test_evidence_pack_completeness.py` — pack contains every audit event in window

**Exit criteria:**
- Generated evidence pack passes external Merkle-root verification (manual cosign verify)
- Initial 8 controls have ≥1 hook tagged each

### Sprint 9.5 — Model Registry primitive *(2 work-units)*

**Goal:** AgentOS tracks the lifecycle of every model it routes a request through (per ADR-013). Metadata + audit layer; no GPU work, no fine-tuning logic. Closes the procurement gap on "which fine-tuned model handled which case" without bringing batch training into the runtime.

**Deliverables:**

*Storage + schema:*
- `src/cognic_agentos/models/__init__.py`, `models/registry.py` — Model record dataclass + lifecycle state machine (`proposed → eval_passed → tenant_approved → serving → deprecated → retired`)
- `models/storage.py` — Postgres-backed model store via `RelationalAdapter`; columns: `model_id`, `base_model`, `version`, `kind` (foundation/fine_tune/adapter/embedding), `recipe_hash`, `training_data_fingerprint`, `eval_results_ref`, `signature_digest`, `serving_endpoint`, `lifecycle_state`, `tenant_scope`, lifecycle history (JSONB)
- `db/migrations/002_model_registry.sql` (Postgres) + `db/migrations/oracle/002_model_registry.sql`

*Portal API endpoints:*
- `POST /api/v1/models` — register new model record (Forge or operator submits this)
- `GET /api/v1/models` — list, filter by tenant + state
- `GET /api/v1/models/{id}` — detail incl. lifecycle history + audit pointer
- `POST /api/v1/models/{id}/promote` — RBAC-gated state transition
- `POST /api/v1/models/{id}/retire` — stop routing on this tenant; preserves history
- `GET /api/v1/models/{id}/audit` — hash-chained audit events for this model
- `GET /api/v1/models/{id}/usage?from&to` — invocation counts derived from `decision_history` (aggregate query)

*RBAC scopes (extends `portal/rbac/`):*
- `model.register` (Forge automation user, registry-publish hook)
- `model.promote.eval_passed` (eval reviewer)
- `model.promote.tenant_approved` (security/compliance reviewer)
- `model.promote.serving` (operator)
- `model.retire` (operator)
- `model.audit.read`, `model.usage.read` (examiner)

*Audit + provider-honesty integration:*
- Every model state transition emits a hash-chained `model.lifecycle` event tagged with ISO 42001 controls (A.6.2.6, A.7.4, A.7.6, A.8.2, A.8.5, A.10.2 per ADR-013)
- `decision_history.append` extended to record `model_id` per call (was: just LiteLLM alias). Decision records become provably linked to the registered model version that handled them.
- `/api/v1/system/effective-routing` (ADR-007) extended: per-tenant recent-call breakdown now shows `model_id` next to the LiteLLM alias

*Signing + cosign verification:*
- `models/trust.py` — verifies model artefact signature against per-tenant trust root before allowing `proposed → eval_passed` transition (same trust gate as packs from ADR-002)
- Models registered without a valid signature stay in `proposed` state and cannot be promoted

*Eval + adversarial gate integration:*
- `tenant_approved` transition refuses unless model's `eval_results_ref` points to an ADR-010 eval-pack-run that passed tenant quality threshold AND an ADR-011 adversarial pass-rate ≥ 0.99

**Tests:**
- `test_model_registry_storage.py` — register, retrieve, list-by-tenant; signature digest stored; recipe-hash determinism
- `test_model_lifecycle_states.py` — every valid transition succeeds; invalid transition raises with clear error
- `test_model_promote_unsigned.py` — unsigned model cannot be promoted past `proposed`
- `test_model_promote_eval_gate.py` — promotion to `tenant_approved` refused without ADR-010 eval pass + ADR-011 adversarial pass
- `test_decision_history_model_id.py` — every decision record after Sprint 9.5 records the `model_id` that handled it
- `test_provider_honesty_model_id.py` — `/effective-routing` response includes per-call `model_id`
- `test_model_audit_chain.py` — full proposed → serving → retired chain integrity verifies via Merkle proof
- `test_model_rbac.py` — Forge user cannot promote past `proposed`; reviewer cannot transition to `serving`; examiner cannot transition lifecycle

**Exit criteria:**
- A model record moves through every lifecycle state end-to-end via portal API
- `decision_history` rows after Sprint 9.5 carry `model_id` linking back to the registered record
- `/effective-routing` shows the registered model identity per call (not just the LiteLLM alias)
- An unsigned model cannot reach `serving`; signing failure is auditable
- ISO 42001 control tags emit correctly on every lifecycle transition
- Cognic Forge (future Wave 2 product) can register a fine-tuned model end-to-end via the published API contract — no AgentOS code change required when Forge ships

### Sprint 10 — Vault credential leasing *(2 work-units)*

**Goal:** sandboxes get short-TTL credentials from Vault scoped to one operation; revoked at sandbox destroy.

**Deliverables:**
- `core/vault.py` — `lease_credential(secret_path, ttl_s)` returns lease + token; `revoke(lease_id)`
- `sandbox/session.py` extension — `create()` accepts `requires_credentials: list[VaultLeaseRequest]`; injects + revokes
- Policy schema for per-tenant max credential TTL

**Tests:**
- `test_vault_lease.py` — lease + use + revoke
- `test_sandbox_credential_lifecycle.py` — sandbox destroy revokes leases
- `test_credential_ttl_cap.py` — request beyond per-tenant max → refused

**Exit criteria:**
- Credentials provably revoked when sandbox destroyed
- Per-tenant TTL caps enforced

**Phase 3 exit:** AgentOS provides bank-grade isolation + audit-evidence-export ready for examiner + model lifecycle registry that closes the "which fine-tuned model handled which case" procurement gap. Future-product hook (Cognic Forge — Wave 2 separate repo per ADR-013) can publish fine-tuned models into the registry end-to-end.

---

## Phase 4 — Sub-agent + Memory Governance + Quality Gates + Policy + Kill Switches + Deploy (Sprints 11, 11.5, 12, 13, 13.5, 14, 15, ~16 work-units)

### Sprint 11 — Sub-agent primitive *(3 work-units)*

**Goal:** dynamic delegation per ADR-005; orchestrator-worker spawning with isolated context + privilege de-escalation.

**Deliverables:**
- `subagent/__init__.py` — `SubAgent` primitive
- `subagent/spawn.py` — A2A-backed `invoke(prompt)` flow
- `subagent/policy.py` — depth, budget, tool-allow-list narrowing
- `core/decision_history.py` extension — child record links to parent's chain hash
- Harness extension — `spawn_subagent(...)` exposed to agent packs

**Tests:**
- `test_subagent_spawn.py` — parent agent spawns child, child returns result, parent context unchanged
- `test_subagent_privilege.py` — child cannot escalate to a tool parent didn't have
- `test_subagent_depth.py` — depth-4 spawn beyond `max_depth=3` → escalation triggered
- `test_subagent_budget.py` — exceeding token budget → child terminated + parent informed
- `test_subagent_audit_chain.py` — Merkle proof over parent + child events verifies

**Exit criteria:**
- Cross-agent audit chain verifiable
- Privilege escalation provably blocked

### Sprint 11.5 — Agent memory governance *(2 work-units)*

**Goal:** ship `core/memory/` per ADR-019 — the governed memory API every Layer C agent uses for `remember / recall / forget / redact / export / list_for_subject`. Three tiers (`scratch` / `task` / `long_term`); default-deny for `long_term`; per-write data-class + purpose + consent enforcement; chain-linked audit; regulator-erasure pathway. Lands before Sprint 12 so the eval harness can exercise memory-aware agents.

**Deliverables:**
- `core/memory/__init__.py`, `memory/api.py` — `MemoryAPI` with the six operations; injected into every Layer C agent via the harness; direct DB access from Layer C is architecturally forbidden (architecture-discipline test enforces)
- `memory/tiers.py` — `MemoryTier` enum (`scratch`, `task`, `long_term`) + per-tier policy defaults
- `memory/storage.py` — `MemoryAdapter` protocol + `PostgresMemoryAdapter` (relational; per-tenant schema; tier columns + JSONB value) + `RedisMemoryAdapter` (scratch-only, sub-second TTL)
- `memory/vector.py` — `VectorStoreAdapter` integration (Qdrant default per ADR-009) for semantic recall; data-class metadata co-stored for per-purpose filtering
- **`core/dlp/__init__.py`, `core/dlp/scanner.py` (minimal seed; expanded in Sprint 13.5)** — write-time DLP scanner so memory writes have classification at registration. Scope of this seed:
  - Pluggable `DLPScanner` protocol; reference implementation uses Microsoft Presidio (or equivalent) with pinned recogniser set for: `customer_pii` (names, IDs, emails, phone numbers), `payment_action` (card numbers, IBANs, SWIFT codes), `regulator_communication` (regulator-name dictionary)
  - Returns `DLPVerdict { detected_classes, redaction_spans, confidence }`
  - Used by `memory/api.remember()` to enforce the consent-token requirement on restricted classes
  - Sprint 13.5 extends with: post-call DLP on tool outputs, custom recogniser plugins, per-tenant recogniser allow/deny lists. The runtime hook integration with the harness's tool-call boundary is **explicitly Sprint 13.5 scope** — Sprint 11.5 only wires the scanner into memory writes
- `memory/consent.py` — `ConsentToken` validator; ledger event chain-linked per write/recall
- `memory/forget.py` — soft-delete with tombstone + reaper; `forget(reason="regulator_erasure")` triggers immediate purge with `memory.regulator_erasure` chain-of-custody event
- `memory/redact.py` — partial-redaction engine; old version sealed until tombstone window expires
- `memory/export.py` — Sigstore-bundled archive per ADR-016 retention rules; RBAC `memory.export.read` required
- `core/audit.py` extension — `memory.write` / `memory.read` / `memory.forget` / `memory.redact` / `memory.regulator_erasure` events with ISO 42001 control tags (A.7.4, A.8.2, A.8.5, A.10.2 per ADR-019)
- **`core/emergency/__init__.py`, `core/emergency/kill_switches.py` (minimal seed; expanded in Sprint 13.5)** — Redis-backed kill-switch state so `memory.write_freeze` works at Sprint 11.5 ship time. Scope of this seed:
  - Single kill-switch class: `memory.write_freeze` (per-tenant); checked by `memory/api.remember()` before every write
  - Redis key format reused by Sprint 13.5 (no schema migration when full kill-switch + quotas land)
  - **Fail-closed identical to Sprint 13.5 final**: Redis unreachable → memory writes refused after ≤60s of cached-state grace
  - Sprint 13.5 extends with the other kill-switch classes (`pack`, `tool`, `model`, `tenant_packs`, `tenant_full`, `cloud`, `feature`) + quotas + portal API + full RBAC scope set. Sprint 11.5 ships only `emergency.kill.memory_write_freeze` RBAC scope; the rest are deferred
- `policies/_default/memory.rego` + `policies/_default/memory_purpose_matrix.rego` — **ship default-deny per ADR-019** (long-term writes refused, cross-subject recall refused, restricted-data-class writes refused). Tenant override via local Rego layer is the only way to permit. Sprint 13.5 expands the bundle (more granular rule decomposition + audit-trail integration) but does NOT relax the defaults. **Never stub permissive — that would silently authorise long-term memory writes the moment Sprint 11.5 ships.** Reuses the Sprint 4 policy-engine seed.
- `db/migrations/003_memory.sql` (Postgres) + `db/migrations/oracle/003_memory.sql` (Oracle)
- Portal API: `GET /api/v1/memory/records?subject=...`, `POST /api/v1/memory/records/{id}/forget`, `POST /api/v1/memory/records/{id}/redact`, `POST /api/v1/memory/export` (RBAC-gated)
- RBAC scopes: `memory.read`, `memory.write.scratch`, `memory.write.task`, `memory.write.long_term`, `memory.forget`, `memory.redact`, `memory.export.read`, `memory.regulator_erasure`
- SDK helper (`agentos_sdk.memory`) — typed wrappers so pack authors don't roll their own
- **UI event-stream `memory` family wired (per ADR-020)** — emit `recall_started`, `recall_completed`, `forget`, `redact` events on the stream so memory-aware UIs can render redaction badges + recall provenance
- **Approval-engine transitional rule (mirrors Sprint 5 MCP rule per ADR-014)**: between Sprint 11.5 ship and Sprint 13.5 (when `core/approval` lands), `long_term` writes from packs with `risk_tier >= customer_data_write` are **refused** with error `memory_approval_engine_not_available`. The write attempt is audit-logged with declared tier so banks can plan rollout. `scratch` and `task` tier writes work normally; `long_term` writes from `read_only` / `internal_write` packs work normally. Sprint 13.5 lifts the refusal by routing high-risk `long_term` writes through `core/approval` (same flow as MCP tool calls). Removal of the transitional rule is itself an audit event (`memory_approval.engine_enabled`) so the cutover is provable.

**Tests:**
- `test_memory_api_six_operations.py` — every operation works for the happy path
- `test_memory_tier_default_deny.py` — `long_term` write without manifest declaration → refused; with declaration but tenant policy denies → refused; both pass → accepted
- `test_memory_data_class_consent.py` — restricted data class + missing consent token → refused; valid consent → accepted with consent ledger event chain-linked
- `test_memory_purpose_alignment.py` — write with purpose A; recall with mismatched purpose → refused per `memory_purpose_matrix.rego`
- `test_memory_cross_subject_recall.py` — recall for Subject B in agent serving Subject A → refused unless `cross_subject_recall = true` AND tenant override
- `test_memory_forget_tombstone.py` — forget produces tombstone; subsequent recall returns miss; reaper purges after tenant window
- `test_memory_regulator_erasure.py` — `forget(reason="regulator_erasure")` triggers immediate purge + `memory.regulator_erasure` event with chain-of-custody fields
- `test_memory_redact.py` — partial redaction produces new version; old version sealed; tombstone window enforced
- `test_memory_export_rbac.py` — export without RBAC scope → refused; with scope → produces Sigstore-bundled archive
- `test_memory_audit_chain.py` — full write → recall → redact → forget chain integrity verifies via Merkle proof
- `test_memory_layer_c_no_direct_access.py` — architecture test: any Layer C module importing `memory.storage` directly → fails
- `test_memory_write_freeze_kill_switch.py` — flipping `memory.write_freeze` immediately blocks subsequent writes; reads still work; flip audit-chained
- `test_memory_high_risk_long_term_refused_pre_13_5.py` — pack with `risk_tier = "customer_data_write"` attempting `long_term` write → refused with `memory_approval_engine_not_available`; same pack's `task` and `scratch` writes succeed; `read_only` pack's `long_term` write succeeds; refusal audit-logged with declared tier

**Exit criteria:**
- All six MemoryAPI operations work end-to-end for all three tiers
- Default-deny long-term enforced; cross-subject recall enforced
- Regulator-erasure pathway provably purges + emits chain-of-custody event
- Layer C agents cannot bypass MemoryAPI (architecture test green)
- Memory events flow into ISO 42001 evidence-pack export
- `memory.write_freeze` kill switch tested; fail-closed under Redis loss

### Sprint 12 — Evaluation harness *(2 work-units)*

**Goal:** First-class evaluation infrastructure per ADR-010. Banks can bulk-test agent packs against their case corpus before promoting to production.

**Deliverables:**
- `eval/__init__.py` + `eval/runner.py` — bulk test executor; runs an agent pack against a corpus; reports per-case pass/fail + aggregate accuracy + latency P50/P95
- `eval/scenarios.py` — declarative YAML scenario loader (multi-turn conversations with `expects` clauses for tool calls, sub-agent spawns, citations, escalations)
- `eval/storage.py` — `eval_runs` + `eval_case_results` Postgres tables; uses RelationalAdapter (per ADR-009)
- `eval/cli.py` — `agentos eval bulk --pack ... --corpus ...` extension to the `agentos-cli` from Sprint 7
- `portal/api/app.py` extension — `POST /api/v1/eval/bulk-run` + `GET /api/v1/eval/runs/{run_id}` endpoints
- `eval/corpora/example/` — reference corpus (PolicyQA scenarios) demonstrating the YAML format

**Tests:**
- `test_eval_bulk_runner.py` — runs corpus against a stub agent; reports correct aggregate
- `test_eval_scenario_yaml.py` — YAML scenarios parse + validate against schema
- `test_eval_storage.py` — eval runs persist; per-case results queryable
- `test_eval_endpoint.py` — POST + GET round-trip
- `test_eval_iso_tagging.py` — eval events emit with ISO 42001 control tags (A.7.6, A.9.2)

**Exit criteria:**
- `agentos eval bulk` runs a 10-case corpus against a stub agent pack in <30s
- Aggregate report includes pass-rate, latency, citation faithfulness, regulatory verdict distribution
- Eval-run hash-chained into `decision_history`

### Sprint 13 — LLM-judge + live replay + adversarial testing *(2 work-units)*

**Goal:** Complete the evaluation harness with explainable LLM verdicts + production-case replay (per ADR-010), and ship the adversarial test generator + promotion gate (per ADR-011).

**Deliverables:**

*Eval harness completion (per ADR-010):*
- `eval/judge.py` — LLM-as-judge runs through governed gateway with rubric-driven scoring; emits per-dimension score + explanation paragraph; hash-chained `eval.judge_verdict` events
- `eval/replay.py` — pull a `decision_history` row by id; re-run against a candidate pack version; diff outcome (answer, citations, compliance score, tool-call sequence)
- `eval/cli.py` extension — `agentos eval replay --case-id ... --pack ... --baseline ...`
- `portal/api/app.py` extension — `POST /api/v1/eval/replay` + `POST /api/v1/eval/judge`

*Adversarial testing (per ADR-011):*
- `eval/adversarial/__init__.py` — adversarial corpus loader
- `eval/adversarial/templates.py` — curated attack templates across 10 categories (prompt injection, jailbreak, PII extraction, tool hijacking, sub-agent escalation, etc.)
- `eval/adversarial/mutator.py` — paraphrase / unicode-confusion / encoding mutation engine
- `eval/adversarial/runner.py` — runs adversarial corpus through the same eval runner (Sprint 12); checks **refusal correctness + guardrail trip events**
- `eval/corpora/adversarial/` — bundled Cognic-published adversarial corpus (initial ~50 cases across categories)

*Promotion gate integration (per both ADRs):*
- `eval/promotion_gate.py` — packs cannot promote dev → stage → prod unless: bulk-test pass-rate ≥ tenant threshold, judge aggregate ≥ tenant threshold, adversarial pass-rate ≥ 0.99 (configurable), zero new attacks succeed vs baseline
- RBAC scope `override.adversarial_gate` for explicit operator override (audit-logged)

**Tests:**
- `test_eval_judge.py` — judge produces score + explanation; output hash-chained
- `test_eval_replay.py` — replay against an older pack version → diff highlights output drift
- `test_adversarial_corpus.py` — 50 attack templates → ≥45 produce semantically distinct test cases after mutation
- `test_adversarial_pass.py` — agent that correctly refuses → adversarial pass-rate = 1.0
- `test_adversarial_fail.py` — deliberately weakened agent → specific category failures detected + categorised
- `test_promotion_gate.py` — pack with 0.7 quality + 0.99 adversarial → promotion refused (quality fail); pack with 0.95 quality + 0.95 adversarial → promotion refused (adversarial below 0.99)
- `test_override_audit.py` — operator override produces audit record with reason + RBAC scope

**Exit criteria:**
- LLM judge scores 100 cases in <2 minutes against a vLLM endpoint
- Replay shows visible diff for an intentionally-changed agent prompt
- Adversarial corpus catches a deliberately-introduced jailbreak vulnerability
- Promotion gate refuses a pack failing either quality or adversarial threshold; allows when both pass; logs explicit override

### Sprint 13.5 — Runtime tool approval + Policy-as-code + Emergency controls *(3 work-units)*

**Goal:** ship the three Phase-4 governance layers (per ADR-014, ADR-015, ADR-018) that turn pack approval from a one-time event into an ongoing operational control.

**Deliverables:**

*Runtime tool approval (per ADR-014):*
- `core/approval/__init__.py`, `approval/engine.py` — approval state machine; create / wait / grant / grant-second / deny / expire
- `approval/storage.py` — Postgres-backed approval store via `RelationalAdapter`; expiry via background sweeper
- Portal API: `POST /api/v1/approvals`, `GET /api/v1/approvals?status=pending`, `GET /api/v1/approvals/{id}`, `POST /api/v1/approvals/{id}/grant`, `POST /api/v1/approvals/{id}/grant-second`, `POST /api/v1/approvals/{id}/deny`, `GET /api/v1/approvals/history`
- Harness integration: every tool call's `risk_tier` (declared in pack manifest per ADR-002) gates the call through `approval.engine` before MCP host dispatch
- **Removes the Sprint 5 transitional refusal**: `protocol/mcp_host.call_tool` no longer hard-refuses high-risk tier invocations; instead it routes them through `approval.engine`. The cutover itself is an audit event (`tool_approval.engine_enabled`) emitted at module-load so banks can prove the moment high-risk tools became invocable.
- RBAC scopes: `tool.approve.customer_data`, `tool.approve.payment` (4-eyes), `tool.approve.regulator` (4-eyes), `tool.approve.cross_tenant`, `tool.approve.observe`

*Policy-as-code (per ADR-015):*
- **`core/policy/engine.py` extension** — extends the Sprint 4 seed evaluator with hot-reload (bundle ETag change → reload + audit event; in-flight evaluations see new bundle ≤60s), decision-trail API, and extends the bundle set
- `policies/_default/` — Cognic-published default Rego bundles complete set: `supply_chain.rego` (Sprint 4), `memory.rego` + `memory_purpose_matrix.rego` (Sprint 11.5), plus this sprint adds `packs.rego`, `models.rego`, `tools.rego`, `sandbox.rego`, `subagent.rego`, `lifecycle.rego`, `sampling.rego`, `shared.rego`
- Refactor existing inline checks (Sprint 7B lifecycle, Sprint 8 sandbox egress, Sprint 11 sub-agent spawn, Sprint 9.5 model promotion) to delegate to `policy.engine.evaluate(decision, input)`. Sprint 4 trust gate and Sprint 11.5 memory enforcement already delegate (via the seed) — this sprint just expands their bundles, no refactor needed
- Portal API: `GET /api/v1/policy/decisions/{trace_id}` returns the per-decision audit trail (which rule matched, what input, what outcome)
- Bundle versioning: each bundle has a content hash; loading a new bundle emits `policy.bundle_loaded` event hash-chained into decision_history

*Emergency controls (per ADR-018):*
- **Extends** the Sprint 11.5 `core/emergency/` seed (which shipped `memory.write_freeze` only) with the full kill-switch class set: `pack`, `tool`, `model`, `tenant_packs`, `tenant_full`, `cloud`, `feature`. Same Redis schema, same fail-closed semantics — only the class enum and the harness call sites grow
- `emergency/quotas.py` — quota classes (tokens, spend, invocations, recursion-depth) accumulating from gateway-call ledger (per ADR-007)
- Portal API: `GET /api/v1/emergency/kill-switches`, `POST /api/v1/emergency/kill-switches`, `DELETE /api/v1/emergency/kill-switches/{key}`, `GET /api/v1/quotas?tenant=...`, `PUT /api/v1/quotas/{class}/{scope}`
- RBAC scopes: `emergency.kill.pack`, `emergency.kill.tool`, `emergency.kill.model`, `emergency.kill.tenant_packs`, `emergency.kill.tenant_full`, `emergency.kill.cloud`, `emergency.kill.feature`, `quota.override.<class>`
- Fail-closed behaviour: if Redis is unreachable, harness uses last-cached state for ≤60s then refuses all invocations (does NOT default permissive)
- All flips and overrides emit `emergency.kill_switch_flipped` / `quota.override` events tagged with ISO 42001 A.6.2.5 + A.9.2

*UI event-stream extension (per ADR-020):*
- Wire `approval` family (`pending`, `granted`, `granted_second`, `denied`, `expired`), `policy` family (`decision_evaluated`, `bundle_loaded`), `kill_switch` family (`flipped`, `reverted`) onto the live event stream. These all ship in 13.5 anyway; ADR-020 just mandates the typed-event mirroring

**Tests:**
- `test_approval_state_machine.py` — every transition path; expiry; 4-eyes distinctness check
- `test_approval_rbac.py` — denial when scope missing
- `test_approval_4_eyes.py` — second grant from same user → refused
- `test_policy_engine_evaluate.py` — Rego query returns expected decision; rule-matched recorded
- `test_policy_bundle_hot_reload.py` — bundle ETag change triggers reload + audit event; in-flight calls see new bundle ≤60s
- `test_policy_default_bundles.py` — every default bundle parses + passes its own example inputs
- `test_kill_switch_propagation.py` — flip a switch; harness rejects within ≤30s P99 across 100 simulated in-flight invocations
- `test_kill_switch_fail_closed.py` — Redis unreachable >60s → harness refuses all calls (no permissive fallback)
- `test_quota_enforcement.py` — soft warn at 80%, hard refuse at 100%, override extends with audit
- `test_emergency_audit_chain.py` — full kill-switch flip → reject → revert → restore audit chain integrity verifies via Merkle proof
- `test_high_risk_tier_unblocked_post_13_5.py` — pack registered in Sprint 5 with `risk_tier = "customer_data_read"` was refused at invocation; after Sprint 13.5 module-load, the same pack invocation succeeds (subject to approval flow); `tool_approval.engine_enabled` audit event is present at the cutover
- `test_memory_high_risk_long_term_unblocked_post_13_5.py` — pack with `risk_tier = "customer_data_write"` was refused at `long_term` write before 13.5; after 13.5 module-load, the same write succeeds (subject to approval flow); `memory_approval.engine_enabled` audit event is present at the cutover

**Exit criteria:**
- Runtime tool approval enforces all 8 risk tiers; 4-eyes distinctness verified
- Policy engine has 6 default bundles loaded; every Sprint 4 / 7B / 8 / 9.5 / 11 / 13.5 inline check refactored to delegate
- Kill switches propagate within 30s P99
- Quotas accumulate from the gateway-call ledger correctly; soft/hard thresholds fire as designed
- Fail-closed Redis behaviour proven (deliberate Redis kill → harness refuses; restart → harness recovers)
- 10 new tests green on top of Sprint 13's eval/adversarial suite

### Sprint 14 — Per-tenant deployment kit *(2 work-units)*

**Goal:** banks can deploy AgentOS into their own environment with one command.

**Deliverables:**
- `infra/deploy/helm/cognic-agentos/` — Helm chart (Postgres + Qdrant + Vault + LiteLLM + AgentOS as deployment)
- `infra/deploy/compose/` — docker-compose for kind clusters or smaller deployments
- `infra/deploy/bank-overlay-template/` — scaffold for bank to fork: `theme.css`, `oidc.yaml`, sample CBS-adapter pack
- `docs/DEPLOY.md` — operator runbook (install → register pack → smoke → trace verification)
- `infra/deploy/secrets-template.yaml` — Vault paths the deployment expects

**Tests:**
- `test_helm_render.py` — helm template produces valid k8s manifests
- Manual: deploy to kind cluster locally, confirm smoke

**Exit criteria:**
- Helm chart installs cleanly in kind
- `helm install ... && kubectl exec ... -- curl localhost:8000/api/v1/healthz` returns 200

### Sprint 15 — End-to-end POC *(2 work-units)*

**Goal:** prove the full pattern works — extract one real tool from parent cognic, ship as MCP pack, install on AgentOS, run a real query through the full audit chain.

**Deliverables:**
- New repo: `cognic-tool-search` (extracted from parent cognic's `tools/search/`)
  - MCP server wrapping `search_circulars`
  - cosign signing in CI
  - Published image
- New repo: `cognic-agent-policyqa` (extracted from parent cognic's `agents/policy_qa/`)
  - A2A-speaking agent pack
  - Declares dependency on `cognic-tool-search`
  - Published image
- AgentOS integration test: install both packs into a kind cluster, run them through the **full quality + adversarial gate** (Sprints 12-13), query "What is CAR?", verify:
  - Decision-history record created
  - Chain hash valid
  - Tool invocation audited with pack signature digest
  - Citations verified
  - Evidence pack exportable
  - Eval bulk-run report generated
  - Adversarial corpus pass-rate reported
- `docs/POC-RESULTS.md` — what worked, what didn't, what changes if we want to onboard a real bank

**Exit criteria:**
- End-to-end query succeeds against a real bank-style knowledge base
- All governance hooks fire and tag with correct ISO 42001 controls
- Eval harness + adversarial gate run on the extracted packs (proof the platform's quality story is live, not theoretical)
- Examiner could in principle audit the run without ever logging into AgentOS

**Phase 4 exit:** Cognic AgentOS is bank-deployable with **first-class quality gates**. SDK ships with the platform. Pack promotion is gated by automated quality + adversarial tests. Engineers (Cognic, banks, ecosystem) can author packs end-to-end.

---

## Phase 5 — AgentOS Studio (Sprints 16-21, ~13 work-units) *(deferred)*

Per ADR-008 Phase B. Ships only after Phase 4 stabilises and bank demand is confirmed. Adds a no-code authoring UI inside AgentOS for non-engineer users.

### Sprint 16 — Studio API + storage *(2 work-units)*

**Goal:** Studio-authored pack definitions persist in AgentOS; CRUD endpoints for tools/skills/agents.

**Deliverables:** `studio/api/` endpoints, `studio/storage/` (Postgres-backed pack-definition store), `studio/compiler/` (compiles pack definition → wheel), Studio-specific RBAC scopes added to `portal/rbac/`.

### Sprint 17 — Studio trust model + ADR-021 *(2 work-units)*

**Goal:** Studio-authored packs sign with the AgentOS instance key, separate trust root from externally-published packs.

**Deliverables:** ADR-021 (Studio trust model — drafted at Phase 5 entry; ADR-014 through ADR-020 are claimed by runtime tool approval / policy-as-code / supply-chain / data governance / emergency controls / agent memory governance / UI event-stream contract), instance-key provisioning, per-tenant Studio-author allow-list, audit fields for "authored-by-Studio + author-identity".

### Sprint 18 — Studio UI shell + tool authoring *(3 work-units)*

**Goal:** Web UI at `/studio/` where users see existing packs and create new tools by composing primitives.

**Deliverables:** `studio-ui/` separate React artefact (mirrors portal-ui pattern), tool-authoring wizard, primitive library (DB query, HTTP call, regex, transform), live validation against MCP schema.

### Sprint 19 — Skill composition view *(2 work-units)*

**Goal:** Visual skill builder — drag-drop tools into a deterministic flow.

### Sprint 20 — Agent authoring view *(2 work-units)*

**Goal:** Declare an agent: prompt, allowed tools, sub-agent permissions, ISO 42001 control declarations.

### Sprint 21 — Promotion workflow *(2 work-units)*

**Goal:** Studio-authored packs flow dev → stage → prod via 4-eyes RBAC-gated workflow (now uses Sprint 13's promotion-gate machinery + Studio-specific RBAC).

**Phase 5 exit:** Non-engineer users can author + promote packs without writing code. Adds ~10-12 calendar weeks if pursued.

---

## Cross-cutting commitments

These hold for every sprint:

| Commitment | Mechanism |
|---|---|
| **No pack imports in OS code** | `tests/unit/architecture/test_no_pack_imports.py` runs in CI |
| **No mock-runtime in production paths** | CLAUDE.md production-grade rule; CI lints for `mock`/`fake`/`stub` strings outside test paths |
| **Every governance hook tagged with ISO 42001 controls** | `compliance/iso42001/controls.py` is single source of truth; missing tags caught in test |
| **Hash-chain integrity** | `chain_verifier` runs at every test setup; suite refuses to start if integrity broken |
| **No commit if tests red** | git pre-commit hook |
| **No push without explicit human authorisation** | per CLAUDE.md governance rules |

---

## Schedule-risk acknowledgement

Seven sprints in the current plan are sized **optimistically** at the work-units shown; treat them as floors, not ceilings. If any of them runs over by ≥1 work-unit, stop and split rather than push through:

| Sprint | Risk | Why |
|---|---|---|
| **Sprint 1D — Enterprise adapters** (2 wu) | Oracle adapter alone (SQLAlchemy + python-oracledb async + dialect-specific migrations + Oracle XE compose overlay + integration test job) is realistically ~1.5 wu on its own. Dynatrace adapter + OpenAI-compat embedding adapter add another 1-2 wu. **Realistic range: 2-3.5 wu.** Mitigation: split into 1D-Oracle + 1D-Observability + 1D-Embedding if it overruns Day 2. |
| **Sprint 5 — MCP host (with OAuth/PRM)** (3.5 wu) | Streamable HTTP transport + STDIO restricted (4-gate) + OAuth/PRM client + capability validator + audit-chain integration + 14 distinct test files. **Realistic range: 3.5-5 wu.** Mitigation: split into 5a-transports + 5b-authorization + 5c-capability-validator if it overruns Day 4. |
| **Sprint 7A — agentos-sdk + agentos-cli** (2 wu) | Original 2-wu envelope expanded with AGNTCY/OASF identity validation + A2A/MCP conformance declaration validation + data-governance contract validation + risk-tier consistency + supply-chain attestation paths — 6 new validators. **Realistic range: 2-3 wu.** Mitigation: split into 7A-cli-base + 7A-validators if it overruns Day 2. |
| **Sprint 7B — Bank pack lifecycle + UI event-stream endpoints** (3.5 wu) | 11 lifecycle states × ~30 portal endpoints × RBAC scopes × OWASP conformance integration × **four reviewer evidence panels (data governance, risk tier, supply chain, conformance)** × **UI event-stream SSE endpoints + frontend-action POST + portable JSON schema** × audit chain linkage × five-gate approval composition. State-machine surface area is the largest single sprint in the plan. **Realistic range: 3.5-5.5 wu.** Mitigation: split into 7B-state-machine-and-storage + 7B-portal-API + 7B-evidence-panels + 7B-ui-events if it overruns Day 3. |
| **Sprint 9.5 — Model Registry** (2 wu) | New entity type + ~7 portal endpoints + 7 RBAC scopes + ISO 42001 control tagging + decision_history schema extension + provider-honesty endpoint extension + cosign verification + eval/adversarial gate integration. **Realistic range: 2-3 wu.** Mitigation: split into 9.5a-storage-and-API + 9.5b-gate-integration if it overruns Day 2. |
| **Sprint 11.5 — Agent memory governance** (2 wu) | New platform primitive: 6 MemoryAPI operations × 3 tiers × per-write enforcement (data-class + purpose + consent) × forget/redact/export pathways × kill-switch integration × Postgres + Redis adapters + vector-store integration. 12 new tests including regulator-erasure chain-of-custody. **Realistic range: 2-3.5 wu.** Mitigation: split into 11.5a-api-and-storage + 11.5b-enforcement-and-erasure if it overruns Day 2. |
| **Sprint 13.5 — Approval + Policy + Kill switches** (3 wu) | Three new platform primitives in one sprint: runtime tool approval state machine + OPA/Rego integration + Redis-backed kill-switch + quotas + 6 portal API surfaces + 10 new tests including fail-closed paths. **Realistic range: 3-5 wu.** Mitigation: split into 13.5a-approval + 13.5b-policy + 13.5c-emergency if it overruns Day 3. |

The 52.5-work-unit Phases-1-4 total assumes these sprints land at their floor estimates. If any overrun → recompute total. **Don't push through a red sprint to keep the calendar; the ADR enforcement architecture makes recovery expensive once code is in.**

### Treat 52.5 wu as a disciplined lower bound, not a commitment

This number is the floor across **seven** already-flagged-optimistic sprints (1D, 5, 7A, 7B, 9.5, 11.5, 13.5). The seven flagged sprints sum to 18 wu at the floor and 28 wu at the ceiling — a Δ of 10 wu. So Phases 1-4 realistic envelope = **52.5 wu floor, ~57 wu midpoint, ~62.5 wu ceiling** if every flagged sprint hits its ceiling. That is not a forecast — it is the honest envelope.

For external commitments (procurement schedules, examiner timelines, board updates), use:

| Posture | Number to use |
|---|---|
| **Internal velocity tracking** | 52.5 wu (the floor) |
| **Bank stakeholder commitment** | 57 wu (midpoint; allows ~half the flagged sprints to overrun) |
| **Procurement / regulatory deadline** | 62.5 wu (ceiling; no sprint splits required) |

Calendar translation (~3-4 wu per week solo + Claude-Code throughput):
- Floor: 13-14 weeks focused / 18-22 calendar
- Mid: 14-16 weeks focused / 20-25 calendar
- Ceiling: 16-18 weeks focused / 24-29 calendar

**Anyone quoting "Phases 1-4 in ~18 weeks" is quoting the floor** — say so explicitly when escalating. Don't let "the plan said 18 weeks" become a commitment that breaks under the first sprint overrun.

## Total budget

| Phase | Sprints | Work-units | Calendar |
|---|---|---|---|
| **1 Foundation** | 1A, 1B, 1C, 1D, 2, 3 | 12 | ~2.5-3 weeks |
| **2 Protocol + SDK + Pack Lifecycle + UI Event-Stream** | 4, 5, 6, 7A, 7B | 14.5 | ~3-3.5 weeks |
| **3 Sandbox (with Resumable Sessions) + Compliance + Model Lifecycle** | 8, 8.5, 9, 9.5, 10 | 10 | ~2-2.5 weeks |
| **4 Sub-agent + Memory Governance + Quality Gates + Policy + Kill Switches + Deploy** | 11, 11.5, 12, 13, 13.5, 14, 15 | 16 | ~3.5 weeks |
| **Phases 1-4 total** | 21 sub-sprints | **52.5 work-units** | **~12-13 weeks focused / 18-22 calendar** |
| **5 Studio (deferred)** | 16-21 | 13 | +3 weeks focused / +5-6 calendar |
| **Including Studio** | 27 sub-sprints | **65.5 work-units** | **~15-16 weeks focused / 23-27 calendar** |

Phases 1-4 are the bank-deployable platform. Phase 5 ships only after Phase 4 stabilises and Studio is explicitly demanded.

**Why the totals went up since the prior revision:** Sprint 8.5 (Resumable Session API per ADR-004 amendment) added 1 wu in Phase 3; Sprint 13.5 (Runtime tool approval + Policy-as-code + Emergency controls per ADR-014/015/018) added 3 wu in Phase 4; Sprint 11.5 (Agent memory governance per ADR-019) added 2 wu in Phase 4; Sprint 4 picked up the policy-engine seed (+0.5 wu); Sprint 6 picked up the UI-events stub (+0.5 wu); Sprint 7B picked up the UI-events SSE endpoints + frontend-action POST (+0.5 wu); MCP auth picked up WWW-Authenticate + step-up + audience validation; A2A picked up signed-Agent-Card verification + correct absent-header rule. Most increases sit inside existing sprint envelopes — flagged in "Schedule-risk acknowledgement" if any overruns.

---

## Decision points

Before each phase starts, decide:

| Phase | Decision |
|---|---|
| **Before Sprint 1** | ✅ resolved — repo at `/Users/bmz/development/cognic-agentos/`, distribution `cognic-agentos`, push to private `bmzee/cognic-agentos` after first commit |
| **Before Sprint 4** | Cosign trust-root provisioning model — Vault path layout |
| **Before Sprint 7** | SDK CLI distribution — bundle in main image vs separate `cognic-agentos-cli` PyPI package |
| **Before Sprint 8** | Sandbox backend choice for Wave 1 — DinD vs gVisor vs Firecracker |
| **Before Sprint 11** | Sub-agent recursion depth default — global, per-tenant, or per-agent |
| **Before Sprint 12** | Target bank for the first POC deployment (drives bank-overlay template content) |
| **Before Phase 5** | Confirm Studio demand — only proceed if a bank explicitly asks for no-code authoring |

---

## Sprint 1A ready to start

All prerequisites resolved:
- Repo location: `/Users/bmz/development/cognic-agentos/` (this folder; doctrine + 20 ADRs + 2 conformance matrices + lessons + PROJECT_PLAN + BUILD_PLAN in place)
- Python distribution: `cognic-agentos`
- Python import: `cognic_agentos`
- GitHub remote: `bmzee/cognic-agentos` (private), pushed after Sprint 1A commit lands
- Sprint 1 split into 1A/1B/1C/1D per the critique — clean bootstrap before observability before adapters before enterprise adapters
- Sprint 5 MCP host design includes the STDIO threat model + four-gate restriction (per ADR-002 amendment + PROJECT_PLAN §5)
- Sprint 7 split into 7A (SDK/CLI) and 7B (lifecycle APIs per ADR-012)

Say "go Sprint 1A" to begin execution.
