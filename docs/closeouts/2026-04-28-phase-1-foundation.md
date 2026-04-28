# Phase 1 Foundation — Closeout Note

**Date:** 2026-04-28
**Sprints closed:** 1A (bootstrap) + 1B (observability) + 1C (adapter protocols + reference adapters) + 1D (enterprise adapters)
**State:** Closed. Phase 2 (governance primitives + LLM gateway, Sprints 2 + 3) is next.
**Main commit at closeout:** `fd80c2a` (squash of [PR #2](https://github.com/bmzee/cognic-agentos/pull/2)) on top of `40ed26a` (squash of [PR #1](https://github.com/bmzee/cognic-agentos/pull/1)).

## What ships in `main` after Phase 1

- **Bootstrap** — `core/config.py` Pydantic settings; `/api/v1/healthz` liveness (Sprint 1A); FastAPI factory pattern (`create_app` for the kernel image, `create_prod_app` for the default-adapters image) ([ADR-001](adrs/ADR-001-os-only-platform.md)).
- **Observability** — JSON structured logging with `request_id` + OTel `trace_id` + `span_id`; OpenTelemetry trace pipeline; Prometheus `/metrics`; OpenAPI at `/api/v1/openapi.json` (Sprint 1B).
- **Adapter contracts** — six PEP-544 protocols (`RelationalAdapter`, `VectorAdapter`, `SecretAdapter`, `EmbeddingAdapter`, `ObservabilityAdapter`, plus `MemoryAdapter` deferred-stub). Auto-registering bundled-registry; kernel-resilient `load_bundled_adapters()` with `_BUNDLED_ADAPTER_OPTIONAL_DEPS` allowlist; per-adapter `/api/v1/readyz` roll-up ([ADR-009](adrs/ADR-009-pluggable-infrastructure-adapters.md)).
- **Sprint 1C bundled adapters** — Postgres / Qdrant / Vault / Ollama / Langfuse-OTel.
- **Sprint 1D bundled adapters** — Oracle (`oracle+oracledb` async, thin mode) / Dynatrace (OTel-bridged + Metric Ingest line protocol) / OpenAI-compat embedding (vLLM / SGLang / OpenAI / Cohere / Azure-OpenAI via OpenAI-compat proxy).
- **Driver factory + per-driver-arg helpers** — `db_driver`/`vector_driver`/`secret_driver`/`embed_driver`/`obs_driver` env vars resolve through `bundled_registry` → `AdapterNotInstalled` on unknown driver (no silent fallback).
- **Compose stack** — 7-service base (`infra/dev/docker-compose.yml`) + opt-in Oracle XE 21c overlay + opt-in single-GPU vLLM overlay.
- **Image split** — kernel image (server + observability only, ≤120 MiB measured 102) and default-adapters image (kernel + bundled adapters, ≤220 MiB measured 174). Default-adapters builder ships `gcc + musl-dev + linux-headers + binutils` for `oracledb` source-build + a `strip --strip-unneeded` pass that reclaims ~64 MiB across the venv.
- **Operator docs** — [`docs/INFERENCE-BACKENDS.md`](../INFERENCE-BACKENDS.md) decision matrix for Ollama / vLLM / SGLang / cloud per-deployment-topology.

## CI / production-grade gates live

| Gate | Workflow | Trigger | Behaviour |
|---|---|---|---|
| Lint + types + tests | `python.yml` → `lint + test` | push / PR | `ruff` + `ruff format --check` + `mypy` strict + `pytest -v` |
| Image-size budgets | `python.yml` → `image size budget` | push / PR | builds kernel + default-adapters; fails CI if either exceeds budget |
| Kernel boot smoke | `python.yml` → `image size budget` step | push / PR | runs the built kernel image, polls `/api/v1/healthz`, asserts 200 |
| Live Oracle integration | `python.yml` → `oracle integration` | push / PR | brings up Oracle XE overlay, waits for healthy, runs `pytest -m oracle`, tears down |
| Reproducible-locking refresh | `dep-upgrade.yml` | weekly Mon 06:00 UTC + manual | `uv lock --upgrade`, opens single rolling `chore/dep-upgrade` PR for human review |

## Doctrine adherence

- **AGENTS.md `core/` stop-rule.** All `core/config.py` edits in Phase 1 were settings additions or description-string corrections — no governance-primitive (`audit` / `decision_history` / `approval` / `policy` / `emergency` / `memory`) was modified. Each `core/` touch was flagged and gated by explicit user authorization.
- **Production-grade rule.** No mocks in runtime paths. `OracleAdapter.run_migrations()` raises `NotImplementedError` referencing Sprint 2 + ADR-009 — loud scaffolding, not silent no-op. `QdrantAdapter.search()` raises on non-None `filter` until data-governance integration. `LangfuseOtelAdapter` ships OTel-bridged emission + HTTP health probe; full Langfuse SDK trace lifecycle deferred to Sprint 2/3 with `core/audit`.
- **Plugin discipline (ADR-001).** No agents, tools, skills, UI, or bank overlays added. All work sits under platform-primitive / persistence-adapter / portal-surface / protocol-layer / compliance-evidence layers.
- **Per-action authorization rule.** Every push, PR open, merge, and branch deletion in Phase 1 was gated on full-word user authorization (`yes` / `go` / `merge` / `push it` / `pr`). No remote-affecting action was bundled or implicit.

## Test + coverage state

- **Tests:** 263 passed + 1 skipped (live Oracle integration, env-gated and run only by the `oracle-integration` CI job).
- **Coverage:** 93% global; adapter modules ≥84%; `core/config.py` 100%.
- **Negative-path coverage:** unknown-driver `AdapterNotInstalled`, all five bundled-adapter unreachable cases, Vault token-missing, Dynatrace 401 + 403 (scope failure), OpenAI-compat dim mismatch + NaN/Infinity rejection, line-protocol dimension sanitization, kernel-image vs default-adapters factory selection.

## Doctrine amendments accepted in Phase 1

- **BUILD_PLAN.md image budget** — Sprint 1C raised the default-adapters ceiling from 180 → 220 MiB (numpy/grpc/cryptography compiled libs dominate; no removable bloat). Sprint 1D `oracledb` addition went *under* the raised ceiling thanks to the strip pass.
- **BUILD_PLAN.md Sprint 1D scope** — 4 amendments: Oracle URL clarification, Dynatrace + OpenAI-compat auth surface, `provider_label` storage-only-in-1D, CI matrix scope.
- **BUILD_PLAN.md structured-logging line** — corrected to claim only what Sprint 1 ships (`request_id` + OTel `trace_id` + `span_id`; Langfuse correlation rides OTel + per-event joining lands with `core/audit` in Sprint 2/3).

## Carryover for Phase 2

These are **stored** in Phase 1 but **wired** in Phase 2:

- `OpenAICompatEmbeddingAdapter.provider_label` — adapter exposes the property; per-embed audit emission via `core/audit` (Sprint 2).
- `OracleAdapter.run_migrations()` — currently raises `NotImplementedError`; Sprint 2 implements via Alembic against `core/` schema.
- `dynatrace_api_token_vault_path`, `embedding_api_key_vault_path` — reserved settings; runtime Vault resolution lands with Sprint 10 alongside Vault credential leasing.

## Out of Phase 1 scope (deferred per plan)

- Wallet / Autonomous-DB / DRCP / thick-mode Oracle config — Sprint-1D scope is URL-only; typed config arrives when banks need it.
- Direct Azure-OpenAI URL shape (`/openai/deployments/<name>/embeddings?api-version=...`) — Phase 1 supports Azure only via OpenAI-compat proxy.
- Live Dynatrace tenant + live vLLM GPU smoke — operator-side; both need real infrastructure.
- Full Langfuse SDK trace lifecycle (parent-child agent spans, generation records, scorer integration) — Sprint 2/3 alongside `core/decision_history` + LLM gateway.
- All governance kernel work (`core/audit`, `core/decision_history`, `core/guardrails`, `core/escalation`, `core/sla`, `core/auto_degradation`, `core/citation`, `core/approval`, `core/policy`, `core/emergency`, `core/memory`) — Phase 2/3/4.

## Next sprint

**Sprint 2 — Governance primitives** ([BUILD_PLAN.md](../BUILD_PLAN.md) Sprint 2). Begins:

- `core/audit` — append-only audit emission consuming the structured-log shape Phase 1 already emits.
- `core/decision_history` — hash-chained decision-history primitive that the Phase-1 `provider_label` storage feeds into.
- Alembic migration baseline — turns `OracleAdapter.run_migrations()` into a real call, retires the `NotImplementedError`.

Phase 1 ships the substrate; Phase 2 starts spending it.
