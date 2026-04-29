# Sprint 2 — Governance Foundation — Closeout Note

**Date:** 2026-04-29
**Sprints closed:** 2 (chain-of-custody foundation: schemas, canonical form, audit + decision_history append-only stores, chain verifier, alembic baseline + initial migration, runtime-role canary).
**State:** READY FOR GATE on branch `feat/sprint-2-governance-primitives`. Awaiting explicit user authorization to push / open PR / merge per the per-action rule. Sprint 2.5 (operational primitives — `core/sla`, `core/escalation`, `core/guardrails`) is next, on top of this foundation.
**Branch tip at closeout:** `52f590c` (Task 12 live canary + concurrency canaries) on top of `34df662` (PR #5 doctrine amendments) on top of `36a3c69` (PR #4 plan-of-record).

## What ships in `feat/sprint-2-governance-primitives` after Sprint 2

- **Canonical form** — `src/cognic_agentos/core/canonical.py`. Single source of truth (`canonical_bytes` + `hash_record` + `ZERO_HASH`) for the audit / decision-history hash chain. Round-2..4 hardenings: tuple/list collision rejected, NaN/Infinity blocked even as dict keys, naive datetimes rejected, datetimes with tzinfo returning None from `utcoffset()` rejected, non-string-valued Enum rejected, non-finite Decimal rejected, non-string dict keys rejected. Locked at `schema_version=1`; per AGENTS.md amendment in PR #5 every edit gets human review.
- **Schema vocabulary** — `src/cognic_agentos/core/schemas.py`. `CognicAction`, `ComplianceVerdict`, `FieldStatus` `StrEnum`s; `FieldMeta` frozen+slotted dataclass (the deliverable that nearly slipped in Round-2).
- **Audit store** — `src/cognic_agentos/core/audit.py`. `AuditStore.append(event)` — INSERT-only, hash-chained, single transaction per append. `SELECT ... FOR UPDATE` on `governance_chain_heads` serialises concurrent appenders; payload normalised through canonical-form round-trip at method boundary (deep snapshot + dialect-portable JSON projection in one step); chain-head UPDATE compare-and-set verified by rowcount check (defence-in-depth against dialect surprises); fail-loud on DB outage.
- **Decision-history store** — `src/cognic_agentos/core/decision_history.py`. Parallel implementation against the `decision_history` chain. `DecisionRecord.actor_id` merged into the normalized payload before hashing/storage with strict-equality collision policy; `_MISSING` sentinel disambiguates "key absent" from "key present with value `None`"; raw-payload-actor-id type check fires BEFORE canonical normalization (catches UUID/Decimal/bytes/regular-Enum that would otherwise survive into the merged dict as JSON strings).
- **Chain verifier** — `src/cognic_agentos/core/chain_verifier.py`. `ChainVerifier(engine, chain_id)` with `walk()` + `verify_record(record_id)` returning typed `TamperReport`. Five `BreakKind` values: `hash_mismatch`, `sequence_gap`, `prev_hash_mismatch`, `head_mismatch` (catches `governance_chain_heads` row tamper — without it a DBA could corrupt the head and leave evidence rows intact while `walk()` returned clean), `record_not_found`. `walk()` opens `engine.begin()` + locks the head row with `SELECT ... FOR UPDATE` BEFORE the evidence-row scan — snapshot safety against concurrent appenders. NULL passthrough on `iso_controls` + `payload` (no coercion that masks DBA-side NULL tamper). SQLite `TIMESTAMP` drops tzinfo on round-trip; `_normalise_datetime()` re-attaches UTC since `canonical_bytes` correctly rejects naive datetimes.
- **DB engine + types** — `src/cognic_agentos/db/engine.py` (`create_engine_from_settings` / `session_factory_from_engine` / `dispose_engine`); `src/cognic_agentos/db/types.py` (`chain_hash_column_type()` → `LargeBinary(32).with_variant(oracle.RAW(32), 'oracle')`; `GovernanceJSON` TypeDecorator → native JSON on PG/SQLite, CLOB-with-`json.dumps(sort_keys=True)` on Oracle since SQLAlchemy 2.0.49 has no `oracle.JSON`).
- **Alembic baseline + initial migration** — `src/cognic_agentos/db/migrations/env.py` (async-shaped, URL resolution: pre-set `sqlalchemy.url` wins over `Settings.database_url`); `versions/20260428_0001_initial_governance_schema.py` creates `governance_chain_heads` + `audit_event` (not `audit` — Oracle reserved word) + `decision_history`. `sequence` is `BIGINT UNIQUE` (no `Identity()` — would double-source vs the chain-head FOR UPDATE lock).
- **Adapter run-migrations wired** — `PostgresAdapter.run_migrations()` + `OracleAdapter.run_migrations()` retire the Phase-1 `NotImplementedError` stubs; both invoke `alembic.command.upgrade` via `asyncio.to_thread`. Per Sprint-2 doctrine: production migrations are operator-driven; the adapter lifespan does NOT auto-invoke.
- **Per-file coverage gate** — `tools/check_critical_coverage.py`. Parses `coverage.json` and asserts each of `core/audit.py`, `core/canonical.py`, `core/chain_verifier.py`, `core/decision_history.py` independently meets ≥95% line + ≥90% branch. Replaces a combined `--cov-fail-under=95` shape that masks an under-covered file behind a well-covered sibling.
- **Operator runbook** — `docs/operator-runbooks/governance-tables-grants.md`. Postgres + Oracle GRANT shapes for runtime + evidence-admin roles. Two pinned Oracle paths for unqualified-table resolution: Path A.1 (cross-schema synonyms via `CREATE ANY SYNONYM`) / Path A.2 (per-user `CREATE SYNONYM`) / Option B (per-session `ALTER SESSION SET CURRENT_SCHEMA`).
- **Live verification canaries** — `tests/integration/db/test_concurrent_append.py` (50 concurrent `Store.append()` calls per chain via `asyncio.gather`; asserts distinct UUIDs + distinct hashes + contiguous sequences 1..50 + `ChainVerifier.walk()` clean) + `tests/integration/db/test_runtime_role_is_append_only.py` (positive append via `Store.append()` through the runtime-role DSN; raw UPDATE/DELETE blocked by GRANTs; chain still walks clean post-deny). Both parametrized on PG + Oracle × `audit_event` + `decision_history`.

## CI / production-grade gates added or extended

| Gate | Workflow | Trigger | Behaviour |
|---|---|---|---|
| Per-file critical-controls coverage gate | `python.yml` → `lint + test` | push / PR | After pytest, runs `tools/check_critical_coverage.py` against `coverage.json`; fails CI if any of the four critical-controls modules drops below 95% line OR 90% branch. |
| Live Postgres integration | `python.yml` → `postgres integration` | push / PR | New job. Brings up Postgres compose service, applies migration as superuser, provisions `agentos_runtime` role + runbook GRANTs, runs canary + concurrent tests FIRST, then alembic round-trip LAST (the round-trip drops grants). |
| Live Oracle integration extended | `python.yml` → `oracle integration` | push / PR | Existing job extended: applies migration as `cognic`, provisions `agentos_runtime` user + cross-schema synonyms via SYSTEM (Path A.1), applies GRANTs from `cognic`. Same canary-first / round-trip-last ordering. |

## Doctrine adherence

- **AGENTS.md per-edit halt-before-commit on critical-controls modules.** Every commit that touched `core/audit.py`, `core/canonical.py`, `core/chain_verifier.py`, or `core/decision_history.py` paused for explicit user authorization before commit. Round-2/3/4 review rounds were folded in inline; no critical-controls edit went unreviewed.
- **AGENTS.md `core/canonical.py` per-edit stop rule (PR #5 amendment).** All Round-2..4 hardenings (NaN dict-key bypass, naive-datetime rejection, tuple rejection, non-string Enum rejection, non-finite Decimal rejection) were reviewed before commit; `_SCHEMA_VERSION` stays at 1 as the wire-format guarantee for evidence-pack export.
- **Production-grade rule.** No mocks in runtime paths. The lifespan does NOT auto-invoke `run_migrations` — that's operator-driven. The runtime role's append-only posture is enforced by DB GRANTs (operator runbook), not by code discipline alone — the canary proves the runbook was applied.
- **Plugin discipline (ADR-001).** No agents, tools, skills, UI, or bank overlays added. All work sits under platform-primitive (`core/*` governance) / persistence-adapter (`db/adapters/*` run-migrations wiring) / compliance-evidence (chain-of-custody substrate for ADR-006) layers.
- **Per-action authorization rule.** Plan-of-record (PR #4) and doctrine amendments (PR #5) were each gated on explicit `merge` authorization. The 13 Sprint-2 implementation commits all sit on a feature branch with **no push, no PR, no merge** until explicit user authorization at this READY FOR GATE checkpoint.

## Test + coverage state

- **Tests:** 464 unit + 18 integration = 482 total. Suite grew from Phase-1 close at 264 (+200 unit / +18 integration). Integration tests self-skip locally without env vars; CI's `postgres-integration` + `oracle-integration` jobs are the only places they execute.
- **Coverage:** 95% global with `db/migrations/env.py` excluded from rollup (alembic CLI-subprocess scaffolding; `test_alembic_migrations.py` exercises it end-to-end but coverage.py cannot trace back to the env.py module). All four critical-controls modules pass the per-file gate: `core/audit.py` 100%/100%, `core/canonical.py` 95.7%/94.4%, `core/chain_verifier.py` 97.9%/95.5%, `core/decision_history.py` 100%/100%.
- **Negative-path coverage:** canonical-form rejects (tuples, NaN/Inf, naive datetimes, non-string Enum values, non-finite Decimals, non-string dict keys, datetimes with tzinfo returning None from `utcoffset()`); chain-head compare-and-set rowcount-mismatch raise; chain-verifier all five `BreakKind` values; `actor_id` merge contract (`_MISSING` sentinel; explicit-None-vs-absent collision; pre-canonical-norm type rejection); SQLite TIMESTAMP tzinfo round-trip.

## Doctrine amendments accepted in Sprint 2

- **BUILD_PLAN.md Sprint 2 / 2.5 split (PR #5).** Original 3-wu single-sprint shape carved into Sprint 2 (chain-of-custody foundation, 2 wu) + Sprint 2.5 (operational primitives — `core/sla`, `core/escalation`, `core/guardrails`, 1 wu). Critical-controls modules at 95%+ couldn't be rushed in 3 wu alongside three more governance modules.
- **AGENTS.md `core/canonical.py` per-edit stop rule (PR #5).** Added to the critical-controls list as the wire-format module for evidence-pack export per ADR-006. Every edit gets human review, not just non-trivial ones.
- **BUILD_PLAN.md no-auto-migrate doctrine (PR #5).** Production migrations are operator-driven; lifespan must NOT auto-invoke `run_migrations` (would fight bank account-management policies + create silent privilege drift across deployments).
- **BUILD_PLAN.md operator-runbook split (PR #5).** Schema management (DDL — alembic) and role management (admin — runbook) are separate concerns. The migration ships pure DDL; `docs/operator-runbooks/governance-tables-grants.md` ships dialect-specific GRANT shapes.
- **BUILD_PLAN.md sweep (commit `a1afb8f`).** `db/types.py` deliverable added; `actor_id` merge contract surfaced; `head_mismatch` BreakKind + walk() snapshot-safety primitive surfaced; Oracle synonym paths spelled out; suite-growth projection corrected from "~340" to "~470" (actual: 482).

## Carryover for Sprint 2.5 / Sprint 3

These are **stored** in Sprint 2 but **wired** in later sprints:

- `provider_label` + `langfuse_trace_id` columns — present on both evidence tables; LLM gateway (Sprint 3) is the first writer.
- `tenant_id` (nullable) on both evidence tables — Wave 2 multi-tenant policy enforcement is the first writer; Sprint 2 only writes NULL.
- `core/sla.py`, `core/escalation.py`, `core/guardrails.py` — operational primitives that consume Sprint 2's chain. Sprint 2.5.
- Evidence-pack export with Merkle root + signed manifest (ADR-006 §"Tamper-evident evidence chain") — Phase 3.3.
- `core/decision_history` `impact: high` ISO 42001 control A.7.4 wiring — Sprint 3 onward as the LLM gateway emits high-impact decisions.

## Out of Sprint 2 scope (deferred per plan)

- `core/sla` / `core/escalation` / `core/guardrails` — Sprint 2.5.
- LLM gateway (`llm/gateway.py`) — Sprint 3.
- Full Langfuse SDK trace lifecycle (parent-child agent spans, generation records, scorer integration) — Sprint 2/3 alongside `core/decision_history` + LLM gateway.
- DB role management automation — operator-driven via the runbook; runtime-role canary is the production-grade verification that the runbook has been applied.
- Push, PR, merge — per per-action rule. This closeout is the READY FOR GATE checkpoint.

## Next sprint

**Sprint 2.5 — Operational governance primitives** ([BUILD_PLAN.md](../BUILD_PLAN.md) Sprint 2.5). Begins after Sprint 2 merges to `main`:

- `core/sla` — SLA timer primitive (deadline computation, breach detection).
- `core/escalation` — escalation lifecycle state machine; transitions emit hash-chained events into `decision_history` (consuming Sprint 2's substrate).
- `core/guardrails` — pluggable input/output filter pipeline (PII, injection — initial filters regex-based; ML filters Wave 2).

Sprint 2 ships the chain-of-custody substrate; Sprint 2.5 starts spending it on operational decisions.
