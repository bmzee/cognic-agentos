# Sprint 2 — Core Governance Primitives (chain-of-custody foundation)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the tamper-evident, append-only governance substrate that every later sprint hangs off — `core/audit`, `core/decision_history`, `core/chain_verifier`, `db/engine`, and the Alembic baseline that makes `OracleAdapter.run_migrations` / `PostgresAdapter.run_migrations` real (retiring the `NotImplementedError` reservations from Sprint 1C/1D).

**Architecture:** Append-only DB tables with a SHA-256 hash chain over canonical JSON; UUID4 record IDs plus a monotonic `sequence` BIGINT (application-assigned under a chain-head row lock — no DB `Identity()` because that would double-source the value); cross-dialect (Postgres + Oracle) via SQLAlchemy `Uuid` / `LargeBinary(32)` / `JSON` / `TIMESTAMP(timezone=True)` types so a single Alembic migration set works on both. Chain verifier walks `sequence ASC`, recomputes hashes, surfaces a typed `TamperReport`. Audit writes fail loud on DB outage (no silent drop, no in-process buffering — the request path that emits an audit event accepts the fate of the audit write).

**Tech Stack:** SQLAlchemy 2.0 async, Alembic 1.13+, asyncpg (Postgres), python-oracledb thin (Oracle), Python `hashlib.sha256`, `json.dumps(sort_keys=True, separators=(",",":"))`, pytest + pytest-asyncio + the existing in-tree `tests/support/` harness.

---

## Round-2 amendments (applied 2026-04-28 after first plan review)

The first draft of this plan failed five doctrine checks during the user's pre-approval review. All five are patched in-place below; this section is the audit trail.

| # | Issue | Severity | Resolution |
|---|---|---|---|
| 1 | Append's chain-head read used `ORDER BY sequence DESC LIMIT 1` — no `FOR UPDATE`, `LIMIT` is not Oracle SQL, two concurrent writers can read the same head | **P1** | Introduce `governance_chain_heads` (one row per chain) with portable `SELECT ... FOR UPDATE`. Append serialises through that lock. No `LIMIT` anywhere; raw SQL replaced by SQLAlchemy Core. |
| 2 | Core modules import SQLAlchemy, but SQLAlchemy + Alembic lived in `[project.optional-dependencies].adapters` — kernel image fails to import `core.audit` | **P1** | Move `sqlalchemy[asyncio]>=2.0` + `alembic>=1.13` + `greenlet` to base `[project]` deps. Kernel image absorbs ~13 MiB; budget re-measured + budget bump (if needed) gated on Task 13. Driver-specific deps (`asyncpg`, `oracledb`, `qdrant-client`, `hvac`, `langfuse`) stay in `[adapters]`. |
| 3 | Hash material omitted row-identity fields; mutating `record_id` could not be detected | **P1** | Canonical envelope now includes `schema_version`, `chain_id`, `record_id`, `sequence`, `created_at`, `tenant_id`, every typed metadata field, and `payload`. Schema starts at version 1; bumps require a migration + canonical-form decision recorded in this plan. |
| 4 | Coverage gate used `--cov-fail-under=95` over 4 targets — combined, not per-file; a 99% file can mask a 91% file | **P2** | Replaced with `tools/check_critical_coverage.py` that parses `coverage.json` and fails if **any** of the four critical modules drops below 95% line OR 90% branch. |
| 5 | `FieldMeta` deliverable named in BUILD_PLAN + plan file-structure table but not implemented | **P2** | Implemented as a frozen dataclass in Task 1. |

Plus three of the user's design calls promoted from "open" to "settled":

| Design call | Decision |
|---|---|
| `schema_version` and `tenant_id` columns on both audit + decision_history tables | **Yes** — `schema_version SMALLINT NOT NULL DEFAULT 1`, `tenant_id VARCHAR(64) NULL`. Sprint 2 ships nullable tenant_id; Sprint 4+ wires the populator. |
| Auto-migrate at app startup | **Removed.** Production migrations are an operator job (`uv run alembic upgrade head` or `kubectl create job`). The adapter still exposes `run_migrations()` so dev tooling + integration tests can call it explicitly; nothing in the prod runtime path invokes it. |
| Concurrency coverage | Concurrent-append integration test parametrises **both** `@pytest.mark.postgres` and `@pytest.mark.oracle`. Oracle is a bundled bank path — equal-rank coverage. |

## Round-3 amendments (applied 2026-04-28 after Round-2 review)

Three remaining production-grade hygiene gaps after Round-2:

| # | Issue | Severity | Resolution |
|---|---|---|---|
| 6 | Task 0 pyproject snippet listed prescriptive adapter version pins (`hvac>=2.3`, `langfuse>=2.55,<3.0`) which were stale guesses; following them literally would regress Phase-1 adapter constraints | **P2** | Step 0.6 rewritten as a **targeted promotion**: read live `pyproject.toml`, preserve all existing adapter pins verbatim, only move `sqlalchemy[asyncio]` from `[adapters]` to base + add `alembic` + `greenlet` to base. Verification step asserts the diff contains no version-floor changes to existing adapter pins. |
| 7 | Append-only GRANT policy was ambiguous: schema section said "migration RAISEs if roles missing"; Task 5 said "warning if `COGNIC_RUNTIME_ROLE` unset". One crisp policy needed; also dialect-specific (PG vs Oracle GRANT syntax differs) | **P2** | **GRANT statements moved out of the migration entirely.** Migration ships DDL only. GRANTs live in `docs/operator-runbooks/governance-tables-grants.md` with PG + Oracle dialect-specific snippets. **A runtime-role append-only verification test (Task 12.5)** asserts the runtime role gets `permission denied` on UPDATE + DELETE against the evidence tables — the production-grade canary that the runbook was applied. The test runs in CI on both PG and Oracle. |
| 8 | End-state line under Step 13.5 still said "Alembic in `[adapters]` extras" — contradicts Round-2 amendment #2 | **P3** | Rewritten to reflect Alembic in base; kernel image grows ~13 MiB; boot smoke now also asserts `import cognic_agentos.core.audit` succeeds inside the kernel container. |

## Round-4 amendments (applied 2026-04-28 after Round-3 review)

Three further hygiene gaps caught after the Round-3 rev:

| # | Issue | Severity | Resolution |
|---|---|---|---|
| 9 | The runtime-role positive-path canary only ran `SELECT chain_id FROM governance_chain_heads`; it did NOT prove the runtime role can perform the full append transaction (lock head + INSERT into evidence + UPDATE chain_heads). A missing INSERT or UPDATE GRANT would silently pass the canary and surface only on the first production audit emission. | **P2** | Replaced the SELECT-only test with `test_runtime_role_can_actually_append_through_audit_store`: drives `AuditStore.append()` against the runtime-role DSN, then verifies the row landed in `audit_event` AND the head moved in `governance_chain_heads`. Catches partial GRANTs at integration-test time. Postgres + Oracle parametrised. |
| 10 | Schema section noted that `AUDIT` is a reserved word in Oracle and pushed the operator runbook to use a quoted identifier `"audit"` — but the migration, the `_audit` Table object, the `chain_id` literal, the verifier whitelist, and the tamper-simulation tests all still used unquoted `audit`. One identifier-strategy needed before implementation, otherwise the inconsistency would flip into runtime errors on Oracle. | **P2** | **Renamed the table to `audit_event`** (DDL, `chain_id` literal, SQLAlchemy Core Table, verifier whitelist, tamper-simulation SQL, runbook GRANTs, BUILD_PLAN principle, schema diagrams — all consistent). Eliminates the reserved-word problem entirely; no quoting strategy needed across migration / app / verifier / tests. Python module + class names (`audit.py`, `AuditStore`, `AuditEvent`) stay as-is — the rename is at the persistence-name layer only. |
| 11 | The "Architecture" line at the top still listed `Identity()` in the SQLAlchemy types tuple, contradicting Round-2 #1 which moved `sequence` to application-assigned under the chain-head row lock | **P3** | Removed `Identity()` from the architecture line; added a parenthetical that calls out why `sequence` is application-assigned ("no DB `Identity()` because that would double-source the value"). |

---

## Scope split + doctrine amendments to land first

**BUILD_PLAN Sprint 2 lists 9 deliverables in 3 work-units.** This plan covers 6 of them — the chain-of-custody foundation. The remaining 3 (`core/sla.py`, `core/escalation.py`, `core/guardrails.py`) are operational primitives that *use* the foundation; this plan proposes amending BUILD_PLAN to introduce **Sprint 2.5 — Operational primitives** for those, on the doctrine principle that critical-controls modules at 95%+ coverage cannot be rushed in a 3-wu sprint alongside three other governance modules.

Doctrine amendments proposed (apply in **Task 0.4** before any code lands):

1. **BUILD_PLAN.md Sprint 2 deliverable list** — split into `Sprint 2` (this plan) + new `Sprint 2.5` (operational primitives).
2. **BUILD_PLAN.md production-grade principles** — append "Append-only governance tables: the runtime DB role used by AgentOS holds INSERT + SELECT only on `audit_event` and `decision_history` tables; UPDATE / DELETE are not granted. Schema-design doctrine, not just code discipline."
3. **AGENTS.md Stop rules** — make explicit that hash-chain canonical-form changes (anything affecting `core/canonical.py`) ARE breaking changes for evidence-pack export and require human review on *every* edit, not just non-trivial ones.

If any of those three amendments are rejected during plan review, the corresponding tasks below need to be revisited.

## Stop gates (per AGENTS.md critical-controls rule)

This sprint touches **three** critical-controls modules. Stop gates apply at every task boundary:

| Gate | When | Who decides |
|---|---|---|
| **Schema design** | Before Task 5 (initial migration) lands | Human review of column types, defaults, indexes, append-only grant model |
| **Canonical form + hash function** | Before Task 2 (`core/canonical.py`) is committed | Human review of JSON canonicalization rules + SHA-256 framing (prev_hash ‖ canonical_bytes) |
| **Tamper-detection report shape** | Before Task 8 (`chain_verifier`) is committed | Human review of what the chain detects vs deliberately doesn't (insider DBA rewrite is out of scope until ADR-006 Merkle-root signing in Phase 3.3) |
| **Migration round-trip** | Before Task 9 wires `run_migrations()` | Human review of upgrade → downgrade → upgrade round-trip on both Postgres and Oracle |
| **Coverage gate** | Before Task 12 closes | Human confirmation that 95%+ on the three critical-controls modules is real (not branch-coverage gamed) |
| **READY-FOR-GATE** | Before any push / PR / merge | Human authorization per `feedback_explicit_authorization_per_action.md` |

Per AGENTS.md: this sprint runs in **pair-engineering mode**. Use `core-controls-engineer` agent + `/critical-module-mode` for any non-trivial edit to `core/audit.py`, `core/decision_history.py`, or `core/chain_verifier.py`.

## File Structure

**Created (~14 files):**

| File | Responsibility |
|---|---|
| `src/cognic_agentos/core/schemas.py` | Governance vocabulary: `CognicAction` / `ComplianceVerdict` / `FieldStatus` enums + `FieldMeta` frozen dataclass. Pure-Python; no DB dependency. |
| `src/cognic_agentos/core/canonical.py` | `canonical_bytes(obj)` + `hash_record(canonical_bytes, prev_hash)` + `ZERO_HASH`. Sole owner of canonical-form rules — every chain participant imports from here so drift is impossible. Hard-coded golden hashes in tests pin the canonical bytes for the Sprint-2 envelope. |
| `src/cognic_agentos/core/audit.py` | `AuditStore.append(event)` — INSERT-only, fail-loud on DB outage, hash-chained per `audit_event` table. Append serialises through `governance_chain_heads` (`SELECT ... FOR UPDATE`); hash material includes the full record-identity envelope (schema_version, chain_id, record_id, sequence, tenant_id, created_at, ...). |
| `src/cognic_agentos/core/decision_history.py` | `DecisionHistoryStore.append(record)` — same shape as AuditStore but against the `decision_history` chain. Returns `(record_id, hash)`. |
| `src/cognic_agentos/core/chain_verifier.py` | `walk(table, start_seq, end_seq)` + `verify_record(table, record_id)`. Returns `TamperReport` dataclass. |
| `src/cognic_agentos/db/engine.py` | Async SQLAlchemy engine factory + per-app `AsyncSession` factory; lifespan-integrated. |
| `src/cognic_agentos/db/migrations/env.py` | Alembic env reading `COGNIC_DATABASE_URL`; supports Postgres + Oracle. |
| `src/cognic_agentos/db/migrations/script.py.mako` | Alembic template (boilerplate). |
| `src/cognic_agentos/db/migrations/alembic.ini` | Alembic config; `script_location = src/cognic_agentos/db/migrations`. |
| `src/cognic_agentos/db/migrations/versions/20260428_0001_initial_governance_schema.py` | Initial migration: `governance_chain_heads` (one row per chain) + `audit_event` + `decision_history` tables. Both evidence tables carry `schema_version SMALLINT NOT NULL DEFAULT 1` + `tenant_id VARCHAR(64) NULL`. |
| `tools/check_critical_coverage.py` | Per-file coverage gate: parses `coverage.json` and fails CI if any of `core/audit.py`, `core/decision_history.py`, `core/chain_verifier.py`, `core/canonical.py` drops below 95% line OR 90% branch. Replaces a combined `--cov-fail-under=95` shape that masks under-covered files. |
| `tests/unit/core/test_schemas.py` | Enum value stability + JSON-serializability. |
| `tests/unit/core/test_canonical.py` | Determinism tests: dict-key sort, datetime ISO 8601 with Z, UUID hex, bytes base64, nested structures, NaN/Inf rejection (defensive). |
| `tests/unit/core/test_audit.py` | Append, query, schema enforcement; uses sqlite-aiosqlite for in-memory unit tests of *logic* layer. |
| `tests/unit/core/test_decision_history.py` | Append → record_id + hash; chain isolation from audit; concurrent-insert race. |
| `tests/unit/core/test_chain_verifier.py` | 10-record clean walk; mutation tamper; deletion tamper; hash-corrupted; prev_hash-corrupted; empty chain; single record; cross-table chain isolation. |
| `tests/integration/db/__init__.py` | Marker for integration suite. |
| `tests/integration/db/test_alembic_migrations.py` | Upgrade → downgrade → upgrade round-trip; `@pytest.mark.postgres` and `@pytest.mark.oracle` parametrized. |
| `tests/integration/db/test_audit_live.py` | Live append + walk on Postgres (and Oracle via mark). |
| `tests/integration/db/test_decision_history_live.py` | Live append + concurrent-insert + chain integrity. |
| `tests/integration/db/test_chain_verifier_live.py` | Tamper detection on live DB (UPDATE / DELETE bypass app). |

**Modified (~9 files):**

| File | Why |
|---|---|
| `pyproject.toml` | Add `alembic>=1.13` + `uuid_utils` (optional, only if v7 IDs land — see open question below); add `postgres` pytest marker. |
| `uv.lock` | Regenerated by `uv lock`. |
| `src/cognic_agentos/db/adapters/postgres_adapter.py` | Replace `NotImplementedError` in `run_migrations` with real Alembic invocation. |
| `src/cognic_agentos/db/adapters/oracle_adapter.py` | Same. |
| `src/cognic_agentos/db/adapters/__init__.py` | Document the migration directory location. |
| `src/cognic_agentos/db/migrations/oracle/.gitkeep` | Keep but README-document its purpose: "Oracle-dialect-specific migrations (PL/SQL functions, partitioning hints) beyond the cross-dialect Alembic baseline. Empty in Sprint 2." |
| `src/cognic_agentos/portal/api/app.py` | Lifespan: `db/engine.create_engine_from_settings()` + dispose at shutdown. **No auto-migrate** (Round-2 amendment #6) — production migrations are an operator job (`uv run alembic upgrade head` or a `kubectl create job`) so a misconfigured runtime can't silently invent schema. Dev convenience is `make migrate`, not lifespan. |
| `src/cognic_agentos/core/config.py` | Two new settings: `db_pool_size` / `db_max_overflow` (already implicitly set by SQLAlchemy defaults — make explicit). NO `db_run_migrations_at_startup` setting; auto-migrate path is removed entirely. **CORE STOP-GATE — flag for human review.** |
| `.github/workflows/python.yml` | New `postgres-integration` job mirroring the existing `oracle-integration` shape; coverage gate fails CI if any of the three critical-controls modules drops below 95%. |
| `docs/BUILD_PLAN.md` | Three amendments: scope split (Sprint 2 / 2.5), append-only doctrine principle, AGENTS.md cross-reference. |
| `docs/closeouts/2026-04-28-phase-1-foundation.md` | Already closed; this plan does NOT modify it. Sprint 2 closeout will be a new file. |

## Design questions — settled in Round-2

All five are now decided. Recorded here for evidentiary trail; the rest of the plan reflects these decisions.

1. **`record_id` shape — UUID4 + monotonic `sequence` BIGINT.** Both fields participate in the hash material (Round-2 amendment #3), so mutating either breaks the chain. UUID v7 deferred until audit-table cardinality forecasts > 1B/year; revisit then with a schema_version bump.
2. **Audit fail-mode — fail-loud, no buffering.** `AuditStore.append` raises on DB outage; the caller decides. No in-process queue, no filesystem journal fallback in Sprint 2. Caller-side discipline: any code path that emits audit must accept the fate of the audit write. Buffering / journalling is a Phase 3 reliability concern, not Phase 1/2 governance scope.
3. **Migration shape — single Alembic set with SQLAlchemy Core types.** No raw `LIMIT` SQL anywhere. Append + verifier paths use `sqlalchemy.select(...).with_for_update()` and `sqlalchemy.insert(...)` — both dialects honour them. `db/migrations/oracle/` reserved for future Oracle-only PL/SQL hooks; empty in Sprint 2.
4. **Coverage gate — per-file enforcement.** Replaced `--cov-fail-under=95` with `tools/check_critical_coverage.py` that parses `coverage.json` and fails if **any** of `core/audit.py`, `core/decision_history.py`, `core/chain_verifier.py`, `core/canonical.py` drops below 95% line OR 90% branch.
5. **Phase-1 carryovers + new envelope fields.** `provider_label`, `langfuse_trace_id` ship as nullable columns on both tables (Sprint 3 LLM gateway populates `langfuse_trace_id`; Sprint 1D OpenAI-compat embedding populates `provider_label`). Plus Round-2 additions: `schema_version SMALLINT NOT NULL DEFAULT 1` + `tenant_id VARCHAR(64) NULL` so the envelope is complete before evidence tables grow. `tenant_id` populator deferred to Sprint 4 (RBAC + tenant context); Sprint 2 stores NULL but the column + hash material exist now.

## Schema (Round-2)

Three tables: two evidence tables (`audit_event`, `decision_history`) plus one **chain-head lock table** (`governance_chain_heads`) that serializes appends without dialect-specific `LIMIT` syntax.

```
governance_chain_heads
  chain_id         VARCHAR(32)                 PRIMARY KEY        -- 'audit_event' | 'decision_history'
  latest_sequence  BIGINT                      NOT NULL DEFAULT 0
  latest_hash      BYTEA(32) / RAW(32)         NOT NULL           -- 32 zero-bytes at genesis
  updated_at       TIMESTAMP(tz=True)          NOT NULL DEFAULT now()

  -- Migration 0001 inserts two rows: ('audit_event', 0, ZERO_HASH, now()) and
  -- ('decision_history', 0, ZERO_HASH, now()). Append flow:
  --   BEGIN
  --   SELECT latest_sequence, latest_hash
  --     FROM governance_chain_heads
  --     WHERE chain_id = :chain
  --     FOR UPDATE                            -- portable; both PG + Oracle honour
  --   ... compute new_seq + new_hash ...
  --   INSERT INTO audit_event (...) VALUES (...)
  --   UPDATE governance_chain_heads
  --     SET latest_sequence = :new_seq,
  --         latest_hash     = :new_hash,
  --         updated_at      = now()
  --     WHERE chain_id = :chain
  --   COMMIT
  --
  -- The FOR UPDATE row-level lock blocks the second concurrent appender
  -- until the first commits. No LIMIT, no DESC ORDER BY scan, no
  -- dialect-specific quirks.

audit_event
  record_id          UUID                      PRIMARY KEY        -- Python uuid4()
  sequence           BIGINT                    UNIQUE NOT NULL    -- assigned from chain_heads + 1
  schema_version     SMALLINT                  NOT NULL DEFAULT 1 -- bumps on canonical-form changes
  tenant_id          VARCHAR(64)               NULL               -- Sprint 2 stores NULL; Sprint 4 populates
  prev_hash          BYTEA(32) / RAW(32)       NOT NULL           -- 32 zero-bytes for genesis
  hash               BYTEA(32) / RAW(32)       UNIQUE NOT NULL    -- sha256(prev_hash || canonical(envelope))
  created_at         TIMESTAMP(tz=True)        NOT NULL DEFAULT now()
  event_type         VARCHAR(64)               NOT NULL           -- e.g. 'tool_invocation', 'config_change'
  request_id         VARCHAR(64)               NOT NULL           -- mirrors observability.logging.REQUEST_ID_CONTEXT
  trace_id           VARCHAR(32)               NULL               -- OTel hex; from active span at emit
  span_id            VARCHAR(16)               NULL
  langfuse_trace_id  VARCHAR(64)               NULL               -- joined later by LLM gateway (Sprint 3)
  provider_label     VARCHAR(32)               NULL               -- joined by OpenAI-compat embedding adapter
  iso_controls       JSON                      NULL               -- tuple[str, ...] of ISO 42001 control IDs (ADR-006)
  payload            JSON                      NOT NULL           -- event-specific structured body

decision_history
  -- identical column set; payload schema differs (decision-specific fields:
  -- decision_type, actor_id, scope, evidence_refs, outcome, impact)
```

**Indexes:**
- `audit_event (sequence)` — UNIQUE (chain-walk path)
- `audit_event (hash)` — UNIQUE (chain-walk path; tamper detection)
- `audit_event (request_id)` — non-unique (per-request audit slice)
- `audit_event (event_type, created_at)` — non-unique (event-type slice)
- `audit_event (tenant_id, created_at)` — non-unique (per-tenant slice; supports Sprint 4 tenant context)
- Identical for `decision_history`.

**Append-only enforcement (Round-3 — operator-runbook + verification test):**

- The runtime DB role gets `INSERT, SELECT` on `audit_event` + `decision_history` and `INSERT, SELECT, UPDATE` on `governance_chain_heads` (the chain-head row is the only legitimately-mutated state in the governance tier). UPDATE / DELETE on the evidence tables are NOT granted to the runtime role.
- A separate `agentos_evidence_admin` role (out-of-scope for Sprint 2; Phase-3 evidence-pack export + retention enforcement) holds DELETE on the evidence tables.
- **GRANT statements live in an operator runbook, NOT in the Alembic migration.** Schema management (DDL) and role management (admin) are separate concerns; banks already have account-management policies that conflict with migration-driven role/grant churn. Mixing them invites silent privilege drift and breaks dialect portability (PG vs Oracle GRANT syntax differs subtly enough to make a single migration brittle).
- The runbook lives at `docs/operator-runbooks/governance-tables-grants.md` and ships dialect-specific snippets:
  - **Postgres:** `GRANT INSERT, SELECT ON audit_event, decision_history TO :runtime_role;` `GRANT INSERT, SELECT, UPDATE ON governance_chain_heads TO :runtime_role;` `GRANT DELETE ON audit_event, decision_history TO :evidence_admin_role;`
  - **Oracle:** identical statements; no quoting needed. The Sprint-2 table is named `audit_event` (Round-4 rename) which **avoids** Oracle's reserved `AUDIT` identifier entirely — no schema-quoting strategy is required across the migration, the application code, the verifier, or the tests.
- **A verification test enforces the policy at runtime.** `tests/integration/db/test_runtime_role_is_append_only.py` connects as the configured runtime role, asserts it can INSERT + SELECT against the evidence tables, and asserts UPDATE + DELETE both raise the dialect's permission-denied error. The test is parametrised on `@pytest.mark.postgres` + `@pytest.mark.oracle`. CI runs it after the migration round-trip; production-bound bank deployments include it in their pre-cutover smoke suite.
- **Without the runbook applied, the runtime is using superuser credentials and the chain is INSERT-only by code discipline only.** Acceptable for dev compose; explicitly NOT acceptable for any environment marked `COGNIC_RUNTIME_PROFILE=prod`. The verification test failing in prod is the production-grade canary; there is no migration-level warning fallback (Round-3 amendment — replaces the earlier "warning if unset" text).

**Hash envelope (canonical content fed to `hash_record`):**

```python
content = {
    "schema_version": 1,                   # SMALLINT — bumps on canonical-form change
    "chain_id": "audit_event",                   # str — "audit_event" | "decision_history"
    "record_id": str(record_id),           # UUID4 string (lowercase hex w/ dashes)
    "sequence": new_sequence,              # int (monotonic, assigned under FOR UPDATE)
    "tenant_id": tenant_id,                # str | None
    "created_at": now,                     # datetime (UTC)
    "event_type": event.event_type,
    "request_id": event.request_id,
    "trace_id": event.trace_id,
    "span_id": event.span_id,
    "langfuse_trace_id": event.langfuse_trace_id,
    "provider_label": event.provider_label,
    "iso_controls": list(event.iso_controls),
    "payload": event.payload,
}
record_hash = hash_record(canonical_bytes(content), prev_hash)
```

Mutating any of `record_id`, `sequence`, `schema_version`, `chain_id`, `tenant_id`, `created_at`, or any metadata / payload field breaks the chain. `prev_hash` is excluded from the canonical content because it's the hash function's IV — already covered by `hash_record(content, prev_hash)`.

## Hash chain math

```python
# core/canonical.py — single source of truth

import json, hashlib

ZERO_HASH: bytes = bytes(32)  # genesis

def canonical_bytes(obj: dict) -> bytes:
    # sort_keys=True ensures dict-key order is stable.
    # separators=(",",":") removes whitespace.
    # default= handles datetimes/UUIDs/bytes via _json_default below.
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    ).encode("utf-8")

def hash_record(canonical: bytes, prev_hash: bytes) -> bytes:
    if len(prev_hash) != 32:
        raise ValueError("prev_hash must be exactly 32 bytes")
    h = hashlib.sha256()
    h.update(prev_hash)
    h.update(canonical)
    return h.digest()
```

`_json_default` handles: `datetime` → ISO 8601 with explicit `+00:00` suffix when UTC; `UUID` → 36-char hex-with-dashes (lowercase); `bytes` → standard base64; `Decimal` → str (preserve precision); `Enum` → `value`. Floating-point `NaN` / `Infinity` raise.

**Rule:** every chain participant calls `canonical_bytes(envelope)` then `hash_record(canonical, prev_hash)` — never reimplements either. The envelope shape is documented in the Schema section above; do NOT reshape envelopes elsewhere. Tests in `test_canonical.py` enforce: dict order independence, datetime/UUID/bytes round-trip stability, nested-dict stability, list-order preservation, NaN/Inf rejection. Cross-platform determinism is asserted by **hard-coded golden hashes** in the test file — any change to canonical-form rules breaks the goldens, forcing an explicit `schema_version` bump + migration before the change can land.

---

## Task 0 — Plan + branch + dependency setup

**Files:**
- Create: this plan file (already written when this is being executed).
- Modify: `pyproject.toml` (add `alembic>=1.13`, register `postgres` pytest marker).
- Modify: `uv.lock` (regenerated).
- Modify: `docs/BUILD_PLAN.md` (three doctrine amendments).
- Branch: `feat/sprint-2-governance-primitives` from `main` (currently `0fdf38c`).

- [ ] **Step 0.1: Stash anything WIP, confirm clean tree.**

```bash
git status              # expect clean
git log --oneline -1     # expect 0fdf38c
```

- [ ] **Step 0.2: Commit this plan file directly to main on a `chore(plan): ...` commit.**

This makes the plan reviewable independently of any implementation branch (matches the Sprint 1C/1D pattern).

```bash
git add docs/superpowers/plans/2026-04-28-sprint-2-governance-primitives.md
git commit -m "$(cat <<'EOF'
chore(plan): sprint 2 governance primitives — chain-of-custody foundation

Detailed implementation plan for core/audit + core/decision_history +
core/chain_verifier + Alembic baseline. Scope-splits BUILD_PLAN's
Sprint 2 deliverable list: this plan covers the foundation; sla /
escalation / guardrails defer to a proposed Sprint 2.5.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
# DO NOT push yet; user reviews + amends + authorizes 'push it' first.
```

- [ ] **Step 0.3: Halt for plan review.**

Per the per-action rule: do not start branch / Task 1 until the user has reviewed this plan and any amendments are folded in.

- [ ] **Step 0.4: Apply user-approved amendments to BUILD_PLAN + AGENTS.md.**

Three amendments listed under "Scope split + doctrine amendments to land first" above. Land in a follow-up `docs(sprint-2)` commit on main *before* branching.

- [ ] **Step 0.5: Branch.**

```bash
git checkout -b feat/sprint-2-governance-primitives
```

- [ ] **Step 0.6: Move SQLAlchemy / Alembic / greenlet into base deps + register postgres marker.**

Per Round-2 amendment #2: `core/audit.py` + `core/decision_history.py` + `db/engine.py` + `core/chain_verifier.py` import SQLAlchemy directly. Those modules live in the kernel image (no `--extra adapters`), so SQLAlchemy + Alembic must be base `[project]` deps, not `[project.optional-dependencies].adapters`.

**Round-3 amendment:** the edit is a **targeted promotion**, not a rewrite of `[adapters]`. Read the current `pyproject.toml` first; preserve every existing adapter dependency constraint verbatim (Phase 1 ended with concrete pins for `asyncpg` / `oracledb` / `qdrant-client` / `hvac` / `langfuse` / etc., and the floors get carried forward unchanged). Only `sqlalchemy[asyncio]` moves from the adapters extra to base; `alembic` + `greenlet` are added to base. Do **not** retype the adapters list from memory or this plan — that risks regressing pins.

The diff to apply (illustrative — apply against the live file's current shape):

```diff
 [project]
 dependencies = [
     # ... existing 1A/1B base deps preserved verbatim
+    "sqlalchemy[asyncio]>=2.0",  # MOVED from [adapters]; Sprint 1C floor preserved
+    "alembic>=1.13",             # NEW in Sprint 2
+    "greenlet>=3.0",             # explicit floor; SQLAlchemy[asyncio] needs it
 ]

 [project.optional-dependencies]
 adapters = [
     # ALL existing adapter pins preserved exactly as they ended Phase 1.
-    "sqlalchemy[asyncio]>=2.0",  # ← only this line moves out
     # asyncpg, oracledb, qdrant-client, hvac, langfuse, ... unchanged
 ]
```

Pytest markers (additive — does not touch existing markers):

```toml
[tool.pytest.ini_options]
markers = [
    # existing markers preserved
    "postgres: live Postgres integration; opt in via COGNIC_RUN_POSTGRES_INTEGRATION=1 + compose up postgres",
]
```

Verification before commit:
```bash
git diff pyproject.toml
# Diff MUST show: 3 added lines under [project] + 1 removed line under [adapters].
# It MUST NOT show any version-floor changes to existing adapter pins.
# If the diff includes adapter version changes, abort and start over.
```

- [ ] **Step 0.7: Lock + verify.**

```bash
uv lock
uv sync --frozen --all-extras
uv run pytest -q                        # 263 + 1 skipped, baseline preserved
```

- [ ] **Step 0.8: Re-measure kernel image budget.**

Round-2 #2 raises the kernel image. SQLAlchemy ~12 MiB + alembic ~1 MiB ≈ +13 MiB. Phase-1-close kernel was 102 MiB; expected new ceiling ~115 MiB. Hard ceiling 120 MiB.

```bash
docker build -f infra/agentos/Dockerfile --target runtime --build-arg PACKAGE_VERSION=ci -t cognic-agentos:kernel-2-test .
docker image inspect cognic-agentos:kernel-2-test --format='{{.Size}}' | awk '{print int($1/1024/1024) " MiB"}'
```

If the new size > 118 MiB (≤2 MiB headroom), pause and request user approval to bump the budget to 130 MiB before continuing. Do **not** silently ship a tight image.

- [ ] **Step 0.9: Default-adapters image must still be ≤220 MiB.**

```bash
docker build -f infra/agentos/Dockerfile --target default-adapters --build-arg PACKAGE_VERSION=ci -t cognic-agentos:adapters-2-test .
docker image inspect cognic-agentos:adapters-2-test --format='{{.Size}}' | awk '{print int($1/1024/1024) " MiB"}'
```

Should be unchanged from Phase-1-close (174 MiB) — moving SQLAlchemy from `[adapters]` to base just shifts where it ships, not whether.

- [ ] **Step 0.10: Commit.**

```bash
git add pyproject.toml uv.lock
git commit -m "chore(sprint-2): promote sqlalchemy + alembic to base deps; postgres marker"
```

---

## Task 1 — `core/schemas.py` (governance vocabulary enums)

**Files:**
- Create: `src/cognic_agentos/core/schemas.py`
- Test: `tests/unit/core/test_schemas.py`
- Test: `tests/unit/core/__init__.py`

- [ ] **Step 1.1: Write the failing test.**

```python
# tests/unit/core/test_schemas.py
from datetime import UTC, datetime

import pytest
from cognic_agentos.core.schemas import (
    CognicAction,
    ComplianceVerdict,
    FieldMeta,
    FieldStatus,
)


def test_cognic_action_values_are_stable() -> None:
    # Values are persisted into audit + decision_history payloads, so
    # they are wire-format and MUST NOT change without a migration.
    assert CognicAction.CALL_TOOL.value == "call_tool"
    assert CognicAction.COMPLETE.value == "complete"
    assert CognicAction.ESCALATE.value == "escalate"


def test_compliance_verdict_values_are_stable() -> None:
    assert ComplianceVerdict.APPROVED.value == "approved"
    assert ComplianceVerdict.DENIED.value == "denied"
    assert ComplianceVerdict.NEEDS_REVIEW.value == "needs_review"


def test_field_status_values_are_stable() -> None:
    assert FieldStatus.OPEN.value == "open"
    assert FieldStatus.PENDING.value == "pending"
    assert FieldStatus.CLOSED.value == "closed"


class TestFieldMeta:
    def test_construct_minimum(self) -> None:
        meta = FieldMeta(name="customer_score", status=FieldStatus.OPEN)
        assert meta.name == "customer_score"
        assert meta.status is FieldStatus.OPEN
        assert meta.last_changed_by is None
        assert meta.last_changed_at is None

    def test_construct_full(self) -> None:
        ts = datetime(2026, 4, 28, 10, 0, 0, tzinfo=UTC)
        meta = FieldMeta(
            name="customer_score",
            status=FieldStatus.PENDING,
            last_changed_by="agent-onboarding",
            last_changed_at=ts,
        )
        assert meta.last_changed_by == "agent-onboarding"
        assert meta.last_changed_at == ts

    def test_immutable(self) -> None:
        meta = FieldMeta(name="x", status=FieldStatus.OPEN)
        with pytest.raises(dataclasses.FrozenInstanceError):
            meta.status = FieldStatus.CLOSED  # type: ignore[misc]
```

- [ ] **Step 1.2: Run.** `uv run pytest tests/unit/core/test_schemas.py -v` — expect ImportError.

- [ ] **Step 1.3: Implement.**

```python
# src/cognic_agentos/core/schemas.py
"""Governance vocabulary — enums + typed metadata records.

Wire-format: every enum value is persisted into audit + decision_history
payloads. Values are append-only; never rename / repurpose without a
schema_version bump + migration. Adding new values is fine.

`FieldMeta` is a small typed record describing a governance-relevant
field on a domain object. Sprint 2 introduces the type so downstream
sprints (escalation, ticket events, evidence-pack export) can reuse a
consistent shape rather than ad-hoc dicts. Frozen for safety.
"""
from __future__ import annotations

import dataclasses
from datetime import datetime
from enum import Enum


class CognicAction(str, Enum):
    CALL_TOOL = "call_tool"
    COMPLETE = "complete"
    ESCALATE = "escalate"


class ComplianceVerdict(str, Enum):
    APPROVED = "approved"
    DENIED = "denied"
    NEEDS_REVIEW = "needs_review"


class FieldStatus(str, Enum):
    OPEN = "open"
    PENDING = "pending"
    CLOSED = "closed"


@dataclasses.dataclass(frozen=True, slots=True)
class FieldMeta:
    """Typed metadata record for a governance-tracked field."""

    name: str
    status: FieldStatus
    last_changed_by: str | None = None
    last_changed_at: datetime | None = None
```

- [ ] **Step 1.4: Run.** `uv run pytest tests/unit/core/test_schemas.py -v` — expect 6 passed.

- [ ] **Step 1.5: Commit.**

```bash
git add src/cognic_agentos/core/schemas.py tests/unit/core/test_schemas.py tests/unit/core/__init__.py
git commit -m "feat(sprint-2): core/schemas governance vocabulary enums + FieldMeta"
```

---

## Task 2 — `core/canonical.py` (canonical form + hash function — single source of truth)

**Files:**
- Create: `src/cognic_agentos/core/canonical.py`
- Test: `tests/unit/core/test_canonical.py`

This task is the FIRST critical-controls module. Use `core-controls-engineer` and `/critical-module-mode`. **Stop gate: human review of the canonical-form rules before commit.**

- [ ] **Step 2.1: Write the failing tests (TDD-driven, full negative-path battery).**

```python
# tests/unit/core/test_canonical.py
from __future__ import annotations
import math, uuid
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from cognic_agentos.core.canonical import (
    ZERO_HASH,
    canonical_bytes,
    hash_record,
)


class TestCanonicalDeterminism:
    def test_dict_key_order_independent(self) -> None:
        a = canonical_bytes({"a": 1, "b": 2, "c": 3})
        b = canonical_bytes({"c": 3, "b": 2, "a": 1})
        assert a == b

    def test_nested_dict_key_order_independent(self) -> None:
        a = canonical_bytes({"x": {"a": 1, "b": 2}})
        b = canonical_bytes({"x": {"b": 2, "a": 1}})
        assert a == b

    def test_list_order_preserved(self) -> None:
        # Lists are ordered; flipping changes the hash.
        a = canonical_bytes({"items": [1, 2, 3]})
        b = canonical_bytes({"items": [3, 2, 1]})
        assert a != b

    def test_no_whitespace(self) -> None:
        out = canonical_bytes({"a": 1, "b": "x"})
        assert b" " not in out
        assert b"\n" not in out

    def test_unicode_preserved(self) -> None:
        out = canonical_bytes({"name": "Zürich"})
        assert "Zürich".encode() in out


class TestCanonicalTypes:
    def test_datetime_iso8601_z_suffix(self) -> None:
        dt = datetime(2026, 4, 28, 10, 30, 45, tzinfo=UTC)
        out = canonical_bytes({"ts": dt})
        assert b'"ts":"2026-04-28T10:30:45+00:00"' in out

    def test_uuid_hex_with_dashes(self) -> None:
        u = uuid.UUID("12345678-1234-5678-1234-567812345678")
        out = canonical_bytes({"id": u})
        assert b'"id":"12345678-1234-5678-1234-567812345678"' in out

    def test_bytes_base64(self) -> None:
        out = canonical_bytes({"b": b"\x00\x01\x02\x03"})
        # base64 of \x00\x01\x02\x03 == "AAECAw=="
        assert b'"b":"AAECAw=="' in out

    def test_decimal_string(self) -> None:
        out = canonical_bytes({"price": Decimal("19.99")})
        assert b'"price":"19.99"' in out

    def test_nan_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-finite"):
            canonical_bytes({"x": math.nan})

    def test_inf_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-finite"):
            canonical_bytes({"x": math.inf})


class TestHashRecord:
    def test_zero_hash_is_32_bytes(self) -> None:
        assert ZERO_HASH == bytes(32)
        assert len(ZERO_HASH) == 32

    def test_hash_is_32_bytes(self) -> None:
        h = hash_record(b'{"k":"v"}', ZERO_HASH)
        assert len(h) == 32

    def test_genesis_hash_is_deterministic(self) -> None:
        h1 = hash_record(b'{"k":"v"}', ZERO_HASH)
        h2 = hash_record(b'{"k":"v"}', ZERO_HASH)
        assert h1 == h2

    def test_different_canonical_produces_different_hash(self) -> None:
        h1 = hash_record(b'{"k":"v"}', ZERO_HASH)
        h2 = hash_record(b'{"k":"w"}', ZERO_HASH)
        assert h1 != h2

    def test_different_prev_produces_different_hash(self) -> None:
        h1 = hash_record(b'{"k":"v"}', ZERO_HASH)
        h2 = hash_record(b'{"k":"v"}', bytes([1] * 32))
        assert h1 != h2

    def test_invalid_prev_hash_length_rejected(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            hash_record(b'{"k":"v"}', bytes(31))
        with pytest.raises(ValueError, match="32 bytes"):
            hash_record(b'{"k":"v"}', bytes(33))


class TestGoldenHashes:
    """Hard-coded canonical-bytes + hash goldens. ANY change here means
    canonical-form rules changed and a `schema_version` bump + migration
    plan are required BEFORE the change can land. Goldens are computed
    by hand once and pinned forever (well, until v2)."""

    def test_canonical_bytes_golden_simple(self) -> None:
        # {"a":1,"b":"x"} sorted, no whitespace, UTF-8.
        assert canonical_bytes({"a": 1, "b": "x"}) == b'{"a":1,"b":"x"}'

    def test_canonical_bytes_golden_full_envelope(self) -> None:
        # Full envelope as Sprint 2 audit will produce. Frozen 2026-04-28.
        envelope = {
            "schema_version": 1,
            "chain_id": "audit_event",
            "record_id": "12345678-1234-5678-1234-567812345678",
            "sequence": 1,
            "tenant_id": None,
            "created_at": datetime(2026, 4, 28, 12, 0, 0, tzinfo=UTC),
            "event_type": "tool_invocation",
            "request_id": "r-1",
            "trace_id": None,
            "span_id": None,
            "langfuse_trace_id": None,
            "provider_label": None,
            "iso_controls": [],
            "payload": {"tool": "echo"},
        }
        canonical = canonical_bytes(envelope)
        # Pre-computed once. Any drift is a doctrine break.
        expected = (
            b'{"chain_id":"audit_event","created_at":"2026-04-28T12:00:00+00:00",'
            b'"event_type":"tool_invocation","iso_controls":[],'
            b'"langfuse_trace_id":null,"payload":{"tool":"echo"},'
            b'"provider_label":null,"record_id":"12345678-1234-5678-1234-567812345678",'
            b'"request_id":"r-1","schema_version":1,"sequence":1,"span_id":null,'
            b'"tenant_id":null,"trace_id":null}'
        )
        assert canonical == expected
        h = hash_record(canonical, ZERO_HASH)
        # Re-compute the genesis hash for this exact canonical form.
        # If this assertion ever changes, schema_version MUST bump.
        assert h.hex() == hashlib.sha256(ZERO_HASH + expected).hexdigest()
```

- [ ] **Step 2.2: Run.** Expect ImportError on first two test classes; subsequent tests fail.

- [ ] **Step 2.3: Implement.**

```python
# src/cognic_agentos/core/canonical.py
"""Canonical form + hash function for the audit / decision_history chain.

**Single source of truth.** Every chain participant (`core/audit.py`,
`core/decision_history.py`, `core/chain_verifier.py`) imports from
here. Reimplementing canonicalization elsewhere is a doctrine
violation — different bytes for the same logical record means a
silent chain break.

Canonical form:
- JSON with sorted dict keys; no whitespace; preserved Unicode.
- Datetimes → ISO 8601 with explicit timezone (UTC for evidence emission).
- UUIDs → 36-char hex-with-dashes (lowercase).
- bytes → standard-base64.
- Decimal → str (preserve precision).
- Enum (str-Enum) → ``.value``.
- Floating-point NaN / Infinity → raise (would silently de-canonicalize
  on round-trip via JSON parsers that lack 'NaN' support).
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import UUID

ZERO_HASH: bytes = bytes(32)


def _json_default(o: Any) -> Any:
    if isinstance(o, datetime):
        return o.isoformat()
    if isinstance(o, UUID):
        return str(o)
    if isinstance(o, bytes | bytearray):
        return base64.b64encode(bytes(o)).decode("ascii")
    if isinstance(o, Decimal):
        return str(o)
    if isinstance(o, Enum):
        return o.value
    if isinstance(o, float) and not math.isfinite(o):
        raise ValueError(f"non-finite float not allowed in canonical form: {o!r}")
    raise TypeError(f"canonical_bytes cannot serialize {type(o).__name__}")


def canonical_bytes(obj: Any) -> bytes:
    # Walk the object once to reject NaN/Inf in nested floats; json.dumps
    # itself does not raise on float('nan') by default (it emits 'NaN'
    # which is non-spec JSON and silently corrupts the chain on parse).
    _reject_non_finite_floats(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    ).encode("utf-8")


def _reject_non_finite_floats(obj: Any) -> None:
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise ValueError(f"non-finite float not allowed in canonical form: {obj!r}")
    elif isinstance(obj, dict):
        for v in obj.values():
            _reject_non_finite_floats(v)
    elif isinstance(obj, list | tuple):
        for v in obj:
            _reject_non_finite_floats(v)


def hash_record(canonical: bytes, prev_hash: bytes) -> bytes:
    if len(prev_hash) != 32:
        raise ValueError(f"prev_hash must be exactly 32 bytes, got {len(prev_hash)}")
    h = hashlib.sha256()
    h.update(prev_hash)
    h.update(canonical)
    return h.digest()
```

- [ ] **Step 2.4: Run.** All test classes green. Coverage on `core/canonical.py` should be ≥95%.

- [ ] **Step 2.5: Coverage check.**

```bash
uv run pytest tests/unit/core/test_canonical.py --cov=cognic_agentos.core.canonical --cov-report=term-missing
# Confirm ≥95% line + branch.
```

- [ ] **Step 2.6: Commit.**

```bash
git add src/cognic_agentos/core/canonical.py tests/unit/core/test_canonical.py
git commit -m "feat(sprint-2): core/canonical — single-source canonical form + hash function"
```

---

## Task 3 — `db/engine.py` (async SQLAlchemy engine + session factory)

**Files:**
- Create: `src/cognic_agentos/db/engine.py`
- Test: `tests/unit/db/test_engine.py`

- [ ] **Step 3.1: Write the failing test.**

```python
# tests/unit/db/test_engine.py
from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from cognic_agentos.core.config import Settings
from cognic_agentos.db.engine import (
    create_engine_from_settings,
    dispose_engine,
    session_factory_from_engine,
)


@pytest.mark.asyncio
async def test_engine_creates_against_sqlite() -> None:
    s = Settings(database_url="sqlite+aiosqlite:///:memory:", db_driver="postgres")
    engine = create_engine_from_settings(s)
    assert isinstance(engine, AsyncEngine)
    await dispose_engine(engine)


@pytest.mark.asyncio
async def test_session_factory_yields_async_session() -> None:
    s = Settings(database_url="sqlite+aiosqlite:///:memory:", db_driver="postgres")
    engine = create_engine_from_settings(s)
    factory = session_factory_from_engine(engine)
    async with factory() as session:
        assert isinstance(session, AsyncSession)
    await dispose_engine(engine)


@pytest.mark.asyncio
async def test_engine_refuses_empty_url() -> None:
    s = Settings(database_url=None, db_driver="postgres")
    with pytest.raises(ValueError, match="database_url"):
        create_engine_from_settings(s)
```

- [ ] **Step 3.2: Run.** Expect failures.

- [ ] **Step 3.3: Implement.**

```python
# src/cognic_agentos/db/engine.py
from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    async_sessionmaker,
    create_async_engine,
)

from cognic_agentos.core.config import Settings


def create_engine_from_settings(settings: Settings) -> AsyncEngine:
    if not settings.database_url:
        raise ValueError("database_url must be set; got empty/None")
    return create_async_engine(
        settings.database_url,
        echo=False,
        future=True,
        pool_pre_ping=True,  # detect stale connections before queries
    )


def session_factory_from_engine(engine: AsyncEngine) -> async_sessionmaker:
    return async_sessionmaker(engine, expire_on_commit=False)


async def dispose_engine(engine: AsyncEngine) -> None:
    await engine.dispose()
```

- [ ] **Step 3.4: Run + commit.**

```bash
uv run pytest tests/unit/db/test_engine.py -v   # expect 3 passed
git add src/cognic_agentos/db/engine.py tests/unit/db/test_engine.py
git commit -m "feat(sprint-2): db/engine async SQLAlchemy engine + session factory"
```

---

## Task 4 — Alembic baseline (env + script template + alembic.ini)

**Files:**
- Create: `src/cognic_agentos/db/migrations/env.py`
- Create: `src/cognic_agentos/db/migrations/script.py.mako`
- Create: `alembic.ini` (root of repo)
- Test: `tests/unit/db/test_alembic_baseline.py` (verifies env loads + script template renders)

- [ ] **Step 4.1: Initialize Alembic skeleton.**

```bash
uv run alembic init -t async src/cognic_agentos/db/migrations
# Move the generated alembic.ini to repo root if Alembic placed it inside the migrations dir.
```

- [ ] **Step 4.2: Edit `env.py` to read `COGNIC_DATABASE_URL` from `Settings`.**

```python
# src/cognic_agentos/db/migrations/env.py
from __future__ import annotations
import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import async_engine_from_config

from cognic_agentos.core.config import get_settings

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

settings = get_settings()
if not settings.database_url:
    raise RuntimeError(
        "Alembic env requires COGNIC_DATABASE_URL — set it in the operator's "
        "environment, or in `.env` for dev runs."
    )
config.set_main_option("sqlalchemy.url", settings.database_url)

# target_metadata is None until Task 5; the initial migration uses
# explicit `op.create_table(...)` rather than autogenerate, so no
# metadata wiring is needed yet.
target_metadata = None


def run_migrations_offline() -> None:
    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        future=True,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
```

- [ ] **Step 4.3: Verify env loads (no real migration yet).**

```bash
COGNIC_DATABASE_URL=sqlite+aiosqlite:///:memory: uv run alembic current
# Expect: empty (no migrations yet) but no errors.
```

- [ ] **Step 4.4: Commit.**

```bash
git add src/cognic_agentos/db/migrations/ alembic.ini
git commit -m "feat(sprint-2): alembic baseline (async env reading COGNIC_DATABASE_URL)"
```

---

## Task 5 — Initial migration: `0001_initial_governance_schema.py`

**Files:**
- Create: `src/cognic_agentos/db/migrations/versions/20260428_0001_initial_governance_schema.py`
- Test: `tests/integration/db/test_alembic_migrations.py`

**STOP GATE — schema design human review before commit.**

- [ ] **Step 5.1: Write the migration.**

```python
# src/cognic_agentos/db/migrations/versions/20260428_0001_initial_governance_schema.py
"""initial governance schema (audit + decision_history + chain_heads)

Round-2 amendments applied:
- governance_chain_heads table (one row per chain) for portable
  SELECT ... FOR UPDATE concurrency control
- schema_version SMALLINT NOT NULL DEFAULT 1 + tenant_id VARCHAR(64)
  on both evidence tables (record-identity envelope expansion)

Revision ID: 0001
Revises:
Create Date: 2026-04-28
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

ZERO_HASH_BYTES = bytes(32)  # 32 zero-bytes; matches core.canonical.ZERO_HASH


def upgrade() -> None:
    # --- chain-head lock table (Round-2 #1) -----------------------
    op.create_table(
        "governance_chain_heads",
        sa.Column("chain_id", sa.String(32), primary_key=True),
        sa.Column("latest_sequence", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("latest_hash", sa.LargeBinary(32), nullable=False),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    # Genesis rows. Both chains start with sequence=0 + ZERO_HASH so the
    # first append's prev_hash is read from THIS row, not from a missing
    # row that an Oracle/PG dialect might surface differently.
    op.bulk_insert(
        sa.table(
            "governance_chain_heads",
            sa.column("chain_id", sa.String(32)),
            sa.column("latest_sequence", sa.BigInteger()),
            sa.column("latest_hash", sa.LargeBinary(32)),
        ),
        [
            {"chain_id": "audit_event", "latest_sequence": 0, "latest_hash": ZERO_HASH_BYTES},
            {"chain_id": "decision_history", "latest_sequence": 0, "latest_hash": ZERO_HASH_BYTES},
        ],
    )

    # --- evidence tables -----------------------------------------
    for table in ("audit_event", "decision_history"):
        op.create_table(
            table,
            sa.Column("record_id", sa.Uuid(), primary_key=True),
            # No Identity() here — sequence is assigned in the application
            # layer under the chain_heads FOR UPDATE lock. Identity() would
            # double-source the value and risk drift between the column's
            # auto-increment and the chain head.
            sa.Column("sequence", sa.BigInteger(), nullable=False, unique=True),
            sa.Column(
                "schema_version",
                sa.SmallInteger(),
                nullable=False,
                server_default="1",
            ),
            sa.Column("tenant_id", sa.String(64), nullable=True),
            sa.Column("prev_hash", sa.LargeBinary(32), nullable=False),
            sa.Column("hash", sa.LargeBinary(32), nullable=False, unique=True),
            sa.Column(
                "created_at",
                sa.TIMESTAMP(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.Column("event_type", sa.String(64), nullable=False),
            sa.Column("request_id", sa.String(64), nullable=False),
            sa.Column("trace_id", sa.String(32), nullable=True),
            sa.Column("span_id", sa.String(16), nullable=True),
            sa.Column("langfuse_trace_id", sa.String(64), nullable=True),
            sa.Column("provider_label", sa.String(32), nullable=True),
            sa.Column("iso_controls", sa.JSON(), nullable=True),
            sa.Column("payload", sa.JSON(), nullable=False),
        )
        op.create_index(f"ix_{table}_request_id", table, ["request_id"])
        op.create_index(f"ix_{table}_event_type_created_at", table, ["event_type", "created_at"])
        op.create_index(f"ix_{table}_tenant_created_at", table, ["tenant_id", "created_at"])


def downgrade() -> None:
    for table in ("decision_history", "audit_event"):
        op.drop_index(f"ix_{table}_tenant_created_at", table)
        op.drop_index(f"ix_{table}_event_type_created_at", table)
        op.drop_index(f"ix_{table}_request_id", table)
        op.drop_table(table)
    op.drop_table("governance_chain_heads")
```

**GRANTs are NOT in this migration (Round-3 amendment).** Schema management and role management are kept separate per the policy in the Schema section above. The migration creates tables only; GRANT statements live in `docs/operator-runbooks/governance-tables-grants.md` (dialect-specific PG / Oracle snippets) and operators apply them out-of-band before the runtime container connects with non-superuser credentials. The verification test (`tests/integration/db/test_runtime_role_is_append_only.py`, Task 12.5 below) is the production-grade canary that the runbook was applied — it asserts UPDATE / DELETE on the evidence tables raise permission-denied for the runtime role.

- [ ] **Step 5.2: Write the round-trip integration test.**

```python
# tests/integration/db/test_alembic_migrations.py
from __future__ import annotations
import os, subprocess

import pytest

POSTGRES_URL = os.environ.get(
    "COGNIC_DATABASE_URL_POSTGRES_TEST",
    "postgresql+asyncpg://cognic:cognic_dev_only@localhost:5432/cognic",
)

ORACLE_URL = os.environ.get(
    "COGNIC_DATABASE_URL_ORACLE_TEST",
    "oracle+oracledb://cognic:cognic_dev_only@localhost:1521/?service_name=XEPDB1",
)


def _alembic(env_url: str, *args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["COGNIC_DATABASE_URL"] = env_url
    return subprocess.run(
        ["uv", "run", "alembic", *args],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )


@pytest.mark.postgres
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION"),
    reason="live Postgres integration; opt in via COGNIC_RUN_POSTGRES_INTEGRATION=1",
)
def test_postgres_upgrade_downgrade_upgrade_roundtrip() -> None:
    _alembic(POSTGRES_URL, "upgrade", "head")
    _alembic(POSTGRES_URL, "downgrade", "base")
    _alembic(POSTGRES_URL, "upgrade", "head")


@pytest.mark.oracle
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"),
    reason="live Oracle XE integration; opt in via COGNIC_RUN_ORACLE_INTEGRATION=1",
)
def test_oracle_upgrade_downgrade_upgrade_roundtrip() -> None:
    _alembic(ORACLE_URL, "upgrade", "head")
    _alembic(ORACLE_URL, "downgrade", "base")
    _alembic(ORACLE_URL, "upgrade", "head")
```

- [ ] **Step 5.3: Run round-trip locally against compose Postgres.**

```bash
docker compose -f infra/dev/docker-compose.yml up -d postgres
COGNIC_RUN_POSTGRES_INTEGRATION=1 \
COGNIC_DATABASE_URL_POSTGRES_TEST=postgresql+asyncpg://cognic:cognic_dev_only@localhost:5432/cognic \
  uv run pytest tests/integration/db/test_alembic_migrations.py::test_postgres_upgrade_downgrade_upgrade_roundtrip -v
```

- [ ] **Step 5.4: Run round-trip locally against Oracle XE overlay.**

```bash
docker compose -f infra/dev/docker-compose.yml -f infra/dev/docker-compose.oracle.yml up -d oracle
# Wait for healthy (3-5 min on first boot)
COGNIC_RUN_ORACLE_INTEGRATION=1 \
  uv run pytest tests/integration/db/test_alembic_migrations.py::test_oracle_upgrade_downgrade_upgrade_roundtrip -v
```

- [ ] **Step 5.5: Commit.**

```bash
git add src/cognic_agentos/db/migrations/versions/ tests/integration/db/
git commit -m "feat(sprint-2): initial migration — audit + decision_history with hash chain"
```

---

## Task 6 — `core/audit.py` (AuditStore.append)

**Files:**
- Create: `src/cognic_agentos/core/audit.py`
- Test: `tests/unit/core/test_audit.py`

**Critical-controls module — `core-controls-engineer` + `/critical-module-mode`. 95% coverage required.**

- [ ] **Step 6.1: Write the failing tests (full negative-path battery).**

The unit-level fixture creates `audit_event` + `governance_chain_heads` against `sqlite+aiosqlite` so the application logic is exercisable without a live DB. **Caveat:** SQLite does not honour `SELECT ... FOR UPDATE` (no row-level locking). Concurrency correctness is not provable on SQLite — that's why Task 12 runs a real concurrency test on Postgres + Oracle. The unit suite exercises the SQL shape + envelope wiring; integration tests prove the lock works.

```python
# tests/unit/core/test_audit.py
from __future__ import annotations
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.audit import AuditEvent, AuditStore, _audit_event, _chain_heads
from cognic_agentos.core.canonical import ZERO_HASH


@pytest.fixture
async def store(tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path}/audit.db"
    engine = create_async_engine(url)
    # Reuse the application's metadata to create both tables — keeps
    # column types in lockstep with production migration 0001.
    from cognic_agentos.core.audit import _metadata
    async with engine.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        # Seed the chain head row exactly like migration 0001.
        await conn.execute(_chain_heads.insert().values(
            chain_id="audit_event",
            latest_sequence=0,
            latest_hash=ZERO_HASH,
            updated_at=datetime.now(UTC),
        ))
    yield AuditStore(engine)
    await engine.dispose()


@pytest.mark.asyncio
async def test_genesis_append_uses_zero_prev_hash(store: AuditStore) -> None:
    event = AuditEvent(
        event_type="tool_invocation",
        request_id="req-1",
        payload={"tool": "echo"},
    )
    record_id, h = await store.append(event)
    assert isinstance(record_id, uuid.UUID)
    assert len(h) == 32
    # Row.prev_hash IS the zero hash; sequence == 1.
    async with store._engine.connect() as conn:
        row = (await conn.execute(select(_audit_event.c.prev_hash, _audit_event.c.sequence))).one()
    assert bytes(row.prev_hash) == ZERO_HASH
    assert row.sequence == 1


@pytest.mark.asyncio
async def test_second_append_links_to_first(store: AuditStore) -> None:
    _, h1 = await store.append(AuditEvent(event_type="t", request_id="r1", payload={}))
    _, h2 = await store.append(AuditEvent(event_type="t", request_id="r2", payload={}))
    async with store._engine.connect() as conn:
        rows = (
            await conn.execute(
                select(_audit_event.c.sequence, _audit_event.c.prev_hash).order_by(_audit_event.c.sequence)
            )
        ).all()
    assert rows[0].sequence == 1
    assert rows[1].sequence == 2
    assert bytes(rows[1].prev_hash) == h1


@pytest.mark.asyncio
async def test_chain_head_advances_with_each_append(store: AuditStore) -> None:
    # Round-2 #1: chain head must update atomically with each insert.
    _, h1 = await store.append(AuditEvent(event_type="t", request_id="r1", payload={}))
    async with store._engine.connect() as conn:
        head = (await conn.execute(
            select(_chain_heads.c.latest_sequence, _chain_heads.c.latest_hash)
            .where(_chain_heads.c.chain_id == "audit_event")
        )).one()
    assert head.latest_sequence == 1
    assert bytes(head.latest_hash) == h1


@pytest.mark.asyncio
async def test_append_raises_on_db_outage(store: AuditStore) -> None:
    async with store._engine.begin() as conn:
        await conn.execute(text("DROP TABLE audit_event"))
    with pytest.raises(Exception):
        await store.append(AuditEvent(event_type="t", request_id="r", payload={}))


@pytest.mark.asyncio
async def test_envelope_includes_record_identity(store: AuditStore) -> None:
    # Round-2 #3: hash material must include record_id + sequence +
    # schema_version + chain_id. The simplest assertion: two appends
    # with identical payload + metadata produce different hashes
    # because record_id (uuid4) differs.
    e = AuditEvent(event_type="t", request_id="r", payload={"k": "v"})
    _, h1 = await store.append(e)
    _, h2 = await store.append(e)
    assert h1 != h2  # record_id differs → envelope differs → hash differs


@pytest.mark.asyncio
async def test_schema_version_persists_as_1(store: AuditStore) -> None:
    await store.append(AuditEvent(event_type="t", request_id="r", payload={}))
    async with store._engine.connect() as conn:
        row = (await conn.execute(select(_audit_event.c.schema_version))).one()
    assert row.schema_version == 1


@pytest.mark.asyncio
async def test_tenant_id_optional_persists_when_provided(store: AuditStore) -> None:
    await store.append(AuditEvent(
        event_type="t", request_id="r", payload={}, tenant_id="bank-acme",
    ))
    async with store._engine.connect() as conn:
        row = (await conn.execute(select(_audit_event.c.tenant_id))).one()
    assert row.tenant_id == "bank-acme"


@pytest.mark.asyncio
async def test_payload_dict_key_order_irrelevant_for_chain(store: AuditStore) -> None:
    # Same logical payload in different dict-key order → same canonical
    # bytes for the payload chunk; envelope still differs because
    # record_id + sequence differ. Hash must differ regardless. The
    # invariant we're proving here is that canonical_bytes is order-
    # invariant (so a deterministic chain is achievable across nodes),
    # NOT that the per-row hash repeats — record_id makes that impossible.
    _, h1 = await store.append(AuditEvent(
        event_type="t", request_id="r", payload={"b": 2, "a": 1},
    ))
    _, h2 = await store.append(AuditEvent(
        event_type="t", request_id="r", payload={"a": 1, "b": 2},
    ))
    assert h1 != h2
    assert len(h1) == len(h2) == 32


@pytest.mark.asyncio
async def test_iso_controls_optional(store: AuditStore) -> None:
    await store.append(AuditEvent(
        event_type="t",
        request_id="r",
        iso_controls=("A.9.2", "A.10.2"),
        payload={},
    ))
    async with store._engine.connect() as conn:
        row = (await conn.execute(select(_audit_event.c.iso_controls))).one()
    # JSON column stores list of str; SQLite returns str (JSON-encoded);
    # PG/Oracle return list. Test for either shape.
    iso = row.iso_controls
    if isinstance(iso, str):
        assert "A.9.2" in iso and "A.10.2" in iso
    else:
        assert iso == ["A.9.2", "A.10.2"]
```

- [ ] **Step 6.2: Run + verify failures.**

- [ ] **Step 6.3: Implement.**

Round-2 #1: append serialises through `governance_chain_heads` with `SELECT ... FOR UPDATE`. No raw `LIMIT`. SQLAlchemy Core constructs (`select(...).with_for_update()`, `insert(...)`, `update(...)`) are dialect-aware — both Postgres and Oracle honour them.

Round-2 #3: hash material includes the full envelope (`schema_version`, `chain_id`, `record_id`, `sequence`, `tenant_id`, `created_at`, ...).

```python
# src/cognic_agentos/core/audit.py
"""AuditStore — append-only audit table with hash-chain integrity.

INSERT-only, fail-loud on DB outage. The runtime DB role is granted
INSERT + SELECT only on the `audit_event` table; UPDATE / DELETE are
revoked. Hash chain detects mutation, deletion, and reordering — but
NOT an insider DBA who rewrites the entire chain consistently
(defended later by ADR-006 §"Tamper-evident evidence chain" Merkle
root + signed manifest).

Concurrency: appends serialise through `governance_chain_heads`
(SELECT ... FOR UPDATE). Two coroutines that arrive simultaneously
both block on the chain-head row lock; the first commits the head
update, the second reads the new head and assigns sequence n+1. No
duplicate sequences, no duplicate hashes, no `LIMIT` SQL, portable
across Postgres + Oracle.
"""
from __future__ import annotations

import dataclasses
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Column,
    LargeBinary,
    MetaData,
    SmallInteger,
    String,
    Table,
    insert,
    select,
    update,
)
from sqlalchemy.dialects.oracle import RAW as ORACLE_RAW
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.types import TIMESTAMP, Uuid

from cognic_agentos.core.canonical import (
    canonical_bytes,
    hash_record,
)

_SCHEMA_VERSION = 1
_CHAIN_ID = "audit_event"

# Reflectionless table definitions — keep the Core SQL dialect-portable
# without paying the cost of inspecting the live schema on each connect.
_metadata = MetaData()

_chain_heads = Table(
    "governance_chain_heads",
    _metadata,
    Column("chain_id", String(32), primary_key=True),
    Column("latest_sequence", BigInteger, nullable=False),
    Column("latest_hash", LargeBinary(32), nullable=False),
    Column("updated_at", TIMESTAMP(timezone=True), nullable=False),
)

_audit_event = Table(
    "audit_event",
    _metadata,
    Column("record_id", Uuid(), primary_key=True),
    Column("sequence", BigInteger, nullable=False, unique=True),
    Column("schema_version", SmallInteger, nullable=False),
    Column("tenant_id", String(64), nullable=True),
    Column("prev_hash", LargeBinary(32), nullable=False),
    Column("hash", LargeBinary(32), nullable=False, unique=True),
    Column("created_at", TIMESTAMP(timezone=True), nullable=False),
    Column("event_type", String(64), nullable=False),
    Column("request_id", String(64), nullable=False),
    Column("trace_id", String(32), nullable=True),
    Column("span_id", String(16), nullable=True),
    Column("langfuse_trace_id", String(64), nullable=True),
    Column("provider_label", String(32), nullable=True),
    Column("iso_controls", JSON, nullable=True),
    Column("payload", JSON, nullable=False),
)


@dataclasses.dataclass(frozen=True, slots=True)
class AuditEvent:
    event_type: str
    request_id: str
    payload: dict[str, Any]
    tenant_id: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    langfuse_trace_id: str | None = None
    provider_label: str | None = None
    iso_controls: tuple[str, ...] = ()


class AuditStore:
    """Append-only audit chain. Hash material includes the full record
    identity envelope (schema_version, chain_id, record_id, sequence,
    tenant_id, created_at, ...) so mutating any of those is detectable
    by the chain verifier."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def append(self, event: AuditEvent) -> tuple[uuid.UUID, bytes]:
        async with self._engine.begin() as conn:
            # Round-2 #1: SELECT ... FOR UPDATE on the chain-head row.
            # Both PG and Oracle honour with_for_update() with the
            # default `nowait=False` (block until lock available).
            head_stmt = (
                select(_chain_heads.c.latest_sequence, _chain_heads.c.latest_hash)
                .where(_chain_heads.c.chain_id == _CHAIN_ID)
                .with_for_update()
            )
            head = (await conn.execute(head_stmt)).one()
            new_sequence = int(head.latest_sequence) + 1
            prev_hash = bytes(head.latest_hash)

            now = datetime.now(UTC)
            record_id = uuid.uuid4()

            # Round-2 #3: full identity envelope in the hash material.
            envelope = {
                "schema_version": _SCHEMA_VERSION,
                "chain_id": _CHAIN_ID,
                "record_id": str(record_id),
                "sequence": new_sequence,
                "tenant_id": event.tenant_id,
                "created_at": now,
                "event_type": event.event_type,
                "request_id": event.request_id,
                "trace_id": event.trace_id,
                "span_id": event.span_id,
                "langfuse_trace_id": event.langfuse_trace_id,
                "provider_label": event.provider_label,
                "iso_controls": list(event.iso_controls),
                "payload": event.payload,
            }
            new_hash = hash_record(canonical_bytes(envelope), prev_hash)

            # INSERT into audit.
            await conn.execute(
                insert(_audit_event).values(
                    record_id=record_id,
                    sequence=new_sequence,
                    schema_version=_SCHEMA_VERSION,
                    tenant_id=event.tenant_id,
                    prev_hash=prev_hash,
                    hash=new_hash,
                    created_at=now,
                    event_type=event.event_type,
                    request_id=event.request_id,
                    trace_id=event.trace_id,
                    span_id=event.span_id,
                    langfuse_trace_id=event.langfuse_trace_id,
                    provider_label=event.provider_label,
                    iso_controls=list(event.iso_controls) or None,
                    payload=event.payload,
                )
            )

            # UPDATE chain head atomically with the INSERT. The whole
            # transaction commits at __aexit__ of `engine.begin()`.
            await conn.execute(
                update(_chain_heads)
                .where(_chain_heads.c.chain_id == _CHAIN_ID)
                .values(latest_sequence=new_sequence, latest_hash=new_hash, updated_at=now)
            )

            return record_id, new_hash
```

**Why no `Identity()` on `audit_event.sequence`:** Round-2 #1 made `sequence` application-assigned under the chain-heads lock. An `Identity()` column would double-source the value (DB auto-increment vs application-assigned), which silently desyncs from `governance_chain_heads.latest_sequence` after the first concurrency hiccup. Migration `0001` was updated accordingly.

- [ ] **Step 6.4: Run + coverage.**

```bash
uv run pytest tests/unit/core/test_audit.py -v --cov=cognic_agentos.core.audit --cov-report=term-missing
# Confirm ≥95%
```

- [ ] **Step 6.5: Commit.**

```bash
git add src/cognic_agentos/core/audit.py tests/unit/core/test_audit.py
git commit -m "feat(sprint-2): core/audit — INSERT-only hash-chained audit store"
```

---

## Task 7 — `core/decision_history.py` (DecisionHistoryStore.append)

**Files:**
- Create: `src/cognic_agentos/core/decision_history.py`
- Test: `tests/unit/core/test_decision_history.py`

**Critical-controls module. Mirror Task 6's TDD approach with these additions:**
- Test that `audit_event` and `decision_history` chains are isolated (mutating one doesn't break the other).
- Test concurrent append: two coroutines append simultaneously; both must succeed with distinct sequences and a valid chain.

The implementation reuses the AuditStore body almost verbatim, parameterised by `_TABLE = "decision_history"`. **Decision:** factor out a `_HashChainedAppendStore` private base class shared between AuditStore and DecisionHistoryStore. Lives in `core/audit.py` (or in a private `core/_chain_store.py`) — flag for review when the diff is in front of the user.

Same TDD steps (failing test → impl → coverage → commit) as Task 6.

---

## Task 8 — `core/chain_verifier.py` (walk + verify_record + TamperReport)

**Files:**
- Create: `src/cognic_agentos/core/chain_verifier.py`
- Test: `tests/unit/core/test_chain_verifier.py`

**Critical-controls module. STOP GATE — `TamperReport` shape is human-reviewed before commit (it's the public contract for every later consumer of chain integrity).**

- [ ] **Step 8.1: Write the failing tests.**

```python
# tests/unit/core/test_chain_verifier.py
from __future__ import annotations

import pytest
from sqlalchemy import text

from cognic_agentos.core.audit import AuditEvent, AuditStore
from cognic_agentos.core.chain_verifier import (
    ChainVerifier,
    TamperReport,
)
# fixtures shared with test_audit.py


@pytest.mark.asyncio
async def test_clean_walk_returns_clean(store: AuditStore) -> None:
    for i in range(10):
        await store.append(AuditEvent(event_type="t", request_id=f"r{i}", payload={"i": i}))
    report = await ChainVerifier(store._engine, "audit_event").walk()
    assert report.is_clean
    assert report.records_checked == 10
    assert report.first_break_sequence is None


@pytest.mark.asyncio
async def test_mutated_payload_detected(store: AuditStore) -> None:
    for i in range(5):
        await store.append(AuditEvent(event_type="t", request_id=f"r{i}", payload={"i": i}))
    # UPDATE bypasses app-level INSERT-only contract; simulates a DBA
    # who tampered with the data.
    async with store._engine.begin() as conn:
        await conn.execute(text("UPDATE audit_event SET payload = '{\"i\":99}' WHERE sequence = 3"))
    report = await ChainVerifier(store._engine, "audit_event").walk()
    assert not report.is_clean
    assert report.first_break_sequence == 3
    assert report.break_kind == "hash_mismatch"


@pytest.mark.asyncio
async def test_deleted_row_detected_as_sequence_gap(store: AuditStore) -> None:
    for i in range(5):
        await store.append(AuditEvent(event_type="t", request_id=f"r{i}", payload={"i": i}))
    async with store._engine.begin() as conn:
        await conn.execute(text("DELETE FROM audit_event WHERE sequence = 3"))
    report = await ChainVerifier(store._engine, "audit_event").walk()
    assert not report.is_clean
    assert report.first_break_sequence == 3
    assert report.break_kind == "sequence_gap"


@pytest.mark.asyncio
async def test_corrupted_prev_hash_detected(store: AuditStore) -> None:
    for i in range(5):
        await store.append(AuditEvent(event_type="t", request_id=f"r{i}", payload={"i": i}))
    async with store._engine.begin() as conn:
        await conn.execute(text("UPDATE audit_event SET prev_hash = X'FFFFFFFF' || X'00' * 28 WHERE sequence = 3"))
    report = await ChainVerifier(store._engine, "audit_event").walk()
    assert not report.is_clean
    assert report.first_break_sequence == 3
    assert report.break_kind == "hash_mismatch"


@pytest.mark.asyncio
async def test_empty_chain_is_clean(store: AuditStore) -> None:
    report = await ChainVerifier(store._engine, "audit_event").walk()
    assert report.is_clean
    assert report.records_checked == 0


@pytest.mark.asyncio
async def test_verify_specific_record(store: AuditStore) -> None:
    rid, _ = await store.append(AuditEvent(event_type="t", request_id="r", payload={}))
    report = await ChainVerifier(store._engine, "audit_event").verify_record(rid)
    assert report.is_clean
```

- [ ] **Step 8.2: Implement.**

```python
# src/cognic_agentos/core/chain_verifier.py
"""ChainVerifier — walk the hash chain on `audit_event` or `decision_history`
and surface a typed TamperReport.

What ChainVerifier detects:
- `hash_mismatch`: row N's stored hash != recomputed sha256(prev_hash || canonical(content))
- `sequence_gap`: row sequence is not strictly N+1 of predecessor
- `prev_hash_mismatch`: row N's prev_hash != row (N-1)'s hash

What ChainVerifier does NOT detect:
- An insider DBA who rewrites the ENTIRE chain consistently. That
  threat is defended by ADR-006 §"Tamper-evident evidence chain"
  Merkle root + signed manifest at evidence-pack export time
  (Phase 3.3); not in scope here.
"""
from __future__ import annotations

import dataclasses
import uuid
from typing import Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.canonical import (
    ZERO_HASH,
    canonical_bytes,
    hash_record,
)

# Round-3 amendment landed during Task 8 implementation review:
# BreakKind expanded from 3 → 5 values. ``head_mismatch`` catches
# tampering with the mutable governance_chain_heads row (a DBA
# could corrupt the head and leave evidence rows intact —
# previously walk() would have returned clean even though future
# appends would compute against a corrupted chain). ``record_not_found``
# is the verify_record() path for a chain_id that doesn't exist.
BreakKind = Literal[
    "hash_mismatch",
    "sequence_gap",
    "prev_hash_mismatch",
    "head_mismatch",
    "record_not_found",
]


@dataclasses.dataclass(frozen=True, slots=True)
class TamperReport:
    # Field renamed ``table`` → ``chain_id`` during Task 8 review:
    # ChainVerifier addresses chains by the logical chain_id literal
    # (``audit_event`` / ``decision_history``), not the physical SQL
    # table name. The two are 1:1 today but logical naming is the
    # right surface for the verifier API.
    chain_id: str
    is_clean: bool
    records_checked: int
    first_break_sequence: int | None = None
    break_kind: BreakKind | None = None
    detail: str | None = None


class ChainVerifier:
    # Constructor parameter renamed ``table`` → ``chain_id`` to match
    # the TamperReport surface (Round-3 amendment, Task 8 review).
    def __init__(self, engine: AsyncEngine, chain_id: str) -> None:
        if chain_id not in {"audit_event", "decision_history"}:
            raise ValueError(f"unsupported chain_id: {chain_id!r}")
        self._engine = engine
        self._chain_id = chain_id

    async def walk(self) -> TamperReport:
        # SQLAlchemy Core select — dialect-portable; no LIMIT or
        # dialect-specific syntax. Reads every column the canonical
        # envelope refers to (Round-2 #3) so the recomputed hash
        # matches what append() actually wrote.
        from sqlalchemy import MetaData, Table

        # Build a reflective Table; in production this comes from a
        # shared metadata module. Inlined here for clarity.
        table = _table_for(self._table)
        stmt = select(
            table.c.record_id, table.c.sequence, table.c.schema_version,
            table.c.tenant_id, table.c.prev_hash, table.c.hash,
            table.c.created_at, table.c.event_type, table.c.request_id,
            table.c.trace_id, table.c.span_id, table.c.langfuse_trace_id,
            table.c.provider_label, table.c.iso_controls, table.c.payload,
        ).order_by(table.c.sequence.asc())

        async with self._engine.connect() as conn:
            rows = (await conn.execute(stmt)).all()

        if not rows:
            return TamperReport(table=self._table, is_clean=True, records_checked=0)

        prev_hash = ZERO_HASH
        prev_seq = 0
        for row in rows:
            seq = int(row.sequence)
            if seq != prev_seq + 1:
                return TamperReport(
                    table=self._table, is_clean=False, records_checked=seq,
                    first_break_sequence=seq, break_kind="sequence_gap",
                    detail=f"expected sequence {prev_seq + 1}, got {seq}",
                )
            stored_prev = bytes(row.prev_hash)
            if stored_prev != prev_hash:
                return TamperReport(
                    table=self._table, is_clean=False, records_checked=seq,
                    first_break_sequence=seq, break_kind="prev_hash_mismatch",
                    detail="row.prev_hash does not link to predecessor",
                )
            # Round-2 #3: canonical envelope must include record_id +
            # sequence + schema_version + chain_id + tenant_id +
            # created_at, exactly as audit.append() wrote them.
            envelope = {
                "schema_version": int(row.schema_version),
                "chain_id": self._table,
                "record_id": str(row.record_id) if not isinstance(row.record_id, str) else row.record_id,
                "sequence": seq,
                "tenant_id": row.tenant_id,
                "created_at": row.created_at,
                "event_type": row.event_type,
                "request_id": row.request_id,
                "trace_id": row.trace_id,
                "span_id": row.span_id,
                "langfuse_trace_id": row.langfuse_trace_id,
                "provider_label": row.provider_label,
                "iso_controls": _normalise_iso_controls(row.iso_controls),
                "payload": _normalise_json_column(row.payload),
            }
            recomputed = hash_record(canonical_bytes(envelope), stored_prev)
            stored_hash = bytes(row.hash)
            if recomputed != stored_hash:
                return TamperReport(
                    table=self._table, is_clean=False, records_checked=seq,
                    first_break_sequence=seq, break_kind="hash_mismatch",
                    detail="row.hash != recomputed",
                )
            prev_hash = stored_hash
            prev_seq = seq

        return TamperReport(table=self._table, is_clean=True, records_checked=prev_seq)

    async def verify_record(self, record_id: uuid.UUID) -> TamperReport:
        # Walk from genesis up to and including record_id; tamper detail
        # narrows to that row when the report breaks. Full implementation
        # lands at commit-time; same canonical-envelope rules apply.
        ...
```

`_normalise_iso_controls` + `_normalise_json_column` handle the shape difference between SQLite (str-encoded JSON) and Postgres/Oracle (native list/dict): both return Python list/dict so the canonical envelope re-hashes deterministically.

- [ ] **Step 8.3: Run + coverage + commit.**

---

## Task 9 — Wire `run_migrations()` in PostgresAdapter + OracleAdapter

**Files:**
- Modify: `src/cognic_agentos/db/adapters/postgres_adapter.py`
- Modify: `src/cognic_agentos/db/adapters/oracle_adapter.py`
- Test: `tests/integration/db/test_run_migrations_live.py`

**Per Round-2 amendment #6: this method is OPERATOR-CALLABLE only.** The lifespan does NOT auto-invoke it. Banks run migrations as a deploy-time job (e.g. `kubectl create job migrate ...` or a manual `uv run alembic upgrade head` in a maintenance window). The adapter exposes the method so dev tooling + integration tests have a programmatic call path; the runtime container's PID-1 path never goes through it.

- [ ] **Step 9.1: Replace `NotImplementedError` with real Alembic invocation.**

```python
# postgres_adapter.py and oracle_adapter.py — same shape.
# Imports are LOCAL to the method so the adapter module doesn't pay
# the alembic import cost on cold-start.

async def run_migrations(self, dir: str | None = None) -> None:
    """Run Alembic upgrade head against this adapter's database URL.

    OPERATOR-CALLABLE ONLY. Sprint 2 amendment: the lifespan does not
    auto-invoke this. Production deployments run `uv run alembic
    upgrade head` (or a Kubernetes job) ahead of rolling out the
    runtime container so a misconfigured runtime can't silently
    invent schema.

    `dir` is accepted for backwards compat with the Sprint 1C/1D
    protocol shape but is ignored: Sprint 2 anchors the canonical
    alembic env at `src/cognic_agentos/db/migrations/`. Banks running
    downstream Alembic envs do so out-of-band.
    """
    from alembic import command
    from alembic.config import Config
    # Run alembic in a thread — alembic.command.upgrade is sync. Keep
    # the adapter's `async` shape clean for callers.
    import asyncio
    def _run() -> None:
        config = Config("alembic.ini")
        # Pin sqlalchemy.url at runtime so the adapter's own URL wins
        # over whatever env.py reads from `Settings`.
        config.set_main_option("sqlalchemy.url", self._url)
        command.upgrade(config, "head")
    await asyncio.to_thread(_run)
```

- [ ] **Step 9.2: Integration test against compose Postgres + Oracle XE overlay.**

```python
@pytest.mark.parametrize("driver", ["postgres", "oracle"])  # gated by env vars
async def test_run_migrations_is_idempotent(driver: str) -> None:
    # First call upgrades to head; second call is a no-op (alembic_version
    # already at HEAD).
    adapter = _adapter_for(driver)
    await adapter.connect()
    await adapter.run_migrations()
    await adapter.run_migrations()  # idempotent
    await adapter.close()
```

- [ ] **Step 9.3: Commit.**

---

## Task 10 — CI: new `postgres-integration` job + coverage gate

**Files:**
- Modify: `.github/workflows/python.yml`
- Add: `tests/integration/db/conftest.py` (postgres-service-up helper if needed)

- [ ] **Step 10.1: Add `postgres-integration` job.**

Mirror the existing `oracle-integration` shape. Bring up `infra/dev/docker-compose.yml postgres`, set `COGNIC_RUN_POSTGRES_INTEGRATION=1` + `COGNIC_DATABASE_URL`, run `pytest -m postgres`, tear down on `always()`.

- [ ] **Step 10.2: Per-file coverage gate (Round-2 amendment #4).**

`pytest --cov-fail-under=95` over multiple `--cov` targets enforces a **combined** threshold; one well-covered module can mask another. Replace with a small script that parses `coverage.json` and fails if **any** of the four critical modules drops below 95% line OR 90% branch.

Create `tools/check_critical_coverage.py`:

```python
"""Per-file coverage gate for Sprint-2 critical-controls modules.

Reads coverage.json produced by `pytest --cov-report=json` and asserts
that EACH listed file independently meets the threshold. Replaces the
combined `--cov-fail-under=95` shape, which can mask a 91% file behind
a 99% file in the same target set.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

CRITICAL_FILES: tuple[tuple[str, float, float], ...] = (
    # (path-relative-to-repo, line-threshold, branch-threshold)
    ("src/cognic_agentos/core/audit.py", 0.95, 0.90),
    ("src/cognic_agentos/core/decision_history.py", 0.95, 0.90),
    ("src/cognic_agentos/core/chain_verifier.py", 0.95, 0.90),
    ("src/cognic_agentos/core/canonical.py", 0.95, 0.90),
)


def main() -> int:
    coverage_json = Path("coverage.json")
    if not coverage_json.exists():
        print("::error::coverage.json missing; run pytest --cov-report=json first")
        return 1
    data = json.loads(coverage_json.read_text())
    files = data.get("files", {})
    fail = False
    for path, line_floor, branch_floor in CRITICAL_FILES:
        entry = files.get(path)
        if entry is None:
            print(f"::error file={path}::no coverage data — module not exercised by suite")
            fail = True
            continue
        s = entry["summary"]
        line_rate = s["percent_covered"] / 100.0
        # branch_rate is reported only when --cov-branch is enabled.
        b_executed = s.get("covered_branches")
        b_total = s.get("num_branches")
        branch_rate = (b_executed / b_total) if (b_total and b_total > 0) else 1.0
        ok_line = line_rate >= line_floor
        ok_branch = branch_rate >= branch_floor
        marker = "OK" if (ok_line and ok_branch) else "FAIL"
        print(
            f"[{marker}] {path}: "
            f"line={line_rate:.2%} (floor {line_floor:.0%}) "
            f"branch={branch_rate:.2%} (floor {branch_floor:.0%})"
        )
        if not ok_line:
            print(f"::error file={path}::line coverage {line_rate:.2%} below floor {line_floor:.0%}")
            fail = True
        if not ok_branch:
            print(f"::error file={path}::branch coverage {branch_rate:.2%} below floor {branch_floor:.0%}")
            fail = True
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
```

Wire into CI:

```yaml
- name: Coverage (with branch + JSON report)
  run: |
    uv run pytest \
      --cov=cognic_agentos \
      --cov-branch \
      --cov-report=json \
      --cov-report=term-missing \
      -m "not postgres and not oracle"

- name: Per-file coverage gate (critical-controls ≥95% line + ≥90% branch)
  run: uv run python tools/check_critical_coverage.py
```

The branch-coverage floor is 90% (not 95%) because branch coverage on async/await + dataclass code is noisier than line coverage; 95%/90% reflects what's achievable on real critical-controls code without test-shape gymnastics. Numbers are revisitable per module if a specific file proves stable at 100%/95%.

- [ ] **Step 10.3: Push branch; observe CI light up.**

---

## Task 11 — BUILD_PLAN amendments + closeout doc placeholder

**Files:**
- Modify: `docs/BUILD_PLAN.md` (sprint-list update for the 2 / 2.5 split)
- (Sprint 2 closeout note happens at the end of Task 13 — separate file in `docs/closeouts/`.)

---

## Task 12 — Live concurrency test on **both** Postgres and Oracle (Round-2 amendment #7)

**Files:**
- Create: `tests/integration/db/test_concurrent_append.py`

Round-2 amendment: Oracle is a bundled bank path (Sprint 1D); concurrency correctness needs equal-rank coverage. Both Postgres and Oracle honour `SELECT ... FOR UPDATE`, but the contention behaviour differs (PG row-level lock vs Oracle row-level lock with different escalation rules); we prove both work.

- [ ] **Step 12.1: Parametrised concurrency test.**

```python
# tests/integration/db/test_concurrent_append.py
from __future__ import annotations

import asyncio
import os

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.audit import AuditEvent, AuditStore, _audit_event


def _engine_for(driver: str):
    if driver == "postgres":
        return create_async_engine(os.environ["COGNIC_DATABASE_URL_POSTGRES_TEST"])
    if driver == "oracle":
        return create_async_engine(os.environ["COGNIC_DATABASE_URL_ORACLE_TEST"])
    raise ValueError(driver)


@pytest.mark.parametrize(
    "driver,marker",
    [
        pytest.param(
            "postgres", "postgres",
            marks=[
                pytest.mark.postgres,
                pytest.mark.skipif(
                    not os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION"),
                    reason="opt in via COGNIC_RUN_POSTGRES_INTEGRATION=1 + compose up postgres",
                ),
            ],
        ),
        pytest.param(
            "oracle", "oracle",
            marks=[
                pytest.mark.oracle,
                pytest.mark.skipif(
                    not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"),
                    reason="opt in via COGNIC_RUN_ORACLE_INTEGRATION=1 + compose up oracle",
                ),
            ],
        ),
    ],
)
@pytest.mark.asyncio
async def test_concurrent_appends_serialise_cleanly(driver: str, marker: str) -> None:
    """Round-2 amendment #1 + #7: 50 concurrent appends on a real DB must
    produce exactly 50 distinct sequences (1..50), 50 distinct hashes, and
    a chain that walks cleanly. Proves the chain_heads SELECT ... FOR
    UPDATE serialises correctly on this dialect."""
    engine = _engine_for(driver)
    try:
        # Migration must already have run; assume the integration job
        # ran `alembic upgrade head` against this DB.
        store = AuditStore(engine)

        async def one_append(i: int) -> bytes:
            _, h = await store.append(
                AuditEvent(event_type="t", request_id=f"r-{i}", payload={"i": i})
            )
            return h

        results = await asyncio.gather(*(one_append(i) for i in range(50)))

        # All hashes distinct.
        assert len(set(results)) == 50

        # Sequences are 1..50 contiguous.
        async with engine.connect() as conn:
            seqs = (
                await conn.execute(select(_audit_event.c.sequence).order_by(_audit_event.c.sequence))
            ).scalars().all()
        assert list(seqs) == list(range(1, 51))

        # Chain walks cleanly.
        from cognic_agentos.core.chain_verifier import ChainVerifier
        report = await ChainVerifier(engine, "audit_event").walk()
        assert report.is_clean
        assert report.records_checked == 50
    finally:
        await engine.dispose()
```

CI extension: the existing `oracle-integration` job is extended to also run `pytest -m "oracle and not postgres"` after the Sprint-1D Oracle adapter test, so this concurrency test runs there. The new `postgres-integration` job (Task 10) similarly runs `pytest -m "postgres and not oracle"`.

- [ ] **Step 12.5: Runtime-role append-only verification test (Round-3).**

`tests/integration/db/test_runtime_role_is_append_only.py` is the production-grade canary that the operator runbook for governance-table GRANTs was applied. Without it, "INSERT-only" is a code-discipline claim, not a DB-enforced one — and code discipline can be bypassed by anyone with raw SQL access.

```python
# tests/integration/db/test_runtime_role_is_append_only.py
from __future__ import annotations
import os

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError
from sqlalchemy.ext.asyncio import create_async_engine


def _runtime_engine_for(driver: str):
    """Connect using the NON-superuser runtime role. The integration
    job is responsible for setting these env vars to a role that has
    been GRANTed only INSERT + SELECT on the evidence tables (per the
    operator runbook). If the env vars point at a superuser, this
    test will spuriously pass. The CI job sets them correctly."""
    if driver == "postgres":
        return create_async_engine(os.environ["COGNIC_RUNTIME_DATABASE_URL_POSTGRES_TEST"])
    if driver == "oracle":
        return create_async_engine(os.environ["COGNIC_RUNTIME_DATABASE_URL_ORACLE_TEST"])
    raise ValueError(driver)


@pytest.mark.parametrize(
    "driver",
    [
        pytest.param("postgres", marks=[pytest.mark.postgres, pytest.mark.skipif(
            not os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION"), reason="opt in")]),
        pytest.param("oracle", marks=[pytest.mark.oracle, pytest.mark.skipif(
            not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"), reason="opt in")]),
    ],
)
@pytest.mark.asyncio
async def test_runtime_role_cannot_update_or_delete_evidence_tables(driver: str) -> None:
    """The runtime role must be denied UPDATE + DELETE on `audit_event` and
    `decision_history`. If this test passes against a superuser, the
    operator runbook hasn't been applied — fix that before shipping."""
    engine = _runtime_engine_for(driver)
    try:
        for table in ("audit_event", "decision_history"):
            for stmt in (
                f"UPDATE {table} SET payload = payload",
                f"DELETE FROM {table} WHERE 1=0",
            ):
                with pytest.raises((DBAPIError, ProgrammingError)) as exc_info:
                    async with engine.connect() as conn:
                        await conn.execute(text(stmt))
                # Sanity: the failure is permission-denied, not "table missing".
                msg = str(exc_info.value).lower()
                assert "permission" in msg or "privilege" in msg or "ora-01031" in msg, \
                    f"expected permission-denied on {driver} {stmt!r}, got: {msg}"
    finally:
        await engine.dispose()


@pytest.mark.parametrize(
    "driver",
    [
        pytest.param("postgres", marks=[pytest.mark.postgres, pytest.mark.skipif(
            not os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION"), reason="opt in")]),
        pytest.param("oracle", marks=[pytest.mark.oracle, pytest.mark.skipif(
            not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"), reason="opt in")]),
    ],
)
@pytest.mark.asyncio
async def test_runtime_role_can_actually_append_through_audit_store(driver: str) -> None:
    """**Round-4 amendment #9:** the production-grade canary must prove the
    full append transaction succeeds for the runtime role — lock chain
    head + INSERT into audit_event + UPDATE governance_chain_heads — not
    just that SELECT against chain_heads works.

    A SELECT-only test would silently pass even if the operator runbook
    forgot to GRANT INSERT on audit_event or UPDATE on
    governance_chain_heads. Calling ``AuditStore.append()`` exercises
    the exact transaction shape AgentOS uses in production, so a
    missing privilege fails here, not at the first audit emission in
    a live deployment.
    """
    from cognic_agentos.core.audit import AuditEvent, AuditStore

    engine = _runtime_engine_for(driver)
    try:
        store = AuditStore(engine)
        record_id, h = await store.append(
            AuditEvent(
                event_type="runbook_canary",
                request_id="canary-runtime-role",
                payload={"check": "runtime role can append"},
            )
        )
        # Hash is 32 bytes → the full append transaction completed
        # (lock head + insert evidence + update head all under the
        # runtime role's grants).
        assert len(h) == 32

        # Sanity: the row landed AND the head moved. SELECTs on both
        # tables must succeed for the runtime role; the canary catches
        # a partial-grant where INSERT on audit_event works but the
        # head UPDATE silently fails (or vice versa).
        from sqlalchemy import select
        from cognic_agentos.core.audit import _audit_event, _chain_heads
        async with engine.connect() as conn:
            evidence_row = (await conn.execute(
                select(_audit_event.c.record_id).where(_audit_event.c.record_id == record_id)
            )).one()
            assert evidence_row.record_id == record_id
            head_row = (await conn.execute(
                select(_chain_heads.c.latest_hash)
                .where(_chain_heads.c.chain_id == "audit_event")
            )).one()
            assert bytes(head_row.latest_hash) == h
    finally:
        await engine.dispose()
```

CI surfaces the env vars (`COGNIC_RUNTIME_DATABASE_URL_POSTGRES_TEST`, `COGNIC_RUNTIME_DATABASE_URL_ORACLE_TEST`) by creating a per-job role inside the integration containers, applying the runbook GRANTs, and pointing the test at the resulting DSN. The integration job thus exercises the operator runbook end-to-end, not just the schema migration.

The canary is **explicitly an integration test on real DBs** — `AuditStore.append()` against SQLite would not prove the runtime-role grants because SQLite has no role-based access control. Round-4 makes the test parametrise on Postgres + Oracle only; SQLite-based unit tests in `tests/unit/core/test_audit.py` cover the application logic separately.

---

## Task 13 — READY-FOR-GATE sweep + handoff

- [ ] **Step 13.1: `uv run ruff check .` + `ruff format --check .` + `mypy src tests` (strict).**
- [ ] **Step 13.2: `uv run pytest -q --cov=cognic_agentos --cov-report=term-missing`.**
   - Critical-controls modules: ≥95% line + ≥90% branch each (per-file gate via `tools/check_critical_coverage.py`).
   - Global: ≥93%. Actual at sprint close: 95% with `db/migrations/env.py` excluded from rollup (it's exercised end-to-end by `test_alembic_migrations.py` via the alembic CLI subprocess, which coverage.py cannot trace back to the env.py module — see `[tool.coverage.run].omit` in `pyproject.toml`).
- [ ] **Step 13.3: Live integration runs.**
   - `COGNIC_RUN_POSTGRES_INTEGRATION=1 uv run pytest -m postgres -v`
   - `COGNIC_RUN_ORACLE_INTEGRATION=1 uv run pytest -m oracle -v` (with the Oracle overlay up)
- [ ] **Step 13.4: Migration round-trip on both databases (Task 5 tests + a manual `alembic downgrade base && alembic upgrade head`).**
- [ ] **Step 13.5: Boot smoke against the kernel + default-adapters images** — neither image should break. The kernel image grows by ~13 MiB (SQLAlchemy + Alembic + greenlet promoted to base per Round-2 #2); the kernel boot smoke step from Phase 1 runs unchanged, asserting that `import cognic_agentos.core.audit` succeeds inside the kernel container (it must, now that SQLAlchemy ships there).
- [ ] **Step 13.6: Handoff summary** — restate to the user with all gates green; await `push it` / `pr` / `merge` per per-action rule.
- [ ] **Step 13.7: After merge — write `docs/closeouts/2026-XX-XX-sprint-2-governance-foundation.md`** (mirror the Phase 1 closeout shape).

---

## Verification — end-state of Sprint 2

- 5 new modules in `src/cognic_agentos/core/` (`schemas`, `canonical`, `audit`, `decision_history`, `chain_verifier`) — Python module names; the underlying DB table is `audit_event`.
- 2 new modules in `src/cognic_agentos/db/` (`engine`, `types`). `db/types` was added in Round-2 of Task 5 (`chain_hash_column_type()` + `GovernanceJSON` TypeDecorator) once the Oracle JSON-CompileError + Oracle RAW(32)-vs-BLOB drift surfaced.
- 1 new tools script (`tools/check_critical_coverage.py`).
- Alembic baseline + 1 migration; both `OracleAdapter.run_migrations` and `PostgresAdapter.run_migrations` are real (not `NotImplementedError`); the lifespan does NOT auto-invoke them — operator-only.
- 3 tables in migration `0001`: `governance_chain_heads` (one row per chain, append serialisation), `audit_event`, `decision_history`. Both evidence tables carry `schema_version` (1) + `tenant_id` (nullable).
- New CI gates: `postgres-integration` job; per-file critical-controls coverage gate; Postgres + Oracle integration jobs each provision the runtime role + apply the operator-runbook GRANTs (Oracle adds cross-schema synonyms via SYSTEM, Path A.1) before running the canary + concurrency tests.
- Test suite grows from 264 (Phase 1 close) to **464 unit + 18 integration = 482 total** (≈+200 unit, +18 integration). Plan-time projection was "~340" (Round-1) revised to "~470" in the BUILD_PLAN sweep — actuals match the BUILD_PLAN figure.
- Critical-controls modules at ≥95% line + ≥90% branch coverage (per-file gate enforced); global at **95%** (with `db/migrations/env.py` excluded from rollup — it is alembic CLI-subprocess scaffolding, not unit-testable; integration tests cover that path).
- Runtime DB role grants: INSERT + SELECT on `audit_event` + `decision_history`; INSERT + SELECT + UPDATE on `governance_chain_heads`. No DELETE / no UPDATE on evidence tables.
- Phase-1 carryovers landed: `provider_label` + `langfuse_trace_id` are columns on both tables; LLM gateway (Sprint 3) emits via these columns.
- New columns in the canonical envelope (Round-2): `schema_version`, `chain_id`, `record_id`, `sequence`, `tenant_id` — mutating any of them is detectable by the chain verifier.
- BUILD_PLAN amended for the 2 / 2.5 split + the SQLAlchemy/Alembic dep promotion + the no-auto-migrate doctrine.
- Kernel image still ≤120 MiB after SQLAlchemy + Alembic land in base deps (or budget bump request gated on Step 0.8); default-adapters still ≤220 MiB.

## What this plan does NOT include

- `core/sla.py`, `core/escalation.py`, `core/guardrails.py` — proposed for Sprint 2.5.
- LLM gateway (Sprint 3).
- Evidence-pack export with Merkle root + signed manifest (Phase 3.3 per ADR-006).
- DB role management automation. The migration ships table DDL only. Role creation + GRANT application + password rotation happen out-of-band per the operator runbook (`docs/operator-runbooks/governance-tables-grants.md`); the runtime-role verification test (Task 12.5) is the production-grade canary that the runbook has been applied.
- Push, PR, merge — per per-action rule.

---

## Self-Review

- **Spec coverage:** every BUILD_PLAN Sprint 2 deliverable except sla/escalation/guardrails has at least one task. Those three are explicitly deferred via the doctrine amendment in Task 0.4. `FieldMeta` (the deliverable that nearly slipped) is a small frozen dataclass in Task 1 (Round-2 #5).
- **Concurrency safety (Round-2 #1):** append serialises through `governance_chain_heads` with a portable `SELECT ... FOR UPDATE`; no `LIMIT`, no DESC scan over the evidence table. SQLite unit tests can't prove the lock, so live concurrency is proven on **both** Postgres and Oracle in Task 12 (Round-2 #7).
- **Dep placement (Round-2 #2):** SQLAlchemy + Alembic + greenlet move to base `[project]` deps. Step 0.8 + 0.9 re-measure both image budgets; if the kernel image creeps past 118 MiB (≤2 MiB headroom inside the 120 MiB ceiling) the plan PAUSES for a budget-bump approval before continuing.
- **Hash material (Round-2 #3):** canonical envelope includes `schema_version`, `chain_id`, `record_id`, `sequence`, `tenant_id`, `created_at`, plus all metadata + payload. Mutating any of them is detectable. Schema starts at version 1; bumping requires a migration + a documented canonical-form change.
- **Coverage gate (Round-2 #4):** per-file enforcement via `tools/check_critical_coverage.py` parsing `coverage.json`. 95% line + 90% branch on each of the four critical files; one under-covered file fails CI even if siblings are at 100%.
- **No auto-migrate (Round-2 #6):** lifespan creates the engine, disposes at shutdown, and never invokes Alembic. Operators run migrations as a deploy-time job; `run_migrations()` exists for tooling + integration tests only.
- **Type consistency:** `record_id` is `uuid.UUID`; `prev_hash` / `hash` are `bytes` (length 32); `sequence` is `int`; `schema_version` is `int` (SMALLINT in DB); `tenant_id` is `str | None`; `TamperReport` is a frozen dataclass; `BreakKind` is `Literal["hash_mismatch", "sequence_gap", "prev_hash_mismatch"]`.
- **Open design questions:** all five Round-1 questions are now closed (recorded in the "Design questions — settled in Round-2" section above). No open questions remain blocking plan approval.
