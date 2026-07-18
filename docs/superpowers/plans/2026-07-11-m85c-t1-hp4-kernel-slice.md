# M8.5-C T1 — HP-4 kernel slice Implementation Plan
<!-- STATUS: HISTORICAL -->
<!-- OWNER: cognic-agentos maintainers -->
<!-- LAST-VERIFIED: 2026-07-18 -->

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Paginated approval queue + actor-bound grant replay across all four consumers, per the landed spec `docs/superpowers/specs/2026-07-11-m85c-cognic-harness-v1-design.md` §2 (main @ `536cc8a4`), as corrected by the plan review (2026-07-11).

**Architecture:** Migration 0017 adds the tenant-leading chronological index; storage gains a `(created_at, request_id)` keyset with a typed strict cursor; `ApprovalEngine.verify_grant_for_action` is reworked to the corrected precedence — tenant-scoped RAW load → originator → UNCONDITIONAL binding → lazy expiry/state projection (the only mutating step); the four replay consumers each map the new refusal into their closed vocabulary (sandbox additionally expands the wake passthrough 5→6); the approvals route's exact `_REFUSAL_STATUS` map gains the new reason; the queue route adds `limit`/`cursor` + a relative `Link: rel="next"` header while preserving the `list[...]` body; four dated ADR amendments + the design-spec index correction land.

**Tech Stack:** existing kernel stack only — SQLAlchemy/Alembic, FastAPI, pytest. No new dependency.

## Global Constraints

- Spec §2 governs; the recon locks at ADR-028 spec §0.2/§0.4 are non-negotiable. NO T2 harness or T3 proof work enters this plan.
- **The eight touched gated modules** (all already on the durable gate): `core/approval/engine.py`, `core/approval/storage.py`, `protocol/mcp_host.py`, `sandbox/protocol.py`, `sandbox/admission.py`, `core/scheduler/engine.py`, `core/memory/gate.py`, `core/memory/tiers.py`. The final ladder runs `tools/check_critical_coverage.py` against FRESH full-suite `--cov-branch coverage.json` and every one of the eight must hold the 95/90 floor. Security-load-bearing arms get TM-revert pins (`feedback_security_regression_hardening`).
- `protocol/mcp_authz.py` stays byte-identical (`git diff main -- src/cognic_agentos/protocol/mcp_authz.py` empty).
- The queue response body stays `list[ApprovalSummaryResponse]`; pagination rides the relative `Link` header only. No `state` filter.
- **New originator-mismatch refusal details and logs must not contain either subject value** (requester or approver) — request ID + bounded reason only. This is scoped to the NEW surfaces: existing approval decision logs deliberately carry `actor_subject` (`portal/api/approvals/routes.py:95`) and are untouched. Every consumer's mapped-refusal test scans the NEW refusal's exception detail AND its caplog records for both subject strings.
- **Corrected verification precedence (this plan's Task 3 statement):** tenant-scoped RAW load (absent/cross-tenant → `ApprovalRequestNotFound`, no mutation) → originator check → **binding check, UNCONDITIONAL** (the persisted `args_digest`/`tool_identity` are set at create time and never change; comparing them requires no state, so a wrong-shape replay of a *pending* request refuses `approval_binding_mismatch`, never "pending") → lazy expiry + state projection (the ONLY step that may mutate or emit evidence). This satisfies the governing lock's ordering ("tenant-not-found collapse → originator → args/tool binding → state projection") with binding explicitly unconditional — no lock amendment required.
- Oracle portability: keyset via explicit tuple expansion; live PG + Oracle lanes are `@pytest.mark.postgres` / `@pytest.mark.oracle` marker-gated and include KEYSET QUERY coverage (equal-timestamp tiebreak + foreign-tenant decoy), not only DDL.
- **Limit ownership:** the route owns the wire contract (`Query(ge=1, le=200)` → FastAPI 422); storage clamps defensively to the same bounds. Both layers are boundary-tested; the route test pins 0→422 and 201→422 at validation, the storage test pins clamp(0)→1 and clamp(201)→200.

## Long-sprint execution model (ruled 2026-07-11)

- Execute Tasks 1–6 in ONE uninterrupted local sprint after this plan is reviewed, committed, and merged.
- **NO implementation commits during the sprint.** Internal checkpoints only: (CP-1) queue pagination = Tasks 1–2; (CP-2) actor-bound replay = Tasks 3–4; (CP-3) route/docs = Tasks 5–6; (CP-4) final integration = Task 7. Do not halt merely because a checkpoint passes — run its gate set, record the result, continue.
- Stop ONLY for: a source contradiction with this plan or the spec; unplanned P0/P1 behavior; scope expansion; a gate that stays red after diagnosis.
- No push, no PR, no provider proof, no cluster.
- **Halt exactly once** at the final pre-commit review (Task 7) with: the integrated diff, the proposed logical commit packets (guard-staged path sets + messages), the mutation/TM-revert pin list, the full-suite result, fresh 152-file CC coverage covering all eight touched gated modules, the live-DB lane results, and remaining risks. Commits happen only after that review.

---

### Task 1: Migration 0017 — the tenant-leading chronological queue index

**Files:**
- Create: `src/cognic_agentos/db/migrations/versions/20260711_0017_approval_queue_index.py`
- Modify: `src/cognic_agentos/core/approval/storage.py` (runtime-table parity: matching `Index` on `_approval_requests`)
- Test: `tests/unit/db/test_migration_20260711_0017.py`
- Test (live lanes): extend `tests/integration/db/test_alembic_migrations.py`

**Interfaces:**
- Consumes: migration `0016` as `down_revision`; the `approval_requests` table (migration 0009).
- Produces: index `ix_approval_requests_tenant_created_request` on `(tenant_id, created_at, request_id)`. **Design-spec correction (recorded in Task 6):** spec §2.1 names the composite as `(created_at, request_id)` — that pair is the KEYSET; the INDEX leads with `tenant_id` for the tenant-scoped WHERE. Task 6 amends the spec sentence accordingly.

- [ ] **Step 1: Write the failing tests** (full harness — the 0016 helper-function style, no fixtures invented):

```python
"""tests/unit/db/test_migration_20260711_0017.py — 0016-discipline mirror:
revision wiring, index shape, partial-state AND fully-applied reruns, the
three guard-shape negatives, downgrade round-trip, runtime-table parity."""

from __future__ import annotations

import importlib
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command

from cognic_agentos.db.migrations.alembic_config import make_alembic_config

MIGRATION = "cognic_agentos.db.migrations.versions.20260711_0017_approval_queue_index"
INDEX = "ix_approval_requests_tenant_created_request"
COLUMNS = ["tenant_id", "created_at", "request_id"]


def _upgrade(url: str, revision: str) -> None:
    # The alembic env requires the async driver scheme (the 0016 lesson).
    cfg = make_alembic_config(url.replace("sqlite://", "sqlite+aiosqlite://"))
    command.upgrade(cfg, revision)


def _db(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path}/t1.sqlite"


def test_revision_wiring() -> None:
    mod = importlib.import_module(MIGRATION)
    assert mod.revision == "0017"
    assert mod.down_revision == "0016"


def test_index_created_with_exact_columns(tmp_path: Path) -> None:
    url = _db(tmp_path)
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    try:
        idx = {i["name"]: i for i in sa.inspect(engine).get_indexes("approval_requests")}
        assert INDEX in idx
        assert idx[INDEX]["column_names"] == COLUMNS
        assert not idx[INDEX]["unique"], "non-unique query index by contract"
    finally:
        engine.dispose()


def test_fully_applied_rerun_is_idempotent(tmp_path: Path) -> None:
    url = _db(tmp_path)
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(sa.text("UPDATE alembic_version SET version_num='0016'"))
    finally:
        engine.dispose()
    _upgrade(url, "head")  # must guard-skip, not raise


def test_partial_state_rerun_recreates_only_the_missing_index(tmp_path: Path) -> None:
    url = _db(tmp_path)
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(sa.text(f"DROP INDEX {INDEX}"))
            conn.execute(sa.text("UPDATE alembic_version SET version_num='0016'"))
    finally:
        engine.dispose()
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    try:
        names = {i["name"] for i in sa.inspect(engine).get_indexes("approval_requests")}
        assert INDEX in names
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "mutation",
    [
        f"DROP INDEX {INDEX}; CREATE INDEX {INDEX} ON approval_requests (tenant_id, created_at)",
        f"DROP INDEX {INDEX}; CREATE UNIQUE INDEX {INDEX} ON approval_requests "
        "(tenant_id, created_at, request_id)",
        f"DROP INDEX {INDEX}; CREATE INDEX {INDEX} ON approval_requests "
        "(created_at, tenant_id, request_id)",
    ],
    ids=["wrong-column-count", "unique-posture", "wrong-column-order"],
)
def test_guard_fails_loud_on_shape_mismatch(tmp_path: Path, mutation: str) -> None:
    url = _db(tmp_path)
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            for stmt in mutation.split(";"):
                conn.execute(sa.text(stmt))
            conn.execute(sa.text("UPDATE alembic_version SET version_num='0016'"))
    finally:
        engine.dispose()
    with pytest.raises(Exception, match="0017 ddl: existing object shape mismatch"):
        _upgrade(url, "head")


def test_downgrade_removes_only_the_index(tmp_path: Path) -> None:
    url = _db(tmp_path)
    _upgrade(url, "head")
    # Seed one row THROUGH the migrated schema, downgrade, assert survival.
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO approval_requests (request_id, tenant_id, flow, risk_tier,"
                    " tool_identity, originator_subject, state, envelope_digest, args_digest,"
                    " redacted_context, data_classes, required_refs, created_at, expires_at,"
                    " updated_at) VALUES (:r, 't1', 'require_single_approval', 'customer_data_read',"
                    " 'mcp:x', 'analyst.amir', 'pending', x'00', x'00', '{}', '[]', '{}',"
                    " '2026-07-11 00:00:00+00:00', '2026-07-11 01:00:00+00:00',"
                    " '2026-07-11 00:00:00+00:00')"
                ),
                {"r": uuid.uuid4().hex},
            )
    finally:
        engine.dispose()
    cfg = make_alembic_config(url.replace("sqlite://", "sqlite+aiosqlite://"))
    command.downgrade(cfg, "0016")
    engine = sa.create_engine(url)
    try:
        names = {i["name"] for i in sa.inspect(engine).get_indexes("approval_requests")}
        assert INDEX not in names
        with engine.connect() as conn:
            count = conn.execute(sa.text("SELECT count(*) FROM approval_requests")).scalar()
        assert count == 1, "downgrade removes ONLY the derived index"
    finally:
        engine.dispose()


def test_runtime_table_parity(tmp_path: Path) -> None:
    from cognic_agentos.core.approval.storage import _approval_requests

    url = _db(tmp_path)
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    try:
        reflected = {i["name"] for i in sa.inspect(engine).get_indexes("approval_requests")}
    finally:
        engine.dispose()
    runtime = {i.name for i in _approval_requests.indexes}
    assert runtime <= reflected, f"runtime Table declares indexes the migration lacks: {runtime - reflected}"
    assert INDEX in runtime
```

Adjust the seeded INSERT's column list/values against the REAL 0009 schema at implementation time (Read `storage.py:78-104`; sqlite accepts the shown literal forms — if a NOT NULL column is missing from the list, the test fails loudly and the INSERT is corrected, never the schema).

- [ ] **Step 2:** `uv run pytest tests/unit/db/test_migration_20260711_0017.py -q` → FAIL (module not found).
- [ ] **Step 3: Write the migration** (identical to the reviewed shape):

```python
"""approval queue index — HP-4 (ADR-014 amendment; spec §2.1 as corrected).

Adds ix_approval_requests_tenant_created_request (tenant_id, created_at,
request_id): tenant-leading for the WHERE; (created_at, request_id) is the
keyset. Guarded + re-runnable; an existing object with a DIFFERENT shape
fails loud rather than being silently trusted.
"""

from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

_INDEX = "ix_approval_requests_tenant_created_request"
_TABLE = "approval_requests"
_COLUMNS = ["tenant_id", "created_at", "request_id"]


def _fail_ddl(detail: str) -> None:
    raise RuntimeError(f"0017 ddl: existing object shape mismatch — {detail}")


def _validate_index_shape(idx: dict[str, Any]) -> None:
    if idx.get("column_names") != _COLUMNS:
        _fail_ddl(f"{_INDEX} columns {idx.get('column_names')!r} != {_COLUMNS!r}")
    if idx.get("unique"):
        _fail_ddl(f"{_INDEX} is UNIQUE; the queue index must be non-unique")


def upgrade() -> None:
    insp = sa.inspect(op.get_bind())
    existing = {i["name"]: i for i in insp.get_indexes(_TABLE)}
    if _INDEX in existing:
        _validate_index_shape(existing[_INDEX])
        return
    op.create_index(_INDEX, _TABLE, _COLUMNS, unique=False)


def downgrade() -> None:
    """Removes ONLY the derived query index; approval rows + every
    governance column are untouched."""
    insp = sa.inspect(op.get_bind())
    if _INDEX in {i["name"] for i in insp.get_indexes(_TABLE)}:
        op.drop_index(_INDEX, table_name=_TABLE)
```

- [ ] **Step 4: Runtime-table parity** — in `core/approval/storage.py`, append to the `_approval_requests` Table (match the module's import idiom; Read `:70-110` first):

```python
    Index("ix_approval_requests_tenant_created_request", "tenant_id", "created_at", "request_id"),
```

- [ ] **Step 5:** `uv run pytest tests/unit/db/test_migration_20260711_0017.py tests/unit/db/test_migration_20260710_0016.py tests/unit/core/approval -q` → PASS (0016's head-drift test must still pass with head=0017). **Checkpoint CP-1 part 1 recorded; continue — no commit.**

---

### Task 2: Storage — chronological keyset + typed strict cursor

**Files:**
- Modify: `src/cognic_agentos/core/approval/storage.py` (`list_pending` at `:490`, `_build_list_pending_stmt` at `:227`, new cursor codec + `ListPendingPage`)
- Test: extend `tests/unit/core/approval/test_storage_reads.py` (the list_pending/read-side suite — the `_build_list_pending_stmt` SQL-shape regression lives HERE; Read its harness first)
- Test (live lanes): create `tests/integration/approval/test_queue_keyset_live.py`

**Interfaces:**
- Consumes: the Task-1 index; `ApprovalRequestSummary` (`storage.py:133`, has `created_at`).
- Produces (Task 5 relies on these exact names):
  - `ApprovalQueueCursor` frozen dataclass `(created_at: datetime, request_id: uuid.UUID)`
  - `encode_queue_cursor(cursor: ApprovalQueueCursor) -> str` / `decode_queue_cursor(raw: str) -> ApprovalQueueCursor` raising `ApprovalCursorInvalid`
  - `APPROVAL_CURSOR_MAX_ENCODED_LEN: Final[int] = 256` — enforced BEFORE decoding
  - `ListPendingPage` frozen dataclass `(items: tuple[ApprovalRequestSummary, ...], next_cursor: str | None)` — a frozen page never carries a mutable list; the route renders the tuple as its `list[...]` response unchanged
  - `async list_pending(tenant_id, *, limit: int = 50, cursor: str | None = None) -> ListPendingPage` (limit clamped defensively to 1..200; the route owns the wire 422)

- [ ] **Step 1: Failing tests.** Codec battery (M8.5-B finding-5 lessons from birth): strict `base64.b64decode(raw.encode("ascii"), altchars=b"-_", validate=True)`; JSON object with EXACT key set `{"v", "created_at", "request_id"}` (extra/missing keys refuse); bool-guarded exact-int version `v == 1`; `created_at` ISO-parsed AND tz-aware-required (mint normalizes naive→UTC via a LOCAL `_mint_aware_utc` copy — drift-pinned test-only against `read_model.py`'s per `feedback_drift_detector_test_only_no_runtime_import`); `request_id` UUID-parsed; over-length (>256 encoded) refused BEFORE decode; trailing-garbage refused; round-trip identity. Keyset behavior over the Alembic-migrated sqlite DB (`feedback_storage_test_migrated_db_not_create_all`): equal-`created_at` rows tiebreak by `request_id`; `limit+1` probe mints `next_cursor` exactly when more rows exist; final page mints none; a 3-page walk over 5 rows yields exact ID-set equality, no duplicates or omissions; foreign-tenant rows NEVER appear (wrong-tenant negative); terminal-state rows (granted/denied/expired) never appear. Defensive clamp: `limit=0 → 1`, `limit=201 → 200`.
- [ ] **Step 2:** run → failures.
- [ ] **Step 3: Implement.** The builder (replaces the `request_id`-ordered form at `:227`):

```python
def _build_list_pending_stmt(
    tenant_id: str, *, limit_plus_one: int, after: ApprovalQueueCursor | None
) -> Select[Any]:
    stmt = (
        select(_approval_requests)
        .where(
            _approval_requests.c.tenant_id == tenant_id,
            _approval_requests.c.state.in_(("pending", "awaiting_second")),
        )
        .order_by(_approval_requests.c.created_at.asc(), _approval_requests.c.request_id.asc())
        .limit(limit_plus_one)
    )
    if after is not None:
        # Portable keyset tuple expansion (Oracle lacks row-value comparison).
        stmt = stmt.where(
            or_(
                _approval_requests.c.created_at > after.created_at,
                and_(
                    _approval_requests.c.created_at == after.created_at,
                    _approval_requests.c.request_id > after.request_id,
                ),
            )
        )
    return stmt
```

`list_pending` decodes the opaque cursor, clamps the limit, fetches `limit+1`, mints `next_cursor` from the last RETURNED row's `(created_at normalized aware, request_id)`. The raw-UUID `cursor` parameter is REMOVED — audit every caller (`grep -rn "list_pending" src tests`): the route (Task 5) + tests only.
- [ ] **Step 4: SQL-shape pin** — the regression imports the SAME builder; assert compiled SQL contains `approval_requests.tenant_id =`, `approval_requests.state IN`, `ORDER BY approval_requests.created_at ASC, approval_requests.request_id ASC`, and (with a cursor) the tuple-expansion `OR`. Update/replace the existing pin of `request_id`-only ordering.
- [ ] **Step 5: Live keyset lanes** — `tests/integration/approval/test_queue_keyset_live.py` under BOTH `@pytest.mark.postgres` and `@pytest.mark.oracle` (mirror `tests/integration/db/test_alembic_migrations.py`'s connection/env conventions): migrate to head; seed via the REAL store (`create_request` path or direct engine INSERTs through the migrated schema) FOUR rows — two with the SAME `created_at` (tiebreak pair), one later, one foreign-tenant decoy with an earlier `created_at`; walk `limit=1` pages; assert order `(t_equal_a, t_equal_b by request_id, t_later)`, the decoy absent, cursors round-trip, final page cursor-free. Self-cleaning (the 0016 live-lane pattern).
- [ ] **Step 6:** `uv run pytest tests/unit/core/approval tests/unit/db/test_migration_20260711_0017.py -q` → PASS. **Checkpoint CP-1 complete: record the gate set (approval suites + migration + scoped ruff/mypy); continue — no commit.**

---

### Task 3: Engine — `expected_originator_subject` under the CORRECTED precedence

**Files:**
- Modify: `src/cognic_agentos/core/approval/engine.py` (`verify_grant_for_action` at `:163`; the load/expiry decomposition)
- Modify: `src/cognic_agentos/core/approval/_types.py` (`ApprovalTransitionRefusedReason` 10 → 11: `"approval_originator_mismatch"` after `"approval_binding_mismatch"` at `:45`)
- Modify: `src/cognic_agentos/portal/api/approvals/routes.py` — **`_REFUSAL_STATUS` gains `"approval_originator_mismatch": 403`** (the exact core-reason map; its completeness pin over `get_args(ApprovalTransitionRefusedReason)` must keep passing)
- Test: extend `tests/unit/core/approval/test_engine_grant_side.py` (the verify-side suite) + `tests/unit/portal/api/approvals/test_routes.py` (the map-completeness pin)
- Test (direct-call audit finds): **`tests/unit/core/approval/test_engine_create_side.py:287`** — the old "pending + wrong binding returns pending" test contradicts unconditional binding; REWRITE it to assert `approval_binding_mismatch` (correct originator) and add the originator-precedes variant. **`tests/unit/core/approval/test_types.py:41`** — the reason-count pin moves 10 → 11.

**Interfaces:**
- Consumes: the EXISTING tenant-scoped raw loader `self._store.load(request_id=..., tenant_id=...)` (`storage.py:442`; returns `ApprovalRequestRow | None`, cross-tenant/unknown → `None`). No new storage method.
- Produces (Tasks 4a–4d rely on this): `verify_grant_for_action(*, request_id, tenant_id, expected_args_digest, expected_tool_identity, expected_originator_subject: str)` raising `ApprovalTransitionRefused("approval_originator_mismatch")` per the corrected precedence.

- [ ] **Step 1: Failing tests** (each a named pin):
  1. wrong originator on a **granted** request → `approval_originator_mismatch`.
  2. wrong originator on a **pending** request → `approval_originator_mismatch` (state never projected — TM-revert pin A: reverting the precedence returns "pending").
  3. wrong originator AND wrong digest → `approval_originator_mismatch` (originator precedes binding — TM-revert pin B).
  4. **correct originator + wrong digest on a PENDING request → `approval_binding_mismatch`** (binding is UNCONDITIONAL before state — the corrected-precedence statement made executable; TM-revert pin C: the old granted-only guard returns "pending").
  5. correct originator + wrong digest on granted → `approval_binding_mismatch` (existing behavior preserved).
  6. **wrong originator on a TIME-EXPIRED, not-yet-projected request → `approval_originator_mismatch` with ZERO mutation and ZERO evidence**: the DB row's `state` is byte-unchanged afterwards AND no `approval.expired` chain row exists (query `decision_history` for the request's expiry event) — the expiry side effect belongs exclusively to the final stage.
  7. correct originator + correct binding on a time-expired request → lazy expiry fires exactly as today (`expired` projected; the `approval.expired` chain row present) — the mutation moved, not vanished.
  8. all-correct on granted → result unchanged, `originator_subject` echoed.
  9. the 11-value Literal count via `typing.get_args` (`feedback_count_enum_values_via_ast_not_regex`).
  10. the refusal's `str(exc)`/detail carries NO subject value (value-free pin).
  11. route map completeness: `_REFUSAL_STATUS` covers every `get_args(ApprovalTransitionRefusedReason)` member; the new reason maps 403.
- [ ] **Step 2:** run → failures (the new required kwarg also breaks the four consumers at mypy — Task 4's contract; Tasks 3+4 form checkpoint CP-2 and one future commit packet).
- [ ] **Step 3: Implement** — decompose `verify_grant_for_action`:

```python
    async def verify_grant_for_action(
        self,
        *,
        request_id: uuid.UUID,
        tenant_id: str,
        expected_args_digest: bytes,
        expected_tool_identity: str,
        expected_originator_subject: str,
    ) -> ApprovalCheckResult:
        """The seam REPLAY gate under the corrected HP-4 precedence:
        (1) tenant-scoped RAW load — absent/cross-tenant collapse, NO mutation;
        (2) ORIGINATOR — a grant is usable only by the original requesting
            subject; refuses before any state is projected or mutated;
        (3) BINDING, UNCONDITIONAL — persisted args_digest/tool_identity are
            create-time constants; a wrong-shape replay refuses regardless of
            state (a pending request's shape mismatch is 'binding', never
            'pending');
        (4) lazy expiry + state projection — the ONLY mutating step.
        A wrong-originator caller therefore causes zero expiry mutation and
        zero evidence emission."""
        row = await self._store.load(request_id=request_id, tenant_id=tenant_id)  # (1)
        if row is None:
            raise ApprovalRequestNotFound(request_id)
        if row.originator_subject != expected_originator_subject:  # (2)
            raise ApprovalTransitionRefused("approval_originator_mismatch")
        if row.args_digest != expected_args_digest or row.tool_identity != expected_tool_identity:  # (3)
            raise ApprovalTransitionRefused("approval_binding_mismatch")
        return await self._lazy_expire_and_project(request_id=request_id, tenant_id=tenant_id)  # (4)
```

Stage 1 uses the EXISTING tenant-scoped raw loader `self._store.load(...)` (`storage.py:442`) with the explicit `None → ApprovalRequestNotFound` branch — no invented method, storage API unchanged (match `ApprovalRequestNotFound`'s real constructor signature at implementation time). NOTE: stage 4 re-reads the row — acceptable (verify is not hot-path); if the implementation dedups the read, the zero-mutation pin (test 6) still governs.
- [ ] **Step 4: caller audit.** Run `rg -l "verify_grant_for_action" src tests` and classify EVERY hit as (a) executable call/signature site — must gain the kwarg, or (b) prose-only (docstrings/comments) — untouched. Known executable sites beyond the four consumers: **`tests/integration/run/test_managed_run_resume_approval_e2e.py:235`** — the env-gated stub engine's EXACT `verify_grant_for_action` signature lacks `expected_originator_subject`; because the lane is env-gated (`COGNIC_RUN_DOCKER_SANDBOX=1`), the ordinary suite will NOT expose the drift — update the stub's signature in the same pass (mypy covers it even when pytest skips). Cross-check the rg inventory against `uv run mypy src tests` — the sets of signature breakages must agree → proceed into Task 4. **No commit.**

---

### Task 4a–4d: The four replay consumers

Every consumer gets THREE mandatory test classes: (i) **exact actor-forwarding** — a spy/stub engine asserts `expected_originator_subject` receives EXACTLY the ruled expression's value; (ii) **mapped refusal** — a stubbed `approval_originator_mismatch` surfaces as the consumer's wire value; (iii) **value-free** — the consumer's refusal detail and caplog records contain neither the requester's nor the approver's subject string.

**4a — MCP host** (`protocol/mcp_host.py`):
- Thread `expected_originator_subject=originator_subject` (the consult already receives it — `_approval_gate`, `mcp_host.py:1168-1177`) at the `verify_grant_for_action` call (`:1195`).
- Except-arm (`:~1220`): two-reason map preserving the evidence-emission shape exactly (Read `:1215-1245` first):

```python
            except ApprovalTransitionRefused as exc:
                if exc.reason == "approval_binding_mismatch":
                    reason: ToolInvocationRefusalReason = "tool_approval_binding_mismatch"
                elif exc.reason == "approval_originator_mismatch":
                    reason = "tool_approval_originator_mismatch"
                else:
                    raise  # defensive: unexpected verify-side refusal -> errored arm
```

- `ToolInvocationRefusalReason` (`mcp_host.py:625`) 9 → 10; update BOTH named pins (`tests/unit/protocol/test_mcp_approval_seam.py::test_tool_invocation_refusal_reason_has_exactly_nine_values` → renamed `_ten_`; `tests/unit/protocol/test_mcp_high_risk_tier_refused.py::TestRiskTierAllowListPinned`).
- Portal MCP route map: `tool_approval_originator_mismatch` → 403 in `portal/api/mcp/routes.py` (mirror `tool_approval_binding_mismatch`) + a route test.

**4b — Sandbox** (`sandbox/admission.py` + `sandbox/protocol.py`):
- Thread `expected_originator_subject=actor.subject` (`admit_policy(..., actor: Actor, ...)` — `admission.py:458-462`).
- Except-arm (`:391`): map to `SandboxLifecycleRefused("sandbox_approval_originator_mismatch", detail="approval request {id} was granted to a different requesting subject; a grant authorises exactly one requester", approval_request_id=...)` — NO subject values in the detail.
- `SandboxRefusalReason` +1 (locate + bump its count/closed-enum pins: `grep -rn "SandboxRefusalReason" tests/unit/sandbox | grep -i "count\|closed\|exactly"`).
- `_APPROVAL_WAKE_PASSTHROUGH_REASONS` (`protocol.py:304`) 5 → 6; extend `tests/unit/sandbox/backends/test_approval_threading.py` to pin the 6-value set AND that BOTH backends pass the new reason through the wake wrapper un-rewrapped (mirror the existing per-reason passthrough tests).

**4c — Scheduler** (`core/scheduler/engine.py` + `core/scheduler/_types.py`):
- Thread `expected_originator_subject=original_submit_input.actor.subject` (`engine.py:693`; `SubmitInput.actor: TaskActor` with `.subject` — `_types.py:115`).
- Consult arm (`:706`): `_ApprovalConsultResult(verified=False, refusal_reason="refused_approval_originator_mismatch", approval_request_id=...)` mirroring the binding arm.
- `_types.py`: the value joins BOTH Literals where `refused_approval_binding_mismatch` appears (`:35` and `:49` — Read both enclosing Literals; extend each + the closed-enum drift tests in `tests/unit/core/scheduler/test_closed_enums.py`).
- Test note: the scheduler's `args_digest` already covers the actor (digest-level binding, `engine.py:257`) — so the scheduler-specific mapping MUST be proven through the scheduler consult / full `submit()` path (a granted request re-submitted under a different `TaskActor` subject surfaces `refused_approval_originator_mismatch` on the admission outcome + chain row); directly invoking the core verifier cannot prove the scheduler's own refusal mapping. Construct the pin so the ORIGINATOR check fires (the engine checks originator before binding, so the different-actor submit refuses originator-first even though its digest also differs — assert the exact reason string).

**4d — Memory** (`core/memory/gate.py` + `core/memory/tiers.py`):
- Thread `expected_originator_subject=ctx.actor_id` (`gate.py:444`; ctx binding at `:347`).
- Except-arm (`:453`): `MemoryOperationRefused("memory_approval_originator_mismatch")` mirroring the binding arm.
- `MemoryRefusalReason` (`tiers.py:76` region) +1 + its count/drift test.

- [ ] **Per consumer:** failing tests (i)(ii)(iii) → implement → targeted suite green.
- [ ] **CP-2 gate set:** `uv run pytest tests/unit/core/approval tests/unit/protocol tests/unit/sandbox tests/unit/core/scheduler tests/unit/core/memory tests/unit/portal/api/mcp tests/unit/portal/api/approvals -q`; `uv run mypy src tests`; `git diff main -- src/cognic_agentos/protocol/mcp_authz.py` empty. **Record; continue — no commit.**

---

### Task 5: Route — `limit`/`cursor` params + relative `Link` header

**Files:**
- Modify: `src/cognic_agentos/portal/api/approvals/routes.py` (`list_queue` at `:158`)
- Test: extend `tests/unit/portal/api/approvals/test_routes.py`

**Interfaces:**
- Consumes: Task 2's `list_pending(tenant_id, *, limit, cursor) -> ListPendingPage`, `ApprovalCursorInvalid`, `APPROVAL_CURSOR_MAX_ENCODED_LEN`.
- Produces: `GET /api/v1/approvals/?limit=&cursor=` — body `list[ApprovalSummaryResponse]` UNCHANGED; relative `Link` header when more rows exist; `422 {"detail": {"reason": "cursor_invalid"}}` on any decode failure.

- [ ] **Step 1: Failing tests:** body shape pins keep passing untouched; `limit` wire bounds (`Query(ge=1, le=200)`): `limit=0` → 422 and `limit=201` → 422 at FastAPI validation with the store never called (spy); a 3-request walk over 5 seeded requests via the `Link` header — exact ID-set equality, one `Link` on page one, none on the final page; the emitted URL is RELATIVE (`/api/v1/approvals/?cursor=...&limit=...`) carrying only those two params; malformed / wrong-version / over-length / trailing-garbage cursors → 422 `cursor_invalid`; the observe scope + tenant preflight behavior unchanged.
- [ ] **Step 2–3: Implement.** Inject `response: Response`; after the store call:

```python
        if page.next_cursor is not None:
            response.headers["Link"] = (
                f'</api/v1/approvals/?cursor={page.next_cursor}&limit={limit}>; rel="next"'
            )
```

wrap the store call's decode failure: `except ApprovalCursorInvalid: raise HTTPException(status_code=422, detail={"reason": "cursor_invalid"}) from None`. Document the header in `responses={200: {"headers": {"Link": {...}}}}`. `from __future__ import annotations` stays ABSENT (verify the module's current header before editing).
- [ ] **Step 4:** approvals route suite + affected portal set; scoped ruff/mypy. **CP-3 part 1; continue — no commit.**

---

### Task 6: The four dated ADR amendments + spec correction + AGENTS.md drift

**Files:**
- Modify: `docs/adrs/ADR-014-runtime-tool-approval.md` — queue = fixed actionable projection over `pending | awaiting_second`; the `?status=pending` line (~`:68`) retired; actor-bound replay + `approval_originator_mismatch` + the corrected precedence (raw load → originator → unconditional binding → lazy expiry/state); the proof-TTL note (configuration via `approval_four_eyes_ttl_s`, not a default change).
- Modify: `docs/adrs/ADR-004-sandbox-primitive.md` — `sandbox_approval_originator_mismatch` + the wake-passthrough 5→6.
- Modify: `docs/adrs/ADR-022-runtime-scheduler.md` — `refused_approval_originator_mismatch`.
- Modify: `docs/adrs/ADR-019-agent-memory-governance.md` — `memory_approval_originator_mismatch`.
- Modify: `docs/superpowers/specs/2026-07-11-m85c-cognic-harness-v1-design.md` §2.1 — the index correction: "composite index on `approval_requests (tenant_id, created_at, request_id)` — tenant-leading for the WHERE; `(created_at, request_id)` is the keyset" (dated correction note).
- Modify: `AGENTS.md` — grep for stale counts first (`grep -n "5-reason\|exactly-nine\|closed 5" AGENTS.md`): the A3c "closed 5-reason set" → 6; any nine-value `ToolInvocationRefusalReason` citation → ten.

**Steps:** verify every file:line citation at write time (`feedback_verify_code_citations_at_doc_write`); whitespace check. **CP-3 complete; continue — no commit.**

---

### Task 7: Final integration — the SINGLE pre-commit halt

- [ ] Full suite with fresh coverage: `uv run pytest --cov=cognic_agentos --cov-branch --cov-report=json -q -m "not postgres and not oracle"` (full log retained for warning capture).
- [ ] `uv run python tools/check_critical_coverage.py` — all 152 gate files pass; **each of the eight touched gated modules explicitly verified at ≥95/90 on this fresh artifact**.
- [ ] `uv run mypy src tests`; full-tree `uv run ruff check` + `format --check`; `git diff --check`.
- [ ] `git diff main -- src/cognic_agentos/protocol/mcp_authz.py` → empty.
- [ ] Live-DB lanes: run the PG lane locally against throwaway `postgres:16-alpine` (the 0016 precedent) for migration 0017 + the keyset-query suite; Oracle rides CI/an XE container if locally available — report which ran where.
- [ ] **Halt ONCE** with: the integrated diff summary; the proposed logical commit packets — **exactly two** (`portal/api/approvals/routes.py` + `test_routes.py` are modified by BOTH Tasks 3 and 5, so finer packets would require partial-hunk staging): **P1 = Tasks 1–5, one integrated HP-4 code/test commit; P2 = Task 6, one documentation commit** — exact guard-staged path sets + messages for review; the TM-revert/mutation pin list (A/B/C + the zero-mutation expiry pin + the wake-passthrough pins); vocabulary deltas (core 10→11; MCP 9→10; sandbox +1 & wake 5→6; scheduler ×2 Literals +1; memory +1); full-suite + coverage + live-DB results; warnings identified; remaining risks. NO commits, push, PR, provider proof, or cluster until the review verdict.
