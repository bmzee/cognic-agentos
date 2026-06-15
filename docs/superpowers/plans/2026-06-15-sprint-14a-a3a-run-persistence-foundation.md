# Sprint 14A-A3a Run-Persistence Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. (Executed INLINE per the operator's standing discipline — halt-before-commit reviewer gate every task, separate full-word commit tokens.)

**Goal:** Ship a correct, durable, tenant-owned `RunRecordStore` substrate (a `runs` table + closed-enum `RunState` machine + atomic chain-row/state-cache transitions) that future resume (A3b) can safely depend on — store-only, dormant, no executor/route wiring.

**Architecture:** Mirror `core/scheduler/storage.py` exactly: a SQLAlchemy Core `runs` table registered against the shared `core.audit._metadata`; a pure-functional `validate_transition` in `core/run/_types.py`; `RunRecordStore.create_run` (genesis) + `.transition` (state-machine) driving `DecisionHistoryStore.append_with_precondition` for atomic chain-row + state-cache writes (Doctrine Lock D). `run.lifecycle.<state>` chain events, distinct from the executor's existing `run.<terminal>` evidence rows.

**Tech Stack:** Python 3.12, uv, pytest (asyncio_mode=auto), SQLAlchemy async (sqlite in-memory for unit; PG/Oracle env-gated for row-lock), Alembic migration, `DecisionHistoryStore.append_with_precondition`.

---

## Source of truth + locks (committed spec `docs/superpowers/specs/2026-06-15-sprint-14a-a3a-run-persistence-foundation-design.md`)

- **A:** store-only/dormant — do NOT touch `core/run/executor.py`, `portal/api/runs/*`, `RunResponse`, or any sandbox module.
- **B:** full 9-value `RunState` upfront; `validate_transition` permits only the **6 synchronous pairs**; `suspended`/`woken`/`cancelled` reserved.
- **C:** distinct `run.lifecycle.<state>` events; the executor's `run.<terminal>` rows stay separate (A3b reconciles).
- **D:** the §3 `runs` table; `checkpoint_id` is `String(32)` (the sandbox `CheckpointId` hex), `approval_request_id` is `UUID` (the approval-engine `request_id`); cross-tenant reads → `None`; `append_with_precondition` atomicity.
- **Doctrine pin:** future slices only EXPAND the legal-transition matrix, never the stored `RunState` vocabulary.
- **CC:** `core/run/storage.py` on-gate (count **130 → 131**); `core/run/_types.py` + the migration off-gate.

## File structure

| File | Task | On gate? | Change |
|---|---|---|---|
| `src/cognic_agentos/core/run/_types.py` | T1 | no | NEW — `RunState`, `RunRecord`, `validate_transition`, `RunTransitionRefused` |
| `tests/unit/core/run/test_run_types.py` | T1 | — | NEW |
| `tests/unit/architecture/test_run_no_sdk_import.py` | T1,T2 | — | expand expected-sources + hvac probe |
| `src/cognic_agentos/core/run/storage.py` | T2 | **YES** | NEW — `RunRecordStore`, `runs` Table, `_LockedRunSnapshot`, `RunNotFound` |
| `src/cognic_agentos/db/migrations/versions/20260615_0011_runs.py` | T2 | no | NEW — `runs` DDL |
| `tests/unit/db/test_migration_20260615_0011.py` | T2 | — | NEW — migration↔Table drift pin |
| `tests/unit/core/run/test_run_storage.py` | T2 | — | NEW |
| `tools/check_critical_coverage.py` + `tests/unit/tools/test_check_critical_coverage.py` | T2 | — | count 130 → 131 |
| `tests/integration/run/test_run_storage_rowlock.py` | T3 | — | NEW (env-gated) |
| ADR-022 + ADR-004 + AGENTS.md + capability map | T4 | — | amendments |

---

## Task 1: `core/run/_types.py` — `RunState` + `validate_transition` + `RunRecord` (off-gate)

**Files:**
- Create: `src/cognic_agentos/core/run/_types.py`
- Test: `tests/unit/core/run/test_run_types.py`
- Modify: `tests/unit/architecture/test_run_no_sdk_import.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/core/run/test_run_types.py`:

```python
"""Sprint 14A-A3a — RunState closed enum + the A3a synchronous transition
subset + the 'full vocab upfront, expand-matrix-only' doctrine pin."""

from __future__ import annotations

from typing import get_args

import pytest

from cognic_agentos.core.run._types import (
    RunRecord,
    RunState,
    RunTransitionRefused,
    validate_transition,
)

_FULL_VOCAB = {
    "pending",
    "running",
    "completed",
    "failed",
    "refused",
    "pending_approval",
    "suspended",
    "woken",
    "cancelled",
}

_A3A_LEGAL_PAIRS = {
    ("pending", "running"),
    ("pending", "refused"),
    ("running", "completed"),
    ("running", "failed"),
    ("running", "refused"),
    ("running", "pending_approval"),
}

# Reserved for A3b/A3c — MUST refuse today (the doctrine: A3b EXPANDS the
# matrix; the vocabulary is fixed at A3a).
_RESERVED_PAIRS = {
    ("running", "suspended"),
    ("suspended", "woken"),
    ("woken", "running"),
    ("running", "cancelled"),
    ("pending", "cancelled"),
}


def test_run_state_vocabulary_is_exactly_nine_values() -> None:
    assert set(get_args(RunState)) == _FULL_VOCAB
    assert len(get_args(RunState)) == 9


@pytest.mark.parametrize("pair", sorted(_A3A_LEGAL_PAIRS))
def test_a3a_synchronous_pairs_are_legal(pair: tuple[str, str]) -> None:
    validate_transition(from_state=pair[0], to_state=pair[1])  # type: ignore[arg-type]  # no raise


@pytest.mark.parametrize("pair", sorted(_RESERVED_PAIRS))
def test_reserved_pairs_refuse_until_expanded(pair: tuple[str, str]) -> None:
    # The doctrine pin: reserved (suspend/wake/cancel) pairs REFUSE today, so an
    # A3b change that permits them is provably an EXPANSION of the legal matrix,
    # not a vocabulary change.
    with pytest.raises(RunTransitionRefused) as exc:
        validate_transition(from_state=pair[0], to_state=pair[1])  # type: ignore[arg-type]
    assert exc.value.reason == "run_transition_invalid_state_pair"


def test_run_record_is_frozen_with_expected_fields() -> None:
    import dataclasses

    fields = {f.name for f in dataclasses.fields(RunRecord)}
    assert fields == {
        "run_id",
        "tenant_id",
        "pack_id",
        "pack_uuid",
        "pack_version",
        "task_id",
        "session_id",
        "checkpoint_id",
        "approval_request_id",
        "state",
        "created_at",
        "updated_at",
    }
```

- [ ] **Step 2: Run — verify it fails**

Run: `uv run pytest tests/unit/core/run/test_run_types.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'cognic_agentos.core.run._types'`.

- [ ] **Step 3: Create `core/run/_types.py`**

```python
"""Sprint 14A-A3a — run-lifecycle closed enums + frozen RunRecord + the
pure-functional run-state validator. Re-export surface for core/run/storage.py.

Mirrors core/scheduler/_types.py. OFF the critical-controls gate (pure types +
pure-functional validator; the closed-enum + state-machine drift detectors at
tests/unit/core/run/test_run_types.py cover the surface). No I/O; no DB access.

DOCTRINE (Sprint 14A-A3a, locked): the RunState VOCABULARY is fixed here at 9
values. Future slices (A3b suspend/wake, A3c) may only EXPAND
``_A3A_VALID_TRANSITIONS`` (add legal pairs over the existing states) — NEVER
add a state value (that would be a stored-column-vocabulary migration). The
``test_reserved_pairs_refuse_until_expanded`` pin proves the reserved pairs
refuse today.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Literal

#: The full forward-compatible run-lifecycle vocabulary (9 values). ACTIVE in
#: A3a: pending (genesis) / running / completed / failed / refused /
#: pending_approval. RESERVED (no A3a transition; A3b/A3c expand the matrix):
#: suspended / woken / cancelled.
RunState = Literal[
    "pending",
    "running",
    "completed",
    "failed",
    "refused",
    "pending_approval",
    "suspended",
    "woken",
    "cancelled",
]

#: A3a synchronous legal-transition subset. A3b EXPANDS this set (suspend/wake);
#: it MUST NOT change the RunState vocabulary above.
_A3A_VALID_TRANSITIONS: Final[frozenset[tuple[RunState, RunState]]] = frozenset(
    {
        ("pending", "running"),
        ("pending", "refused"),
        ("running", "completed"),
        ("running", "failed"),
        ("running", "refused"),
        ("running", "pending_approval"),
    }
)


class RunTransitionRefused(Exception):
    """Raised by validate_transition on an illegal (from_state, to_state) pair.
    Thin wrapper carrying only the closed-enum reason (mirrors
    core/scheduler/_types.SchedulerTransitionRefused)."""

    def __init__(self, reason: Literal["run_transition_invalid_state_pair"]) -> None:
        super().__init__(reason)
        self.reason = reason


def validate_transition(*, from_state: RunState, to_state: RunState) -> None:
    """Pure-functional run-state-machine validator. No I/O. Keyword-only args
    eliminate the positional-misuse bug class. Raises RunTransitionRefused on an
    illegal pair; returns None on a legal pair."""
    if (from_state, to_state) not in _A3A_VALID_TRANSITIONS:
        raise RunTransitionRefused("run_transition_invalid_state_pair")


@dataclass(frozen=True)
class RunRecord:
    """Read projection of a ``runs`` row (returned by RunRecordStore.load /
    list_for_tenant). ``checkpoint_id`` is the sandbox ``CheckpointId`` hex
    string (32 chars), NOT a UUID; ``approval_request_id`` is the approval-engine
    request UUID."""

    run_id: uuid.UUID
    tenant_id: str
    pack_id: str
    pack_uuid: uuid.UUID
    pack_version: str
    task_id: uuid.UUID | None
    session_id: str | None
    checkpoint_id: str | None
    approval_request_id: uuid.UUID | None
    state: RunState
    created_at: datetime
    updated_at: datetime
```

- [ ] **Step 4: Run — verify it passes**

Run: `uv run pytest tests/unit/core/run/test_run_types.py -q`
Expected: PASS.

- [ ] **Step 5: Expand the architecture fence for `_types.py`**

In `tests/unit/architecture/test_run_no_sdk_import.py`, update `test_run_dir_has_expected_sources` to admit the new module (the no-SDK / no-portal / no-packs / no-module-level-sandbox rules already iterate ALL `_run_sources()`, so they cover `_types.py` automatically):

```python
def test_run_dir_has_expected_sources() -> None:
    # Non-vacuous guard: a NEW core/run module forces a deliberate fence review.
    assert {p.name for p in _run_sources()} == {"__init__.py", "executor.py", "_types.py"}
```

- [ ] **Step 6: Run the fence + the neighbourhood**

Run: `uv run pytest tests/unit/architecture/test_run_no_sdk_import.py tests/unit/core/run/ -q`
Expected: PASS (the fence admits `_types.py`; `_types.py` carries no SDK/portal/packs/sandbox import).

- [ ] **Step 7: HALT — reviewer gate (off-gate)**

- Gate ladder: `uv run pytest tests/unit/core/run/ tests/unit/architecture/test_run_no_sdk_import.py -q` → `uv run ruff check .` → `uv run ruff format --check .` → `uv run mypy src tests`.
- Watchpoint→pin: 9-value vocab → `test_run_state_vocabulary_is_exactly_nine_values`; 6 legal pairs → `test_a3a_synchronous_pairs_are_legal`; doctrine pin → `test_reserved_pairs_refuse_until_expanded`; RunRecord shape → `test_run_record_is_frozen_with_expected_fields`; fence admits `_types.py` → `test_run_dir_has_expected_sources`.
- Report files MODIFIED + fresh gate evidence. Await commit token.

- [ ] **Step 8: Commit (on token)**

```bash
git add src/cognic_agentos/core/run/_types.py tests/unit/core/run/test_run_types.py tests/unit/architecture/test_run_no_sdk_import.py
git commit -m "feat(run): RunState closed enum + validate_transition + RunRecord (ADR-022)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: `core/run/storage.py` + migration `0011` (CC, on-gate; count 130 → 131)

**Files:**
- Create: `src/cognic_agentos/core/run/storage.py` (CC)
- Create: `src/cognic_agentos/db/migrations/versions/20260615_0011_runs.py`
- Create: `tests/unit/db/test_migration_20260615_0011.py`
- Create: `tests/unit/core/run/test_run_storage.py`
- Modify: `tests/unit/architecture/test_run_no_sdk_import.py`
- Modify: `tools/check_critical_coverage.py` + `tests/unit/tools/test_check_critical_coverage.py`

- [ ] **Step 1: Write the failing store test**

Create `tests/unit/core/run/test_run_storage.py`:

```python
"""Sprint 14A-A3a — RunRecordStore: genesis, the 6 synchronous transitions,
reserved-pair refusal, optional-column seams, tenant-isolation reads, value-free
chain snapshot, atomicity. REAL DecisionHistoryStore over in-memory sqlite."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.core.run._types import RunTransitionRefused
from cognic_agentos.core.run.storage import RunNotFound, RunRecordStore

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def db(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'runs.db'}")
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    yield eng
    await eng.dispose()


def _mk(store: RunRecordStore, **kw):  # type: ignore[no-untyped-def]
    base = dict(
        run_id=uuid.uuid4(),
        tenant_id="tenant-a",
        pack_id="cognic-tool-foo",
        pack_uuid=uuid.uuid4(),
        pack_version="1.0.0",
        request_id="req-1",
    )
    base.update(kw)
    return base


async def _event_types(db: AsyncEngine) -> list[str]:
    async with db.connect() as conn:
        rows = (
            await conn.execute(
                select(_decision_history.c.event_type).order_by(_decision_history.c.sequence)
            )
        ).all()
    return [r[0] for r in rows]


async def test_create_run_genesis_inserts_pending_and_emits_lifecycle_pending(
    db: AsyncEngine,
) -> None:
    store = RunRecordStore(db)
    args = _mk(store)
    await store.create_run(**args)
    rec = await store.load(args["run_id"], tenant_id="tenant-a")
    assert rec is not None
    assert rec.state == "pending"
    assert rec.task_id is None and rec.session_id is None and rec.checkpoint_id is None
    assert await _event_types(db) == ["run.lifecycle.pending"]


async def test_full_synchronous_path_pending_running_completed(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    args = _mk(store)
    run_id = args["run_id"]
    await store.create_run(**args)
    await store.transition(
        run_id=run_id, tenant_id="tenant-a", from_state="pending", to_state="running",
        actor_id="svc", request_id="r", session_id="sess-1", task_id=uuid.uuid4(),
    )
    await store.transition(
        run_id=run_id, tenant_id="tenant-a", from_state="running", to_state="completed",
        actor_id="svc", request_id="r",
    )
    rec = await store.load(run_id, tenant_id="tenant-a")
    assert rec is not None and rec.state == "completed" and rec.session_id == "sess-1"
    assert await _event_types(db) == [
        "run.lifecycle.pending",
        "run.lifecycle.running",
        "run.lifecycle.completed",
    ]


async def test_pending_to_refused_pre_running(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    args = _mk(store)
    await store.create_run(**args)
    await store.transition(
        run_id=args["run_id"], tenant_id="tenant-a", from_state="pending", to_state="refused",
        actor_id="svc", request_id="r",
    )
    rec = await store.load(args["run_id"], tenant_id="tenant-a")
    assert rec is not None and rec.state == "refused"


async def test_reserved_pair_transition_refuses(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    args = _mk(store)
    await store.create_run(**args)
    await store.transition(
        run_id=args["run_id"], tenant_id="tenant-a", from_state="pending", to_state="running",
        actor_id="svc", request_id="r",
    )
    with pytest.raises(RunTransitionRefused) as exc:
        await store.transition(
            run_id=args["run_id"], tenant_id="tenant-a", from_state="running",
            to_state="suspended", actor_id="svc", request_id="r",
        )
    assert exc.value.reason == "run_transition_invalid_state_pair"


async def test_from_state_mismatch_refuses(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    args = _mk(store)
    await store.create_run(**args)  # state=pending
    with pytest.raises(RunTransitionRefused):
        # claim from_state=running but the row is pending
        await store.transition(
            run_id=args["run_id"], tenant_id="tenant-a", from_state="running",
            to_state="completed", actor_id="svc", request_id="r",
        )


async def test_transition_unknown_run_raises_not_found(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    with pytest.raises(RunNotFound):
        await store.transition(
            run_id=uuid.uuid4(), tenant_id="tenant-a", from_state="pending", to_state="running",
            actor_id="svc", request_id="r",
        )


async def test_cross_tenant_load_returns_none(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    args = _mk(store)
    await store.create_run(**args)
    # owner tenant sees it; another tenant gets None (invisible).
    assert await store.load(args["run_id"], tenant_id="tenant-a") is not None
    assert await store.load(args["run_id"], tenant_id="tenant-OTHER") is None


async def test_cross_tenant_transition_reads_as_not_found(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    args = _mk(store)
    await store.create_run(**args)
    with pytest.raises(RunNotFound):
        await store.transition(
            run_id=args["run_id"], tenant_id="tenant-OTHER", from_state="pending",
            to_state="running", actor_id="svc", request_id="r",
        )


async def test_list_for_tenant_scoped_and_state_filtered(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    a1 = _mk(store, tenant_id="tenant-a")
    a2 = _mk(store, tenant_id="tenant-a")
    b1 = _mk(store, tenant_id="tenant-b")
    for args in (a1, a2, b1):
        await store.create_run(**args)
    rows_a = await store.list_for_tenant("tenant-a")
    assert {r.run_id for r in rows_a} == {a1["run_id"], a2["run_id"]}
    rows_b = await store.list_for_tenant("tenant-b", state="pending")
    assert {r.run_id for r in rows_b} == {b1["run_id"]}


async def test_list_for_tenant_cursor_paginates(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    run_ids = []
    for _ in range(3):
        args = _mk(store, tenant_id="tenant-a")
        await store.create_run(**args)
        run_ids.append(args["run_id"])
    ordered = sorted(run_ids)  # list_for_tenant orders by run_id (keyset cursor)
    page1 = await store.list_for_tenant("tenant-a", limit=2)
    assert [r.run_id for r in page1] == ordered[:2]
    page2 = await store.list_for_tenant("tenant-a", cursor=ordered[1])
    assert [r.run_id for r in page2] == ordered[2:]


async def test_chain_payload_is_value_free_snapshot(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    args = _mk(store)
    await store.create_run(**args)
    await store.transition(
        run_id=args["run_id"], tenant_id="tenant-a", from_state="pending", to_state="running",
        actor_id="svc", request_id="r", session_id="sess-9",
    )
    async with db.connect() as conn:
        row = (
            await conn.execute(
                select(_decision_history.c.payload).where(
                    _decision_history.c.event_type == "run.lifecycle.running"
                )
            )
        ).first()
    assert row is not None
    payload = row[0]
    assert payload["to_state"] == "running" and payload["from_state"] == "pending"
    assert payload["session_id"] == "sess-9"
    assert payload["run_id"] == str(args["run_id"])
    # value-free: no raw output keys
    assert "stdout" not in payload and "stderr" not in payload


async def test_reserved_payload_key_overlap_raises(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    args = _mk(store)
    await store.create_run(**args)
    with pytest.raises(ValueError, match="payload_extras overlaps"):
        await store.transition(
            run_id=args["run_id"], tenant_id="tenant-a", from_state="pending", to_state="running",
            actor_id="svc", request_id="r", payload_extras={"run_id": "forged"},
        )
```

- [ ] **Step 2: Run — verify it fails**

Run: `uv run pytest tests/unit/core/run/test_run_storage.py -q`
Expected: FAIL — `No module named 'cognic_agentos.core.run.storage'`.

- [ ] **Step 3: Create `core/run/storage.py`**

```python
"""Sprint 14A-A3a — Postgres/Oracle-backed run-record store (ADR-022 + ADR-004).

The run mirror of ``core/scheduler/storage.py`` + ``packs/storage.py``. CRITICAL
CONTROL (core/ stop-rule per AGENTS.md). Consumer of
``DecisionHistoryStore.append_with_precondition`` — appends
``run.lifecycle.<state>`` chain rows. Does NOT modify the chain substrate.

STORE-ONLY / DORMANT (Sprint 14A-A3a): no production caller yet — A3b wires the
executor + the resolver. Two write paths: ``create_run()`` (genesis: INSERT a
``pending`` row + append ``run.lifecycle.pending``) and ``transition()``
(SELECT ... FOR UPDATE → validate_transition → UPDATE state + optional nullable
columns → append ``run.lifecycle.<to_state>``). Atomic semantics (Doctrine Lock
D): chain-head FOR UPDATE → run-row FOR UPDATE → validate → state-cache UPDATE →
chain row INSERT → chain-head UPDATE, all in one ``engine.begin()`` transaction.

Tenant isolation: every read (``load`` / ``list_for_tenant``) + the transition
SELECT is tenant-scoped — a cross-tenant ``run_id`` reads as absent (``load`` →
None; ``transition`` → ``RunNotFound``), the wire-collapse doctrine
``packs``/``models`` ship.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import (
    TIMESTAMP,
    CheckConstraint,
    Column,
    Index,
    String,
    Table,
    Uuid,
    insert,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from cognic_agentos.core.audit import _metadata
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.core.run._types import (
    RunRecord,
    RunState,
    RunTransitionRefused,
    validate_transition,
)

RUN_TENANT_ID_MAX_LEN: Final[int] = 128
RUN_PACK_ID_MAX_LEN: Final[int] = 128
RUN_PACK_VERSION_MAX_LEN: Final[int] = 128
RUN_SESSION_ID_MAX_LEN: Final[int] = 128
RUN_CHECKPOINT_ID_MAX_LEN: Final[int] = 32  # sandbox CheckpointId = uuid4().hex (32 hex chars)

#: run.* ISO-control mapping deferred (Human-only decision), matching the
#: executor's _RUN_EVIDENCE_ISO_CONTROLS = ().
RUN_LIFECYCLE_ISO_CONTROLS: Final[tuple[str, ...]] = ()

#: Reserved chain-payload keys that transition() builds from the row-locked
#: snapshot — caller-supplied payload_extras MUST NOT overlap (chain-payload-is-
#: evidence-snapshot doctrine; mirrors scheduler storage's reserved-key guard).
_RESERVED_TRANSITION_PAYLOAD_KEYS: Final[frozenset[str]] = frozenset(
    {
        "run_id",
        "from_state",
        "to_state",
        "tenant_id",
        "pack_id",
        "pack_uuid",
        "pack_version",
        "task_id",
        "session_id",
        "checkpoint_id",
        "approval_request_id",
        "created_at",
        "updated_at",
    }
)

#: Transition-target state → chain decision_type. The A3a subset (5 reachable
#: transition targets; genesis ``pending`` uses run.lifecycle.pending in
#: create_run). A3b EXPANDS this map (suspended/woken/cancelled) alongside
#: _A3A_VALID_TRANSITIONS — NEVER the RunState vocabulary (the doctrine pin).
_STATE_TO_DECISION_TYPE: Final[dict[RunState, str]] = {
    "running": "run.lifecycle.running",
    "completed": "run.lifecycle.completed",
    "failed": "run.lifecycle.failed",
    "refused": "run.lifecycle.refused",
    "pending_approval": "run.lifecycle.pending_approval",
}

_GENESIS_DECISION_TYPE: Final[str] = "run.lifecycle.pending"

#: SQLAlchemy Core Table, registered against the shared core.audit._metadata so
#: _metadata.create_all (tests) + alembic upgrade head (migration 0011) both
#: build it. The migration at 20260615_0011_runs.py MUST mirror this Table
#: exactly; drift pinned by tests/unit/db/test_migration_20260615_0011.py.
_runs = Table(
    "runs",
    _metadata,
    Column("run_id", Uuid(), primary_key=True),
    Column("tenant_id", String(RUN_TENANT_ID_MAX_LEN), nullable=False),
    Column("pack_id", String(RUN_PACK_ID_MAX_LEN), nullable=False),
    Column("pack_uuid", Uuid(), nullable=False),
    Column("pack_version", String(RUN_PACK_VERSION_MAX_LEN), nullable=False),
    Column("task_id", Uuid(), nullable=True),
    Column("session_id", String(RUN_SESSION_ID_MAX_LEN), nullable=True),
    Column("checkpoint_id", String(RUN_CHECKPOINT_ID_MAX_LEN), nullable=True),
    Column("approval_request_id", Uuid(), nullable=True),
    Column("state", String(32), nullable=False),
    Column("created_at", TIMESTAMP(timezone=True), nullable=False),
    Column("updated_at", TIMESTAMP(timezone=True), nullable=False),
    CheckConstraint(
        "state IN ('pending', 'running', 'completed', 'failed', 'refused', "
        "'pending_approval', 'suspended', 'woken', 'cancelled')",
        name="ck_runs_state",
    ),
    Index("ix_runs_tenant_state", "tenant_id", "state"),
)


@dataclass(frozen=True, slots=True)
class _LockedRunSnapshot:
    """Row-locked runs projection threaded precondition → record builder so the
    chain payload is the canonical evidence snapshot. Reflects the post-UPDATE
    values (nullable columns carry the just-set values when the transition
    supplied them)."""

    tenant_id: str
    pack_id: str
    pack_uuid: uuid.UUID
    pack_version: str
    task_id: uuid.UUID | None
    session_id: str | None
    checkpoint_id: str | None
    approval_request_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class RunNotFound(Exception):
    """Raised when transition() / a tenant-scoped read targets a run_id with no
    (tenant-visible) row. Caller-distinct from RunTransitionRefused."""

    def __init__(self, run_id: uuid.UUID) -> None:
        super().__init__(f"run_not_found: {run_id}")
        self.run_id = run_id


def _to_record(row: Any) -> RunRecord:
    return RunRecord(
        run_id=row.run_id,
        tenant_id=row.tenant_id,
        pack_id=row.pack_id,
        pack_uuid=row.pack_uuid,
        pack_version=row.pack_version,
        task_id=row.task_id,
        session_id=row.session_id,
        checkpoint_id=row.checkpoint_id,
        approval_request_id=row.approval_request_id,
        state=row.state,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


class RunRecordStore:
    """Postgres/Oracle-backed run lifecycle store. Async; raises on every
    refusal/failure (no silent-skip)."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._history = DecisionHistoryStore(engine)

    async def create_run(
        self,
        *,
        run_id: uuid.UUID,
        tenant_id: str,
        pack_id: str,
        pack_uuid: uuid.UUID,
        pack_version: str,
        task_id: uuid.UUID | None = None,
        request_id: str,
    ) -> tuple[uuid.UUID, bytes]:
        """Genesis: INSERT a ``pending`` runs row + append run.lifecycle.pending
        atomically. Returns (chain_record_id, chain_hash). INSERT failure (PK
        collision) rolls back before any chain row."""
        now = datetime.now(UTC)

        async def _precondition(conn: AsyncConnection, _seq: int, _hash: bytes) -> None:
            await conn.execute(
                insert(_runs).values(
                    run_id=run_id,
                    tenant_id=tenant_id,
                    pack_id=pack_id,
                    pack_uuid=pack_uuid,
                    pack_version=pack_version,
                    task_id=task_id,
                    session_id=None,
                    checkpoint_id=None,
                    approval_request_id=None,
                    state="pending",
                    created_at=now,
                    updated_at=now,
                )
            )

        def _build(_: None) -> DecisionRecord:
            return DecisionRecord(
                decision_type=_GENESIS_DECISION_TYPE,
                request_id=request_id,
                payload={
                    "run_id": str(run_id),
                    "from_state": None,
                    "to_state": "pending",
                    "tenant_id": tenant_id,
                    "pack_id": pack_id,
                    "pack_uuid": str(pack_uuid),
                    "pack_version": pack_version,
                    "task_id": str(task_id) if task_id is not None else None,
                    "session_id": None,
                    "checkpoint_id": None,
                    "approval_request_id": None,
                    "created_at": now.isoformat(),
                    "updated_at": now.isoformat(),
                },
                actor_id=tenant_id,  # genesis has no actor context yet; A3b threads the real actor
                tenant_id=tenant_id,
                iso_controls=RUN_LIFECYCLE_ISO_CONTROLS,
            )

        return await self._history.append_with_precondition(
            record_builder=_build, precondition=_precondition
        )

    async def transition(
        self,
        *,
        run_id: uuid.UUID,
        tenant_id: str,
        from_state: RunState,
        to_state: RunState,
        actor_id: str,
        request_id: str,
        session_id: str | None = None,
        task_id: uuid.UUID | None = None,
        checkpoint_id: str | None = None,
        approval_request_id: uuid.UUID | None = None,
        payload_extras: dict[str, Any] | None = None,
    ) -> tuple[uuid.UUID, bytes]:
        """State-machine transition (tenant-scoped, atomic). Preflight: to_state
        must be a known A3a transition target; payload_extras must not overlap
        the reserved evidence keys. In-precondition: SELECT ... FOR UPDATE the
        tenant-scoped row (absent → RunNotFound) → from_state cross-check (stale
        → RunTransitionRefused) → validate_transition → UPDATE state + updated_at
        + any provided nullable columns → append run.lifecycle.<to_state>.

        The nullable column kwargs (session_id/task_id/checkpoint_id/
        approval_request_id) are additive A3b/A3c seams: set ONLY when non-None
        (None = leave column unchanged). A3a tests exercise them; no production
        caller."""
        extras = payload_extras or {}
        # Preflight #1 — known A3a transition target (mirrors scheduler preflight).
        if to_state not in _STATE_TO_DECISION_TYPE:
            raise RunTransitionRefused("run_transition_invalid_state_pair")
        # Preflight #2 — reserved evidence-key overlap guard.
        overlap = _RESERVED_TRANSITION_PAYLOAD_KEYS & extras.keys()
        if overlap:
            raise ValueError(
                f"payload_extras overlaps reserved transition evidence keys: "
                f"{sorted(overlap)}. Reserved: {sorted(_RESERVED_TRANSITION_PAYLOAD_KEYS)}."
            )

        now = datetime.now(UTC)
        decision_type = _STATE_TO_DECISION_TYPE[to_state]

        async def _precondition(conn: AsyncConnection, _seq: int, _hash: bytes) -> _LockedRunSnapshot:
            row = (
                await conn.execute(
                    select(
                        _runs.c.state,
                        _runs.c.pack_id,
                        _runs.c.pack_uuid,
                        _runs.c.pack_version,
                        _runs.c.task_id,
                        _runs.c.session_id,
                        _runs.c.checkpoint_id,
                        _runs.c.approval_request_id,
                        _runs.c.created_at,
                    )
                    .where(_runs.c.run_id == run_id)
                    .where(_runs.c.tenant_id == tenant_id)  # tenant boundary
                    .with_for_update()
                )
            ).first()
            if row is None:
                raise RunNotFound(run_id)
            if row.state != from_state:
                raise RunTransitionRefused("run_transition_invalid_state_pair")
            validate_transition(from_state=from_state, to_state=to_state)

            update_values: dict[str, Any] = {"state": to_state, "updated_at": now}
            new_session = row.session_id
            new_task = row.task_id
            new_ckpt = row.checkpoint_id
            new_appr = row.approval_request_id
            if session_id is not None:
                update_values["session_id"] = session_id
                new_session = session_id
            if task_id is not None:
                update_values["task_id"] = task_id
                new_task = task_id
            if checkpoint_id is not None:
                update_values["checkpoint_id"] = checkpoint_id
                new_ckpt = checkpoint_id
            if approval_request_id is not None:
                update_values["approval_request_id"] = approval_request_id
                new_appr = approval_request_id
            await conn.execute(
                update(_runs).where(_runs.c.run_id == run_id).values(**update_values)
            )
            return _LockedRunSnapshot(
                tenant_id=tenant_id,
                pack_id=row.pack_id,
                pack_uuid=row.pack_uuid,
                pack_version=row.pack_version,
                task_id=new_task,
                session_id=new_session,
                checkpoint_id=new_ckpt,
                approval_request_id=new_appr,
                created_at=row.created_at,
                updated_at=now,
            )

        def _build(cap: _LockedRunSnapshot) -> DecisionRecord:
            payload: dict[str, Any] = {
                "run_id": str(run_id),
                "from_state": from_state,
                "to_state": to_state,
                "tenant_id": cap.tenant_id,
                "pack_id": cap.pack_id,
                "pack_uuid": str(cap.pack_uuid),
                "pack_version": cap.pack_version,
                "task_id": str(cap.task_id) if cap.task_id is not None else None,
                "session_id": cap.session_id,
                "checkpoint_id": cap.checkpoint_id,
                "approval_request_id": (
                    str(cap.approval_request_id) if cap.approval_request_id is not None else None
                ),
                "created_at": cap.created_at.isoformat(),
                "updated_at": cap.updated_at.isoformat(),
                **extras,
            }
            return DecisionRecord(
                decision_type=decision_type,
                request_id=request_id,
                payload=payload,
                actor_id=actor_id,
                tenant_id=cap.tenant_id,
                iso_controls=RUN_LIFECYCLE_ISO_CONTROLS,
            )

        return await self._history.append_with_precondition(
            record_builder=_build, precondition=_precondition
        )

    async def load(self, run_id: uuid.UUID, *, tenant_id: str) -> RunRecord | None:
        """Tenant-scoped read (the A3b resolver substrate). A run owned by
        another tenant returns None (cross-tenant-invisible)."""
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(_runs)
                    .where(_runs.c.run_id == run_id)
                    .where(_runs.c.tenant_id == tenant_id)
                )
            ).first()
        return _to_record(row) if row is not None else None

    async def list_for_tenant(
        self,
        tenant_id: str,
        *,
        limit: int = 50,
        cursor: uuid.UUID | None = None,
        state: RunState | None = None,
    ) -> list[RunRecord]:
        """Paginated tenant-scoped list (mirrors packs.storage.list_for_tenant).
        The ``tenant_id`` WHERE clause IS the boundary. ``cursor`` is the last
        run_id of the previous page (None = first page); ordering is by
        ``runs.run_id`` so keyset cursor pagination is dialect-portable across
        PG/Oracle/SQLite. Optional ``state`` filter over ix_runs_tenant_state."""
        stmt = select(_runs).where(_runs.c.tenant_id == tenant_id)
        if state is not None:
            stmt = stmt.where(_runs.c.state == state)
        if cursor is not None:
            stmt = stmt.where(_runs.c.run_id > cursor)
        stmt = stmt.order_by(_runs.c.run_id).limit(limit)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(stmt)).all()
        return [_to_record(r) for r in rows]
```

- [ ] **Step 4: Run — verify the store tests pass**

Run: `uv run pytest tests/unit/core/run/test_run_storage.py -q`
Expected: PASS (genesis, full path, pending→refused, reserved-pair refusal, from_state mismatch, not-found, cross-tenant load/transition, list, value-free snapshot, reserved-key guard).

- [ ] **Step 5: Create the migration**

Create `src/cognic_agentos/db/migrations/versions/20260615_0011_runs.py` (mirror the `_runs` Table exactly):

```python
"""runs — Sprint 14A-A3a run-persistence foundation (ADR-022 + ADR-004).

The durable run-record substrate backing ``core.run.storage.RunRecordStore``.
``run.lifecycle.<state>`` aggregate evidence lives in the ``decision_history``
chain; this table holds the operational per-run state + the session/checkpoint/
approval correlators (A3b/A3c populate the nullable columns).

Pins (mirroring 0005/0008): ``sa.TIMESTAMP(timezone=True)`` for timestamps —
NOT ``sa.DateTime`` (Oracle drops the offset); ``checkpoint_id`` is
``String(32)`` (the sandbox CheckpointId hex), NOT a Uuid. Column shapes MUST
agree with the in-process Table at ``core/run/storage.py``; drift pinned by
``tests/unit/db/test_migration_20260615_0011.py``.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | None = None
depends_on: str | None = None

_TS = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "runs",
        sa.Column("run_id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("pack_id", sa.String(length=128), nullable=False),
        sa.Column("pack_uuid", sa.Uuid(), nullable=False),
        sa.Column("pack_version", sa.String(length=128), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=True),
        sa.Column("session_id", sa.String(length=128), nullable=True),
        sa.Column("checkpoint_id", sa.String(length=32), nullable=True),
        sa.Column("approval_request_id", sa.Uuid(), nullable=True),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("updated_at", _TS, nullable=False),
        sa.CheckConstraint(
            "state IN ('pending', 'running', 'completed', 'failed', 'refused', "
            "'pending_approval', 'suspended', 'woken', 'cancelled')",
            name="ck_runs_state",
        ),
    )
    op.create_index("ix_runs_tenant_state", "runs", ["tenant_id", "state"])


def downgrade() -> None:
    op.drop_index("ix_runs_tenant_state", table_name="runs")
    op.drop_table("runs")
```

- [ ] **Step 6: Create the migration↔Table drift pin**

Create `tests/unit/db/test_migration_20260615_0011.py` — mirror the **landed mechanism** of `tests/unit/db/test_migration_20260607_0008.py` exactly: build an alembic config via `make_alembic_config(url)`, run the real migration (`command.upgrade(cfg, "head")` via `asyncio.to_thread`), then `sa.inspect` the resulting DB. (Do NOT `importlib.import_module` the version file — its name starts with a digit and won't import as a module.) Plus a Table-level `checkpoint_id String(32)` pin (reliable; not dialect-fragile DB introspection) for the P1:

```python
"""Sprint 14A-A3a — pin migration 0011 (runs) via real alembic upgrade + inspect
(mirrors tests/unit/db/test_migration_20260607_0008.py)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine


async def _migrated_engine(tmp_path: Any) -> Any:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'runs.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


@pytest.mark.asyncio
async def test_runs_table_exists_after_migration(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        async with eng.connect() as c:
            names = await c.run_sync(lambda sc: sa.inspect(sc).get_table_names())
        assert "runs" in names
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_migration_round_trips(tmp_path: Any) -> None:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'runs_rt.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    await asyncio.to_thread(command.downgrade, cfg, "0010")
    eng = create_async_engine(url)
    try:
        async with eng.connect() as c:
            names = await c.run_sync(lambda sc: sa.inspect(sc).get_table_names())
        assert "runs" not in names
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_migration_table_matches_in_process_table(tmp_path: Any) -> None:
    from cognic_agentos.core.run.storage import _runs

    eng = await _migrated_engine(tmp_path)
    try:
        async with eng.connect() as c:
            cols = await c.run_sync(
                lambda sc: {col["name"] for col in sa.inspect(sc).get_columns("runs")}
            )
        assert cols == {c.name for c in _runs.columns}
    finally:
        await eng.dispose()


def test_runs_checkpoint_id_is_string_32_not_uuid() -> None:
    # The P1: checkpoint_id is the sandbox CheckpointId hex (32 chars), a String,
    # NOT a Uuid column. Pinned at the in-process Table level (reliable across
    # dialects, unlike DB-introspected length).
    from cognic_agentos.core.run.storage import _runs

    col = _runs.c.checkpoint_id
    assert isinstance(col.type, sa.String) and col.type.length == 32
```

- [ ] **Step 7: Expand the architecture fence for `storage.py`**

In `tests/unit/architecture/test_run_no_sdk_import.py`: update the expected-sources guard to include `storage.py`, and add `core.run.storage` to the hvac subprocess probe:

```python
def test_run_dir_has_expected_sources() -> None:
    assert {p.name for p in _run_sources()} == {
        "__init__.py", "executor.py", "_types.py", "storage.py",
    }
```

In `test_core_run_imports_without_hvac`, extend the probe code to also import the new modules (they must stay hvac-clean):

```python
        "import cognic_agentos.core.run.executor\n"
        "import cognic_agentos.core.run.storage\n"
        "import cognic_agentos.harness.sandbox\n"
```

- [ ] **Step 8: Promote `storage.py` to the CC gate (count 130 → 131)**

In `tools/check_critical_coverage.py`, add the entry to `_CRITICAL_FILES` (with a Sprint-14A-A3a rationale docstring paragraph mirroring the scheduler-storage entry):

```python
    ("src/cognic_agentos/core/run/storage.py", 0.95, 0.90),
```

In `tests/unit/tools/test_check_critical_coverage.py`, bump `_EXPECTED_ENTRY_COUNT` 130 → 131.

- [ ] **Step 9: Run the focused suite + fence + migration**

Run: `uv run pytest tests/unit/core/run/ tests/unit/db/test_migration_20260615_0011.py tests/unit/architecture/test_run_no_sdk_import.py tests/unit/tools/test_check_critical_coverage.py -q`
Expected: PASS.

- [ ] **Step 10: HALT — reviewer gate (CC; storage.py on-gate; verify-at-promotion)**

- Full suite + gate: `uv run pytest --cov=cognic_agentos --cov-branch -q` → `uv run coverage json -o coverage.json` → `uv run python tools/check_critical_coverage.py` — confirm `core/run/storage.py` ≥ 95/90 on FRESH data; gate PASSES at **131**.
- Gate ladder: `uv run ruff check .` → `uv run ruff format --check .` → `uv run mypy src tests`.
- Watchpoint→pin: atomic genesis+pending → `test_create_run_genesis_...`; the 6 sync transitions → `test_full_synchronous_path...` + `test_pending_to_refused_pre_running`; reserved-pair refusal → `test_reserved_pair_transition_refuses`; from_state mismatch → `test_from_state_mismatch_refuses`; not-found → `test_transition_unknown_run_raises_not_found`; tenant isolation → `test_cross_tenant_load_returns_none` + `test_cross_tenant_transition_reads_as_not_found` + `test_list_for_tenant_scoped...`; value-free snapshot → `test_chain_payload_is_value_free_snapshot`; reserved-key guard → `test_reserved_payload_key_overlap_raises`; migration drift → `test_runs_table_columns_match_expected`; count 131 → the self-test.
- Report files MODIFIED + fresh gate evidence (incl. the 131 count). Await commit token.

- [ ] **Step 11: Commit (on token)**

```bash
git add src/cognic_agentos/core/run/storage.py src/cognic_agentos/db/migrations/versions/20260615_0011_runs.py tests/unit/db/test_migration_20260615_0011.py tests/unit/core/run/test_run_storage.py tests/unit/architecture/test_run_no_sdk_import.py tools/check_critical_coverage.py tests/unit/tools/test_check_critical_coverage.py
git commit -m "feat(run): durable RunRecordStore + runs table (CC; ADR-022/004)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: env-gated PG/Oracle row-lock integration

**Files:**
- Create: `tests/integration/run/test_run_storage_rowlock.py`

- [ ] **Step 1: Write the env-gated integration test**

Mirror `tests/integration/packs/test_storage_lock_serialisation.py` canary 1 EXACTLY: per-test `@_PG_SKIPIF`/`@_ORACLE_SKIPIF` (env `COGNIC_RUN_POSTGRES_INTEGRATION` + `COGNIC_DATABASE_URL_POSTGRES_TEST`), `_superuser_url(driver)`, `_reset_state(engine)`, two concurrent `transition(pending→running)` via `asyncio.gather`. Complete body:

```python
"""Sprint 14A-A3a — RunRecordStore SELECT ... FOR UPDATE serialisation on real
Postgres + Oracle. Mirrors tests/integration/packs/test_storage_lock_serialisation.py
canary 1. Env-gated; per-test skipif self-skips without the live DB + DSN."""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
from sqlalchemy import delete, text, update
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.core.run._types import RunTransitionRefused
from cognic_agentos.core.run.storage import RunRecordStore, _runs

pytestmark = pytest.mark.asyncio

_PG_SKIPIF = pytest.mark.skipif(
    not (
        os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION")
        and os.environ.get("COGNIC_DATABASE_URL_POSTGRES_TEST")
    ),
    reason=(
        "live Postgres required; set COGNIC_RUN_POSTGRES_INTEGRATION=1 + apply "
        "migrations + export COGNIC_DATABASE_URL_POSTGRES_TEST"
    ),
)
_ORACLE_SKIPIF = pytest.mark.skipif(
    not (
        os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION")
        and os.environ.get("COGNIC_DATABASE_URL_ORACLE_TEST")
    ),
    reason=(
        "live Oracle XE required; set COGNIC_RUN_ORACLE_INTEGRATION=1 + apply "
        "migrations + export COGNIC_DATABASE_URL_ORACLE_TEST"
    ),
)


def _superuser_url(driver: str) -> str:
    return os.environ[f"COGNIC_DATABASE_URL_{driver.upper()}_TEST"]


async def _reset_state(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        await conn.execute(delete(_runs))
        await conn.execute(delete(_decision_history))
        await conn.execute(
            update(_chain_heads)
            .where(_chain_heads.c.chain_id == "decision_history")
            .values(latest_sequence=0, latest_hash=ZERO_HASH)
        )


async def _canary_row_lock_serialisation(driver: str) -> None:
    """Two concurrent transition(pending→running) for the same run — exactly one
    wins; the loser sees the advanced state and refuses
    run_transition_invalid_state_pair. Loser rolls back; chain count for
    run.lifecycle.% is exactly 2 (genesis pending + winner's running); final
    state is running."""
    engine = create_async_engine(_superuser_url(driver), pool_size=4, max_overflow=0)
    try:
        await _reset_state(engine)
        store = RunRecordStore(engine)
        run_id = uuid.uuid4()
        await store.create_run(
            run_id=run_id, tenant_id="t", pack_id="cognic-tool-canary",
            pack_uuid=uuid.uuid4(), pack_version="1.0.0", request_id="genesis",
        )

        async def _do(label: str):  # type: ignore[no-untyped-def]
            try:
                return await store.transition(
                    run_id=run_id, tenant_id="t", from_state="pending",
                    to_state="running", actor_id=label, request_id=f"race-{label}",
                )
            except RunTransitionRefused as exc:
                return exc

        results = await asyncio.gather(_do("a"), _do("b"))
        wins = [r for r in results if not isinstance(r, RunTransitionRefused)]
        losses = [r for r in results if isinstance(r, RunTransitionRefused)]
        assert len(wins) == 1, f"expected one winner; got {results}"
        assert len(losses) == 1, f"expected one loser; got {results}"
        assert losses[0].reason == "run_transition_invalid_state_pair"

        async with engine.connect() as conn:
            chain_count = (
                await conn.execute(
                    text(
                        "SELECT COUNT(*) FROM decision_history "
                        "WHERE event_type LIKE 'run.lifecycle.%'"
                    )
                )
            ).scalar_one()
        assert chain_count == 2, f"expected 2 chain rows (pending+running); got {chain_count}"

        loaded = await store.load(run_id, tenant_id="t")
        assert loaded is not None and loaded.state == "running"
    finally:
        await engine.dispose()


@pytest.mark.postgres
@_PG_SKIPIF
async def test_postgres_row_lock_serialises_competing_transitions() -> None:
    await _canary_row_lock_serialisation("postgres")


@pytest.mark.oracle
@_ORACLE_SKIPIF
async def test_oracle_row_lock_serialises_competing_transitions() -> None:
    await _canary_row_lock_serialisation("oracle")
```

(The barrier-based pack-row-lock-isolation proof — packs canary 2 — is NOT duplicated here: the run store adds NO new locking logic over the `append_with_precondition` + `SELECT ... FOR UPDATE` primitive, whose row-lock isolation is already proven by `tests/integration/packs/test_storage_lock_serialisation.py` canary 2 + `tests/integration/db/test_concurrent_append.py`. Canary 1 above proves the run store serialises competing transitions end-to-end.)

- [ ] **Step 2: Run (skips without env)**

Run: `uv run pytest tests/integration/run/test_run_storage_rowlock.py -q`
Expected: SKIPPED (no live DB env). Concrete; not run in CI without the DB.

- [ ] **Step 3: HALT — reviewer gate (off-gate; no gated source touched)**

- `uv run ruff check tests/integration/run/ && uv run ruff format --check tests/integration/run/ && uv run mypy tests/integration/run/`.
- Confirm `git status` shows only the new integration file. Report + await commit token.

- [ ] **Step 4: Commit (on token)**

```bash
git add tests/integration/run/__init__.py tests/integration/run/test_run_storage_rowlock.py
git commit -m "test(run): env-gated PG/Oracle row-lock proof for RunRecordStore (ADR-022)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

(Note: `tests/integration/run/__init__.py` already exists from 14A-A; stage it only if new.)

---

## Task 4: docs

**Files:**
- Modify: `docs/adrs/ADR-022-runtime-scheduler.md`, `docs/adrs/ADR-004-sandbox-primitive.md`, `AGENTS.md`, `docs/AS_BUILT_CAPABILITY_MAP.md`

- [ ] **Step 1: ADR-022 + ADR-004 — Sprint 14A-A3a amendment**

Document: the durable `RunRecordStore` + `runs` table (the run-persistence foundation); the full-9-value `RunState` vocabulary + the 6-pair synchronous subset + the "expand-matrix-only" doctrine; `run.lifecycle.<state>` distinct from the executor's `run.<terminal>` evidence; store-only/dormant (no executor/route wiring — A3b); `checkpoint_id` as the sandbox `CheckpointId` String(32). New on-gate `core/run/storage.py` (count 130 → 131).

- [ ] **Step 2: AGENTS.md — `*Run-persistence foundation (Sprint 14A-A3a)*`**

New CC section: `core/run/storage.py` ON the gate (run-lifecycle tenant-isolation + chain-atomicity boundary; mirrors `core/scheduler/storage.py`); `core/run/_types.py` off-gate (RunState + validate_transition, drift-pinned); the migration off-gate; the doctrine pin (vocabulary fixed; A3b expands the matrix). Count 130 → 131.

- [ ] **Step 3: AS_BUILT_CAPABILITY_MAP.md — pillar 2 + forward sequence**

Pillar 2: add the run-persistence substrate (store-only; A3b wires it into the run lifecycle + the resolver). Forward sequence: 14A-A3a DONE (substrate); 14A-A3b (resolver + resume route) + 14A-A3c (wake approval correlator) next.

- [ ] **Step 4: HALT — docs reviewer gate**

- Docs-only: `git status --porcelain` shows only the 4 doc files; NEVER `docs/reviews/` or the 2026-05-26 gap-analysis spec. No-overstatement sweep: store is dormant (no caller); A3b/A3c deferred. Report + await commit token.

- [ ] **Step 5: Commit (on token)**

```bash
git add docs/adrs/ADR-022-runtime-scheduler.md docs/adrs/ADR-004-sandbox-primitive.md AGENTS.md docs/AS_BUILT_CAPABILITY_MAP.md
git commit -m "docs(run): Sprint 14A-A3a run-persistence foundation (ADR-022/004)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-review notes (author)

- **Spec coverage:** §3 table → T2 `_runs` + migration; §4 enum + §5 transitions → T1 `_types`; §6 doctrine pin → `test_reserved_pairs_refuse_until_expanded`; §7 store API + atomicity → T2 `RunRecordStore` (mirrors scheduler `append_with_precondition`); §8 tenant isolation → tenant-scoped `load`/`transition`/`list_for_tenant` + tests; §9 value-free snapshot → `_build` payload + `test_chain_payload_is_value_free_snapshot`; §10 `run.lifecycle.*` → `_STATE_TO_DECISION_TYPE` + `_GENESIS_DECISION_TYPE`; §11 CC → T2 gate promotion (131); §13 tests → T1/T2.
- **A-lock (no executor touch):** T1–T4 touch NONE of `executor.py` / `portal/api/runs/*` / `RunResponse` / sandbox.
- **Placeholder scan:** ALL bodies are COMPLETE — unit tests (T1/T2), the migration, the migration-drift test (alembic-`command.upgrade`-based, mirroring the landed `test_migration_20260607_0008.py`), and **T3's env-gated PG/Oracle row-lock test** (a real `asyncio.gather` serialisation canary mirroring `tests/integration/packs/test_storage_lock_serialisation.py` canary 1, per-test skipif). No `...`/placeholder remains.
- **Review-fix log:** P1a — stale-read reason aligned to the single `run_transition_invalid_state_pair` (spec patched to match the scheduler doctrine); P1b — `list_for_tenant` gained the spec's `cursor` seam (keyset by `run_id`) + `test_list_for_tenant_cursor_paginates`; P2 — T3 grounded as a complete canary; P3 — dropped the unused `RunRecord`/`_runs` imports from the T2 test.
- **Type consistency:** `checkpoint_id` String(32) everywhere (table, snapshot, migration, drift test); `approval_request_id` UUID; `RunRecord` fields == the table columns; `append_with_precondition` returns `tuple[uuid.UUID, bytes]`; `_STATE_TO_DECISION_TYPE` keys ⊂ `RunState` (5 transition targets) + the genesis hardcode.
- **Count:** 130 → 131 (one new gate module `storage.py`); pin both gate files.
