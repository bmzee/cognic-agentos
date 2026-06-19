# Parent budget resolver seam — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land a production `LocalParentBudgetResolver` (granted-budget snapshot, tenant-scoped, fail-loud typed), replacing the `_NullParentBudgetResolver` sentinel so a `parent_task_id`-bearing scheduler submit computes the inherited child budget instead of raising `NotImplementedError`.

**Architecture:** A read primitive over the existing `scheduler_tasks.requested_estimated_tokens` snapshot. The storage read owns the data fetch + tenant boundary; the resolver owns the policy interpretation (absence → `parent_not_found`, terminal → `parent_terminal`, else the inherited ceiling). The engine already consults the seam + applies `compute_child_budget`; this slice makes the seam real + wires it.

**Tech Stack:** Python 3.12, uv, FastAPI-adjacent (no HTTP here), SQLAlchemy async, pytest. Spec: `docs/superpowers/specs/2026-06-19-parent-budget-resolver-seam-design.md`.

---

## Execution discipline (controller-owned)

- **The controller commits, not the subagents.** Each task's subagent implements + verifies + reports "files modified" (NOT staged). The controller runs the halt-before-commit reviewer gate, requests the user's per-action token, stages by explicit path, runs `git diff --cached --check` + an exact-staged-set + `__pycache__`/protected-doc guard, and commits.
- **Per-action tokens**, restated before executing. Branch already exists (`feat/parent-budget-resolver-seam`); spec committed (`6c4f04b`).
- **Subagents on Opus 4.8** (`model: opus`). The on-gate scheduler modules (`storage.py`, `budget_resolver.py`, `engine.py`) are **critical controls** — task instructions carry the 95% line / 90% branch floor + mandatory negative-path tests + no casual refactors.
- **Protected untracked docs — NEVER stage:** `docs/reviews/` and `docs/superpowers/specs/2026-05-26-agentos-local-managed-agents-gap-analysis.md`.
- **Commit footer:** `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- **Posture invariant (verify at T7):** CC **131 → 132** (`budget_resolver.py` newly on-gate; the other edits land in already-on/off-gate modules); no migration; no `SchedulerRefusalReason`/`scheduler.rego` change; no `subagent/` touch; mypy via the whole-project `mypy src tests` (the MCP-slice lesson — single-file mypy emits false `import-untyped`).

## File Structure

**Created:**
- `src/cognic_agentos/core/scheduler/budget_resolver.py` — `LocalParentBudgetResolver` + the narrow `BudgetSnapshotReader` Protocol (on-gate).
- `tests/unit/core/scheduler/test_budget_resolver_exception.py` — the exception + `Literal` drift + sentinel-still-fail-loud (T1; direct imports, no fixtures).
- `tests/unit/core/scheduler/test_budget_resolver.py` — resolver unit tests (T3; stub reader, no fixtures).

**Modified:**
- `src/cognic_agentos/core/scheduler/_seams.py` — the `ParentTaskBudgetUnavailable` exception + 2-value `Literal`; `*, tenant_id` on the Protocol + the `_NullParentBudgetResolver` sentinel (off-gate).
- `src/cognic_agentos/core/scheduler/storage.py` — the `_BudgetSnapshot` + `get_budget_snapshot` pure-read + `_build_budget_snapshot_stmt` (on-gate).
- `src/cognic_agentos/core/scheduler/engine.py` — the one call-site `tenant_id=` pass (on-gate).
- `src/cognic_agentos/harness/runtime.py` — construct + inject the real resolver (off-gate).
- `tests/unit/core/scheduler/test_engine.py` — the T1 `_StubParentBudgetResolver` sig update + the T4 engine↔resolver integration tests (reuses `engine_db`/`caps`/`class_settings`/`_make_engine`/`_make_submit_input`; these fixtures live in this file, so the tests are added HERE).
- `tests/unit/core/scheduler/test_storage.py` — the T2 `get_budget_snapshot` tests + a local `_seed_task` (reuses the `store`/`engine` fixtures defined in this file).
- `tests/integration/scheduler/test_scheduler_composition_e2e.py` — T5 updates `test_composition_subagent_submit_fails_loud` (sentinel → real resolver).
- Docs (T6): `docs/adrs/ADR-005-*.md`, `docs/adrs/ADR-022-*.md`, `docs/AS_BUILT_CAPABILITY_MAP.md`, `AGENTS.md`.

---

## Task 1: Seam contract + signature extension (`_seams.py` + the engine call-site)

The Protocol signature change, the sentinel, the engine call-site, and the new exception are **one coherent change** — changing the Protocol without the call-site would fail mypy. Lands together so the tree stays green (the sentinel is still the only wired resolver → a `parent_task_id` submit still raises, now `NotImplementedError` with the tenant kwarg).

**Files:**
- Modify: `src/cognic_agentos/core/scheduler/_seams.py`
- Modify: `src/cognic_agentos/core/scheduler/engine.py:426`
- Test: `tests/unit/core/scheduler/test_budget_resolver_exception.py` (new) + reuse existing seam tests

- [ ] **Step 1: Write the failing test** — `tests/unit/core/scheduler/test_budget_resolver_exception.py`:

```python
"""ParentTaskBudgetUnavailable typed exception + closed-enum reason (ADR-005)."""

from __future__ import annotations

import uuid
from typing import get_args

import pytest

from cognic_agentos.core.scheduler._seams import (
    ParentTaskBudgetUnavailable,
    ParentTaskBudgetUnavailableReason,
    _NullParentBudgetResolver,
)


def test_reason_literal_is_exactly_two_values() -> None:
    assert set(get_args(ParentTaskBudgetUnavailableReason)) == {
        "parent_not_found",
        "parent_terminal",
    }


def test_exception_carries_reason() -> None:
    exc = ParentTaskBudgetUnavailable("parent_not_found")
    assert exc.reason == "parent_not_found"
    assert isinstance(exc, Exception)


async def test_sentinel_still_fail_loud_with_tenant_kwarg() -> None:
    # The signature extension keeps the sentinel fail-loud (NotImplementedError),
    # NOT a closed-enum refusal — the seam doctrine is preserved.
    with pytest.raises(NotImplementedError):
        await _NullParentBudgetResolver().remaining_budget_for(uuid.uuid4(), tenant_id="t")
```

- [ ] **Step 2: Run → fails** (`ImportError: ParentTaskBudgetUnavailable` / sentinel sig mismatch).
Run: `uv run pytest tests/unit/core/scheduler/test_budget_resolver_exception.py -x`

- [ ] **Step 3: Add the exception + extend the signatures in `_seams.py`.**

Add near the `ParentBudgetResolver` Protocol (after the `compute_child_budget` block or adjacent to the Protocol):

```python
ParentTaskBudgetUnavailableReason = Literal["parent_not_found", "parent_terminal"]


class ParentTaskBudgetUnavailable(Exception):
    """Raised by a ParentBudgetResolver when a valid-UUID parent reference
    cannot confer budget: absent / cross-tenant (collapsed to
    ``parent_not_found`` per the cross-tenant-invisibility doctrine) or
    terminal (``parent_terminal``). The engine does NOT catch this — it
    propagates fail-loud (the _NullParentBudgetResolver doctrine; NOT a
    closed-enum scheduler refusal). A malformed parent_task_id string stays
    the existing SchedulerSubmitInputInvalid input-validation refusal."""

    def __init__(self, reason: ParentTaskBudgetUnavailableReason) -> None:
        self.reason: ParentTaskBudgetUnavailableReason = reason
        super().__init__(reason)
```

(Ensure `from typing import Literal` is imported.) Extend the Protocol method signature:

```python
    async def remaining_budget_for(
        self, parent_task_id: uuid.UUID, *, tenant_id: str
    ) -> int: ...
```

Extend the `_NullParentBudgetResolver.remaining_budget_for` signature identically (keep its `NotImplementedError` body unchanged):

```python
    async def remaining_budget_for(
        self, parent_task_id: uuid.UUID, *, tenant_id: str
    ) -> int:
        raise NotImplementedError(
            # ... existing message unchanged ...
        )
```

- [ ] **Step 4: Update the engine call-site** (`engine.py:426`):

```python
            parent_remaining = await self._parent_budget.remaining_budget_for(
                parent_uuid, tenant_id=submit_input.tenant_id
            )
```

- [ ] **Step 4b: Update the EXISTING test stub** — `tests/unit/core/scheduler/test_engine.py:141` `_StubParentBudgetResolver.remaining_budget_for` carries the OLD signature; extend it to match the new Protocol (else mypy + the existing parent_task_id happy-path tests break):

```python
    async def remaining_budget_for(self, parent_task_id: uuid.UUID, *, tenant_id: str) -> int:
        self.calls.append(parent_task_id)
        return self.budget
```

- [ ] **Step 5: Run → passes; whole-project types + lint.**
Run: `uv run pytest tests/unit/core/scheduler/test_budget_resolver_exception.py tests/unit/core/scheduler/ -x -q && uv run ruff check src/cognic_agentos/core/scheduler/ && uv run mypy src tests`
Expected: PASS + clean. (The existing engine `parent_task_id` tests still hit the sentinel → `NotImplementedError`, unchanged. `mypy src tests` confirms the call-site conforms to the new Protocol.)

- [ ] **Step 6: Commit (controller, token-gated)** — `feat(scheduler): parent-budget seam tenant_id + ParentTaskBudgetUnavailable (ADR-005)`

---

## Task 2: Storage read — `get_budget_snapshot` (on-gate, pure-read)

**Files:**
- Modify: `src/cognic_agentos/core/scheduler/storage.py`
- Modify: `tests/unit/core/scheduler/test_storage.py` (add the tests + `_seed_task` HERE — the `store`/`engine` fixtures live in this file)

- [ ] **Step 1: Write the failing test** — append to `tests/unit/core/scheduler/test_storage.py`. The `store`/`engine` fixtures + `SubmitInput`/`TaskActor`/`uuid` imports already exist in this file; extend the `storage` import with `_BudgetSnapshot` + `_build_budget_snapshot_stmt` and add `from cognic_agentos.core.scheduler._types import SchedulerTaskState`:

```python
# --- get_budget_snapshot (parent-budget resolver read seam) ---------------


async def _seed_task(
    store: SchedulerStorage, *, tenant_id: str, tokens: int, state: SchedulerTaskState
) -> uuid.UUID:
    """Seed a scheduler task in `state` via the real submit→transition path
    (NO raw INSERT). Terminal states follow _VALID_TRANSITIONS; `expired` goes
    directly from pending (running→expired is illegal), the others via running."""
    task_id = uuid.uuid4()
    submit = SubmitInput(
        tenant_id=tenant_id,
        pack_id="cognic-tool-loan-eligibility",
        actor=TaskActor(subject="svc", tenant_id=tenant_id, actor_type="service"),
        class_="interactive",
        pack_kind="tool",
        pack_risk_tier="internal_write",
        requested_estimated_tokens=tokens,
    )
    await store.submit(task_id=task_id, submit_input=submit, request_id=f"seed-{task_id}")
    if state == "pending":
        return task_id
    if state == "expired":
        # expired goes DIRECTLY from pending (running→expired is NOT in _VALID_TRANSITIONS).
        await store.transition(
            task_id=task_id, from_state="pending", to_state="expired",
            actor_id="seed", request_id=f"seed-expire-{task_id}", payload_extras={},
        )
        return task_id
    await store.transition(
        task_id=task_id, from_state="pending", to_state="running",
        actor_id="seed", request_id=f"seed-run-{task_id}", payload_extras={},
    )
    if state != "running":
        await store.transition(
            task_id=task_id, from_state="running", to_state=state,
            actor_id="seed", request_id=f"seed-term-{task_id}", payload_extras={},
        )
    return task_id


def test_budget_snapshot_stmt_where_carries_task_id_and_tenant_id() -> None:
    # SQL-shape regression: the PRODUCTION builder is used; both predicates present.
    compiled = str(_build_budget_snapshot_stmt(task_id=uuid.uuid4(), tenant_id="t"))
    assert "scheduler_tasks.task_id = " in compiled
    assert "scheduler_tasks.tenant_id = " in compiled


async def test_budget_snapshot_absent_returns_none(store: SchedulerStorage) -> None:
    assert await store.get_budget_snapshot(uuid.uuid4(), tenant_id="tenant-acme") is None


async def test_budget_snapshot_present_returns_tokens_and_state(store: SchedulerStorage) -> None:
    task_id = await _seed_task(store, tenant_id="tenant-acme", tokens=500, state="running")
    assert await store.get_budget_snapshot(task_id, tenant_id="tenant-acme") == _BudgetSnapshot(
        granted_tokens=500, state="running"
    )


async def test_budget_snapshot_cross_tenant_returns_none(store: SchedulerStorage) -> None:
    task_id = await _seed_task(store, tenant_id="tenant-b", tokens=500, state="running")
    # Same UUID, different tenant → invisible (the cross-tenant boundary).
    assert await store.get_budget_snapshot(task_id, tenant_id="tenant-a") is None
```

- [ ] **Step 2: Run → fails** (`ImportError`/no method).

- [ ] **Step 3: Implement in `storage.py`.** Add the frozen result + the shared builder + the method:

```python
@dataclass(frozen=True)
class _BudgetSnapshot:
    """Pure-read projection for the parent-budget resolver: the granted token
    budget + the lifecycle state of a tenant-scoped scheduler task."""

    granted_tokens: int
    state: SchedulerTaskState


def _build_budget_snapshot_stmt(*, task_id: uuid.UUID, tenant_id: str):
    """SOLE query-construction path for get_budget_snapshot. The WHERE on BOTH
    task_id AND tenant_id IS the cross-tenant boundary (absent OR cross-tenant
    → no row). Shared with the SQL-shape regression (no vacuous duplicate)."""
    return (
        select(
            _scheduler_tasks.c.requested_estimated_tokens,
            _scheduler_tasks.c.state,
        )
        .where(_scheduler_tasks.c.task_id == task_id)
        .where(_scheduler_tasks.c.tenant_id == tenant_id)
    )
```

Method on `SchedulerStorage` (pure-read, no transaction — `connect()`, not `begin()`):

```python
    async def get_budget_snapshot(
        self, task_id: uuid.UUID, *, tenant_id: str
    ) -> _BudgetSnapshot | None:
        """Tenant-scoped granted-budget snapshot for the parent-budget resolver.
        Returns None when the task is absent OR belongs to another tenant (the
        cross-tenant-invisibility boundary). Pure read — no lock, no mutation."""
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    _build_budget_snapshot_stmt(task_id=task_id, tenant_id=tenant_id)
                )
            ).first()
        if row is None:
            return None
        return _BudgetSnapshot(
            granted_tokens=row.requested_estimated_tokens, state=row.state
        )
```

(Confirm `self._engine` is the stored async engine — the existing reads use it; `dataclass` + `select` are already imported.)

- [ ] **Step 4: Run → passes; on-gate floor; lint + types.**
Run: `uv run pytest tests/unit/core/scheduler/test_storage.py -x -q && uv run ruff check src/cognic_agentos/core/scheduler/storage.py tests/unit/core/scheduler/test_storage.py && uv run mypy src tests`

- [ ] **Step 5: Commit** — `feat(scheduler): tenant-scoped get_budget_snapshot pure-read (ADR-022)`

---

## Task 3: `LocalParentBudgetResolver` (NEW on-gate module)

**Files:**
- Create: `src/cognic_agentos/core/scheduler/budget_resolver.py`
- Test: `tests/unit/core/scheduler/test_budget_resolver.py` (new)

- [ ] **Step 1: Write the failing test** — `tests/unit/core/scheduler/test_budget_resolver.py`:

```python
"""LocalParentBudgetResolver — granted-snapshot ceiling primitive (ADR-005)."""

from __future__ import annotations

import uuid
from typing import get_args

import pytest

from cognic_agentos.core.scheduler._seams import ParentTaskBudgetUnavailable
from cognic_agentos.core.scheduler._types import SchedulerTaskState
from cognic_agentos.core.scheduler.budget_resolver import (
    LocalParentBudgetResolver,
    _TERMINAL_STATES,
)
from cognic_agentos.core.scheduler.storage import _BudgetSnapshot

_PID = uuid.uuid4()


class _StubReader:
    def __init__(self, snapshot: _BudgetSnapshot | None) -> None:
        self._snapshot = snapshot
        self.seen: tuple[uuid.UUID, str] | None = None

    async def get_budget_snapshot(self, task_id, *, tenant_id):
        self.seen = (task_id, tenant_id)
        return self._snapshot


async def test_returns_granted_tokens_for_running_parent() -> None:
    reader = _StubReader(_BudgetSnapshot(granted_tokens=750, state="running"))
    r = LocalParentBudgetResolver(reader)
    assert await r.remaining_budget_for(_PID, tenant_id="t") == 750
    assert reader.seen == (_PID, "t")  # tenant threaded to the read


async def test_returns_granted_tokens_for_pending_parent() -> None:
    reader = _StubReader(_BudgetSnapshot(granted_tokens=10, state="pending"))
    assert await LocalParentBudgetResolver(reader).remaining_budget_for(_PID, tenant_id="t") == 10


async def test_absent_raises_parent_not_found() -> None:
    r = LocalParentBudgetResolver(_StubReader(None))
    with pytest.raises(ParentTaskBudgetUnavailable) as ei:
        await r.remaining_budget_for(_PID, tenant_id="t")
    assert ei.value.reason == "parent_not_found"


@pytest.mark.parametrize("state", ["completed", "failed", "cancelled", "preempted", "expired"])
async def test_terminal_raises_parent_terminal(state: SchedulerTaskState) -> None:
    reader = _StubReader(_BudgetSnapshot(granted_tokens=500, state=state))
    with pytest.raises(ParentTaskBudgetUnavailable) as ei:
        await LocalParentBudgetResolver(reader).remaining_budget_for(_PID, tenant_id="t")
    assert ei.value.reason == "parent_terminal"


def test_terminal_set_partitions_scheduler_task_state() -> None:
    # Drift guard: terminal ∪ {pending, running} == all states; a new state fails this.
    assert _TERMINAL_STATES | {"pending", "running"} == set(get_args(SchedulerTaskState))
```

- [ ] **Step 2: Run → fails** (no module).

- [ ] **Step 3: Implement `budget_resolver.py`:**

```python
"""Production ParentBudgetResolver — granted-budget snapshot ceiling primitive
(ADR-005 / ADR-022). Replaces the _NullParentBudgetResolver fail-loud sentinel.

Owns the policy interpretation of a parent task's snapshot: tenant-scoped
absence → parent_not_found, terminal state → parent_terminal, else the granted
token budget returned as the inherited ceiling. This budget authority is why
the module is on the durable critical-controls coverage gate.
"""

from __future__ import annotations

import uuid
from typing import Protocol, runtime_checkable

from cognic_agentos.core.scheduler._seams import ParentTaskBudgetUnavailable
from cognic_agentos.core.scheduler._types import SchedulerTaskState
from cognic_agentos.core.scheduler.storage import _BudgetSnapshot

#: Terminal SchedulerTaskState values — a parent in any of these cannot confer
#: budget. Partition-pinned against SchedulerTaskState by the resolver test.
_TERMINAL_STATES: frozenset[SchedulerTaskState] = frozenset(
    {"completed", "failed", "cancelled", "preempted", "expired"}
)


@runtime_checkable
class BudgetSnapshotReader(Protocol):
    """Narrow consumer-owned read seam (SchedulerStorage conforms structurally)."""

    async def get_budget_snapshot(
        self, task_id: uuid.UUID, *, tenant_id: str
    ) -> _BudgetSnapshot | None: ...


class LocalParentBudgetResolver:
    """Resolves a parent task's GRANTED token budget (a snapshot, not a live
    balance). Ceiling-inheritance read primitive; sibling/shared-pool depletion
    is the later sub-agent-dispatch slice."""

    def __init__(self, reader: BudgetSnapshotReader) -> None:
        self._reader = reader

    async def remaining_budget_for(self, parent_task_id: uuid.UUID, *, tenant_id: str) -> int:
        snapshot = await self._reader.get_budget_snapshot(parent_task_id, tenant_id=tenant_id)
        if snapshot is None:
            # Absent OR cross-tenant — collapsed to not-found (invisibility).
            raise ParentTaskBudgetUnavailable("parent_not_found")
        if snapshot.state in _TERMINAL_STATES:
            raise ParentTaskBudgetUnavailable("parent_terminal")
        return snapshot.granted_tokens
```

- [ ] **Step 4: Run → passes; on-gate floor; lint + types.**
Run: `uv run pytest tests/unit/core/scheduler/test_budget_resolver.py -x -q && uv run ruff check src/cognic_agentos/core/scheduler/budget_resolver.py && uv run mypy src tests`

- [ ] **Step 5: Commit** — `feat(scheduler): LocalParentBudgetResolver granted-snapshot primitive (ADR-005)`

---

## Task 4: Engine integration behavioral proof (real resolver + in-memory storage)

**Files:**
- Modify: `tests/unit/core/scheduler/test_engine.py` (add the tests HERE — `engine_db`/`caps`/`class_settings`/`_make_engine`/`_make_submit_input` live in this file)

- [ ] **Step 1: Write the tests** — append to `tests/unit/core/scheduler/test_engine.py`. Add imports: `LocalParentBudgetResolver` (from `core.scheduler.budget_resolver`), `ParentTaskBudgetUnavailable` (from `core.scheduler._seams`), and `from sqlalchemy import func` if not already imported (`select` + `SchedulerStorage` already are). `_make_submit_input` already has `parent_task_id` + `requested_tokens` params; its default `tenant_id="tenant-a"` is what the resolver receives, so seed the parent in the SAME tenant.

```python
# --- T4: engine ↔ LocalParentBudgetResolver integration -------------------


class _RecordingQuotaInterrogator:
    """Captures the estimated_tokens the engine asks the quota gate to admit —
    i.e. the narrowed effective_tokens after parent-budget inheritance."""

    def __init__(self) -> None:
        self.seen_estimated_tokens: int | None = None

    async def would_admit(self, *, task_id, tenant_id, pack_id, estimated_tokens) -> bool:
        self.seen_estimated_tokens = estimated_tokens
        return True

    async def release_reservation(self, task_id) -> None:  # pragma: no cover
        return None


async def _seed_parent(eng_db: AsyncEngine, *, tokens: int, state: str) -> uuid.UUID:
    """Seed a parent task in the SHARED engine_db via the real submit→transition
    path so the resolver (reading the same db) resolves it. Default tenant-a.
    Terminal states follow _VALID_TRANSITIONS; `expired` goes directly from
    pending (running→expired is illegal), the others via running."""
    store = SchedulerStorage(eng_db)
    task_id = uuid.uuid4()
    await store.submit(
        task_id=task_id,
        submit_input=_make_submit_input(requested_tokens=tokens),
        request_id=f"seed-{task_id}",
    )
    if state == "pending":
        return task_id
    if state == "expired":
        # expired goes DIRECTLY from pending (running→expired is NOT in _VALID_TRANSITIONS).
        await store.transition(
            task_id=task_id, from_state="pending", to_state="expired",
            actor_id="seed", request_id=f"seed-expire-{task_id}", payload_extras={},
        )
        return task_id
    await store.transition(
        task_id=task_id, from_state="pending", to_state="running",
        actor_id="seed", request_id=f"seed-run-{task_id}", payload_extras={},
    )
    if state != "running":
        await store.transition(
            task_id=task_id, from_state="running", to_state=state,
            actor_id="seed", request_id=f"seed-term-{task_id}", payload_extras={},
        )
    return task_id


async def _count_admission_refused(eng_db: AsyncEngine) -> int:
    from cognic_agentos.core.decision_history import _decision_history

    async with eng_db.connect() as conn:
        return int(
            (
                await conn.execute(
                    select(func.count(_decision_history.c.sequence)).where(
                        _decision_history.c.event_type == "scheduler.admission_refused"
                    )
                )
            ).scalar_one()
        )


def _resolver(eng_db: AsyncEngine) -> LocalParentBudgetResolver:
    return LocalParentBudgetResolver(reader=SchedulerStorage(eng_db))


async def test_child_budget_narrowed_to_parent_grant_when_parent_smaller(
    engine_db: AsyncEngine, caps: ConcurrencyCaps, class_settings: dict[str, tuple[int, float]]
) -> None:
    parent_id = await _seed_parent(engine_db, tokens=50, state="running")
    quota = _RecordingQuotaInterrogator()
    eng = _make_engine(
        db=engine_db, caps=caps, class_settings=class_settings,
        quota=quota, parent_budget=_resolver(engine_db),
    )
    await eng.submit(
        submit_input=_make_submit_input(parent_task_id=str(parent_id), requested_tokens=200),
        request_id="child-1",
    )
    assert quota.seen_estimated_tokens == 50  # min(200, 50) — the ceiling bit


async def test_child_budget_keeps_own_quota_when_parent_larger(
    engine_db: AsyncEngine, caps: ConcurrencyCaps, class_settings: dict[str, tuple[int, float]]
) -> None:
    parent_id = await _seed_parent(engine_db, tokens=1000, state="running")
    quota = _RecordingQuotaInterrogator()
    eng = _make_engine(
        db=engine_db, caps=caps, class_settings=class_settings,
        quota=quota, parent_budget=_resolver(engine_db),
    )
    await eng.submit(
        submit_input=_make_submit_input(parent_task_id=str(parent_id), requested_tokens=200),
        request_id="child-2",
    )
    assert quota.seen_estimated_tokens == 200


async def test_parentless_submit_budget_unchanged(
    engine_db: AsyncEngine, caps: ConcurrencyCaps, class_settings: dict[str, tuple[int, float]]
) -> None:
    quota = _RecordingQuotaInterrogator()
    eng = _make_engine(
        db=engine_db, caps=caps, class_settings=class_settings,
        quota=quota, parent_budget=_resolver(engine_db),
    )
    await eng.submit(
        submit_input=_make_submit_input(parent_task_id=None, requested_tokens=200),
        request_id="top-1",
    )
    assert quota.seen_estimated_tokens == 200  # resolver never consulted


async def test_not_found_parent_propagates_fail_loud_zero_refusal_rows(
    engine_db: AsyncEngine, caps: ConcurrencyCaps, class_settings: dict[str, tuple[int, float]]
) -> None:
    eng = _make_engine(
        db=engine_db, caps=caps, class_settings=class_settings, parent_budget=_resolver(engine_db),
    )
    with pytest.raises(ParentTaskBudgetUnavailable) as ei:
        await eng.submit(
            submit_input=_make_submit_input(parent_task_id=str(uuid.uuid4()), requested_tokens=200),
            request_id="child-nf",
        )
    assert ei.value.reason == "parent_not_found"
    assert await _count_admission_refused(engine_db) == 0  # propagated, NOT a refusal row


async def test_terminal_parent_propagates_parent_terminal(
    engine_db: AsyncEngine, caps: ConcurrencyCaps, class_settings: dict[str, tuple[int, float]]
) -> None:
    parent_id = await _seed_parent(engine_db, tokens=50, state="completed")
    eng = _make_engine(
        db=engine_db, caps=caps, class_settings=class_settings, parent_budget=_resolver(engine_db),
    )
    with pytest.raises(ParentTaskBudgetUnavailable) as ei:
        await eng.submit(
            submit_input=_make_submit_input(parent_task_id=str(parent_id), requested_tokens=200),
            request_id="child-term",
        )
    assert ei.value.reason == "parent_terminal"
```

> NOTE: the parent-budget consult precedes pack_state/OPA/the admission gates (per the composition-test docstring), so a resolver raise occurs BEFORE any chain write — hence `_count_admission_refused == 0` (no accepted row either). `engine_db` already provisions the `decision_history` chain head (the existing engine tests submit + write chain rows), so `_seed_parent`'s `store.submit` works.

- [ ] **Step 2: Run → all pass.**
Run: `uv run pytest tests/unit/core/scheduler/test_engine.py -x -q`

- [ ] **Step 3: Lint + types.**
Run: `uv run ruff check tests/unit/core/scheduler/ && uv run mypy src tests`

- [ ] **Step 4: Commit** — `test(scheduler): engine↔resolver budget-inheritance integration (ADR-005)`

---

## Task 5: Composition wiring (`harness/runtime.py`, off-gate)

**Files:**
- Modify: `src/cognic_agentos/harness/runtime.py` (the cache-conditional scheduler block, ~line 290)
- Modify: `tests/integration/scheduler/test_scheduler_composition_e2e.py` (the existing `test_composition_subagent_submit_fails_loud` — sentinel → real resolver)

- [ ] **Step 1: Wire the real resolver.** Add the import (top of `runtime.py`, with the other scheduler imports):

```python
from cognic_agentos.core.scheduler.budget_resolver import LocalParentBudgetResolver
```

Extract a single `SchedulerStorage` instance (reused for `storage=` + the resolver) and inject the resolver — replacing the OMITTED comment at line 313. The block becomes:

```python
        scheduler_storage = SchedulerStorage(engine)
        scheduler = _SchedulerEngine(
            storage=scheduler_storage,
            caps=ConcurrencyCaps(
                per_tenant_interactive=settings.scheduler_per_tenant_interactive,
                per_tenant_background=settings.scheduler_per_tenant_background,
                per_pack=settings.scheduler_per_pack,
                per_actor=settings.scheduler_per_actor,
            ),
            class_settings={
                "interactive": (
                    settings.scheduler_queue_depth_interactive,
                    settings.scheduler_class_sla_interactive_s,
                ),
                "background": (
                    settings.scheduler_queue_depth_background,
                    settings.scheduler_class_sla_background_s,
                ),
            },
            policy_evaluator=SchedulerPolicy(opa_engine=scheduler_opa).evaluate,
            quota_interrogator=quota_engine,
            kill_switch_interrogator=SchedulerKillSwitchConformer(engine=kill_switch_engine),
            pack_state_interrogator=PackStoreStateInterrogator(store=PackRecordStore(engine)),
            approval_engine=approval_engine,
            parent_budget_resolver=LocalParentBudgetResolver(reader=scheduler_storage),
        )
```

- [ ] **Step 2: Update the existing composition e2e proof.** In `tests/integration/scheduler/test_scheduler_composition_e2e.py::test_composition_subagent_submit_fails_loud` (~line 180), flip the sentinel expectation to the real resolver. Add `from cognic_agentos.core.scheduler._seams import ParentTaskBudgetUnavailable` and change the body from the `NotImplementedError` raise to:

```python
        sub = _submit_input(parent_task_id=str(uuid.uuid4()))
        with pytest.raises(ParentTaskBudgetUnavailable) as ei:
            await scheduler.submit(submit_input=sub, request_id="req-3")
        assert ei.value.reason == "parent_not_found"
```

Update the test docstring (drop the sentinel/Fork-E/"14A wires" prose → the real `LocalParentBudgetResolver` resolves a random parent id to `parent_not_found`). This IS the composition behavioral proof: `build_runtime` now wires the real resolver, so a sub-agent submit with a random `parent_task_id` reads as absent → `ParentTaskBudgetUnavailable("parent_not_found")` (no longer `NotImplementedError`). Consider renaming the test (e.g. `…_resolves_unknown_parent_not_found`) — optional; if renamed, grep for any xref.

Run: `uv run pytest tests/integration/scheduler/test_scheduler_composition_e2e.py -x -q && uv run ruff check src/cognic_agentos/harness/runtime.py && uv run mypy src tests`

- [ ] **Step 3: Commit** — `feat(scheduler): wire LocalParentBudgetResolver at the composition root (ADR-005)`

---

## Task 6: Docs

**Files:**
- Modify: `docs/adrs/ADR-005-*.md` (sub-agent primitive) — amendment: the parent-budget resolver seam landed (granted-snapshot, fail-loud typed; the dispatch caller + sibling ledger remain the next slice).
- Modify: `docs/adrs/ADR-022-*.md` (scheduler) — the Fork-E "`parent_budget_resolver` OMITTED → sentinel" note resolves; the real resolver + the `get_budget_snapshot` read land; CC 131→132.
- Modify: `docs/AS_BUILT_CAPABILITY_MAP.md` — the scheduler/parent-budget current-state (the sentinel → live resolver); a milestone entry; CC 131→132. Sweep BOTH the scheduler pillar row and any "`_NullParentBudgetResolver` / sub-agent submit fails loud / Fork E / Sprint 11" current-state phrasing → updated; leave dated chronology.
- Modify: `AGENTS.md` — add `core/scheduler/budget_resolver.py` to the critical-controls list (the new on-gate module + its 2-value exception + the granted-snapshot contract); note `get_budget_snapshot` on `storage.py`; CC count 131→132. Update the 13.7 composition-root note's "`parent_budget_resolver` is OMITTED → `_NullParentBudgetResolver`… until Sprint 14A wires the real `LocalParentBudgetResolver`" to reflect that this slice wired it (resolver seam; sub-agent dispatch caller still forward).

- [ ] **Step 1-4:** write each amendment; coupled-surface sweep (update current-state summaries; leave dated chronology); grep each anchor; confirm no stale "fails loud until Sprint 11/14A wires it" current-state phrasing remains.
- [ ] **Step 5: Commit** — `docs(scheduler): parent budget resolver seam — Fork-E resolution (ADR-005/ADR-022)`

---

## Task 7: Closeout gate

- [ ] **Step 1** — `uv run ruff check . && uv run ruff format --check . && uv run mypy src tests`
- [ ] **Step 2** — full suite on fresh coverage: `uv run pytest -q --cov=cognic_agentos --cov-branch --cov-report=json:coverage.json`
- [ ] **Step 3** — `uv run python tools/check_critical_coverage.py` → **132/132** (the new `budget_resolver.py` + the edited `storage.py`/`engine.py` all ≥ floor). Confirm `budget_resolver.py` is registered in the gate list (`tools/check_critical_coverage.py`) — **add it** if the gate uses an explicit module list.
- [ ] **Step 4** — `git diff --stat main...HEAD`: only the scheduler seam/storage/resolver/engine + harness + tests + docs; exactly **one** new on-gate module (`budget_resolver.py`); `git status --porcelain` shows only the 2 protected untracked docs.
- [ ] **Step 5** — finish-the-branch (push + PR, controller-owned + token-gated; `--squash --delete-branch`).

> NOTE on the gate registration: if `tools/check_critical_coverage.py` enumerates on-gate modules explicitly, T3 (or T7 Step 3) must add `core/scheduler/budget_resolver.py` to that list — that registration IS the CC 131→132 promotion. Verify the count asserts 132.

---

## Self-Review (controller, after writing — fix inline)

- **Spec coverage:** §3 contract → T1 (exception + sig) + T3 (resolver semantics); the tenant-scoped source → T2; `compute_child_budget` ceiling → T4 (the "exhaustion/narrowing" proof); fail-loud propagation + zero refusal rows → T4; composition → T5; CC 131→132 → T3/T7; docs/posture → T6/T7; out-of-scope boundary → unchanged (no subagent/, no ledger, no Rego).
- **Type consistency:** `ParentTaskBudgetUnavailable` + `ParentTaskBudgetUnavailableReason` (T1) used by T3 + tests; `_BudgetSnapshot` + `get_budget_snapshot` + `_build_budget_snapshot_stmt` (T2) used by T3 (reader) + tests; `BudgetSnapshotReader` + `_TERMINAL_STATES` + `LocalParentBudgetResolver` (T3) used by T4 + T5; the call-site `tenant_id=` (T1) matches the Protocol.
- **Placeholders:** none. T2/T4 fixtures are pinned to the REAL existing helpers — `store`/`engine`/`SubmitInput`/`TaskActor` in `test_storage.py`; `engine_db`/`caps`/`class_settings`/`_make_engine`/`_make_submit_input` (which already has `parent_task_id` + `requested_tokens`) + the existing `_StubParentBudgetResolver` (T1 sig-updated) in `test_engine.py`; `_submit_input`/`_build_composed_runtime` in the composition e2e. The new in-file helpers (`_seed_task`/`_seed_parent`/`_RecordingQuotaInterrogator`/`_count_admission_refused`/`_resolver`) carry complete code. The remaining `> NOTE` blocks are clarifying invariants (consult-precedes-chain-write; `engine_db` chain-head provisioning), not deferrals.
- **Critical-controls:** the on-gate tasks (T1 engine, T2 storage, T3 resolver) carry the 95/90 floor + negative-path tests; T7 verifies 132/132 on fresh coverage + the gate-list registration.
