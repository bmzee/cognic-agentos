# Sprint 11 — Sub-Agent Primitive Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Every task touches the `subagent/` stop-rule isolation boundary or a `core/` stop-rule → halt-before-commit per `[[feedback_strict_review_off_gate]]`, `core-controls-engineer` + `/critical-module-mode`.**

**Goal:** Ship the AgentOS sub-agent primitive per ADR-005 — orchestrator→worker delegation with isolated context, privilege de-escalation, capped budget + recursion depth, and a cross-agent audit chain — dispatched in-process through the Sprint-10.5 scheduler.

**Architecture:** `subagent/` is a thin kernel primitive: pure-functional policy (privilege subset + depth cap + budget narrowing) + an audit emitter feed an in-process, scheduler-mediated Wave-1 dispatch that preserves A2A trace/audit semantics. Parent↔child linkage rides entirely in the hash-chained `decision_history` payload (`payload["parent_record_id"]`) and is verified by a cross-row linkage verifier modelled on `verify_suspend_wake_linkage` — no `DecisionRecord` schema change, no `core/canonical.py`, no literal Merkle tree. The sprint splits into **11a** (pure primitive — this plan in full TDD) and **11b** (integration — structured outline below a valve check).

**Tech Stack:** Python 3.12, `uv`, pytest + pytest-asyncio, SQLAlchemy async (SQLite in unit tests; Postgres/Oracle behind `COGNIC_RUN_*_INTEGRATION`), pydantic-settings, ruff, mypy, `tools/check_critical_coverage.py` (per-file 95% line / 90% branch gate over `coverage.json`).

**Source spec:** `docs/superpowers/specs/2026-05-30-sprint-11-subagent-primitive-design.md` (committed `a7a72a1`).

---

## Conventions for every task

- **Gate ladder per `[[feedback_gate_ladder_per_microfix]]`:** at HALT run `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src tests` (full-tree) + the task's **narrow** pytest slice. The **full** suite runs only at the `commit` token.
- **Halt-before-commit:** each task ends at a HALT step with a summary (files modified, narrow tests green, mypy/ruff clean, every user watchpoint mapped to ≥1 regression). No commit without the explicit `commit` token. Commit by **explicit path** + footer `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. Never `git add -A`; never stage `docs/superpowers/specs/2026-05-26-agentos-local-managed-agents-gap-analysis.md`.
- **All Python via `uv run`.**
- **Substrate independence:** `core/scheduler/*` must NOT import `subagent/*` (the real `ParentBudgetResolver` is injected via DI in 11b). The reverse — `subagent/*` importing the scheduler's pure seam helpers (`compute_child_budget`) — IS allowed. `subagent/audit*.py` consume `core/decision_history` + read the `_decision_history` table; they do NOT edit `core/decision_history.py`, `core/canonical.py`, or `core/chain_verifier.py`.

---

## File structure (11a)

| File | Responsibility |
|---|---|
| `src/cognic_agentos/subagent/__init__.py` | Package marker (11a); re-exports `_types`. `SubAgent` facade arrives in 11b/T7. |
| `src/cognic_agentos/subagent/_types.py` | Closed-enum vocab (`SubAgentRefusalReason`, `SubAgentAuditEvent`), typed exceptions, frozen `SubAgentSpawnRequest`, `SUBAGENT_ISO_CONTROLS`. |
| `src/cognic_agentos/subagent/policy.py` | Pure: `narrow_tool_allow_list` (privilege subset) + `check_depth` (recursion cap) + `compute_spawn_budget` (budget narrowing). |
| `src/cognic_agentos/subagent/audit.py` | `SubAgentAuditEmitter` — emits the 4 ADR-005 events + child-genesis payload linkage via `DecisionHistoryStore.append`. |
| `src/cognic_agentos/subagent/audit_verifier.py` | `verify_subagent_linkage` + `SubAgentLinkageReport` — cross-row payload-linkage verifier mirroring `verify_suspend_wake_linkage`. |
| `src/cognic_agentos/core/config.py` | + 1 field `subagent_max_recursion_depth` (core/ stop-rule). |
| `tests/unit/subagent/conftest.py` | Shared async fixtures: `engine`, `decision_store`, `decision_store_rows`, `insert_raw_decision_row`. |
| `tests/unit/subagent/test_*.py` | Per-task unit + drift-detector tests. |
| `tools/check_critical_coverage.py` | Z1a: + 4 `subagent/` modules; bump `_EXPECTED_ENTRY_COUNT` 90→94. |

---

## Task T0: Source-of-truth reconciliation (docs only — runs BEFORE any code)

**Files:**
- Modify: `docs/adrs/ADR-005-subagent-primitive.md`
- Modify: `docs/BUILD_PLAN.md`

ADR-005 is APPROVED and currently states the Wave-2 shape; reconcile to the Wave-1 design before any code lands so the implementation never diverges from an approved ADR (`[[feedback_patch_plan_against_doctrine]]`). No code, no tests — documentation reconciliation, halt-before-commit (these are governance docs).

- [ ] **Step 1: ADR-005 amendment — Wave-1 dispatch.** Append a `## Sprint 11 amendment (2026-05-30) — Wave-1 in-process dispatch` section: Wave-1 sub-agent dispatch is **in-process, scheduler-mediated**, preserving A2A trace/audit/identity *semantics* (parent_trace→child_trace propagation; identity metadata in the audit payload; **no AgentCard/JWS verification at in-process spawn**). The A2A *endpoint transport* (cross-pod) is deferred to Wave 2. Cite the consistency anchor: ADR-005 §Consequences/Neutral already names in-process (`ADR-005:61`). State explicitly this is additive — §Decision's "spawn via the A2A endpoint" remains the cross-pod Wave-2 contract.

- [ ] **Step 2: ADR-005 amendment — Wave-1 recursion cap.** In the same amendment section: Wave-1 recursion cap is a **global** `Settings.subagent_max_recursion_depth = 3`; per-tenant/per-agent overrides (`ADR-005:30`) are deferred to the policy/approval layer (Sprint 13.5). Note this is the BUILD_PLAN `:1342` human-decision, now decided (global).

- [ ] **Step 3: BUILD_PLAN Sprint-11 reword.** In `docs/BUILD_PLAN.md` §"Sprint 11 — Sub-agent primitive":
  - Deliverable `subagent/spawn.py — A2A-backed invoke(prompt)` → `scheduler-mediated invoke(prompt) (A2A semantics; A2A transport Wave-2)`.
  - **Remove** the deliverable line `core/decision_history.py extension — child record links to parent's chain hash`; replace with `parent↔child linkage is payload-only (payload["parent_record_id"]); no DecisionRecord schema, no core/canonical.py, no schema_version bump`.
  - Test/exit-criteria reword: `test_subagent_audit_chain.py — Merkle proof over parent + child events verifies` → `…cross-row payload-linkage verification (modelled on verify_suspend_wake_linkage)`; exit criterion "Cross-agent audit chain verifiable" stays; add "no direct child execution bypasses core/scheduler".
  - Add a Sprint-11 row to the schedule-risk table (currently stops at 10.5, `BUILD_PLAN:1288`): `Sprint 11 — Sub-agent primitive (3 wu) | Realistic range: 3-5.5 wu. Mitigation: split into 11a-core-primitive + 11b-integration at a valve checkpoint.`

- [ ] **Step 4: Verify + HALT.** Use `git diff --check` (tracked edits). Confirm no stray edits. HALT — summary: 2 ADR-005 amendment paragraphs + 4 BUILD_PLAN rewrites; no code. On `commit`: `git add docs/adrs/ADR-005-subagent-primitive.md docs/BUILD_PLAN.md` + commit `docs(sprint-11): T0 reconcile ADR-005 + BUILD_PLAN to Wave-1 in-process dispatch + payload-only linkage`.

---

## Task T1: Closed-enum vocabulary + types (`subagent/_types.py`)

**Files:**
- Create: `src/cognic_agentos/subagent/__init__.py`
- Create: `src/cognic_agentos/subagent/_types.py`
- Test: `tests/unit/subagent/test_subagent_types_closed_enums.py`

Pure module, no I/O. The closed enums are wire-public; the test is the single pinning surface per `[[feedback_drift_detector_test_only_no_runtime_import]]` (mirrors `tests/unit/core/scheduler/test_closed_enums.py`).

- [ ] **Step 1: Write the failing drift-detector test.**

```python
# tests/unit/subagent/test_subagent_types_closed_enums.py
"""Closed-enum drift detectors for the sub-agent vocabulary
(per [[feedback_drift_detector_test_only_no_runtime_import]]). Single
pinning surface; production declares its own Literals, this asserts the sets."""
from typing import get_args

from cognic_agentos.subagent._types import (
    SUBAGENT_ISO_CONTROLS,
    SubAgentAuditEvent,
    SubAgentRefusalReason,
)


class TestSubAgentRefusalReasonVocabulary:
    def test_exactly_three_values(self):
        assert len(get_args(SubAgentRefusalReason)) == 3

    def test_value_set(self):
        assert set(get_args(SubAgentRefusalReason)) == {
            "subagent_depth_exceeded",
            "subagent_privilege_escalation",
            "subagent_parent_budget_exhausted",
        }


class TestSubAgentAuditEventVocabulary:
    def test_exactly_four_values_in_adr005_order(self):
        assert get_args(SubAgentAuditEvent) == (
            "subagent.spawn",
            "subagent.start",
            "subagent.return",
            "subagent.budget",
        )


class TestSubAgentIsoControls:
    def test_a_6_2_5(self):
        assert SUBAGENT_ISO_CONTROLS == ("A.6.2.5",)
```

- [ ] **Step 2: Run — verify it fails.** `uv run pytest tests/unit/subagent/test_subagent_types_closed_enums.py -q` → FAIL (`ModuleNotFoundError: cognic_agentos.subagent`).

- [ ] **Step 3: Create the package marker.**

```python
# src/cognic_agentos/subagent/__init__.py
"""Sprint 11 — sub-agent primitive (ADR-005). Stop-rule isolation
boundary (privilege de-escalation). The SubAgent facade lands in 11b."""
from __future__ import annotations

from cognic_agentos.subagent._types import (
    SUBAGENT_ISO_CONTROLS,
    SubAgentAuditEvent,
    SubAgentBudgetExhausted,
    SubAgentDepthExceeded,
    SubAgentPrivilegeEscalation,
    SubAgentRefusalReason,
    SubAgentSpawnRequest,
)

__all__ = [
    "SUBAGENT_ISO_CONTROLS",
    "SubAgentAuditEvent",
    "SubAgentBudgetExhausted",
    "SubAgentDepthExceeded",
    "SubAgentPrivilegeEscalation",
    "SubAgentRefusalReason",
    "SubAgentSpawnRequest",
]
```

- [ ] **Step 4: Implement the types.**

```python
# src/cognic_agentos/subagent/_types.py
"""Sprint 11 — sub-agent closed-enum vocabulary + frozen dataclasses per
ADR-005. Pure (no I/O). Critical-controls (subagent/ stop-rule)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

# Spawn-time refusal vocabulary (wire-public; pinned by the drift detector).
SubAgentRefusalReason = Literal[
    "subagent_depth_exceeded",
    "subagent_privilege_escalation",
    "subagent_parent_budget_exhausted",
]

# Audit decision_types on the decision_history chain (ADR-005 §Audit).
SubAgentAuditEvent = Literal[
    "subagent.spawn",
    "subagent.start",
    "subagent.return",
    "subagent.budget",
]

# ISO 42001 control tuple stamped on every subagent.* chain row
# (delegation accountability + action traceability per ADR-005 §ISO;
# A.6.2.5 is implemented in the iso42001 registry + used by the scheduler).
SUBAGENT_ISO_CONTROLS: Final[tuple[str, ...]] = ("A.6.2.5",)


class SubAgentDepthExceeded(Exception):
    """Spawn refused: child would exceed the recursion-depth cap."""

    def __init__(self, *, current_depth: int, max_depth: int) -> None:
        super().__init__("subagent_depth_exceeded")
        self.reason: SubAgentRefusalReason = "subagent_depth_exceeded"
        self.current_depth = current_depth
        self.max_depth = max_depth


class SubAgentPrivilegeEscalation(Exception):
    """Spawn refused: requested tools are not a subset of the parent's."""

    def __init__(self, *, extra_tools: frozenset[str]) -> None:
        super().__init__("subagent_privilege_escalation")
        self.reason: SubAgentRefusalReason = "subagent_privilege_escalation"
        self.extra_tools = extra_tools


class SubAgentBudgetExhausted(Exception):
    """Spawn refused: the parent's narrowed budget is zero."""

    def __init__(self, *, parent_remaining_budget: int) -> None:
        super().__init__("subagent_parent_budget_exhausted")
        self.reason: SubAgentRefusalReason = "subagent_parent_budget_exhausted"
        self.parent_remaining_budget = parent_remaining_budget


@dataclass(frozen=True)
class SubAgentSpawnRequest:
    """Explicit inputs to a sub-agent spawn — no inference from MCP host
    (Wave-1). ``parent_tool_allow_list`` and ``requested_tool_allow_list``
    are frozensets of tool IDs; the latter must be a subset of the former."""

    prompt: str
    parent_tool_allow_list: frozenset[str]
    requested_tool_allow_list: frozenset[str]
    current_depth: int
    requested_estimated_tokens: int
    tenant_id: str
    parent_task_id: str | None = None
```

- [ ] **Step 5: Run — verify pass.** `uv run pytest tests/unit/subagent/test_subagent_types_closed_enums.py -q` → PASS.

- [ ] **Step 6: HALT.** Gate ladder (ruff/format/mypy full-tree + narrow pytest). Summary: 2 files created + 1 test; closed-enum vocab pinned; ISO tuple = A.6.2.5. On `commit`: full suite, then `git add src/cognic_agentos/subagent/__init__.py src/cognic_agentos/subagent/_types.py tests/unit/subagent/test_subagent_types_closed_enums.py` + `feat(sprint-11): T1 sub-agent closed-enum vocabulary + types`.

---

## Task T2: Settings depth field + pure policy (`subagent/policy.py`)

**Files:**
- Modify: `src/cognic_agentos/core/config.py` (add 1 field, after the server/profile fields block, ~`config.py:101`) — **core/ stop-rule, halt.**
- Create: `src/cognic_agentos/subagent/policy.py`
- Test: `tests/unit/subagent/test_subagent_privilege.py`, `tests/unit/subagent/test_subagent_depth.py`, `tests/unit/subagent/test_subagent_budget_helper.py`, `tests/unit/core/test_config_subagent.py`

Pure-functional. Three helpers: `narrow_tool_allow_list` (privilege subset), `check_depth` (recursion cap), `compute_spawn_budget` (budget narrowing, delegating to the scheduler's pure `compute_child_budget`). Depth semantics: root orchestrator = depth 0; a child spawned from a parent at `current_depth` sits at `current_depth + 1`; refuse when `current_depth + 1 > max_depth`. With `max_depth=3` the deepest legal child is depth 3; a depth-4 spawn (parent at depth 3) is refused — matches the BUILD_PLAN `test_subagent_depth.py` case.

- [ ] **Step 1: Write failing privilege test.**

```python
# tests/unit/subagent/test_subagent_privilege.py
import pytest

from cognic_agentos.subagent._types import SubAgentPrivilegeEscalation
from cognic_agentos.subagent.policy import narrow_tool_allow_list


def test_subset_request_is_granted_unchanged():
    parent = frozenset({"search", "read", "summarize"})
    requested = frozenset({"search", "read"})
    assert narrow_tool_allow_list(parent=parent, requested=requested) == requested


def test_equal_request_is_granted():
    s = frozenset({"search"})
    assert narrow_tool_allow_list(parent=s, requested=s) == s


def test_extra_tool_raises_privilege_escalation():
    parent = frozenset({"search"})
    requested = frozenset({"search", "wire_transfer"})
    with pytest.raises(SubAgentPrivilegeEscalation) as exc:
        narrow_tool_allow_list(parent=parent, requested=requested)
    assert exc.value.extra_tools == frozenset({"wire_transfer"})
    assert exc.value.reason == "subagent_privilege_escalation"
```

- [ ] **Step 2: Write failing depth test.**

```python
# tests/unit/subagent/test_subagent_depth.py
import pytest

from cognic_agentos.subagent._types import SubAgentDepthExceeded
from cognic_agentos.subagent.policy import check_depth


@pytest.mark.parametrize("current_depth", [0, 1, 2])
def test_depth_below_cap_is_allowed(current_depth):
    check_depth(current_depth=current_depth, max_depth=3)  # no raise


def test_depth_4_spawn_beyond_max_3_raises():
    # parent at depth 3 → child would be depth 4 > max_depth 3
    with pytest.raises(SubAgentDepthExceeded) as exc:
        check_depth(current_depth=3, max_depth=3)
    assert exc.value.current_depth == 3
    assert exc.value.max_depth == 3
    assert exc.value.reason == "subagent_depth_exceeded"
```

- [ ] **Step 3: Write failing budget-helper test.**

```python
# tests/unit/subagent/test_subagent_budget_helper.py
import pytest

from cognic_agentos.subagent._types import SubAgentBudgetExhausted
from cognic_agentos.subagent.policy import compute_spawn_budget


def test_narrows_to_min_of_parent_and_child():
    assert compute_spawn_budget(parent_remaining_budget=500, child_pack_quota=300) == 300
    assert compute_spawn_budget(parent_remaining_budget=200, child_pack_quota=300) == 200


def test_raises_when_narrowed_budget_is_zero():
    # parent exhausted → min(...) is 0 → refuse
    with pytest.raises(SubAgentBudgetExhausted) as exc:
        compute_spawn_budget(parent_remaining_budget=0, child_pack_quota=300)
    assert exc.value.parent_remaining_budget == 0
    assert exc.value.reason == "subagent_parent_budget_exhausted"
```

- [ ] **Step 4: Write failing Settings test.**

```python
# tests/unit/core/test_config_subagent.py
import pytest
from pydantic import ValidationError

from cognic_agentos.core.config import Settings


def test_subagent_max_recursion_depth_defaults_to_3():
    assert Settings().subagent_max_recursion_depth == 3


def test_subagent_max_recursion_depth_rejects_zero():
    with pytest.raises(ValidationError):
        Settings(subagent_max_recursion_depth=0)
```

- [ ] **Step 5: Run — verify all four fail.** `uv run pytest tests/unit/subagent/test_subagent_privilege.py tests/unit/subagent/test_subagent_depth.py tests/unit/subagent/test_subagent_budget_helper.py tests/unit/core/test_config_subagent.py -q` → FAIL.

- [ ] **Step 6: Add the Settings field** (after the profile/log block, ~`config.py:101`):

```python
    # --- Sub-agent primitive (Sprint 11, ADR-005) --------------------
    subagent_max_recursion_depth: int = Field(
        default=3,
        ge=1,
        description=(
            "Wave-1 global recursion-depth cap for sub-agent spawning "
            "(ADR-005 §Recursion-depth). A spawn whose child would sit at "
            "depth greater than this value is refused (SubAgentDepthExceeded) "
            "and escalated. Per-tenant / per-agent overrides are deferred to "
            "the policy/approval layer (Sprint 13.5)."
        ),
    )
```

- [ ] **Step 7: Implement policy.** (`compute_spawn_budget` imports the scheduler's pure helper `compute_child_budget` from `core.scheduler._seams` — the documented Wave-1 seam per the ADR-005 §"Sprint 10.5 amendment"; subagent→scheduler is the allowed import direction.)

```python
# src/cognic_agentos/subagent/policy.py
"""Sprint 11 — pure-functional sub-agent policy per ADR-005: privilege
de-escalation (tool allow-list subset) + recursion-depth cap + budget
narrowing. No I/O. Critical-controls (subagent/ stop-rule)."""
from __future__ import annotations

from cognic_agentos.core.scheduler._seams import compute_child_budget
from cognic_agentos.subagent._types import (
    SubAgentBudgetExhausted,
    SubAgentDepthExceeded,
    SubAgentPrivilegeEscalation,
)


def narrow_tool_allow_list(
    *, parent: frozenset[str], requested: frozenset[str]
) -> frozenset[str]:
    """Return ``requested`` iff it is a subset of ``parent`` (privilege
    de-escalation per ADR-005 §"Privilege de-escalation rule"). Raise
    :class:`SubAgentPrivilegeEscalation` listing the extra tools otherwise.
    The granted set is never wider than ``parent``."""
    extra = requested - parent
    if extra:
        raise SubAgentPrivilegeEscalation(extra_tools=extra)
    return requested


def check_depth(*, current_depth: int, max_depth: int) -> None:
    """Raise :class:`SubAgentDepthExceeded` if a child spawned from a parent
    at ``current_depth`` would exceed ``max_depth``. Root orchestrator is
    depth 0; the child sits at ``current_depth + 1``."""
    if current_depth + 1 > max_depth:
        raise SubAgentDepthExceeded(current_depth=current_depth, max_depth=max_depth)


def compute_spawn_budget(
    *, parent_remaining_budget: int, child_pack_quota: int
) -> int:
    """Narrow the child's token budget to ``min(child_pack_quota,
    parent_remaining_budget)`` via the scheduler's pure ``compute_child_budget``
    helper. Raise :class:`SubAgentBudgetExhausted` when the narrowed budget is
    zero — the parent has nothing left to delegate."""
    granted = compute_child_budget(
        parent_remaining_budget=parent_remaining_budget,
        child_pack_quota=child_pack_quota,
    )
    if granted == 0:
        raise SubAgentBudgetExhausted(parent_remaining_budget=parent_remaining_budget)
    return granted
```

- [ ] **Step 8: Run — verify pass.** Same command as Step 5 → PASS.

- [ ] **Step 9: HALT.** Gate ladder. Watchpoints: privilege subset (extra tool → raise), depth cap (depth-4 → raise), budget narrowing (min + raise-on-zero), Settings `ge=1`. Note: the *escalation-triggered* half of `test_subagent_depth.py` (depth-exceed → `EscalationStore.open`) is an 11b carry-forward (needs the spawn flow + an engine); T2 pins only the pure raise. On `commit`: full suite, then `git add src/cognic_agentos/core/config.py src/cognic_agentos/subagent/policy.py tests/unit/subagent/test_subagent_privilege.py tests/unit/subagent/test_subagent_depth.py tests/unit/subagent/test_subagent_budget_helper.py tests/unit/core/test_config_subagent.py` + `feat(sprint-11): T2 global depth Settings + pure privilege/depth/budget policy`.

---

## Task T3: Shared fixtures + audit emitter (`subagent/audit.py`)

**Files:**
- Create: `tests/unit/subagent/conftest.py` (shared async fixtures — reused by T4)
- Create: `src/cognic_agentos/subagent/audit.py`
- Test: `tests/unit/subagent/test_subagent_audit_emit.py`

The emitter mirrors the `EscalationStore.open` pattern (`escalation.py:467-508`): construct a `DecisionRecord(decision_type=…, request_id=…, actor_id=…, tenant_id=…, iso_controls=SUBAGENT_ISO_CONTROLS, payload={…})` and `await store.append(record) -> (record_id, hash)`. Parent↔child linkage is `payload["parent_record_id"] = str(parent_spawn_record_id)`. **No edit to `core/decision_history.py`.**

- [ ] **Step 1: Create the shared conftest** (the `engine` + chain-head seeding mirror the verified `tests/unit/core/test_decision_history.py:37-70`; `decision_store_rows` reads the chain back; `insert_raw_decision_row` fabricates a row with controlled columns for the T4 negatives the in-order append API cannot reach — built from the `_decision_history` columns at `decision_history.py:185-203`):

```python
# tests/unit/subagent/conftest.py
"""Shared async fixtures for the sub-agent unit tests. engine + chain-head
seeding mirror tests/unit/core/test_decision_history.py:37-70."""
from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import DecisionHistoryStore, _decision_history


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    url = f"sqlite+aiosqlite:///{tmp_path / 'subagent.db'}"
    eng: AsyncEngine = create_async_engine(url)
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


@pytest.fixture
async def decision_store(engine: AsyncEngine) -> DecisionHistoryStore:
    return DecisionHistoryStore(engine)


@pytest.fixture
def decision_store_rows(engine: AsyncEngine):
    """Zero-arg async reader: all decision_history rows ordered by sequence."""

    async def _read() -> list[Any]:
        async with engine.begin() as conn:
            return (
                await conn.execute(
                    select(_decision_history).order_by(_decision_history.c.sequence)
                )
            ).all()

    return _read


@pytest.fixture
def insert_raw_decision_row(engine: AsyncEngine):
    """Fabricate a decision_history row with controlled columns, bypassing the
    hash-chain append. The linkage verifier is independent of the hash-walk, so
    a chain-detached row is still read by its SELECT — this reaches the negative
    cases (forward links, malformed parent_record_id) the in-order API cannot."""

    async def _insert(
        *,
        record_id: uuid.UUID,
        sequence: int,
        event_type: str,
        payload: dict[str, Any],
        tenant_id: str | None = None,
    ) -> None:
        async with engine.begin() as conn:
            await conn.execute(
                _decision_history.insert().values(
                    record_id=record_id,
                    sequence=sequence,
                    schema_version=1,
                    tenant_id=tenant_id,
                    prev_hash=ZERO_HASH,
                    hash=hashlib.sha256(str(record_id).encode()).digest(),
                    created_at=datetime.now(UTC),
                    event_type=event_type,
                    request_id="fab",
                    payload=payload,
                )
            )

    return _insert
```

- [ ] **Step 2: Write the failing emitter test** (`decision_store` + `decision_store_rows` come from the conftest above):

```python
# tests/unit/subagent/test_subagent_audit_emit.py
import uuid

import pytest

from cognic_agentos.subagent.audit import SubAgentAuditEmitter


@pytest.mark.asyncio
async def test_spawn_then_child_genesis_links_by_parent_record_id(
    decision_store, decision_store_rows
):
    emitter = SubAgentAuditEmitter(decision_store)
    spawn_id = await emitter.emit_spawn(
        actor_id="orchestrator",
        tenant_id="bank-a",
        request_id="req-1",
        parent_trace_id="ptrace",
        child_request={"prompt": "verify AML"},
        policy_snapshot={"tools": ["aml_check"]},
    )
    child_id = await emitter.emit_child_genesis(
        actor_id="worker",
        tenant_id="bank-a",
        request_id="req-1",
        parent_record_id=spawn_id,
        child_trace_id="ctrace",
    )
    assert isinstance(spawn_id, uuid.UUID)
    assert isinstance(child_id, uuid.UUID)
    rows = await decision_store_rows()
    child = next(r for r in rows if r.record_id == child_id)
    assert child.event_type == "subagent.start"
    assert child.payload["parent_record_id"] == str(spawn_id)
    assert list(child.iso_controls) == ["A.6.2.5"]
    spawn = next(r for r in rows if r.record_id == spawn_id)
    assert spawn.event_type == "subagent.spawn"
    assert "parent_record_id" not in spawn.payload  # root has no parent link


@pytest.mark.asyncio
async def test_return_and_budget_carry_parent_link(decision_store, decision_store_rows):
    emitter = SubAgentAuditEmitter(decision_store)
    spawn_id = await emitter.emit_spawn(
        actor_id="o", tenant_id="bank-a", request_id="r",
        parent_trace_id="pt", child_request={}, policy_snapshot={},
    )
    ret_id = await emitter.emit_return(
        actor_id="o", tenant_id="bank-a", request_id="r",
        parent_record_id=spawn_id, result_summary="ok", outcome="completed",
    )
    bud_id = await emitter.emit_budget(
        actor_id="o", tenant_id="bank-a", request_id="r",
        parent_record_id=spawn_id, tokens_used=120, wall_time_used_s=0.4,
    )
    rows = await decision_store_rows()
    ret = next(r for r in rows if r.record_id == ret_id)
    bud = next(r for r in rows if r.record_id == bud_id)
    assert ret.event_type == "subagent.return"
    assert ret.payload["parent_record_id"] == str(spawn_id)
    assert ret.payload["outcome"] == "completed"
    assert bud.event_type == "subagent.budget"
    assert bud.payload["tokens_used"] == 120
```

- [ ] **Step 3: Run — verify it fails.** `uv run pytest tests/unit/subagent/test_subagent_audit_emit.py -q` → FAIL (`ModuleNotFoundError: …subagent.audit`).

- [ ] **Step 4: Implement the emitter.**

```python
# src/cognic_agentos/subagent/audit.py
"""Sprint 11 — sub-agent audit emitter per ADR-005 §Audit. Emits the four
parent-chain events + the child genesis record, linked to the parent spawn
row by payload['parent_record_id']. Consumes DecisionHistoryStore.append;
does NOT edit core/decision_history.py or core/canonical.py. Critical-
controls (subagent/ stop-rule)."""
from __future__ import annotations

import uuid
from typing import Any, Literal

from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.subagent._types import SUBAGENT_ISO_CONTROLS

ReturnOutcome = Literal["completed", "failed"]


class SubAgentAuditEmitter:
    """Thin emitter over the decision-history chain. One instance per request
    flow; each method appends exactly one chain row and returns its record_id."""

    def __init__(self, history: DecisionHistoryStore) -> None:
        self._history = history

    async def emit_spawn(
        self,
        *,
        actor_id: str,
        tenant_id: str,
        request_id: str,
        parent_trace_id: str,
        child_request: dict[str, Any],
        policy_snapshot: dict[str, Any],
    ) -> uuid.UUID:
        """Emit subagent.spawn on the parent chain. Returns the spawn row's
        record_id — the value every child row carries as parent_record_id."""
        record_id, _ = await self._history.append(
            DecisionRecord(
                decision_type="subagent.spawn",
                request_id=request_id,
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=SUBAGENT_ISO_CONTROLS,
                payload={
                    "parent_trace_id": parent_trace_id,
                    "child_request": child_request,
                    "policy": policy_snapshot,
                },
            )
        )
        return record_id

    async def emit_child_genesis(
        self,
        *,
        actor_id: str,
        tenant_id: str,
        request_id: str,
        parent_record_id: uuid.UUID,
        child_trace_id: str,
    ) -> uuid.UUID:
        """Emit subagent.start — the child's own genesis record, linked to the
        parent spawn row by payload['parent_record_id']."""
        record_id, _ = await self._history.append(
            DecisionRecord(
                decision_type="subagent.start",
                request_id=request_id,
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=SUBAGENT_ISO_CONTROLS,
                payload={
                    "parent_record_id": str(parent_record_id),
                    "child_trace_id": child_trace_id,
                },
            )
        )
        return record_id

    async def emit_return(
        self,
        *,
        actor_id: str,
        tenant_id: str,
        request_id: str,
        parent_record_id: uuid.UUID,
        result_summary: str,
        outcome: ReturnOutcome,
    ) -> uuid.UUID:
        """Emit subagent.return on the parent chain."""
        record_id, _ = await self._history.append(
            DecisionRecord(
                decision_type="subagent.return",
                request_id=request_id,
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=SUBAGENT_ISO_CONTROLS,
                payload={
                    "parent_record_id": str(parent_record_id),
                    "result_summary": result_summary,
                    "outcome": outcome,
                },
            )
        )
        return record_id

    async def emit_budget(
        self,
        *,
        actor_id: str,
        tenant_id: str,
        request_id: str,
        parent_record_id: uuid.UUID,
        tokens_used: int,
        wall_time_used_s: float,
    ) -> uuid.UUID:
        """Emit subagent.budget on the parent chain."""
        record_id, _ = await self._history.append(
            DecisionRecord(
                decision_type="subagent.budget",
                request_id=request_id,
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=SUBAGENT_ISO_CONTROLS,
                payload={
                    "parent_record_id": str(parent_record_id),
                    "tokens_used": tokens_used,
                    "wall_time_used_s": wall_time_used_s,
                },
            )
        )
        return record_id
```

- [ ] **Step 5: Run — verify pass.** Same command as Step 3 → PASS.

- [ ] **Step 6: HALT.** Gate ladder. Watchpoints: 4 decision_types exact; child rows carry `payload["parent_record_id"]`; spawn (root) does NOT; ISO tag = `A.6.2.5`; no `core/decision_history.py` edit. On `commit`: full suite, then `git add tests/unit/subagent/conftest.py src/cognic_agentos/subagent/audit.py tests/unit/subagent/test_subagent_audit_emit.py` + `feat(sprint-11): T3 sub-agent audit emitter (payload-only parent linkage)`.

---

## Task T4: Cross-agent linkage verifier (`subagent/audit_verifier.py`)

**Files:**
- Create: `src/cognic_agentos/subagent/audit_verifier.py`
- Test: `tests/unit/subagent/test_subagent_audit_chain.py` (uses the T3 conftest fixtures)

Mirrors `verify_suspend_wake_linkage` (`chain_verifier.py:310`) **as a new module** (no edit to the CC `chain_verifier.py`). Like the precedent — which filters on `event_type == "sandbox.lifecycle.woken"`, **not** payload-key presence — this verifier filters on the sub-agent **child** event types (`subagent.start` / `subagent.return` / `subagent.budget`) so a foreign decision row that happens to use a `parent_record_id` payload key is ignored. For each child row it runs the first-break checks below.

- [ ] **Step 1: Write the failing tests** (clean + 5 negatives incl. the foreign-row guard; `engine` / `decision_store` / `insert_raw_decision_row` come from the T3 conftest):

```python
# tests/unit/subagent/test_subagent_audit_chain.py
import uuid

import pytest

from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.subagent.audit import SubAgentAuditEmitter
from cognic_agentos.subagent.audit_verifier import verify_subagent_linkage


@pytest.mark.asyncio
async def test_clean_parent_child_chain_verifies(engine, decision_store):
    emitter = SubAgentAuditEmitter(decision_store)
    spawn_id = await emitter.emit_spawn(
        actor_id="o", tenant_id="bank-a", request_id="r",
        parent_trace_id="pt", child_request={}, policy_snapshot={},
    )
    await emitter.emit_child_genesis(
        actor_id="w", tenant_id="bank-a", request_id="r",
        parent_record_id=spawn_id, child_trace_id="ct",
    )
    await emitter.emit_return(
        actor_id="o", tenant_id="bank-a", request_id="r",
        parent_record_id=spawn_id, result_summary="ok", outcome="completed",
    )
    report = await verify_subagent_linkage(engine)
    assert report.is_clean is True
    assert report.records_checked == 2  # start + return carry parent_record_id


@pytest.mark.asyncio
async def test_foreign_row_with_parent_record_id_key_is_ignored(engine, decision_store):
    # An unrelated decision row that happens to use the same payload key must
    # NOT be checked by the sub-agent verifier (Finding 2 guard).
    await decision_store.append(
        DecisionRecord(
            decision_type="escalation.opened",
            request_id="r",
            tenant_id="bank-a",
            payload={"parent_record_id": "not-a-real-uuid", "level": "x"},
        )
    )
    report = await verify_subagent_linkage(engine)
    assert report.is_clean is True
    assert report.records_checked == 0  # the non-subagent row was skipped


@pytest.mark.asyncio
async def test_child_pointing_at_non_spawn_row_breaks(engine, decision_store):
    emitter = SubAgentAuditEmitter(decision_store)
    spawn_id = await emitter.emit_spawn(
        actor_id="o", tenant_id="bank-a", request_id="r",
        parent_trace_id="pt", child_request={}, policy_snapshot={},
    )
    ret_id = await emitter.emit_return(
        actor_id="o", tenant_id="bank-a", request_id="r",
        parent_record_id=spawn_id, result_summary="ok", outcome="completed",
    )
    await emitter.emit_child_genesis(
        actor_id="w", tenant_id="bank-a", request_id="r",
        parent_record_id=ret_id, child_trace_id="ct",  # WRONG: points at a return row
    )
    report = await verify_subagent_linkage(engine)
    assert report.is_clean is False
    assert report.break_kind == "parent_record_id_wrong_decision_type"


@pytest.mark.asyncio
async def test_parent_row_not_found(engine, decision_store):
    emitter = SubAgentAuditEmitter(decision_store)
    await emitter.emit_child_genesis(
        actor_id="w", tenant_id="bank-a", request_id="r",
        parent_record_id=uuid.uuid4(), child_trace_id="ct",  # no spawn row exists
    )
    report = await verify_subagent_linkage(engine)
    assert report.is_clean is False
    assert report.break_kind == "parent_row_not_found"


@pytest.mark.asyncio
async def test_tenant_id_mismatch(engine, decision_store):
    emitter = SubAgentAuditEmitter(decision_store)
    spawn_id = await emitter.emit_spawn(
        actor_id="o", tenant_id="bank-a", request_id="r",
        parent_trace_id="pt", child_request={}, policy_snapshot={},
    )
    await emitter.emit_child_genesis(
        actor_id="w", tenant_id="bank-b", request_id="r",  # cross-tenant child
        parent_record_id=spawn_id, child_trace_id="ct",
    )
    report = await verify_subagent_linkage(engine)
    assert report.is_clean is False
    assert report.break_kind == "tenant_id_mismatch"


@pytest.mark.asyncio
async def test_child_missing_parent_record_id(engine, insert_raw_decision_row):
    # Fabricated subagent.start row with no parent_record_id (the in-order
    # append API always sets it; reachable only via tampering).
    await insert_raw_decision_row(
        record_id=uuid.uuid4(), sequence=1, event_type="subagent.start",
        payload={"child_trace_id": "ct"}, tenant_id="bank-a",
    )
    report = await verify_subagent_linkage(engine)
    assert report.is_clean is False
    assert report.break_kind == "child_missing_parent_record_id"


@pytest.mark.asyncio
async def test_parent_row_not_before_child_row(engine, insert_raw_decision_row):
    # Forward link: child (seq 1) points at a spawn row at a LATER seq 2.
    parent_id = uuid.uuid4()
    await insert_raw_decision_row(
        record_id=uuid.uuid4(), sequence=1, event_type="subagent.start",
        payload={"parent_record_id": str(parent_id), "child_trace_id": "ct"},
        tenant_id="bank-a",
    )
    await insert_raw_decision_row(
        record_id=parent_id, sequence=2, event_type="subagent.spawn",
        payload={"parent_trace_id": "pt"}, tenant_id="bank-a",
    )
    report = await verify_subagent_linkage(engine)
    assert report.is_clean is False
    assert report.break_kind == "parent_row_not_before_child_row"
```

- [ ] **Step 2: Run — verify it fails.** `uv run pytest tests/unit/subagent/test_subagent_audit_chain.py -q` → FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement the verifier** (full mirror of the `verify_suspend_wake_linkage` first-break shape; `_decision_history` columns used: `record_id`, `event_type` = decision_type, `payload`, `tenant_id` (ROW column), `sequence`):

```python
# src/cognic_agentos/subagent/audit_verifier.py
"""Sprint 11 — cross-agent sub-agent linkage verifier per ADR-005 §Audit.
Mirrors core/chain_verifier.verify_suspend_wake_linkage: per-row payload
linkage (lookup-by-record_id + decision_type assert + tenant-column parity
+ causal sequence ordering), independent of the hash-walk (hash integrity is
the separate, existing guarantee). NOT a literal Merkle tree. New module — no
edit to core/chain_verifier.py. Critical-controls (subagent/ stop-rule)."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.decision_history import _decision_history

# Only the child-linked sub-agent rows carry payload['parent_record_id'].
# Filtering on event_type (NOT payload-key presence) mirrors
# verify_suspend_wake_linkage and ignores foreign rows that reuse the key.
_LINKED_EVENT_TYPES = frozenset(
    {"subagent.start", "subagent.return", "subagent.budget"}
)

SubAgentLinkageBreakKind = Literal[
    "child_missing_parent_record_id",
    "parent_row_not_found",
    "parent_record_id_wrong_decision_type",
    "tenant_id_mismatch",
    "parent_row_not_before_child_row",
]


@dataclass(frozen=True)
class SubAgentLinkageReport:
    is_clean: bool
    records_checked: int
    first_break_record_id: uuid.UUID | None = None
    break_kind: SubAgentLinkageBreakKind | None = None
    detail: str | None = None


def _coerce_record_id(value: Any) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


async def verify_subagent_linkage(engine: AsyncEngine) -> SubAgentLinkageReport:
    """Verify parent↔child sub-agent linkage over the decision_history chain.
    For every subagent.start/return/budget row, assert: (1) the parent row
    exists, (2) it is a subagent.spawn row, (3) tenant_id parity (ROW column),
    (4) parent.sequence < child.sequence. First-break semantics."""
    async with engine.begin() as conn:
        rows = (
            await conn.execute(
                select(_decision_history).order_by(_decision_history.c.sequence.asc())
            )
        ).all()

    rows_by_record_id: dict[uuid.UUID, Any] = {
        _coerce_record_id(r.record_id): r for r in rows
    }
    checked = 0
    for row in rows:
        if row.event_type not in _LINKED_EVENT_TYPES:
            continue  # foreign rows (incl. the spawn root) carry no parent link
        checked += 1
        child_id = _coerce_record_id(row.record_id)
        payload: dict[str, Any] = row.payload or {}
        raw_parent = payload.get("parent_record_id")
        if not isinstance(raw_parent, str) or raw_parent == "":
            return SubAgentLinkageReport(
                is_clean=False, records_checked=checked, first_break_record_id=child_id,
                break_kind="child_missing_parent_record_id",
                detail=f"row {child_id} has non-string payload['parent_record_id']={raw_parent!r}",
            )
        try:
            parent_id = uuid.UUID(raw_parent)
        except ValueError:
            return SubAgentLinkageReport(
                is_clean=False, records_checked=checked, first_break_record_id=child_id,
                break_kind="child_missing_parent_record_id",
                detail=f"row {child_id} has non-UUID parent_record_id={raw_parent!r}",
            )

        parent_row = rows_by_record_id.get(parent_id)
        if parent_row is None:
            return SubAgentLinkageReport(
                is_clean=False, records_checked=checked, first_break_record_id=child_id,
                break_kind="parent_row_not_found",
                detail=f"row {child_id} points at parent_record_id={parent_id} with no matching row",
            )
        if parent_row.event_type != "subagent.spawn":
            return SubAgentLinkageReport(
                is_clean=False, records_checked=checked, first_break_record_id=child_id,
                break_kind="parent_record_id_wrong_decision_type",
                detail=f"parent row {parent_id} is {parent_row.event_type!r}, not 'subagent.spawn'",
            )
        if row.tenant_id != parent_row.tenant_id:
            return SubAgentLinkageReport(
                is_clean=False, records_checked=checked, first_break_record_id=child_id,
                break_kind="tenant_id_mismatch",
                detail=f"child tenant_id={row.tenant_id!r} != parent tenant_id={parent_row.tenant_id!r}",
            )
        if int(parent_row.sequence) >= int(row.sequence):
            return SubAgentLinkageReport(
                is_clean=False, records_checked=checked, first_break_record_id=child_id,
                break_kind="parent_row_not_before_child_row",
                detail=f"parent seq {parent_row.sequence} not before child seq {row.sequence}",
            )

    return SubAgentLinkageReport(is_clean=True, records_checked=checked)
```

- [ ] **Step 4: Run — verify pass.** Same command as Step 2 → PASS (clean + all 6 negatives).

- [ ] **Step 5: HALT.** Gate ladder. Watchpoints: clean chain verifies; foreign-row-with-`parent_record_id` ignored (Finding 2); all 5 break_kinds fire on their tamper; first-break semantics; tenant parity uses the ROW column; no `core/chain_verifier.py` edit. On `commit`: full suite, then `git add src/cognic_agentos/subagent/audit_verifier.py tests/unit/subagent/test_subagent_audit_chain.py` + `feat(sprint-11): T4 cross-agent sub-agent linkage verifier`.

---

## Task Z1a: 11a critical-controls coverage-gate promotion + valve check

**Files:**
- Modify: `tools/check_critical_coverage.py` (`_CRITICAL_FILES` += 4; docstring section)
- Modify: `tests/unit/tools/test_check_critical_coverage.py` (`_EXPECTED_ENTRY_COUNT` 90 → 94)

Per `[[feedback_verify_promotion_meets_floor_at_promotion_time]]`: run the gate against **fresh `--cov-branch coverage.json` in this commit** — the count-guard pins gate metadata, the gate itself pins the actual threshold; both axes run here.

- [ ] **Step 1: Generate fresh coverage.** `uv run pytest --cov=cognic_agentos --cov-branch --cov-report=json -q` (full suite — produces `coverage.json`).

- [ ] **Step 2: Add the 4 modules to `_CRITICAL_FILES`** (with a Sprint-11 docstring section mirroring the Sprint-10.5 block), each at the `(path, 0.95, 0.90)` floor:

```python
    # --- Sprint 11 — sub-agent primitive (ADR-005) 11a -----------------
    ("src/cognic_agentos/subagent/_types.py", 0.95, 0.90),
    ("src/cognic_agentos/subagent/policy.py", 0.95, 0.90),
    ("src/cognic_agentos/subagent/audit.py", 0.95, 0.90),
    ("src/cognic_agentos/subagent/audit_verifier.py", 0.95, 0.90),
```

- [ ] **Step 3: Bump the count guard** in `tests/unit/tools/test_check_critical_coverage.py`: `_EXPECTED_ENTRY_COUNT = 94` (+ a Sprint-11 comment in the running tally). Add an on-gate-at-95/90 assertion test for the 4 modules mirroring the existing per-sprint promotion tests.

- [ ] **Step 4: Run the gate against fresh data.** `uv run python tools/check_critical_coverage.py` → every subagent module ≥ 95% line / ≥ 90% branch. If any is short, land the focused negative-path regressions in THIS commit (same-commit repair, per the tightening-edit-B doctrine) until green.

- [ ] **Step 5: Count-guard test.** `uv run pytest tests/unit/tools/test_check_critical_coverage.py -q` → PASS (94).

- [ ] **Step 6: HALT + VALVE CHECK.** Gate ladder + full suite. Summary: gate 90 → 94, all 4 modules verified at-floor on fresh coverage. **VALVE:** if cumulative 11a wall-clock is within budget and the C3 conformer choice + harness-exposure shape are ready to lock, proceed to 11b; otherwise stop 11a here (it is independently shippable — pure primitive + audit chain) and split 11b to a follow-up sprint, mirroring the Sprint-10.5 10.5c→10.6 split. On `commit`: `git add tools/check_critical_coverage.py tests/unit/tools/test_check_critical_coverage.py` (+ any same-commit coverage-repair test files) + `test(sprint-11): Z1a promote 4 sub-agent 11a modules to the CC gate (90→94)`.

---

## 11b — Integration (structured outline; full TDD deferred to the 11a→11b valve)

> **VALVE CHECK (per Sprint-10.5 precedent).** 11b's TDD is intentionally NOT written here: two design choices the spec defers to this gate (§16) change the task code, so writing it now would force placeholders. Resolve both at the valve, then expand this section to full TDD (or split 11b to a follow-up sprint):
> 1. **C3 conformer choice** — does 11b stay test/DI-runnable only, or ship a minimal **real** `PackStateInterrogator` over `packs/storage`? Either way: **no permissive production quota/kill-switch fakes**; real `QuotaInterrogator` + `KillSwitchInterrogator` remain Sprint 13.5.
> 2. **Harness-exposure shape** — `spawn_subagent` as a standalone function vs a thin agent-context object; lives in `subagent/` public API vs a first `harness/` module.

- **T5 — `subagent/budget_resolver.py`** — real `ParentBudgetResolver` conformer (`async remaining_budget_for(parent_task_id) -> int`) over a Sprint-11-local budget snapshot; DI-injected into `SchedulerEngine`; never imported by `core/scheduler/*`. Tests: structural conformance to the `_seams.ParentBudgetResolver` Protocol + the `compute_spawn_budget` narrowing from T2. CC, halt.
- **T6 — `subagent/spawn.py`** — in-process scheduler-mediated dispatch: policy gate (T2) → `emit_spawn` (T3) → build `SubmitInput(parent_task_id=…, requested_estimated_tokens=…)` → `SchedulerEngine.submit(..., request_id=…)` with injected conformers → run child worker (isolated context) → `emit_child_genesis`/`emit_return`/`emit_budget` → discard child context. Depth-exceed → `EscalationStore.open(level="depth_exceeded", …)`. Budget-exceed mid-flight → `SchedulerEngine.preempt`. Tests: `test_subagent_spawn.py`, `test_subagent_scheduler_inheritance.py` (no scheduler bypass), `test_subagent_budget.py` (preempt + parent informed), the escalation-triggered half of `test_subagent_depth.py`. CC, halt. **Resolves C3.**
- **T7 — `subagent/__init__.py` `SubAgent` facade + `invoke(prompt)`** — the privilege-de-escalation enforcement boundary that composes T2 policy + T3 audit + T6 spawn. CC, halt.
- **T8 — minimal harness exposure** — `spawn_subagent(...)` seam (shape per the valve decision); not a broad `harness/base_agent.py`. CC, halt.
- **T9 — `protocol/ui_events.py` emit-hook wiring** — register a `DecisionAppendHook` (`decision_history.py:313`) mapping `subagent.*` rows to the existing `subagent.spawned/completed/failed/recursion_capped` models; audit↔UI map per spec §6; `.well-known` snapshot unchanged; never rename the 4 models. ADR-020 stop-rule, halt.
- **T10 — closeout reconciliation only** — closeout note; verify ADR-005/BUILD_PLAN already amended at T0 (no first-time amendments); confirm Sprint-11 schedule-risk row.
- **Z1b — CC-gate promotion of 11b modules** + full gate ladder, fresh-coverage at promotion time.

---

## Self-review

**Spec coverage:** T0 ↔ spec §0; T1 ↔ §3/§6/§13 (vocab, ISO); T2 ↔ §7/§8/§9 (privilege, budget, depth, Settings); T3 ↔ §5/§6 (4 events, payload linkage, ISO); T4 ↔ §11 (verifier mirror); Z1a ↔ §14 (gate). 11b T5–T10 ↔ §15/§16. The 6 ADR-005 tests map: `test_subagent_privilege` (T2), `test_subagent_depth` (T2 pure + T6 escalation), `test_subagent_audit_chain` (T4), and `test_subagent_spawn`/`test_subagent_scheduler_inheritance`/`test_subagent_budget` (T6). The `subagent_parent_budget_exhausted` enum/exception (T1) is now exercised by `compute_spawn_budget` in T2 (not left dangling for 11b). No spec requirement is left without a task.

**Placeholder scan:** No "TBD/TODO/handle edge cases". Both fixture and verifier seams are now fully concrete — the T3 conftest provides `engine`/`decision_store`/`decision_store_rows`/`insert_raw_decision_row` with exact code (mirroring the verified `test_decision_history.py:37-70` setup + the `_decision_history` columns at `decision_history.py:185-203`), and the T4 verifier imports `_decision_history` directly + reimplements the 3-line `_coerce_record_id` inline (no "confirm at task start" left). T4's negatives are 6 concrete test functions, not a "parametrized negatives" hand-wave. 11b is a deliberate valve-gated outline (precedent: Sprint-10.5 plan truncated at its valve), not under-specified tasks.

**Type consistency:** `SubAgentRefusalReason`/`SubAgentAuditEvent`/`SUBAGENT_ISO_CONTROLS`/`SubAgentSpawnRequest`/`SubAgentDepthExceeded`/`SubAgentPrivilegeEscalation`/`SubAgentBudgetExhausted` (T1) are used consistently in T2/T3/T4. `narrow_tool_allow_list(*, parent, requested)` + `check_depth(*, current_depth, max_depth)` + `compute_spawn_budget(*, parent_remaining_budget, child_pack_quota)` (T2) match their test call sites; `compute_spawn_budget` delegates to the verified `compute_child_budget` (`_seams.py:195`). `SubAgentAuditEmitter` method names (`emit_spawn`/`emit_child_genesis`/`emit_return`/`emit_budget`) and `verify_subagent_linkage`/`SubAgentLinkageReport`/`SubAgentLinkageBreakKind`/`_LINKED_EVENT_TYPES` (T4) are stable across tasks and tests. `DecisionRecord(...)` + `store.append(...) -> (record_id, hash)` match `escalation.py:493-508`. The conftest's `insert_raw_decision_row` supplies exactly the `_decision_history` NOT-NULL columns (`record_id`/`sequence`/`schema_version`/`prev_hash`/`hash`/`created_at`/`event_type`/`request_id`/`payload`). The verifier reads `record_id`/`event_type`/`payload`/`tenant_id`/`sequence` — all real columns.

---

*End of plan. 11a is fully specified and immediately executable (after T0). 11b is valve-gated. No code written — awaiting review before commit.*
