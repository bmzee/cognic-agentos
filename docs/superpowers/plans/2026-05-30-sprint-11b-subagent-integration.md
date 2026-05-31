# Sprint 11b — Sub-agent integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax. **Every `subagent/*` change is a stop-rule isolation boundary → halt-before-commit per `[[feedback_strict_review_off_gate]]`, `core-controls-engineer` + `/critical-module-mode`.** Each commit gated on a green full suite (the 11a rhythm).

**Goal:** Ship the 11b integration layer on top of the merged 11a primitive — scheduler-mediated spawn, the `SubAgent` facade, the thin `spawn_subagent(...)` seam, and UI emit — as a **test/DI-proven** increment (no live production dispatch path).

**Architecture:** Builds on the merged 11a core (`subagent/_types`, `policy`, `audit`, `audit_verifier`). The spawn flow is: policy gate → `emit_spawn` → `SchedulerEngine.submit(SubmitInput(parent_task_id=…))` → run child via an **injected `ChildRunner`** (receiving a frozen `ChildRunContext`) → `emit_child_genesis`/`return`/`budget`. Per the decision memo (committed `a093810`): conformers are test/DI-only (Quota/KillSwitch stay Null → 13.5; real minimal `PackStateInterrogator`); the harness surface is a thin `spawn_subagent(...)` seam (no `harness/`); the budget vocab is **split** (`subagent_child_quota_zero` added). The scheduler is **not** app-wired — 11b exercises it only under an injected engine + conformers.

**Tech Stack:** Python 3.12, `uv`, pytest + pytest-asyncio, SQLAlchemy async (SQLite unit / Postgres+Oracle behind env flags), ruff, mypy, `tools/check_critical_coverage.py`.

**Source:** decision memo `docs/superpowers/specs/2026-05-30-sprint-11b-subagent-integration-decision-memo.md` (committed `a093810`); 11a plan `docs/superpowers/plans/2026-05-30-sprint-11-subagent-primitive.md`.

---

## Child-execution seam — `ChildRunner(context: ChildRunContext)` *(CONFIRMED 2026-05-30)*

D1 locks "no agent runtime in 11b," so `spawn.py` cannot *run* an LLM/agent itself — child execution is delegated to an **injected `ChildRunner` Protocol** taking a **frozen `ChildRunContext`** (not loose kwargs, so threading trace IDs / memory scope / harness metadata never churns the signature). Production wiring (a future harness / agent pack) supplies the real runner; 11b tests inject a fake. Keeps `subagent/` substrate-independent (no `cognic_agentos.agents.*` import).

**Ownership boundary (crisp):**
- `spawn.py` owns policy narrowing, scheduler submit, audit emit, and budget accounting.
- `ChildRunner` ONLY executes the child with the already-granted `ChildRunContext`.
- **No production agent runtime in 11b**; tests inject a fake runner.
- `ChildRunContext` carries a **memory-ready inert** `memory_scope` (+ room for an optional frozen snapshot) — forward-compat for Sprint 11.5, but **no durable memory writes in 11b**.

---

## Conventions
- Gate ladder per `[[feedback_gate_ladder_per_microfix]]`: HALT = ruff/format/mypy full-tree + narrow pytest; full suite at the `commit` token (every 11b task touches `subagent/` and/or exercises the scheduler/decision-history chain → full suite at commit).
- Commit by explicit path + footer `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`; never stage the gap-analysis doc.
- Substrate independence: `core/scheduler/*` never imports `subagent/*`; `subagent/*` never imports `cognic_agentos.agents.*`; conformers injected via DI.
- Reuse the merged 11a `tests/unit/subagent/conftest.py` fixtures (`engine`, `decision_store`, `decision_store_rows`, `insert_raw_decision_row`).

## File structure (11b)
| File | Responsibility |
|---|---|
| `subagent/_types.py` (modify) | + `subagent_child_quota_zero` in `SubAgentRefusalReason`; + `SubAgentChildQuotaZero`; + `ChildResult` / `ChildRunContext` / `SubAgentResult` frozen dataclasses; + `ChildRunner` Protocol (takes `ChildRunContext`). |
| `subagent/policy.py` (modify) | `compute_spawn_budget` split: parent==0 → `SubAgentBudgetExhausted`; child==0 → `SubAgentChildQuotaZero`. |
| `subagent/conformers.py` (create) | real `ParentBudgetResolver` (local snapshot) + real `PackStateInterrogator` (`packs/storage` closure). |
| `subagent/spawn.py` (create) | scheduler-mediated in-process dispatch orchestrator. |
| `subagent/__init__.py` (modify) | export `SubAgent` facade + `spawn_subagent`. |
| `subagent/_facade.py` (create) | `SubAgent` class + `invoke(prompt)`. |
| `protocol/ui_events.py` (modify) | wire `subagent.*` audit → UI-event emit hook (ADR-020 stop-rule). |
| `tools/check_critical_coverage.py` (modify) | Z1b: promote new substantive modules; bump count. |

---

## Task T4.5: Budget-vocab split (do first — before the spawn seam exposes it)

**Files:** Modify `src/cognic_agentos/subagent/_types.py`, `src/cognic_agentos/subagent/policy.py`; Test `tests/unit/subagent/test_subagent_budget_helper.py` (extend), `tests/unit/subagent/test_subagent_types_closed_enums.py` (extend).

D3 locked: a zero **child** quota must not surface as "parent exhausted."

- [ ] **Step 1: Extend the drift detector** (red) — in `test_subagent_types_closed_enums.py`, bump `SubAgentRefusalReason` to 4 values incl. `subagent_child_quota_zero`:
```python
def test_value_set(self):
    assert set(get_args(SubAgentRefusalReason)) == {
        "subagent_depth_exceeded",
        "subagent_privilege_escalation",
        "subagent_parent_budget_exhausted",
        "subagent_child_quota_zero",
    }
```
(and update `test_exactly_three_values` → `test_exactly_four_values`, asserting `len == 4`.)

- [ ] **Step 2: Extend the budget test** (red) — in `test_subagent_budget_helper.py`:
```python
def test_child_quota_zero_raises_distinct_refusal():
    from cognic_agentos.subagent._types import SubAgentChildQuotaZero
    with pytest.raises(SubAgentChildQuotaZero) as exc:
        compute_spawn_budget(parent_remaining_budget=500, child_pack_quota=0)
    assert exc.value.reason == "subagent_child_quota_zero"

def test_parent_zero_still_raises_parent_exhausted():
    with pytest.raises(SubAgentBudgetExhausted) as exc:
        compute_spawn_budget(parent_remaining_budget=0, child_pack_quota=300)
    assert exc.value.reason == "subagent_parent_budget_exhausted"
```

- [ ] **Step 3: Run → fail.** `uv run pytest tests/unit/subagent/test_subagent_types_closed_enums.py tests/unit/subagent/test_subagent_budget_helper.py -q` → FAIL.

- [ ] **Step 4: Implement.** In `_types.py`: add `"subagent_child_quota_zero"` to the `SubAgentRefusalReason` Literal; add:
```python
class SubAgentChildQuotaZero(Exception):
    """Spawn refused: the child pack quota is zero (parent has budget)."""
    def __init__(self, *, child_pack_quota: int) -> None:
        super().__init__("subagent_child_quota_zero")
        self.reason: SubAgentRefusalReason = "subagent_child_quota_zero"
        self.child_pack_quota = child_pack_quota
```
In `policy.py` `compute_spawn_budget`, replace the single `granted == 0` raise with the split (raise child-quota-zero **before** delegating when `child_pack_quota == 0`; parent-exhausted when the narrowed result is 0 from a zero parent):
```python
def compute_spawn_budget(*, parent_remaining_budget: int, child_pack_quota: int) -> int:
    if child_pack_quota == 0:
        raise SubAgentChildQuotaZero(child_pack_quota=child_pack_quota)
    granted = compute_child_budget(
        parent_remaining_budget=parent_remaining_budget,
        child_pack_quota=child_pack_quota,
    )
    if granted == 0:
        raise SubAgentBudgetExhausted(parent_remaining_budget=parent_remaining_budget)
    return granted
```
Update `__init__.py` `__all__` to export `SubAgentChildQuotaZero`.

- [ ] **Step 5: Run → pass.** Same command → PASS.

- [ ] **Step 6: HALT.** Gate ladder. Watchpoint: child==0 → `subagent_child_quota_zero`; parent==0 → `subagent_parent_budget_exhausted`; closed-enum is 4 values. Commit (full suite first): `git add` the 4 paths + `feat(sprint-11b): T4.5 split budget refusal vocab (child_quota_zero)`.

---

## Task T5: Real conformers + the `ChildRunner` Protocol

**Files:** Create `src/cognic_agentos/subagent/conformers.py`; Modify `src/cognic_agentos/subagent/_types.py` (add `ChildRunner` / `ChildResult` / `SubAgentResult`); Test `tests/unit/subagent/test_subagent_conformers.py`.

- [ ] **Step 1: Add the runner + result types** to `_types.py`:
```python
from typing import Protocol, runtime_checkable

@dataclass(frozen=True)
class ChildResult:
    summary: str
    tokens_used: int
    wall_time_used_s: float
    ok: bool = True

@dataclass(frozen=True)
class ChildRunContext:
    """The already-narrowed execution context spawn.py hands to the runner.
    Frozen + stable so threading new fields (trace IDs, memory scope,
    harness metadata) never churns the ChildRunner signature."""
    prompt: str
    granted_tools: frozenset[str]
    budget: int
    tenant_id: str
    current_depth: int
    child_trace_id: str
    request_id: str
    parent_record_id: uuid.UUID
    memory_scope: str | None = None  # 11.5-ready inert hook; NO durable writes in 11b

@runtime_checkable
class ChildRunner(Protocol):
    """Injected child-execution seam (D1: no agent runtime in 11b). spawn.py
    owns policy narrowing + scheduler submit + audit emit + budget accounting;
    the runner ONLY executes the child with the already-granted context.
    Production supplies a real runner; tests inject a fake."""
    async def run(self, context: ChildRunContext) -> ChildResult: ...

@dataclass(frozen=True)
class SubAgentResult:
    spawn_record_id: uuid.UUID
    child_result: ChildResult
    preempted: bool = False
```
(add `import uuid` if absent.)

- [ ] **Step 2: Write the failing conformer test** (uses the 11a `decision_store`/`engine` conftest + a `PackRecordStore` over the same engine — confirm `PackRecordStore` construction at task start from `tests/unit/packs/test_storage.py`):
```python
# tests/unit/subagent/test_subagent_conformers.py
import uuid
import pytest
from cognic_agentos.core.scheduler._seams import ParentBudgetResolver, PackStateInterrogator
from cognic_agentos.subagent.conformers import LocalParentBudgetResolver, PackStoreStateInterrogator


def test_resolver_conforms_to_protocol():
    r = LocalParentBudgetResolver({})
    assert isinstance(r, ParentBudgetResolver)


@pytest.mark.asyncio
async def test_local_parent_budget_resolver_returns_snapshot():
    pid = uuid.uuid4()
    r = LocalParentBudgetResolver({pid: 1200})
    assert await r.remaining_budget_for(pid) == 1200


def test_pack_state_interrogator_conforms():
    assert isinstance(PackStoreStateInterrogator(store=None), PackStateInterrogator)  # type: ignore[arg-type]
```
(+ an integration test that builds a `PackRecordStore` over the conftest `engine`, drives a pack to `installed`, and asserts `is_installed` True for that tenant/pack and False for a different tenant — mirror the pack-storage test setup.)

- [ ] **Step 3: Run → fail.** `uv run pytest tests/unit/subagent/test_subagent_conformers.py -q` → FAIL.

- [ ] **Step 4: Implement `conformers.py`:**
```python
"""Sprint 11b — real DI conformers for the sub-agent spawn path.
ParentBudgetResolver over a local budget snapshot; PackStateInterrogator
over packs/storage. Critical-controls (subagent/ stop-rule)."""
from __future__ import annotations
import uuid
from cognic_agentos.packs.storage import PackRecordStore


class LocalParentBudgetResolver:
    """Real ParentBudgetResolver over a Sprint-11-local snapshot dict."""
    def __init__(self, snapshot: dict[uuid.UUID, int]) -> None:
        self._snapshot = dict(snapshot)
    async def remaining_budget_for(self, parent_task_id: uuid.UUID) -> int:
        return self._snapshot.get(parent_task_id, 0)


class PackStoreStateInterrogator:
    """Real minimal PackStateInterrogator: load → state == 'installed' +
    tenant parity. Thin packs/storage closure (D1)."""
    def __init__(self, *, store: PackRecordStore) -> None:
        self._store = store
    async def is_installed(self, *, tenant_id: str, pack_id: str) -> bool:
        record = await self._store.load(uuid.UUID(pack_id))
        return (
            record is not None
            and record.tenant_id == tenant_id
            and record.state == "installed"
        )
```
(Confirm `PackRecord.tenant_id` exists at task start — `packs/storage.py:359-376`; if the field name differs, adjust the parity check.)

- [ ] **Step 5: Run → pass.** PASS.

- [ ] **Step 6: HALT.** Gate ladder. Watchpoints: both conformers structurally conform to their `_seams` Protocols; `is_installed` checks state **and** tenant parity; `LocalParentBudgetResolver` reads the snapshot. Commit (full suite first): `feat(sprint-11b): T5 real ParentBudgetResolver + PackStateInterrogator conformers + ChildRunner protocol`.

---

## Task T6: Scheduler-mediated spawn orchestrator (`subagent/spawn.py`)

**Files:** Create `src/cognic_agentos/subagent/spawn.py`; Test `tests/unit/subagent/test_subagent_spawn.py`, `tests/unit/subagent/test_subagent_scheduler_inheritance.py`, `tests/unit/subagent/test_subagent_budget.py`, and the escalation half of `test_subagent_depth.py`.

The orchestrator binds 11a policy + audit + the injected scheduler + child runner. The test builds a **real** `SchedulerEngine` (mirror `tests/unit/core/scheduler/test_engine.py`'s construction: `SchedulerStorage` over the conftest `engine`, `ConcurrencyCaps`, `class_settings`) with the T5 conformers + test quota/kill-switch conformers + a permissive `policy_evaluator`, and a fake `ChildRunner`.

- [ ] **Step 1: Write the failing happy-path test** (`test_subagent_spawn.py`) — parent spawns child, child returns, parent context unchanged, audit chain has spawn+start+return+budget:
```python
@pytest.mark.asyncio
async def test_spawn_returns_child_result_and_emits_chain(spawn_harness):
    # spawn_harness fixture builds: real SchedulerEngine (injected conformers),
    # SubAgentAuditEmitter over decision_store, fake ChildRunner returning
    # ChildResult(summary="ok", tokens_used=120, wall_time_used_s=0.3).
    result = await spawn_harness.spawn(
        prompt="verify AML",
        parent_tool_allow_list=frozenset({"aml_check", "read"}),
        requested_tool_allow_list=frozenset({"aml_check"}),
        current_depth=0,
        requested_estimated_tokens=300,
        tenant_id="bank-a",
        parent_task_id=None,
    )
    assert result.child_result.summary == "ok"
    rows = await spawn_harness.rows()
    kinds = [r.event_type for r in rows if r.event_type.startswith("subagent.")]
    assert kinds == ["subagent.spawn", "subagent.start", "subagent.return", "subagent.budget"]
    from cognic_agentos.subagent.audit_verifier import verify_subagent_linkage
    assert (await verify_subagent_linkage(spawn_harness.engine)).is_clean is True
```

- [ ] **Step 2: Privilege + scheduler-inheritance + budget tests** (red):
  - `test_subagent_privilege` (escalation half): requesting a tool ∉ parent → `SubAgentPrivilegeEscalation`, **no** spawn row emitted, scheduler never called.
  - `test_subagent_scheduler_inheritance`: a child submit with `parent_task_id` set narrows via the injected `LocalParentBudgetResolver` (assert the scheduler saw the narrowed `effective_tokens`); a recursive spawn cannot bypass `submit()` (assert every child path calls `scheduler.submit`).
  - `test_subagent_budget`: fake `ChildRunner` reports `tokens_used > budget` (or `ok=False`) → orchestrator calls `scheduler.preempt(child_task_id, …)`, returns `SubAgentResult(preempted=True)`, and emits the `subagent.budget` row with the overage.
  - `test_subagent_depth` (escalation half): `current_depth=3, max_depth=3` → `SubAgentDepthExceeded` **and** `EscalationStore.open(level="depth_exceeded", …)` invoked (assert an `escalation.opened` row).

- [ ] **Step 3: Run → fail.**

- [ ] **Step 4: Implement `spawn.py`** — the orchestrator (pseudocode-accurate; fill the real calls):
```python
"""Sprint 11b — in-process scheduler-mediated sub-agent spawn (ADR-005
Wave-1). NOT a deployable production path (D1): runs only under an
injected SchedulerEngine + conformers. Critical-controls (subagent/)."""
from __future__ import annotations
import uuid
from cognic_agentos.core.scheduler.engine import SchedulerEngine
from cognic_agentos.core.scheduler._types import SubmitInput, TaskActor
from cognic_agentos.core.escalation import EscalationStore
from cognic_agentos.subagent._types import (
    ChildRunContext, ChildRunner, SubAgentResult, SubAgentDepthExceeded,
)
from cognic_agentos.subagent.audit import SubAgentAuditEmitter
from cognic_agentos.subagent.policy import (
    narrow_tool_allow_list, check_depth, compute_spawn_budget,
)


class SubAgentSpawner:
    def __init__(
        self, *, scheduler: SchedulerEngine, audit: SubAgentAuditEmitter,
        child_runner: ChildRunner, escalation: EscalationStore,
        max_recursion_depth: int,
    ) -> None:
        self._scheduler = scheduler
        self._audit = audit
        self._runner = child_runner
        self._escalation = escalation
        self._max_depth = max_recursion_depth

    async def spawn(self, *, prompt, parent_tool_allow_list, requested_tool_allow_list,
                    current_depth, requested_estimated_tokens, tenant_id,
                    parent_task_id, actor) -> SubAgentResult:
        # 1. policy gate (pure) — privilege subset; depth cap (escalate on exceed)
        granted = narrow_tool_allow_list(parent=parent_tool_allow_list,
                                         requested=requested_tool_allow_list)
        try:
            check_depth(current_depth=current_depth, max_depth=self._max_depth)
        except SubAgentDepthExceeded:
            await self._escalation.open(actor_id=actor.subject, level="depth_exceeded",
                                        reason=f"depth {current_depth+1} > {self._max_depth}",
                                        request_id=..., tenant_id=tenant_id)
            raise
        # 2. emit_spawn → R_spawn
        spawn_id = await self._audit.emit_spawn(...)
        # 3. scheduler.submit(SubmitInput(parent_task_id=..., requested_estimated_tokens=...))
        decision = await self._scheduler.submit(submit_input=SubmitInput(...), request_id=...)
        # (refused → emit return(failed) + raise/return; accepted → task_id)
        # 4. emit_child_genesis(parent_record_id=spawn_id)
        # 5. run child via injected runner (already-narrowed context); on overage → scheduler.preempt
        child = await self._runner.run(ChildRunContext(
            prompt=prompt, granted_tools=granted, budget=budget, tenant_id=tenant_id,
            current_depth=current_depth + 1, child_trace_id=..., request_id=...,
            parent_record_id=spawn_id, memory_scope=None,
        ))
        preempted = False
        if (not child.ok) or child.tokens_used > budget:
            await self._scheduler.preempt(task_id, request_id=...)
            preempted = True
        # 6. emit_return + emit_budget; mark scheduler task complete on success
        # 7. return SubAgentResult(spawn_record_id=spawn_id, child_result=child, preempted=preempted)
```
(Note: `compute_spawn_budget` is used to derive `budget` before submit; child-quota-zero/parent-exhausted refusals from T4.5 surface here BEFORE emit_spawn.)

- [ ] **Step 5: Run → pass** (all four test files).

- [ ] **Step 6: HALT.** Gate ladder. Watchpoints: privilege escalation blocks before scheduler; depth-exceed escalates; budget-overage preempts + informs parent; **no path bypasses `scheduler.submit`**; audit chain verifies. Commit (full suite first): `feat(sprint-11b): T6 scheduler-mediated in-process spawn orchestrator`.

---

## Task T7: `SubAgent` facade (`subagent/_facade.py` + `__init__`)

**Files:** Create `subagent/_facade.py`; Modify `subagent/__init__.py`; Test `tests/unit/subagent/test_subagent_facade.py`.

Thin facade composing T6: `SubAgent(scheduler=…, audit=…, child_runner=…, escalation=…, settings=…)` with `async invoke(prompt, *, requested_tool_allow_list, current_depth, …) -> SubAgentResult`. Reads `settings.subagent_max_recursion_depth` (11a Settings field). The facade is the privilege-de-escalation enforcement boundary (delegates to `SubAgentSpawner`). TDD: `invoke` returns the child result; depth/privilege refusals propagate. **HALT**, commit: `feat(sprint-11b): T7 SubAgent facade`.

## Task T8: Thin `spawn_subagent(...)` seam (D2)

**Files:** Modify `subagent/__init__.py` (+ `subagent/_facade.py` or a small `subagent/_seam.py`); Test `tests/unit/subagent/test_spawn_subagent_seam.py`.

D2: a module-level `async def spawn_subagent(*, request: SubAgentSpawnRequest, scheduler, audit, child_runner, escalation, settings) -> SubAgentResult` convenience wrapper over `SubAgent(...).invoke(...)`. **No `harness/` package.** Export `spawn_subagent` + `SubAgent` from `subagent/__init__.py`. TDD: the seam spawns + returns; structurally takes the explicit `SubAgentSpawnRequest`. **HALT**, commit: `feat(sprint-11b): T8 thin spawn_subagent seam`.

## Task T9: UI emit hooks (`protocol/ui_events.py` — ADR-020 stop-rule)

**Files:** Modify `protocol/ui_events.py`; Test `tests/unit/protocol/test_ui_events_subagent_emit.py`.

Wire a `DecisionAppendHook` (`decision_history.py:313`) that maps `subagent.*` audit rows to the **existing** `subagent.spawned/completed/failed/recursion_capped` UI models (never rename them). Mapping per the 11a spec §6: `subagent.spawn`→`spawned`; `subagent.return` ok→`completed`, not-ok→`failed`; depth-cap refusal→`recursion_capped`. `.well-known` snapshot must stay byte-stable. **ADR-020 stop-rule — halt-before-commit.** TDD: emitting a `subagent.spawn` row fires a `subagent.spawned` UI event; snapshot unchanged. **HALT**, commit: `feat(sprint-11b): T9 wire subagent UI emit hooks`.

## Task T10: Closeout + doc reconciliation

**Files:** Create `docs/closeouts/2026-05-30-sprint-11b-subagent-integration.md`; Modify `docs/BUILD_PLAN.md` (Sprint-11 marker → 11a+11b both shipped; decide whether Sprint 11 now reads CLOSED).

Records the D1/D2/D3 locks + the **production-path-deferred-to-13.5** honesty (no live dispatch; scheduler not app-wired; Quota/KillSwitch 13.5). Verify ADR-005 already amended at 11a T0 (no new amendment). **HALT**, commit: `docs(sprint-11b): T10 closeout + BUILD_PLAN Sprint-11 marker`.

## Task Z1b: CC-gate promotion

**Files:** Modify `tools/check_critical_coverage.py` (+ substantive 11b modules), `tests/unit/tools/test_check_critical_coverage.py` (bump count + Sprint-11b test).

Promote the substantive new modules at the 95/90 floor — `subagent/spawn.py`, `subagent/conformers.py`, `subagent/_facade.py` (and `_seam.py` if separate). `_types.py`/`policy.py` are already on the gate (extended, not re-added). Run the gate against **fresh `--cov-branch coverage.json` in this commit** per `[[feedback_verify_promotion_meets_floor_at_promotion_time]]`; same-commit coverage repair if any module < floor. Bump `_EXPECTED_ENTRY_COUNT` (94 → N). **HALT + final review** before push/PR. Commit (full suite first): `test(sprint-11b): Z1b promote 11b modules to the CC gate (94→N)`.

---

## Self-review
- **Memo coverage:** D1 → T5 (test/DI conformers; real PackStateInterrogator) + T6 (injected scheduler, no app-wiring) + T10 (production-deferred honesty); D2 → T8 (thin seam, no harness); D3 → T4.5 (split vocab). ✓
- **6 ADR-005 tests** land in T6/T7 (spawn, privilege, depth+escalation, budget+preempt, scheduler-inheritance) + the merged 11a `test_subagent_audit_chain` (verifier). ✓
- **Placeholder check:** T4.5/T5/T6 carry concrete code; T7-T10/Z1b are tight task specs over established patterns (11a facade/Z1a gate; the `ChildRunner` seam is the one new design point, flagged at top). The T6 orchestrator body is pseudocode-accurate at the seam calls — the executing agent fills the exact `emit_*`/`submit`/`request_id` args (all verified-signature seams).
- **Stop-rule surfaces:** all `subagent/*` + `protocol/ui_events.py` (ADR-020) halt-before-commit; `core/scheduler/*` consumed via DI, never imported-from by subagent.

*End of plan. No code. Awaiting review before commit; on approval, execute T4.5 first (it precedes the spawn seam exposing the budget vocab).*
