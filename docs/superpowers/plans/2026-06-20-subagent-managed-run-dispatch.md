# Live SubAgentSpawner dispatch (child-is-a-managed-run) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compose and prove the first production sub-agent dispatch path, where a child sub-agent runs as a governed managed run and the scheduler is the single budget authority.

**Architecture:** `ManagedRunExecutor` becomes the sole owner of `scheduler.submit → mark_running → sandbox create/exec/destroy → complete/fail` for a child. `spawn.py` keeps only privilege-narrowing + the sub-agent audit and delegates execution to a new `ManagedRunChildRunner` (implements the existing `ChildRunner` Protocol) that adapts `ChildRunContext → RunRequest → ManagedRunExecutor.run`. The spawner + runner are composed WIRED-but-DORMANT in the portal app lifespan (no production trigger this slice — that is the next slice).

**Tech Stack:** Python 3.12, `uv`, pytest (`pytest-asyncio`), SQLAlchemy async, strict mypy, ruff, FastAPI. Source of truth: `docs/superpowers/specs/2026-06-20-subagent-managed-run-dispatch-design.md`.

**Process rules (this repo):** use `uv run`; per-task **whole-project** mypy `uv run mypy src tests` (single-file emits false `import-untyped` for `cognic_agentos.*`); `subagent/` + `core/` are stop-rule boundaries (critical-controls scrutiny); the controller commits per task on an explicit token. Do NOT stage `docs/reviews/` or `docs/superpowers/specs/2026-05-26-agentos-local-managed-agents-gap-analysis.md`.

---

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `src/cognic_agentos/core/run/executor.py` | modify (on-gate) | `RunRequest` +`parent_task_id`/`requested_estimated_tokens`; `run()` threads both into `SubmitInput` |
| `src/cognic_agentos/core/scheduler/engine.py` | modify (on-gate) | zero-effective-budget guard → `refused_quota_exhausted` before quota reservation |
| `src/cognic_agentos/subagent/_types.py` | modify (subagent/ CC) | `ManagedRunChildSpec`; `ChildRunContext.{parent_task_id, managed_run}`; rename `budget → requested_estimated_tokens` |
| `src/cognic_agentos/subagent/spawn.py` | modify (subagent/ CC) | live path = narrow + audit + run; drop scheduler/parent_budget/`pack_kind`/`pack_risk_tier`/`class_`; take `managed_run` + `actor: Actor` |
| `src/cognic_agentos/subagent/policy.py` | modify (subagent/ CC) | `compute_spawn_budget` leaves the live path; delete only if no consumer |
| `src/cognic_agentos/subagent/managed_run_runner.py` | **create (on-gate, CC 132→133)** | `ManagedRunChildRunner`: fail-closed, exact tenant-scoped pack lookup, `RunResult → ChildResult` mapping |
| `src/cognic_agentos/harness/sandbox.py` | modify (off-gate) | `build_subagent_spawner(...)` composition builder |
| `src/cognic_agentos/portal/api/app.py` | modify (off-gate) | lifespan composes `app.state.subagent_spawner` after the executor; pre-seed `None` |
| `tools/check_critical_coverage.py` + `tests/unit/tools/test_check_critical_coverage.py` | modify | register `managed_run_runner.py` (CC 132→133) |
| `tests/unit/...` + `tests/integration/run/...` | create/modify | unit per task + an env-gated docker e2e |

**Task order + dependency:** T1 (RunRequest) and T2 (engine guard) are independent foundations. T3 (types) precedes T4 (spawn refactor, which does the rename) and T5 (runner, which reads the renamed field). T6 (composition) needs T4+T5. T7 (closeout) is last.

---

## Task 1: `RunRequest` parent_task_id + requested_estimated_tokens override

**Files:**
- Modify: `src/cognic_agentos/core/run/executor.py` (`RunRequest` ~`:145-162`; the `SubmitInput(...)` build ~`:367-378`)
- Test: `tests/unit/core/run/test_executor.py`

- [ ] **Step 1: Write the failing tests** — append to `tests/unit/core/run/test_executor.py`. Use the **real** existing helpers — `_request` (the `RunRequest` builder at `:285`), `_executor` (the executor builder at `:335`, which takes `backend=`/`loader=`/`scheduler=`), `_StubBackend`, `_StubLoader`, `_record`, `SandboxExecResult`. A **recording-stub scheduler** captures the `SubmitInput` so we prove the executor THREADS the two fields (the scheduler's own narrowing is tested in T2, not re-tested here). Add `from cognic_agentos.core.scheduler._types import AdmissionDecision` to the imports if absent.

```python
async def test_run_request_defaults_parent_task_id_and_tokens_to_none() -> None:
    # Pure dataclass default check — additive fields default None so top-level
    # runs are byte-identical. `_request` is the existing helper at :285.
    req = _request()
    assert req.parent_task_id is None
    assert req.requested_estimated_tokens is None


class _RecordingScheduler:
    """Captures the SubmitInput the executor builds, then admits immediately.
    Proves the executor THREADS parent_task_id + requested_estimated_tokens into
    the scheduler submit; the scheduler's narrowing is T2's concern."""

    def __init__(self) -> None:
        self.seen: SubmitInput | None = None

    async def submit(self, *, submit_input: SubmitInput, request_id: str) -> AdmissionDecision:
        self.seen = submit_input
        return AdmissionDecision(outcome="accepted_immediate", task_id=str(uuid.uuid4()))

    async def mark_running(self, task_id: str, *, request_id: str) -> None: ...

    async def complete(self, task_id: str, *, request_id: str) -> None: ...


async def test_run_threads_parent_task_id_and_tokens_into_scheduler_submit(
    db: AsyncEngine, settings: Settings
) -> None:
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"ok\n", stderr=b"", exit_code=0))
    sched = _RecordingScheduler()
    ex = _executor(
        db, backend=backend, loader=_StubLoader(_record()), settings=settings,
        scheduler=sched,  # type: ignore[arg-type]  # duck-typed; the executor only calls submit/mark_running/complete
    )
    await ex.run(_request(
        parent_task_id="11111111-1111-1111-1111-111111111111",
        requested_estimated_tokens=200,
    ))
    assert sched.seen is not None
    assert sched.seen.parent_task_id == "11111111-1111-1111-1111-111111111111"  # threaded UNCHANGED (str)
    assert sched.seen.requested_estimated_tokens == 200  # the override (NOT _DEFAULT_ESTIMATED_TOKENS=1000)
```

> NOTE: no `_seed_parent` is needed — the recording stub captures the raw `SubmitInput` the executor builds, so the threading proof needs no real scheduler/resolver. The end-to-end narrowing (`min(child, parent)`) is proven in T2 (the engine, with a seeded parent) and the T7 operator e2e.

- [ ] **Step 2: Run to verify failure** — `uv run pytest tests/unit/core/run/test_executor.py -k 'parent_task_id' -x -q`. Expected: FAIL (`RunRequest` has no `parent_task_id`).

- [ ] **Step 3: Add the two `RunRequest` fields.** In `executor.py`, after the **last** `RunRequest` field `suspend_after_exec: bool = False` (`:166`), add (keep them GENUINELY last — `suspend_after_exec` follows `approval_request_id`, so inserting between them would shift positional/by-name construction of every existing caller):

```python
    #: Sprint 2026-06-20 (sub-agent dispatch) — when set, the parent scheduler
    #: task id for budget inheritance; threaded UNCHANGED to SubmitInput (the
    #: scheduler owns the str→UUID parse + SchedulerSubmitInputInvalid).
    parent_task_id: str | None = None
    #: When set, overrides the executor's _DEFAULT_ESTIMATED_TOKENS in the
    #: SubmitInput (the child's requested quota); None preserves top-level behavior.
    requested_estimated_tokens: int | None = None
```

- [ ] **Step 3b: Extend the `_request` test helper.** `_request` (`tests/unit/core/run/test_executor.py:285`) builds `RunRequest`; add two params `parent_task_id: str | None = None` and `requested_estimated_tokens: int | None = None` to its signature and pass them through to the returned `RunRequest(...)`, so the Step-1 tests (`_request(parent_task_id=…, requested_estimated_tokens=…)`) compile. Every existing `_request()` call is unaffected (both default `None`).

- [ ] **Step 4: Thread them into the `SubmitInput` build** (`:367-378`). Change the two lines:

```python
            requested_estimated_tokens=(
                request.requested_estimated_tokens
                if request.requested_estimated_tokens is not None
                else _DEFAULT_ESTIMATED_TOKENS
            ),
            # (the existing kwargs stay unchanged: actor=task_actor, class_="interactive",
            # pack_kind=record.kind, pack_risk_tier=record.risk_tier,
            # data_classes=record.data_classes or (), approval_delegated_to="sandbox_admission")
            parent_task_id=request.parent_task_id,
```

Add `parent_task_id=request.parent_task_id,` alongside the existing kwargs (it is `str | None` in both `RunRequest` and `SubmitInput` — no parse here).

- [ ] **Step 5: Run + lint + types** — `uv run pytest tests/unit/core/run/test_executor.py -q && uv run ruff check src/cognic_agentos/core/run/executor.py tests/unit/core/run/test_executor.py && uv run mypy src tests`. Expected: PASS; ruff clean; mypy Success.

- [ ] **Step 6: Commit** — `feat(run): RunRequest parent_task_id + requested_estimated_tokens override (ADR-022)`

---

## Task 2: Scheduler zero-effective-budget guard (P1)

**Files:**
- Modify: `src/cognic_agentos/core/scheduler/engine.py` (`submit()` — insert after the policy gate `:565`, before Step 5 quota `:567`)
- Test: `tests/unit/core/scheduler/test_engine.py`

- [ ] **Step 1: Write the failing tests** — append to `tests/unit/core/scheduler/test_engine.py`. Reuse the existing `_make_engine` / `engine_db` / `caps` / `class_settings` / `_make_submit_input` helpers and the `_RaisingQuotaInterrogator` (a quota whose `would_admit` AssertionErrors if reached — the parent-budget slice added/used it) and `_count_admission_refused` / `_count_task_rows` helpers.

```python
async def test_submit_refuses_top_level_zero_tokens_before_quota(
    engine_db: AsyncEngine, caps: ConcurrencyCaps, class_settings: dict[str, tuple[int, float]]
) -> None:
    eng = _make_engine(
        db=engine_db, caps=caps, class_settings=class_settings,
        quota=_RaisingQuotaInterrogator(),  # AssertionError if quota is reached
    )
    decision = await eng.submit(
        submit_input=_make_submit_input(parent_task_id=None, requested_tokens=0),
        request_id="zero-top",
    )
    assert decision.outcome == "refused_quota_exhausted"
    assert decision.task_id is None
    assert await _count_task_rows(engine_db) == 0  # no row inserted


async def test_submit_refuses_parent_narrowed_to_zero_before_quota(
    engine_db: AsyncEngine, caps: ConcurrencyCaps, class_settings: dict[str, tuple[int, float]]
) -> None:
    parent_id = await _seed_parent(engine_db, tokens=0, state="running")  # parent granted 0
    eng = _make_engine(
        db=engine_db, caps=caps, class_settings=class_settings,
        quota=_RaisingQuotaInterrogator(),
        parent_budget=_resolver(engine_db),  # the real SchedulerTaskParentBudgetResolver
    )
    decision = await eng.submit(
        submit_input=_make_submit_input(parent_task_id=str(parent_id), requested_tokens=200),
        request_id="zero-narrowed",
    )
    assert decision.outcome == "refused_quota_exhausted"  # min(200, 0) == 0
    assert decision.task_id is None
    # admission_refused row written (the refusal evidence); NO *child* scheduler_tasks row —
    # `_seed_parent` inserted the parent row, so the count is 1 (the parent only), not 0.
    assert await _count_admission_refused(engine_db) >= 1
    assert await _count_task_rows(engine_db) == 1
```

- [ ] **Step 2: Run to verify failure** — `uv run pytest tests/unit/core/scheduler/test_engine.py -k 'zero' -x -q`. Expected: FAIL (the `_RaisingQuotaInterrogator` AssertionErrors today — a zero task currently reaches the quota gate).

- [ ] **Step 3: Insert the guard.** In `engine.py`, between the policy gate (`:565`, after its `return`) and `# Step 5: quota reservation` (`:567`), add:

```python
        # Step 4.5: zero-effective-budget guard (2026-06-20 sub-agent dispatch).
        # The spawn-side compute_spawn_budget retirement moves the zero/exhausted
        # refusal here: a zero effective budget (top-level requested 0, OR a parent
        # narrowed to zero by compute_child_budget) is refused with the EXISTING
        # refused_quota_exhausted outcome BEFORE any quota reservation — no
        # reservation made. Placed after pack_state/kill_switch/approval/policy so
        # those more-specific refusals keep precedence.
        if effective_tokens <= 0:
            await self._emit_admission_refused(
                refused_task_id=task_id,
                submit_input=effective_submit_input,
                reason="refused_quota_exhausted",
                request_id=request_id,
            )
            return AdmissionDecision(
                outcome="refused_quota_exhausted",
                task_id=None,
            )
```

> NOTE: `refused_quota_exhausted` is an EXISTING `SchedulerAdmissionOutcome` / `_emit_admission_refused` reason (used by the Step-5 quota path) — NO new enum value, NO drift-detector change.

- [ ] **Step 4: Run + lint + types** — `uv run pytest tests/unit/core/scheduler/test_engine.py -q && uv run ruff check src/cognic_agentos/core/scheduler/engine.py tests/unit/core/scheduler/test_engine.py && uv run mypy src tests`. Expected: PASS; clean.

- [ ] **Step 5: Full scheduler suite (architecture-guard exhaustiveness — no new module, so it stays green)** — `uv run pytest tests/unit/core/scheduler/ -q`. Expected: PASS (lesson from the parent-budget slice: run the FULL package suite, not just the focused test).

- [ ] **Step 6: Commit** — `feat(scheduler): zero-effective-budget guard → refused_quota_exhausted (ADR-005/ADR-022)`

---

## Task 3: `ManagedRunChildSpec` + `ChildRunContext` fields (additive)

**Files:**
- Modify: `src/cognic_agentos/subagent/_types.py` (after `ChildResult` `:88`; `ChildRunContext` `:95-109`)
- Test: `tests/unit/subagent/test_subagent_types.py` (create if absent)

- [ ] **Step 1: Write the failing test** — `tests/unit/subagent/test_subagent_types.py`:

```python
import uuid

from cognic_agentos.subagent._types import ChildRunContext, ManagedRunChildSpec


def test_managed_run_child_spec_shape() -> None:
    spec = ManagedRunChildSpec(pack_id="cognic-tool-x", pack_version="1.0.0", argv=("--run",))
    assert (spec.pack_id, spec.pack_version, spec.argv) == ("cognic-tool-x", "1.0.0", ("--run",))


def test_child_run_context_new_optional_fields_default_to_none() -> None:
    # Build WITHOUT actor/parent_task_id/managed_run — all are additive optionals.
    ctx = ChildRunContext(
        prompt="p", granted_tools=frozenset(), requested_estimated_tokens=10,
        tenant_id="t", current_depth=1, child_trace_id="c", request_id="r",
        parent_record_id=uuid.uuid4(),
    )
    assert ctx.actor is None  # optional/additive — the managed-run runner fail-closes on None
    assert ctx.parent_task_id is None
    assert ctx.managed_run is None
    assert ctx.requested_estimated_tokens == 10  # renamed from `budget`
```

- [ ] **Step 2: Run to verify failure** — `uv run pytest tests/unit/subagent/test_subagent_types.py -x -q`. Expected: FAIL (`ManagedRunChildSpec` undefined; `ChildRunContext` has `budget` not `requested_estimated_tokens`).

- [ ] **Step 3: Add `ManagedRunChildSpec` + extend `ChildRunContext`.** In `_types.py`, add after `ChildResult` (`:92`):

```python
@dataclass(frozen=True)
class ManagedRunChildSpec:
    """Runner-specific managed-run execution shape (B + thin-C). Kept OUT of the
    runner-agnostic SubAgentSpawnRequest so a pack-provided runner is unaffected.
    No pack_kind/risk_tier — the executor derives them from the validated record.
    pack_version IS caller-provided (PackRecord has no version column)."""

    pack_id: str
    pack_version: str
    argv: tuple[str, ...]
```

Then add the `TYPE_CHECKING` import of `Actor` near the top of `_types.py` (the module already has `from __future__ import annotations`, so this stays a type-only import — NO runtime `subagent → portal` dependency, mirroring `core/run/executor.py`):

```python
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from cognic_agentos.portal.rbac.actor import Actor
```

Then edit `ChildRunContext` (`:95-109`): rename `budget: int` to `requested_estimated_tokens: int`, and add three **optional** fields. `actor` is **`Actor | None = None` (NOT required)** — so the type addition is ADDITIVE and `spawn.py`'s existing `ChildRunContext(...)` (which passes no `actor`, and whose `actor` local is a `TaskActor` until T4) stays green at THIS commit; the managed-run runner fail-closes on `actor is None` (T5). All three are defaulted, so dataclass field-ordering is satisfied without touching the required-field block:

```python
    requested_estimated_tokens: int  # was `budget`; the REQUESTED (pre-narrowing)
    tenant_id: str
    current_depth: int
    child_trace_id: str
    request_id: str
    parent_record_id: uuid.UUID
    parent_task_id: str | None = None  # budget-inheritance key (from request.parent_task_id)
    managed_run: ManagedRunChildSpec | None = None  # None → pack-provided runner; managed-run runner fail-closes
    actor: Actor | None = None  # OPTIONAL/additive — the full portal Actor; managed-run runner fail-closes on None
    memory_scope: str | None = None
```

- [ ] **Step 3b: MANDATORY rename-propagation (keep the tree GREEN at this commit).** The rename breaks `spawn.py` + any test that reads `ChildRunContext.budget`. As part of THIS task: in `spawn.py` (`:225-235`) change the construction keyword `budget=budget` → `requested_estimated_tokens=budget` (value unchanged — T4 restructures the value source); and grep `uv run python -c "import subprocess;print(subprocess.run(['grep','-rn','\.budget','tests/unit/subagent'],capture_output=True,text=True).stdout)"` and update any `ChildRunContext` reader of `.budget` → `.requested_estimated_tokens`. Do NOT restructure `spawn.py` further here (that is T4). This keeps the per-task green/commit discipline.

- [ ] **Step 4: Run + types** — `uv run pytest tests/unit/subagent/ -q && uv run ruff check src/cognic_agentos/subagent/ tests/unit/subagent/ && uv run mypy src tests`. Expected: **PASS** — the Step-3b propagation keeps the whole `subagent/` suite + `mypy src tests` green; ruff clean.

- [ ] **Step 5: Commit** — `feat(subagent): ManagedRunChildSpec + ChildRunContext managed-run fields (ADR-005)`

---

## Task 4: `spawn.py` live-path refactor (scheduler lifecycle leaves spawn)

**Files:**
- Modify: `src/cognic_agentos/subagent/spawn.py` (`SubAgentSpawner.__init__` + `_resolve_budget` + `spawn`)
- Modify: `src/cognic_agentos/subagent/policy.py` (`compute_spawn_budget` leaves the live path)
- Test: `tests/unit/subagent/test_subagent_spawn.py`

- [ ] **Step 1: Rewrite the spawn tests** — `tests/unit/subagent/test_subagent_spawn.py`. The existing `_FakeChildRunner` (`:79`) + `spawn_harness` fixture (`:102`) stay, but the harness no longer wires a scheduler/`parent_budget` into `SubAgentSpawner` (`:139`), and `spawn()` no longer takes `class_`/`pack_kind`/`pack_risk_tier`/the separate `pack_id` (gains `managed_run: ManagedRunChildSpec` + a full `actor: Actor`). Replace the scheduler-coupled tests (`test_scheduler_inheritance_narrows_budget`, `test_accepted_queued_is_cancelled_not_run`, `test_top_level_zero_quota_refuses_before_any_emit`, `test_child_over_budget_preempts_and_returns_failed`) — those behaviors now live in the executor/scheduler (T1/T2). Keep + adapt the policy/audit tests:

```python
async def test_spawn_live_path_narrows_audits_and_delegates_to_runner(
    spawn_harness: Any,
) -> None:
    # The live path: narrow_tool_allow_list -> check_depth -> emit_spawn ->
    # child_runner.run(ctx) -> emit_return + emit_budget. NO scheduler calls.
    h = spawn_harness  # builds SubAgentSpawner(audit, child_runner=_FakeChildRunner(...), escalation, max_recursion_depth)
    result = await h.spawner.spawn(
        request=_make_request(requested_estimated_tokens=120, parent_task_id=None),
        managed_run=ManagedRunChildSpec(pack_id="cognic-tool-x", pack_version="1.0.0", argv=("--run",)),
        actor=h.actor,  # a portal Actor (the harness builds an Actor, not a TaskActor)
        parent_trace_id="trace-1",
    )
    assert result.child_result.ok is True
    # The fake runner captured the ChildRunContext it received:
    ctx = h.child_runner.seen_context
    assert ctx.managed_run == ManagedRunChildSpec(pack_id="cognic-tool-x", pack_version="1.0.0", argv=("--run",))
    assert ctx.actor is h.actor  # the full Actor threaded onto the context
    assert ctx.requested_estimated_tokens == 120
    assert ctx.granted_tools <= h.parent_tools  # privilege subset preserved


async def test_spawn_privilege_escalation_blocks_before_runner(spawn_harness: Any) -> None:
    h = spawn_harness
    with pytest.raises(SubAgentPrivilegeEscalation):
        await h.spawner.spawn(
            request=_make_request(requested_tool_allow_list=frozenset({"forbidden"})),
            managed_run=ManagedRunChildSpec(pack_id="cognic-tool-x", pack_version="1.0.0", argv=("--run",)),
            actor=h.actor, parent_trace_id="t",
        )
    assert h.child_runner.seen_context is None  # never reached the runner


async def test_spawn_depth_exceeded_escalates_before_runner(spawn_harness: Any) -> None:
    h = spawn_harness
    with pytest.raises(SubAgentDepthExceeded):
        await h.spawner.spawn(
            request=_make_request(current_depth=h.max_depth),
            managed_run=ManagedRunChildSpec(pack_id="cognic-tool-x", pack_version="1.0.0", argv=("--run",)),
            actor=h.actor, parent_trace_id="t",
        )
    assert h.child_runner.seen_context is None
```

> The `_FakeChildRunner` (`:79`) must record `seen_context` and return a `ChildResult(summary="ok", tokens_used=10, wall_time_used_s=0.1, ok=True)`. Update the `spawn_harness` fixture to build `SubAgentSpawner` with the T4 constructor (no scheduler/parent_budget) AND to expose `h.actor` as a portal `Actor` (`Actor(subject=…, tenant_id=…, scopes=frozenset(), actor_type="service")`), NOT a `TaskActor`.

- [ ] **Step 2: Run to verify failure** — `uv run pytest tests/unit/subagent/test_subagent_spawn.py -x -q`. Expected: FAIL (`spawn()` still requires `class_`; `__init__` still requires `scheduler`).

- [ ] **Step 3: Refactor `SubAgentSpawner.__init__`** (`:50-65`) — drop `scheduler` + `parent_budget`:

```python
    def __init__(
        self,
        *,
        audit: SubAgentAuditEmitter,
        child_runner: ChildRunner,
        escalation: EscalationStore,
        max_recursion_depth: int,
    ) -> None:
        self._audit = audit
        self._runner = child_runner
        self._escalation = escalation
        self._max_depth = max_recursion_depth
```

- [ ] **Step 4: Delete `_resolve_budget`** (`:67-87`) entirely (the scheduler now narrows).

- [ ] **Step 5: Rewrite `spawn()`** (`:89-297`) to the live path. New signature takes `managed_run: ManagedRunChildSpec` + `actor: Actor`; drops `class_`/`pack_kind`/`pack_risk_tier` + the separate `pack_id`:

```python
    async def spawn(
        self,
        *,
        request: SubAgentSpawnRequest,
        managed_run: ManagedRunChildSpec,
        actor: Actor,
        parent_trace_id: str,
    ) -> SubAgentResult:
        request_id = _mint_request_id()
        tenant_id = request.tenant_id

        # 1. policy gate (pure): privilege subset + depth cap (escalate on exceed).
        granted = narrow_tool_allow_list(
            parent=request.parent_tool_allow_list,
            requested=request.requested_tool_allow_list,
        )
        try:
            check_depth(current_depth=request.current_depth, max_depth=self._max_depth)
        except SubAgentDepthExceeded:
            await self._escalation.open(
                actor_id=actor.subject, level="depth_exceeded",
                reason=(
                    f"sub-agent spawn at depth {request.current_depth + 1} "
                    f"exceeds max {self._max_depth}"
                ),
                request_id=request_id, tenant_id=tenant_id,
            )
            raise

        # 2. emit_spawn -> R_spawn (the parent-chain root). The budget in the
        # snapshot is the REQUESTED tokens; the effective/narrowed value lives in
        # the scheduler chain row (the executor's submit), not here.
        spawn_id = await self._audit.emit_spawn(
            actor_id=actor.subject, tenant_id=tenant_id, request_id=request_id,
            parent_trace_id=parent_trace_id,
            child_request={"prompt": request.prompt},
            policy_snapshot={
                "granted_tools": sorted(granted),
                "requested_estimated_tokens": request.requested_estimated_tokens,
            },
        )

        # 3. build the already-narrowed-privilege context + delegate execution.
        child_trace_id = uuid.uuid4().hex
        await self._audit.emit_child_genesis(
            actor_id=actor.subject, tenant_id=tenant_id, request_id=request_id,
            parent_record_id=spawn_id, child_trace_id=child_trace_id,
        )
        context = ChildRunContext(
            prompt=request.prompt,
            granted_tools=granted,
            requested_estimated_tokens=request.requested_estimated_tokens,
            tenant_id=tenant_id,
            current_depth=request.current_depth + 1,
            child_trace_id=child_trace_id,
            request_id=request_id,
            parent_record_id=spawn_id,
            actor=actor,
            parent_task_id=request.parent_task_id,
            managed_run=managed_run,
            memory_scope=None,
        )
        child = await self._runner.run(context)

        # 4. emit return + budget; the child's run lifecycle/evidence is the
        # executor's (run-record + run.* rows), not re-emitted here.
        outcome: ReturnOutcome = "completed" if child.ok else "failed"
        await self._audit.emit_return(
            actor_id=actor.subject, tenant_id=tenant_id, request_id=request_id,
            parent_record_id=spawn_id, result_summary=child.summary, outcome=outcome,
        )
        await self._audit.emit_budget(
            actor_id=actor.subject, tenant_id=tenant_id, request_id=request_id,
            parent_record_id=spawn_id, tokens_used=child.tokens_used,
            wall_time_used_s=child.wall_time_used_s,
        )
        return SubAgentResult(spawn_record_id=spawn_id, child_result=child)
```

Update imports: drop `SchedulerEngine`, `SubmitInput`, `SchedulerPriorityClass`, `TaskFailedPayload`, `compute_spawn_budget`, `SubAgentChildQuotaZero`, `TaskActor`; add `ManagedRunChildSpec` and a `TYPE_CHECKING` import of `Actor` (`from cognic_agentos.portal.rbac.actor import Actor`; `spawn.py` already has `from __future__ import annotations`, so it stays type-only — no runtime `subagent → portal`). The unused `SubAgentBudgetExhausted`/`SubAgentChildQuotaZero` exceptions + `compute_spawn_budget` leave the live path.

- [ ] **Step 6: Retire `compute_spawn_budget` (P1 / §6 LOCKED).** In `subagent/policy.py`, if `compute_spawn_budget` has no remaining importer after Step 5 (grep: `uv run python -c "import subprocess; print(subprocess.run(['grep','-rn','compute_spawn_budget','src','tests'],capture_output=True,text=True).stdout)"`), delete it + its tests. **KEEP** the `SubAgentRefusalReason` Literal values `subagent_parent_budget_exhausted` / `subagent_child_quota_zero` and the `SubAgentBudgetExhausted`/`SubAgentChildQuotaZero` classes **only if a non-live consumer remains**; otherwise delete the classes but **leave the two Literal values** (wire-public; no drift/vocab pruning this slice — spec §6 LOCKED).

- [ ] **Step 7: Run + facade + types** — `uv run pytest tests/unit/subagent/ -q && uv run ruff check src/cognic_agentos/subagent/ tests/unit/subagent/ && uv run mypy src tests`. The facade (`subagent/_facade.py`) delegates to `spawn()`; update its `spawn_subagent` signature + `tests/unit/subagent/test_subagent_facade.py` to drop `class_`/`pack_kind`/`pack_risk_tier` + the separate `pack_id`/`child_argv`, and add `managed_run: ManagedRunChildSpec` + `actor: Actor`. **The `spawn()`/`spawn_subagent`/`SubAgentSpawner.__init__` signature change ALSO cascades to every other caller** — at minimum `tests/unit/subagent/test_spawn_subagent_seam.py` (the seam test, inside the verify dir) and `tests/unit/protocol/test_ui_events_subagent_emit.py` (constructs `SubAgentSpawner` + calls `spawn()`; caught by `mypy src tests`); apply the same mechanical signature adaptation there (no design change). Expected: PASS; clean.

- [ ] **Step 8: Commit** — `refactor(subagent): live spawn path = narrow + audit + run; scheduler owns lifecycle (ADR-005)`

---

## Task 5: `ManagedRunChildRunner` (the new on-gate module)

**Files:**
- Create: `src/cognic_agentos/subagent/managed_run_runner.py`
- Test: `tests/unit/subagent/test_managed_run_runner.py`

- [ ] **Step 1: Write the failing tests** — `tests/unit/subagent/test_managed_run_runner.py`. Stub the executor seam (records the `RunRequest`, returns a configurable `RunResult`) + a stub pack store (returns a configurable installed-pack list).

```python
import uuid
from typing import Any

import pytest

from cognic_agentos.core.run.executor import RunRequest, RunResult
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.subagent._types import ChildRunContext, ManagedRunChildSpec
from cognic_agentos.subagent.managed_run_runner import ManagedRunChildRunner


class _StubExecutor:
    def __init__(self, result: RunResult) -> None:
        self._result = result
        self.seen: RunRequest | None = None
    async def run(self, request: RunRequest) -> RunResult:
        self.seen = request
        return self._result


class _Rec:  # minimal installed-pack record shape the runner reads — PackRecord has NO version column.
    def __init__(self, pack_id: str, row_id: uuid.UUID) -> None:
        self.pack_id, self.id = pack_id, row_id


class _StubPackStore:
    def __init__(self, records: list[_Rec]) -> None:
        self._records = records
    async def list_for_tenant(
        self, tenant_id: str, *, limit: int, cursor: uuid.UUID | None = None, state: str | None = None
    ) -> list[_Rec]:
        return self._records


def _actor(tenant: str = "t") -> Actor:
    return Actor(subject="svc-a", tenant_id=tenant, scopes=frozenset(), actor_type="service")


def _spec(*, pack_id: str = "p", pack_version: str = "1.2", argv: tuple[str, ...] = ("--x",)) -> ManagedRunChildSpec:
    return ManagedRunChildSpec(pack_id=pack_id, pack_version=pack_version, argv=argv)


def _ctx(
    managed_run: ManagedRunChildSpec | None, *, tenant: str = "t", tokens: int = 100,
    parent: str | None = None,
) -> ChildRunContext:
    return ChildRunContext(
        prompt="p", granted_tools=frozenset(), requested_estimated_tokens=tokens,
        tenant_id=tenant, current_depth=1, child_trace_id="c", request_id="r",
        parent_record_id=uuid.uuid4(), actor=_actor(tenant), parent_task_id=parent,
        managed_run=managed_run,
    )


def _result(**kw: Any) -> RunResult:
    base: dict[str, Any] = dict(run_id="run-1", task_id="task-1", terminal_state="completed",
                                exit_code=0, stdout=b"", stderr=b"", refusal_reason=None)
    base.update(kw)
    return RunResult(**base)


async def test_fail_closed_when_managed_run_is_none() -> None:
    runner = ManagedRunChildRunner(executor=_StubExecutor(_result()), pack_store=_StubPackStore([]))
    child = await runner.run(_ctx(None))
    assert child.ok is False
    assert "managed_run" in child.summary  # fail-closed; no executor call


async def test_fail_closed_when_actor_is_none() -> None:
    # The other `or` branch of the runner's guard — managed_run present but actor=None.
    ctx = ChildRunContext(
        prompt="p", granted_tools=frozenset(), requested_estimated_tokens=10,
        tenant_id="t", current_depth=1, child_trace_id="c", request_id="r",
        parent_record_id=uuid.uuid4(), managed_run=_spec(), actor=None,
    )
    runner = ManagedRunChildRunner(executor=_StubExecutor(_result()), pack_store=_StubPackStore([]))
    child = await runner.run(ctx)
    assert child.ok is False
    assert "actor" in child.summary  # fail-closed on the missing portal Actor


async def test_zero_pack_matches_fail_closed() -> None:
    runner = ManagedRunChildRunner(
        executor=_StubExecutor(_result()), pack_store=_StubPackStore([]),
    )
    child = await runner.run(_ctx(_spec(pack_id="missing")))
    assert child.ok is False


async def test_multiple_pack_matches_fail_closed() -> None:
    dupes = [_Rec("p", uuid.uuid4()), _Rec("p", uuid.uuid4())]
    runner = ManagedRunChildRunner(
        executor=_StubExecutor(_result()), pack_store=_StubPackStore(dupes),
    )
    child = await runner.run(_ctx(_spec()))
    assert child.ok is False


async def test_happy_path_builds_run_request_and_maps_completed() -> None:
    row_id = uuid.uuid4()
    ex = _StubExecutor(_result(terminal_state="completed", exit_code=0))
    runner = ManagedRunChildRunner(executor=ex, pack_store=_StubPackStore([_Rec("p", row_id)]))
    child = await runner.run(_ctx(_spec(pack_id="p", pack_version="1.2"),
                                  tokens=77, parent="11111111-1111-1111-1111-111111111111"))
    assert child.ok is True
    assert ex.seen is not None  # narrows RunRequest | None for the reads below (mypy union-attr)
    assert ex.seen.pack_id == "p" and ex.seen.pack_uuid == row_id
    assert ex.seen.pack_version == "1.2"  # from the SPEC, not the record (PackRecord has no version)
    assert ex.seen.actor.subject == "svc-a"  # the full Actor threaded to RunRequest
    assert ex.seen.argv == ("--x",)
    assert ex.seen.parent_task_id == "11111111-1111-1111-1111-111111111111"  # string passthrough
    assert ex.seen.requested_estimated_tokens == 77
    assert child.tokens_used == 0  # documented metering gap


@pytest.mark.parametrize("state,ok", [
    ("completed", True), ("failed", False), ("refused", False),
    ("pending_approval", False), ("suspended", False),
])
async def test_maps_every_run_terminal_state(state: str, ok: bool) -> None:
    exit_code = 0 if state == "completed" else 1
    ex = _StubExecutor(_result(terminal_state=state, exit_code=exit_code))
    runner = ManagedRunChildRunner(executor=ex, pack_store=_StubPackStore([_Rec("p", uuid.uuid4())]))
    child = await runner.run(_ctx(_spec()))
    assert child.ok is ok


@pytest.mark.parametrize("state,expected_summary", [
    ("suspended", "suspended_child_unsupported"),
    ("pending_approval", "pending_approval_child_unsupported"),
])
async def test_special_case_summaries(state: str, expected_summary: str) -> None:
    # suspended + pending_approval get EXPLICIT summaries (spec §4), not the generic
    # `run=... state=... exit=...` fall-through.
    ex = _StubExecutor(_result(terminal_state=state, exit_code=1))
    runner = ManagedRunChildRunner(executor=ex, pack_store=_StubPackStore([_Rec("p", uuid.uuid4())]))
    child = await runner.run(_ctx(_spec()))
    assert child.ok is False
    assert child.summary == expected_summary


async def test_completed_nonzero_exit_is_not_ok() -> None:
    ex = _StubExecutor(_result(terminal_state="completed", exit_code=3))
    runner = ManagedRunChildRunner(executor=ex, pack_store=_StubPackStore([_Rec("p", uuid.uuid4())]))
    child = await runner.run(_ctx(_spec()))
    assert child.ok is False
```

- [ ] **Step 2: Run to verify failure** — `uv run pytest tests/unit/subagent/test_managed_run_runner.py -x -q`. Expected: FAIL (module does not exist).

- [ ] **Step 3: Implement the module.** `src/cognic_agentos/subagent/managed_run_runner.py`:

```python
"""ManagedRunChildRunner — the default ChildRunner: a child sub-agent runs as a
governed managed run (ADR-005 + ADR-022). On-gate (subagent/ stop-rule + the
live-dispatch enforcement surface). Imports core/run TYPES + a consumer-owned
executor Protocol seam (the real ManagedRunExecutor structurally conforms), so
subagent/ stays decoupled from the executor's construction."""

from __future__ import annotations

import time
import uuid
from typing import Any, Literal, Protocol

from cognic_agentos.core.run.executor import RunRequest, RunResult
from cognic_agentos.subagent._types import ChildResult, ChildRunContext


class _ManagedRunExecutorSeam(Protocol):
    async def run(self, request: RunRequest) -> RunResult: ...


class _PackStoreSeam(Protocol):
    async def list_for_tenant(
        self,
        tenant_id: str,
        *,
        limit: int,
        cursor: uuid.UUID | None = ...,
        # Narrow Literal (NOT `str | None`): the concrete PackRecordStore takes
        # `PackState | None`, which structurally conforms to this (a supertype of the
        # seam's param) but NOT to a broad `str | None`. Decoupled (no PackState import).
        state: Literal["installed"] | None = ...,
    ) -> list[Any]: ...


# Page size for the exact tenant-scoped pack lookup; mirrors the
# PackStoreStateInterrogator pagination idiom.
_PACK_LOOKUP_PAGE: int = 200


class ManagedRunChildRunner:
    """Adapts ChildRunContext -> RunRequest -> ManagedRunExecutor.run. Fail-closed
    on a missing managed_run spec or an ambiguous pack identity."""

    def __init__(self, *, executor: _ManagedRunExecutorSeam, pack_store: _PackStoreSeam) -> None:
        self._executor = executor
        self._pack_store = pack_store

    async def run(self, context: ChildRunContext) -> ChildResult:
        spec = context.managed_run
        actor = context.actor  # locals so the guard narrows both to non-None for mypy
        if spec is None or actor is None:
            return ChildResult(
                summary="managed_run spec or actor missing (prompt/tools-only child unsupported by the "
                "managed-run runner this slice)",
                tokens_used=0, wall_time_used_s=0.0, ok=False,
            )
        pack_uuid = await self._resolve_pack_uuid(context.tenant_id, spec.pack_id)
        if pack_uuid is None:
            return ChildResult(
                summary=f"pack identity unresolved for tenant={context.tenant_id} pack_id={spec.pack_id} "
                "(zero or multiple installed matches)",
                tokens_used=0, wall_time_used_s=0.0, ok=False,
            )
        request = RunRequest(
            tenant_id=context.tenant_id,
            pack_id=spec.pack_id,
            pack_uuid=pack_uuid,
            pack_version=spec.pack_version,  # P1: caller-provided (PackRecord has no version column)
            argv=spec.argv,
            actor=actor,  # P1: required at executor.py:158; narrowed to Actor by the guard above
            parent_task_id=context.parent_task_id,
            requested_estimated_tokens=context.requested_estimated_tokens,
        )
        started = time.monotonic()
        result = await self._executor.run(request)
        elapsed = time.monotonic() - started
        ok = result.terminal_state == "completed" and result.exit_code == 0
        summary = f"run={result.run_id} state={result.terminal_state} exit={result.exit_code}"
        if result.terminal_state == "suspended":
            summary = "suspended_child_unsupported"
        elif result.terminal_state == "pending_approval":
            # High-risk child pended at sandbox admission; the async child-approval
            # resume loop is a non-goal this slice (spec §4).
            summary = "pending_approval_child_unsupported"
        return ChildResult(summary=summary, tokens_used=0, wall_time_used_s=elapsed, ok=ok)

    async def _resolve_pack_uuid(self, tenant_id: str, pack_id: str) -> uuid.UUID | None:
        """Exact tenant-scoped lookup over installed packs — resolves ONLY the
        pack_uuid (row id). Zero AND multiple matches both fail closed (return
        None) — no caller UUID-threading, no ambiguity. pack_version is NOT
        resolved (PackRecord has no version column); the caller supplies it via
        ManagedRunChildSpec.pack_version. Paginates so a target past the first
        page is still found."""
        matches: list[Any] = []
        cursor: uuid.UUID | None = None
        while True:
            page = await self._pack_store.list_for_tenant(
                tenant_id, limit=_PACK_LOOKUP_PAGE, cursor=cursor, state="installed"
            )
            matches.extend(r for r in page if r.pack_id == pack_id)
            if len(matches) > 1:
                return None  # ambiguous — fail closed early
            if len(page) < _PACK_LOOKUP_PAGE:
                break
            cursor = page[-1].id
        if len(matches) != 1:
            return None
        resolved: uuid.UUID = matches[0].id  # typed local (matches is list[Any]) for warn_return_any
        return resolved
```

> NOTE: `RunRequest.actor` is required (`executor.py:158`); the runner supplies it from the `actor` local that the `spec is None or actor is None` guard above narrowed to non-`Actor` (`ChildRunContext.actor` is optional). `pack_uuid` is the resolved `uuid.UUID` row id; `pack_version` comes from the spec (not the record). The pack record's `.id` attribute is its UUID row id (`PackRecord.id`); the matcher reads `.pack_id` — both confirmed in `packs/storage.py` `PackRecord`.

- [ ] **Step 4: Run + lint + types** — `uv run pytest tests/unit/subagent/test_managed_run_runner.py -q && uv run ruff check src/cognic_agentos/subagent/managed_run_runner.py tests/unit/subagent/test_managed_run_runner.py && uv run mypy src tests`. Expected: PASS; clean.

- [ ] **Step 5: Commit** — `feat(subagent): ManagedRunChildRunner — child-is-a-managed-run (ADR-005/ADR-022)`

---

## Task 6: Composition in the portal lifespan (WIRED-but-DORMANT)

**Files:**
- Modify: `src/cognic_agentos/harness/sandbox.py` (add `build_subagent_spawner(...)`)
- Modify: `src/cognic_agentos/portal/api/app.py` (lifespan ~`:703-713`; pre-seed ~`:928`)
- Test: `tests/unit/harness/test_subagent_spawner_composition.py` (create)

- [ ] **Step 1: Write the failing test** — assert `build_subagent_spawner` returns a `SubAgentSpawner` whose `child_runner` is a `ManagedRunChildRunner`, given a real `Runtime` + a stub executor + the in-memory `AsyncEngine`. Use the existing harness test fixtures (`build_runtime` over an in-memory engine) as in `tests/unit/harness/` precedents.

```python
async def test_build_subagent_spawner_wires_managed_run_runner(runtime, db) -> None:
    from cognic_agentos.harness.sandbox import build_subagent_spawner
    from cognic_agentos.subagent.managed_run_runner import ManagedRunChildRunner

    spawner = build_subagent_spawner(
        runtime=runtime,
        managed_run_executor=_StubExecutor(),  # any object with async run()
        engine=db,  # the in-memory AsyncEngine (the `db` fixture)
        settings=runtime_settings,  # has subagent_max_recursion_depth
    )
    assert isinstance(spawner._runner, ManagedRunChildRunner)  # noqa: SLF001 (composition assert)
```

- [ ] **Step 2: Run to verify failure** — `uv run pytest tests/unit/harness/test_subagent_spawner_composition.py -x -q`. Expected: FAIL (`build_subagent_spawner` undefined).

- [ ] **Step 3: Add `build_subagent_spawner` to `harness/sandbox.py`** (off-gate; mirrors the existing `build_sandbox_backend` builder):

```python
def build_subagent_spawner(
    *,
    runtime: Runtime,
    managed_run_executor: object,  # the ManagedRunExecutor (duck-typed run())
    engine: AsyncEngine,
    settings: Settings,
) -> SubAgentSpawner:
    """Compose the live SubAgentSpawner (child-is-a-managed-run). SDK-free —
    constructs the audit emitter (from runtime.decision_history_store) and the
    pack store + escalation (from the shared AsyncEngine). Off-gate composition
    glue (the enforcement is on-gate in managed_run_runner.py + spawn.py)."""
    from cognic_agentos.core.escalation import EscalationStore
    from cognic_agentos.subagent.audit import SubAgentAuditEmitter
    from cognic_agentos.subagent.managed_run_runner import ManagedRunChildRunner
    from cognic_agentos.subagent.spawn import SubAgentSpawner

    # PackRecordStore is module-level imported (~:21); cast/Any at module level.
    return SubAgentSpawner(
        audit=SubAgentAuditEmitter(history=runtime.decision_history_store),
        child_runner=ManagedRunChildRunner(
            executor=cast(Any, managed_run_executor),  # object → _ManagedRunExecutorSeam (strict mypy)
            pack_store=PackRecordStore(engine),
        ),
        escalation=EscalationStore(engine=engine),
        max_recursion_depth=settings.subagent_max_recursion_depth,
    )
```

> NOTE: `AsyncEngine` is **NOT** already imported in `harness/sandbox.py` — add it (+ `SubAgentSpawner` for the return annotation) under `TYPE_CHECKING` (the module has `from __future__ import annotations`, so type-only resolution is correct; mirrors the existing `SandboxBackend` type-only import). `PackRecordStore` IS module-level imported (~line 21) — do NOT re-import it function-locally. `executor=` is typed `object` (so the test's duck-typed stub is accepted), but `ManagedRunChildRunner.executor` is the `_ManagedRunExecutorSeam` Protocol, so strict mypy needs `cast(Any, managed_run_executor)` at that arg (`from typing import Any, cast`). The builder owns BOTH the pack store and escalation construction from the single `engine` — no private-attribute access, no caller fork.

- [ ] **Step 4: Wire it in the lifespan** (`app.py` ~`:713`, immediately after `app.state.managed_run_executor = ManagedRunExecutor(...)`, INSIDE the same `try`):

```python
                        from cognic_agentos.harness.sandbox import build_subagent_spawner

                        app.state.subagent_spawner = build_subagent_spawner(
                            runtime=runtime,
                            managed_run_executor=app.state.managed_run_executor,
                            engine=adapters.relational.engine,
                            settings=settings,
                        )
```

In the `except` (`:714-720`) add `app.state.subagent_spawner = None`. Pre-seed near `:928` (`app.state.managed_run_executor = None`): add `app.state.subagent_spawner = None  # 2026-06-20 sub-agent dispatch — lifespan populates.`

- [ ] **Step 5: Run + lint + types** — `uv run pytest tests/unit/harness/ -q && uv run ruff check src/cognic_agentos/harness/sandbox.py src/cognic_agentos/portal/api/app.py && uv run mypy src tests`. Expected: PASS; clean.

- [ ] **Step 6: Commit** — `feat(subagent): compose live SubAgentSpawner in the portal lifespan (ADR-005)`

---

## Task 7: Closeout — CC gate (132→133), e2e, full suite

**Files:**
- Modify: `tools/check_critical_coverage.py` (`_CRITICAL_FILES`)
- Modify: `tests/unit/tools/test_check_critical_coverage.py` (`_EXPECTED_ENTRY_COUNT`)
- Create: `tests/integration/run/test_managed_run_subagent_e2e.py`

- [ ] **Step 1: Register the runner on the CC gate.** In `tools/check_critical_coverage.py`, append to `_CRITICAL_FILES` (after the parent-budget `budget_resolver.py` entry):

```python
    # Live sub-agent dispatch (2026-06-20; ADR-005 + ADR-022) — the default
    # ChildRunner: a child sub-agent runs as a governed managed run. CC because
    # fail-closed (missing argv), the exact tenant-scoped pack identity resolution
    # (zero/multiple → fail closed), and the RunResult→ChildResult mapping are the
    # live-dispatch enforcement surface. Gate 132 -> 133. Fresh --cov-branch in the
    # same commit per feedback_verify_promotion_meets_floor_at_promotion_time.
    ("src/cognic_agentos/subagent/managed_run_runner.py", 0.95, 0.90),
```

In `tests/unit/tools/test_check_critical_coverage.py`, add a chronology comment line and bump `_EXPECTED_ENTRY_COUNT = 132` → `133`.

- [ ] **Step 2: Author the operator-run e2e proof** — `tests/integration/run/test_managed_run_subagent_e2e.py` (env-gated `COGNIC_RUN_DOCKER_SANDBOX=1`; **operator-run, never in CI** — same posture as the other 14A docker e2es). It is authored **at this step against the real, now-landed impl** (T1-T6 exist), NOT pre-written as a placeholder. Author it by **copying the harness from `tests/integration/run/test_managed_run_e2e.py`** verbatim — the module-level skip-before-SDK-imports guard, the `create_async_engine` + governance migrations, the `SchedulerEngine` with `_AllowQuota`/`_AllowKill`/`_Installed` stubs + a stubbed-allow `PolicyDecision`, the real `DockerSiblingSandboxBackend`, and the direct `_packs` insert of an installed pack. On that harness, the new test MUST:
  1. wire the scheduler with a real `SchedulerTaskParentBudgetResolver(reader=SchedulerStorage(engine))` and seed a **parent** scheduler task granted `N` tokens via `SchedulerStorage(engine).submit(...)` (mirror the parent-budget composition e2e's `_seed_parent`);
  2. build the spawner via `build_subagent_spawner(runtime=…, managed_run_executor=…, engine=engine, settings=…)` and call `await spawner.spawn(request=SubAgentSpawnRequest(prompt=…, parent_task_id=str(parent_id), requested_estimated_tokens=200, …), managed_run=ManagedRunChildSpec(pack_id=_PACK_ID, pack_version=_PACK_VERSION, argv=("--run",)), actor=…, parent_trace_id=…)`;
  3. assert: (a) `result.child_result.ok is True`; (b) a `runs` run-record row exists for the child; (c) the child's `scheduler.admission_accepted` chain row carries `requested_estimated_tokens == min(200, N)` (the budget inheritance).

> The in-CI proof of this slice is the unit suites T1-T6 (which fully exercise the runner mapping, the spawn refactor, the engine guard, and the composition with stubs). This e2e is the operator's real-sandbox audit and runs only under `COGNIC_RUN_DOCKER_SANDBOX=1`. Because it is authored after the impl lands, its wiring is real code (copied harness + the three assertions above) — there is no placeholder body.

- [ ] **Step 3: Full quality gate (whole repo).** `uv run ruff check . && uv run ruff format --check . && uv run mypy src tests`. Expected: clean.

- [ ] **Step 4: Full suite on fresh coverage.** `uv run pytest -q --cov=cognic_agentos --cov-branch --cov-report=json:coverage.json`. Expected: all pass (env-gated docker/k8s skip).

- [ ] **Step 5: CC gate at 133/133.** `uv run python tools/check_critical_coverage.py`. Expected: `passed`; `managed_run_runner.py` ≥ 95% line / 90% branch on fresh data. If below floor, add focused negative-path tests in the SAME commit (the meets-floor-at-promotion-time rule).

- [ ] **Step 6: Commit** — `chore(subagent): register managed_run_runner on the CC gate (132→133) + e2e (ADR-005)`

- [ ] **Step 7: finish-the-branch** — controller-owned + token-gated (push + PR + merge, `--squash --delete-branch`).

---

## Self-Review (controller — fix inline)

- **Spec coverage:** §2 RunRequest → T1; §2/§6 engine guard (P1) → T2; §2 ManagedRunChildSpec + ChildRunContext fields + rename → T3 (additive) + T4 (rename, with the spawn rewrite); §3 spawn refactor → T4; §4 runner + the all-`RunTerminalState` mapping + fail-closed + exact lookup → T5; §5 composition → T6; §6 budget collapse + `compute_spawn_budget` retirement + the LOCKED wire-public keep → T4 Step 6; §7 CC 132→133 + tests + e2e → T5/T7. All §-requirements have a task.
- **Type consistency:** `ManagedRunChildSpec{pack_id, pack_version, argv}` (T3) used by T4 (construction) + T5 (read — `spec.pack_version` straight onto `RunRequest`). `ChildRunContext.actor: Actor | None = None` (optional/additive, T3) threaded `spawn(actor: Actor) → ctx.actor → RunRequest.actor` (T4→T5), with the runner fail-closing on `actor is None` (the guard narrows it to `Actor` for the `RunRequest` build); the `Actor`/`ManagedRunChildSpec`/`requested_estimated_tokens`/`parent_task_id`/`managed_run` field set is used consistently across T3/T4/T5. `RunRequest` already requires `actor: Actor` + `pack_version: str` (`executor.py:158`/`:156`), and `_request`/`_executor` are the real helpers (T1 Step 3b extends `_request`). The runner resolves only `pack_uuid` via `PackRecord.id` (no `.version` — `PackRecord` has none). `refused_quota_exhausted` (T2) is an existing outcome. `SubAgentAuditEmitter(history=...)` + `EscalationStore(engine=...)` (T6) match the verified constructors.
- **Placeholders:** none. The T7 e2e is an **operator-run proof authored at execution time** against the landed impl (copied harness + three concrete assertions — no placeholder body); the in-CI proof is the T1-T6 unit suites. The tree stays **green-at-commit** across all tasks: T3's rename rides the mandatory Step-3b propagation, and the new `ChildRunContext` fields (incl. `actor: Actor | None`) are all **additive optionals** (no constructor churn, no required-field across the in-flight refactor). T6's composition signature is **pinned** (`engine: AsyncEngine`, no private-attr, no caller fork). The runner resolves only `PackRecord.id` (the row UUID); `pack_version` is **caller-provided** on the spec, so there is no `PackRecord.version` dependency — **no outstanding confirm-notes**.
- **Critical-controls:** T1/T2 (executor/engine on-gate) + T5 (new on-gate runner) carry the 95/90 floor + negative-path tests; T7 verifies 133/133 on fresh coverage + the gate-list registration. The architecture-guard exhaustiveness lesson (run the FULL `tests/unit/core/scheduler/` suite) is pinned in T2 Step 5 — though no NEW `core/scheduler/*.py` module is added this slice, so the exhaustiveness lists are untouched.
