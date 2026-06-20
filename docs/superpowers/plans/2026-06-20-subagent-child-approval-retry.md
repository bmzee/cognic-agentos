# Sub-Agent Child Approval-Retry Semantics — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax. **This slice is inside the `subagent/` + ADR-020 `ui_events` stop-rule boundaries — use `core-controls-engineer` + `/critical-module-mode`; every change is backward-compatible-additive.**

**Goal:** Make a `pending_approval` child sub-agent honest in the audit chain + the UI event stream, and actionable over the wire (`202` + `approval_request_id`; re-POST is the approval retry).

**Architecture:** Un-flatten the runner so the child's `run_id`/`terminal_state`/`approval_request_id` survive; `ReturnOutcome += "pending_approval"`; spawn.py emits an honest pending `subagent.return` + skips budget; the ui_events projector routes pending to a new `SubagentPending` event; the route `202`s with the actionable id; the retry is the same route + a granted `approval_request_id`.

**Tech stack:** Python 3.12, strict mypy, ruff, pytest-asyncio, FastAPI, Pydantic v2.

**Source of truth:** `docs/superpowers/specs/2026-06-20-subagent-child-approval-retry-semantics-design.md`.

---

## File structure

| File | Responsibility | Gate / boundary |
|---|---|---|
| `subagent/_types.py` | `ChildResult` +3 fields; `SubAgentSpawnRequest`/`ChildRunContext` + `approval_request_id` | on-gate, `subagent/` stop rule |
| `subagent/managed_run_runner.py` | un-flatten the `RunResult → ChildResult` map; thread `approval_request_id` into `RunRequest` | on-gate, `subagent/` stop rule |
| `subagent/audit.py` | `ReturnOutcome += "pending_approval"`; `emit_return` optional `approval_request_id`/`run_id` payload | on-gate, `subagent/` stop rule |
| `subagent/spawn.py` | terminal-state-aware outcome + skip-budget-when-pending | on-gate, `subagent/` stop rule |
| `protocol/ui_events.py` | `SubagentPending` event + `_project_subagent_return` arm | on-gate, ADR-020 stop rule |
| `tests/unit/portal/api/ui/well_known_schema_snapshot.json` | additive snapshot (new event type) | test asset |
| `portal/api/subagents/dto.py` | request `approval_request_id`; response top-level `approval_request_id` | off-gate |
| `portal/api/subagents/routes.py` | `202` for pending; thread `approval_request_id` | off-gate |

**Grounded shapes (verified on `da74698` parent `87e211d`):**
- `ChildResult` (`subagent/_types.py`): `summary: str`, `tokens_used: int`, `wall_time_used_s: float`, `ok: bool` (frozen dataclass).
- `ChildRunContext` (`subagent/_types.py`): the Fork-B optionals `parent_task_id: str | None = None`, `managed_run: ManagedRunChildSpec | None = None`, `actor: Actor | None = None` are the last fields.
- `SubAgentSpawnRequest` (`subagent/_types.py:76`): `prompt`, `parent_tool_allow_list`, `requested_tool_allow_list`, `current_depth`, `requested_estimated_tokens`, `tenant_id`, `parent_task_id: str | None = None`.
- The runner (`managed_run_runner.py`): builds `RunRequest(...)` (no `approval_request_id` today) at the `run()` body; `result = await self._executor.run(request)`; maps `RunResult → ChildResult` with `ok = result.terminal_state == "completed" and result.exit_code == 0` + the `suspended`/`pending_approval` summary special-cases.
- `RunResult` (`core/run/executor.py:179-196`): `run_id: str`, `task_id: str | None`, `terminal_state`, `exit_code`, …, `approval_request_id: str | None` (set only when pending). `RunRequest.approval_request_id: uuid.UUID | None = None` (`:162`).
- `audit.py`: `ReturnOutcome = Literal["completed","failed"]` (`:15`); `emit_return(*, actor_id, tenant_id, request_id, parent_record_id, result_summary, outcome)` payload `{parent_record_id, result_summary, outcome}` (`:79-104`); `emit_budget(...)` (`:106`).
- `spawn.py:138-150`: `outcome: ReturnOutcome = "completed" if child.ok else "failed"` → `await self._audit.emit_return(... outcome=outcome)` → `await self._audit.emit_budget(... tokens_used=child.tokens_used, wall_time_used_s=child.wall_time_used_s)`.
- `protocol/ui_events.py`: `SubagentSpawned/Completed/Failed/RecursionCapped` (`:544-559`); `_SubagentEvent` union (`:783`); `_project_subagent_return` (`:969`) — `outcome=="completed" → SubagentCompleted` else `SubagentFailed`; `_DECISION_HISTORY_TYPED_PROJECTORS["subagent.return"]` (`:1209`).
- The route (`portal/api/subagents/routes.py`): `SubAgentSpawnResponse(spawn_record_id=str(result.spawn_record_id), child_result=ChildResultBody(...))`, always 200 today. `SubAgentSpawnResponse`/`ChildResultBody`/`SubAgentSpawnRequestBody` in `dto.py`.

---

## Task 1: `subagent/_types.py` — additive `ChildResult` + `approval_request_id` fields

**Files:** Modify `src/cognic_agentos/subagent/_types.py`; Test `tests/unit/subagent/test_subagent_types.py` (extend).

- [ ] **Step 1: Write the failing tests** — append to `tests/unit/subagent/test_subagent_types.py`:

```python
def test_child_result_new_fields_default_to_none() -> None:
    from cognic_agentos.subagent._types import ChildResult

    cr = ChildResult(summary="s", tokens_used=0, wall_time_used_s=0.0, ok=False)
    assert cr.run_id is None
    assert cr.terminal_state is None
    assert cr.approval_request_id is None


def test_child_result_carries_pending_fields() -> None:
    from cognic_agentos.subagent._types import ChildResult

    cr = ChildResult(
        summary="pending_approval_child",
        tokens_used=0,
        wall_time_used_s=0.1,
        ok=False,
        run_id="r1",
        terminal_state="pending_approval",
        approval_request_id="a1",
    )
    assert (cr.run_id, cr.terminal_state, cr.approval_request_id) == ("r1", "pending_approval", "a1")


def test_spawn_request_and_context_accept_approval_request_id() -> None:
    import uuid

    from cognic_agentos.subagent._types import ChildRunContext, SubAgentSpawnRequest

    req = SubAgentSpawnRequest(
        prompt="p",
        parent_tool_allow_list=frozenset(),
        requested_tool_allow_list=frozenset(),
        current_depth=0,
        requested_estimated_tokens=10,
        tenant_id="t",
        approval_request_id="a1",
    )
    assert req.approval_request_id == "a1"
    ctx = ChildRunContext(
        prompt="p",
        granted_tools=frozenset(),
        requested_estimated_tokens=10,
        tenant_id="t",
        current_depth=0,
        child_trace_id="c",
        request_id="r",
        parent_record_id=uuid.uuid4(),
    )
    assert ctx.approval_request_id is None  # additive optional default
```

- [ ] **Step 2: Run — verify fail.** `uv run pytest tests/unit/subagent/test_subagent_types.py -q` → FAIL (`unexpected keyword argument 'run_id'` / `'approval_request_id'`).

- [ ] **Step 3: Add the fields** (all additive, defaulted, last in each frozen dataclass so positional callers are unshifted).

`ChildResult`:
```python
    ok: bool
    #: 2026-06-20 (child approval-retry) — surfaced from the child RunResult on every
    #: branch (no longer flattened). approval_request_id is set ONLY on the pending path.
    run_id: str | None = None
    terminal_state: str | None = None  # mirrors core/run RunTerminalState; str avoids a core import
    approval_request_id: str | None = None
```
`SubAgentSpawnRequest` — append after `parent_task_id`:
```python
    approval_request_id: str | None = None  # the granted id on an approval retry (else None)
```
`ChildRunContext` — append after `memory_scope` (the ACTUAL last field — `actor` at `:128` is followed by `memory_scope: str | None = None` at `:129`):
```python
    approval_request_id: str | None = None  # threaded into RunRequest.approval_request_id by the runner
```

- [ ] **Step 4: Run + ruff + mypy.** `uv run pytest tests/unit/subagent/test_subagent_types.py -q` (PASS) ; `uv run ruff check src/cognic_agentos/subagent/_types.py tests/unit/subagent/test_subagent_types.py && uv run ruff format --check <same>` (clean) ; `uv run mypy src tests` (Success).

- [ ] **Step 5: Commit** — `feat(subagent): ChildResult pending fields + approval_request_id threading types (ADR-005)`.

---

## Task 2: the runner — un-flatten + thread `approval_request_id`

**Files:** Modify `src/cognic_agentos/subagent/managed_run_runner.py`; Test `tests/unit/subagent/test_managed_run_runner.py` (extend).

- [ ] **Step 1: Write the failing tests** — append:

```python
async def test_pending_approval_result_is_honest() -> None:
    ex = _StubExecutor(_result(terminal_state="pending_approval", exit_code=None))
    runner = ManagedRunChildRunner(
        executor=ex, pack_store=_StubPackStore([_Rec("p", uuid.uuid4())])
    )
    child = await runner.run(_ctx(_spec()))
    assert child.ok is False
    assert child.terminal_state == "pending_approval"
    assert child.run_id is not None
    assert child.approval_request_id is not None
    assert child.summary == "pending_approval_child"


async def test_terminal_result_carries_run_id_and_state() -> None:
    ex = _StubExecutor(_result(terminal_state="completed", exit_code=0))
    runner = ManagedRunChildRunner(
        executor=ex, pack_store=_StubPackStore([_Rec("p", uuid.uuid4())])
    )
    child = await runner.run(_ctx(_spec()))
    assert child.ok is True
    assert child.terminal_state == "completed"
    assert child.run_id is not None
    assert child.approval_request_id is None


async def test_runner_threads_approval_request_id_into_run_request() -> None:
    ex = _StubExecutor(_result(terminal_state="completed", exit_code=0))
    runner = ManagedRunChildRunner(
        executor=ex, pack_store=_StubPackStore([_Rec("p", uuid.uuid4())])
    )
    grant_id = uuid.uuid4()
    await runner.run(_ctx(_spec(), approval_request_id=str(grant_id)))
    assert ex.seen is not None
    # the context carries str; the runner parses it to RunRequest.approval_request_id: uuid.UUID
    assert ex.seen.approval_request_id == grant_id
```

Extend the existing `_result(...)` helper to set `run_id` + `approval_request_id` (the executor sets `approval_request_id` only when pending):
```python
def _result(*, terminal_state="completed", exit_code=0) -> RunResult:
    return RunResult(
        run_id="run-xyz",
        task_id="task-1",
        terminal_state=terminal_state,
        exit_code=exit_code,
        stdout=b"",
        stderr=b"",
        refusal_reason=None,
        approval_request_id="appr-1" if terminal_state == "pending_approval" else None,
    )
```
Extend `_ctx(...)` to accept `approval_request_id` and pass it onto the built `ChildRunContext`. (Confirm the real `RunResult` field order/names against `core/run/executor.py:179-196` during Step 1 — mirror it exactly; do NOT invent fields.)

- [ ] **Step 2: Run — verify fail.** `uv run pytest tests/unit/subagent/test_managed_run_runner.py -q` → FAIL (`ChildResult` has no `terminal_state` populated / `RunRequest` got no `approval_request_id`).

- [ ] **Step 3: Implement.** In `managed_run_runner.py`:
- Thread the approval id into the request build:
```python
        request = RunRequest(
            tenant_id=context.tenant_id,
            pack_id=spec.pack_id,
            pack_uuid=pack_uuid,
            pack_version=spec.pack_version,
            argv=spec.argv,
            actor=actor,
            parent_task_id=context.parent_task_id,
            requested_estimated_tokens=context.requested_estimated_tokens,
            approval_request_id=(
                uuid.UUID(context.approval_request_id)
                if context.approval_request_id is not None
                else None
            ),
        )
```
(`RunRequest.approval_request_id` is `uuid.UUID | None`; the context carries a `str`. Parse here — a malformed id is a caller error; let the `ValueError` propagate or, if the route already validated it as `uuid.UUID`, keep it `str` end-to-end and pass through. Pick ONE end-to-end type during Step 1: the route DTO will use `uuid.UUID`, so simplest is `context.approval_request_id: str` holding the canonical hex and parsing here. Pin with `test_runner_threads_approval_request_id_into_run_request`.)
- Un-flatten the mapping. Replace the `ok`/`summary`-only return with a single enriched builder used by every branch:
```python
        ok = result.terminal_state == "completed" and result.exit_code == 0
        summary = f"run={result.run_id} state={result.terminal_state} exit={result.exit_code}"
        if result.terminal_state == "suspended":
            summary = "suspended_child_unsupported"
        elif result.terminal_state == "pending_approval":
            summary = "pending_approval_child"
        return ChildResult(
            summary=summary,
            tokens_used=0,
            wall_time_used_s=elapsed,
            ok=ok,
            run_id=result.run_id,
            terminal_state=result.terminal_state,
            approval_request_id=result.approval_request_id,
        )
```
(The early fail-closed returns — `managed_run`/`actor` None, pack unresolved — keep `run_id=None`/`terminal_state=None`; they never reached the executor.)

The summary rename `"pending_approval_child_unsupported"` → `"pending_approval_child"` (pending is now supported/actionable) also **updates the existing parametrized `test_special_case_summaries` in `test_managed_run_runner.py`** — change its `pending_approval` expected value to `"pending_approval_child"` (a contract change, not a redefinition).

- [ ] **Step 4: Run + the broader subagent suite + ruff + mypy.** `uv run pytest tests/unit/subagent/ -q` (PASS) ; ruff/format clean ; `uv run mypy src tests` (Success).

- [ ] **Step 5: Commit** — `feat(subagent): un-flatten runner — surface pending run_id/state/approval_request_id (ADR-005)`.

---

## Task 3: audit honesty — `ReturnOutcome += "pending_approval"` + spawn.py skip-budget

**Files:** Modify `src/cognic_agentos/subagent/audit.py` + `src/cognic_agentos/subagent/spawn.py`; Test `tests/unit/subagent/test_subagent_types_closed_enums.py` (the `ReturnOutcome` drift — `test_subagent_audit.py` does NOT exist; the closed-enum test is the sanctioned drift surface) + `tests/unit/subagent/test_subagent_spawn.py` (the spawn-honesty tests; extend).

- [ ] **Step 1: Write the failing tests.**
Audit-vocabulary drift (extend the closed-enum drift surface `test_subagent_types_closed_enums.py`):
```python
import typing

from cognic_agentos.subagent.audit import ReturnOutcome


def test_return_outcome_has_pending_approval() -> None:
    assert set(typing.get_args(ReturnOutcome)) == {"completed", "failed", "pending_approval"}
```
spawn.py honesty (extend `test_subagent_spawn.py`, over a real in-memory `DecisionHistoryStore` like the existing spawn tests): a pending child (the `_FakeChildRunner` returns `ChildResult(ok=False, terminal_state="pending_approval", run_id="r", approval_request_id="a", …)`) →
```python
    # exactly one subagent.return with outcome="pending_approval" carrying the ids; NO subagent.budget.
    # Use the REAL fixture + column — `decision_store_rows` + `r.event_type` (the pattern in
    # test_subagent_audit_emit.py); `_load_chain_rows`/`r.decision_type` do NOT exist.
    returns = [r for r in decision_store_rows if r.event_type == "subagent.return"]
    assert len(returns) == 1
    assert returns[0].payload["outcome"] == "pending_approval"
    assert returns[0].payload["approval_request_id"] == "a"
    assert returns[0].payload["run_id"] == "r"
    assert not [r for r in decision_store_rows if r.event_type == "subagent.budget"]
```
And a regression: a completed child still emits `subagent.return(completed)` + `subagent.budget`; the completed return payload keyset stays `{parent_record_id, result_summary, outcome, actor_id}` (`DecisionHistoryStore.append` merges `actor_id` into the persisted payload) with **no** `approval_request_id`/`run_id` keys.

- [ ] **Step 2: Run — verify fail.**

- [ ] **Step 3: Implement.**
`audit.py`:
```python
ReturnOutcome = Literal["completed", "failed", "pending_approval"]
```
Extend `emit_return` with optional ids, added to the payload ONLY when non-None (byte-shape-compatible with every existing return row):
```python
    async def emit_return(
        self,
        *,
        actor_id: str,
        tenant_id: str,
        request_id: str,
        parent_record_id: uuid.UUID,
        result_summary: str,
        outcome: ReturnOutcome,
        approval_request_id: str | None = None,
        run_id: str | None = None,
    ) -> uuid.UUID:
        payload: dict[str, Any] = {
            "parent_record_id": str(parent_record_id),
            "result_summary": result_summary,
            "outcome": outcome,
        }
        if approval_request_id is not None:
            payload["approval_request_id"] = approval_request_id
        if run_id is not None:
            payload["run_id"] = run_id
        record_id, _ = await self._history.append(
            DecisionRecord(
                decision_type="subagent.return",
                request_id=request_id,
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=SUBAGENT_ISO_CONTROLS,
                payload=payload,
            )
        )
        return record_id
```
`spawn.py` (the `:138-150` block) — terminal-state-aware + skip budget when pending:
```python
        pending = child.terminal_state == "pending_approval"
        outcome: ReturnOutcome = (
            "pending_approval" if pending else ("completed" if child.ok else "failed")
        )
        await self._audit.emit_return(
            actor_id=...,  # unchanged args
            ...,
            result_summary=child.summary,
            outcome=outcome,
            approval_request_id=child.approval_request_id if pending else None,
            run_id=child.run_id if pending else None,
        )
        if not pending:
            await self._audit.emit_budget(
                ...,
                tokens_used=child.tokens_used,
                wall_time_used_s=child.wall_time_used_s,
            )
```
(Keep the existing `emit_return`/`emit_budget` keyword args verbatim — only add the two new return kwargs + the `if not pending` guard around budget.)

- [ ] **Step 4: Run the subagent suite + ruff + mypy.** PASS / clean / Success.

- [ ] **Step 5: Commit** — `feat(subagent): honest pending_approval audit — return outcome + skip budget (ADR-005)`.

---

## Task 4: ui_events projector — `SubagentPending` (ADR-020, backward-compatible)

**Files:** Modify `src/cognic_agentos/protocol/ui_events.py`; Modify `tests/unit/portal/api/ui/well_known_schema_snapshot.json`; Test `tests/unit/protocol/test_ui_events_subagent_emit.py` (extend — its `_snap` helper at `:95` + the `_project_typed_decision_history` dispatcher; the existing `subagent.return → completed/failed/default` tests are at `:149-167`) + the replay-drift `tests/unit/protocol/test_ui_events_dh_replay_snapshot.py` + `tests/unit/portal/api/ui/test_well_known_routes.py`.

- [ ] **Step 1: Write the failing tests.** The projector arm (mirror the existing subagent-return projector test):
```python
# Extend tests/unit/protocol/test_ui_events_subagent_emit.py — use its `_snap` helper (:95) + the
# `_project_typed_decision_history` dispatcher, mirroring the existing subagent.return tests (:149-167).
def test_subagent_return_pending_projects_to_pending() -> None:
    evt = _project_typed_decision_history(
        _snap(
            decision_type="subagent.return",
            payload={"outcome": "pending_approval", "approval_request_id": "a", "run_id": "r"},
        )
    )
    assert evt.family == "subagent"
    assert evt.type == "pending"  # NOT "failed"
    assert evt.data["approval_request_id"] == "a"


def test_subagent_return_completed_and_unknown_unchanged() -> None:
    assert (
        _project_typed_decision_history(
            _snap(decision_type="subagent.return", payload={"outcome": "completed"})
        ).type
        == "completed"
    )
    assert (
        _project_typed_decision_history(
            _snap(decision_type="subagent.return", payload={"outcome": "weird"})
        ).type
        == "failed"
    )
```
Plus the replay-snapshot drift test (already parametrized over every projector — it must still produce a typed non-None event for the pending case) and the `.well-known` snapshot test (expected to fail until the JSON is regenerated additively).

- [ ] **Step 2: Run — verify fail.**

- [ ] **Step 3: Implement.**
Add the model next to `SubagentFailed` (`:554`), mirroring its `_BaseEvent` shape:
```python
class SubagentPending(_BaseEvent):
    family: Literal["subagent"] = "subagent"
    type: Literal["pending"] = "pending"
```
Add it to the `_SubagentEvent` union (`:783`) as an additive arm. **Also register `SubagentPending` in BOTH `_TYPED_PROJECTION_CLASSES` and `__all__`** — the codebase's inline drift-invariant (`ui_events.py:1198-1200`) requires a new typed-projected class in `_TYPED_PROJECTION_CLASSES` (so the ContextVar capture fires); `SubagentFailed`/`SubagentCompleted` are in both lists, so mirror them. (These are internal-runtime + public-API registrations — they do NOT change the wire/JSON schema; the `.well-known` snapshot diff stays purely the 3 additive `subagent.pending` entries.) Update `_project_subagent_return`'s signature to `-> SubagentCompleted | SubagentFailed | SubagentPending` and insert the arm BEFORE the conservative `SubagentFailed` fallback:
```python
    if snapshot.payload.get("outcome") == "completed":
        return SubagentCompleted( ... )  # unchanged
    if snapshot.payload.get("outcome") == "pending_approval":
        return SubagentPending(
            event_id=_chain_derived_event_id(
                chain_id="decision_history", sequence=snapshot.sequence, ordinal=0,
                family=family, type_="pending",
            ),
            ts=snapshot.created_at, tenant=snapshot.tenant_id, trace_id=snapshot.trace_id,
            audit_chain_hash=_format_chain_hash(snapshot.new_hash), data=snapshot.payload,
        )
    return SubagentFailed( ... )  # unchanged conservative default
```
Regenerate the `.well-known` snapshot additively: run the well-known route / the snapshot generator and confirm the diff is ONLY the new `subagent.pending` event schema (no change to existing entries). (Confirm the exact `_BaseEvent` required fields + the snapshot-regeneration mechanism against `test_well_known_routes.py` during Step 1.)

- [ ] **Step 4: Run** the protocol ui_events suite + the well-known test + ruff + mypy. PASS / clean / Success.

- [ ] **Step 5: Commit** — `feat(ui-events): SubagentPending — project subagent.return pending_approval (ADR-020)`.

---

## Task 5: the route — `202` + `approval_request_id` threading

**Files:** Modify `src/cognic_agentos/portal/api/subagents/dto.py` + `routes.py`; Test `tests/unit/portal/api/subagents/test_routes.py` + `test_dto.py` (extend).

- [ ] **Step 1: Write the failing tests** (over the existing `_client` / `_StubSpawner` harness):
```python
def test_pending_child_returns_202_and_approval_id() -> None:
    spawner = _StubSpawner(result=SubAgentResult(
        spawn_record_id=uuid.uuid4(),
        child_result=ChildResult(summary="pending_approval_child", tokens_used=0,
            wall_time_used_s=0.1, ok=False, run_id="r1",
            terminal_state="pending_approval", approval_request_id="appr-1"),
    ))
    resp = _client(spawner=spawner).post("/api/v1/subagents", json=_body())
    assert resp.status_code == 202
    payload = resp.json()
    assert payload["approval_request_id"] == "appr-1"
    assert payload["child_result"]["terminal_state"] == "pending_approval"


def test_retry_threads_approval_request_id_to_spawn() -> None:
    grant_id = uuid.uuid4()
    spawner = _StubSpawner(result=_result())  # completed
    _client(spawner=spawner).post(
        "/api/v1/subagents", json=_body(approval_request_id=str(grant_id))
    )
    # DTO parses str -> uuid.UUID; the route str()s it back into SubAgentSpawnRequest (a str field)
    assert spawner.seen is not None  # narrows Optional for mypy (set by the spawn call)
    assert spawner.seen["request"].approval_request_id == str(grant_id)


def test_completed_child_still_200() -> None:
    resp = _client(spawner=_StubSpawner(result=_result())).post("/api/v1/subagents", json=_body())
    assert resp.status_code == 200
```
DTO: a malformed `approval_request_id` → 422 (Pydantic `uuid.UUID`); absent → None (optional).

- [ ] **Step 2: Run — verify fail.**

- [ ] **Step 3: Implement.**
`dto.py` — `SubAgentSpawnRequestBody` gains `approval_request_id: uuid.UUID | None = None`; `SubAgentSpawnResponse` gains `approval_request_id: str | None = None`. `ChildResultBody` gains `terminal_state: str | None = None` (so the pending state is visible in the body) — this additive field **ripples to the existing `test_spawn_200_returns_record_id_and_child_result`** exact-dict assertion on `child_result`: add `"terminal_state": None` to its expected dict.
`routes.py` — thread the id into the spawn request + the 202 map:
```python
        spawn_request = SubAgentSpawnRequest(
            prompt=body.prompt,
            ...,
            parent_task_id=str(record.task_id),
            approval_request_id=str(body.approval_request_id) if body.approval_request_id else None,
        )
        ...
        is_pending = (
            result.child_result.terminal_state == "pending_approval"
            and result.child_result.approval_request_id is not None
        )
        response.status_code = 202 if is_pending else 200
        return SubAgentSpawnResponse(
            spawn_record_id=str(result.spawn_record_id),
            child_result=ChildResultBody(
                ok=result.child_result.ok,
                summary=result.child_result.summary,
                tokens_used=result.child_result.tokens_used,
                wall_time_used_s=result.child_result.wall_time_used_s,
                terminal_state=result.child_result.terminal_state,
            ),
            approval_request_id=result.child_result.approval_request_id,
        )
```
(Add `response: Response` to the handler params + `from fastapi import Response` — mirror the run route's status-setting pattern. The 404/409/403×2/503 gates are unchanged.)

- [ ] **Step 4: Run** `tests/unit/portal/api/subagents/ -q` + ruff + mypy. PASS / clean / Success.

- [ ] **Step 5: Commit** — `feat(portal): subagents 202 + approval_request_id retry (ADR-005)`.

---

## Task 6: closeout — full gates + CC + docs

- [ ] **Step 1: Full quality gate** — `uv run ruff check . && uv run ruff format --check . && uv run mypy src tests`.
- [ ] **Step 2: Full suite on fresh coverage** — `uv run pytest -q --cov=cognic_agentos --cov-branch --cov-report=json:coverage.json`.
- [ ] **Step 3: CC gate** — `uv run python tools/check_critical_coverage.py` → `passed`. **No new gate module** (edits to already-on-gate `subagent/*` + `protocol/ui_events.py`); every on-gate touched module must stay ≥ 95/90 on fresh data — if any dropped, add focused tests in the SAME commit.
- [ ] **Step 4: Operator e2e (env-gated `COGNIC_RUN_DOCKER_SANDBOX=1`)** — new `tests/integration/run/test_subagent_approval_retry_e2e.py`: high-risk child spawn → pending (`child_result.terminal_state="pending_approval"` + `approval_request_id`) → real `ApprovalEngine.grant()` → re-spawn with the id → `completed`; assert the chain carries `subagent.return(pending_approval)` (no `subagent.budget`) then a fresh `subagent.spawn → return(completed)` (+ budget). Module-collectable-skips-without-docker (copy `test_managed_run_subagent_e2e.py` + the high-risk `pack.lifecycle.submitted` manifest + real `ApprovalEngine` from `test_managed_run_high_risk_e2e.py`).
  - **GAP this e2e surfaced (fix landed in the closeout commit):** the full `SubAgentSpawnRequest → ChildRunContext` threading was incomplete — `spawn.py`'s `ChildRunContext(...)` constructor (`:120-133`) was missing `approval_request_id=request.approval_request_id`, so the granted id was dropped before the runner (the retry pended forever). No unit test caught it (T2 set `context.approval_request_id` directly; T5 stubbed the spawner). **Fix:** add `approval_request_id=request.approval_request_id` to the `ChildRunContext(...)` build (`subagent/spawn.py`, on-gate stop-rule) + a pinning unit test `test_spawn_threads_approval_request_id_onto_child_context` in `test_subagent_spawn.py` (asserts the runner's `seen_context.approval_request_id`). A re-execution should fold this into T3 (the spawn.py edit) rather than re-discovering it here.
- [ ] **Step 5: Docs** — ADR-005 amendment ("child approval-retry semantics") + ADR-020 amendment (the `SubagentPending` additive event) + AS_BUILT milestone + the spec status DRAFT → LANDED. Commit `docs(subagent): ADR-005/ADR-020 + AS_BUILT — child approval-retry (ADR-005/ADR-020)`.

---

## Self-review checklist (run before execution)

- **Spec coverage:** §1 ChildResult (T1), §2 threading (T1+T2+T5), §3 runner (T2), §4 ReturnOutcome (T3), §5 spawn.py skip-budget (T3), §6 ui_events projector (T4), §7 route 202 (T5), §8 no-resume-endpoint (honored — no new route). ✓
- **Backward-compat-additive everywhere:** a new enum value (`ReturnOutcome`), a new event type (`SubagentPending`), defaulted fields — confirmed; existing chain rows + UI consumers unaffected; the non-pending `subagent.return` payload stays byte-identical (conditional keys). ✓
- **Harness-verify points (don't guess):** the real `RunResult` field shape (T2 Step 1), the `.well-known` snapshot-regeneration mechanism (T4 Step 1; the projector test uses the existing `_snap` helper + `_project_typed_decision_history` in `test_ui_events_subagent_emit.py` — `_dh_snapshot` does NOT exist), the spawn.py `emit_return`/`emit_budget` exact call-site args (T3 Step 3).
- **CC stays at current count, no migration, `core-controls-engineer` + `/critical-module-mode`.** ✓
