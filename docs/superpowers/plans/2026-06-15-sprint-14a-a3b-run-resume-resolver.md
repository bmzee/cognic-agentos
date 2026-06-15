# Sprint 14A-A3b — Run→Session Resolver + Resume Route Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the A3a-dormant `RunRecordStore` into the managed-run executor, add an explicit-suspend path, and add a `POST /api/v1/runs/{run_id}/resume` route that resolves `run_id → session_id` and dispatches `backend.wake()` — proving the resumable-session vertical end-to-end while keeping `POST /api/v1/runs` additively-stable and the A3c approval correlator fully out.

**Architecture:** The executor (`core/run/executor.py`, on the CC gate) becomes the run-record authority: mints a `run_id`, writes a genesis `run.lifecycle.pending`, drives the record through its lifecycle, and on `suspend_after_exec` calls `session.suspend()` instead of `session.destroy()` (persisting `session_id` + `checkpoint_id`). A new `executor.resume()` + resume route resolves the record, wakes by `session_id`, runs a continuation `argv`, completes. `RunState` vocab is unchanged (fixed at A3a); only the transition matrix expands.

**Tech Stack:** Python 3.12, SQLAlchemy async (in-memory sqlite for unit DB; the `runs` table from A3a migration `0011` — **no new migration**), FastAPI, the existing resumable-session API (`SandboxSession.suspend()`, `SandboxBackend.wake()`, `CheckpointStore.load_latest()`), `RunRecordStore`. uv; pytest (`asyncio_mode=auto`); mypy strict (`tests.*` untyped allowed); 100-char lines.

**Source of truth:** `docs/superpowers/specs/2026-06-15-sprint-14a-a3b-run-resume-resolver-design.md` (committed `079f1fd`). This plan mirrors it exactly.

---

## File structure

| File | Gate | Change |
|---|---|---|
| `src/cognic_agentos/core/run/_types.py` | off | `_A3B_VALID_TRANSITIONS` + `_VALID_TRANSITIONS` union; `validate_transition` checks the union; doctrine docstring |
| `src/cognic_agentos/core/run/storage.py` | **CC** | `_STATE_TO_DECISION_TYPE += {suspended, woken}` |
| `src/cognic_agentos/core/run/executor.py` | **CC** | `RunResult.run_id`; `RunTerminalState +suspended`; `RunRequest.suspend_after_exec`; emitter contract (`run_id`+nullable `task_id`) + `_emit_suspended`; `run()` rework (genesis + run-record wiring + suspend path + conditional teardown); new constructor deps; `resume()` (claim-gated teardown) + `RunNotResumable` + `RunResumeConflict` |
| `src/cognic_agentos/portal/api/app.py` | off | checkpoint-store fail-soft resolution + thread `run_record_store`/`checkpoint_store` into the executor |
| `src/cognic_agentos/harness/sandbox.py` | off | docstring only (already accepts `checkpoint_store`) |
| `src/cognic_agentos/portal/rbac/scopes.py` | **CC** | `RunRBACScope += "run.resume"` + `RUN_SCOPES` |
| `src/cognic_agentos/portal/api/runs/dto.py` | off | `_validate_argv_bounds` shared helper; `RunResumeRequest`; `RunResponse.run_id` + `terminal_state +suspended` |
| `src/cognic_agentos/portal/api/runs/routes.py` | off | `_run_response_from_result` projector; resume route + `run.resume` + `suspended→202` + pre-flight 404/409 |
| docs | — | ADR-022, ADR-004, AGENTS.md, capability map |

**Tests:** `tests/unit/core/run/test_run_types.py`, `tests/unit/core/run/test_run_storage.py`, `tests/unit/core/run/test_executor.py`, `tests/unit/portal/rbac/test_run_scopes.py`, `tests/unit/portal/api/runs/test_run_routes.py` (+ dto tests), `tests/unit/portal/api/test_app_sandbox_state.py` (composition), `tests/unit/architecture/test_run_no_sdk_import.py`, `tests/integration/run/test_managed_run_resume_e2e.py`.

**CC count stays 131** — A3b touches only modules already on the gate (`executor.py`, `storage.py`, `scopes.py`); it adds **no** new on-gate module. `tools/check_critical_coverage.py` `_CRITICAL_FILES` and `tests/unit/tools/test_check_critical_coverage.py` `_EXPECTED_ENTRY_COUNT` are **UNCHANGED**.

---

## Standing execution discipline (every task)

- **TDD:** write the failing test first, run it, watch it fail for the right reason, then the minimal implementation, then watch it pass.
- **Halt-before-commit reviewer gate (EVERY task):** after the gate ladder, STOP and present: the watchpoint→pin mapping, fresh gate-ladder evidence (commands + output), and "files modified" (not staged). Wait for an explicit full-word commit token. Stage by explicit path; commit with footer `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- **Gate ladder (per task):** focused pytest → neighborhood pytest (incl. `tests/unit/architecture/`) → `uv run ruff check .` → `uv run ruff format --check .` → full-tree `uv run mypy src tests`.
- **Verify-at-promotion (CC tasks T2/T3/T4/T5):** in the SAME commit, run the full suite with `--cov-branch`, then `uv run coverage json -o coverage.json` (NOT `--cov-report=json`), then `uv run python tools/check_critical_coverage.py`. The touched on-gate file must be ≥95% line / ≥90% branch; if at-floor, add coverage for headroom.
- **Boundary checkpoint (after T3 and after T6):** full suite + `check_critical_coverage.py` (count must read 131).
- **NEVER stage** `docs/reviews/` or `docs/superpowers/specs/2026-05-26-agentos-local-managed-agents-gap-analysis.md`.
- One `uv run` at a time (the venv lock deadlocks on parallel runs). No src edits during a background `--cov` run.
- Branch is `feat/sprint-14a-a3b-run-resume-resolver` (already created; spec `079f1fd` on it).

---

## Task 1: `_types.py` — expand the transition matrix (off-gate)

**Files:**
- Modify: `src/cognic_agentos/core/run/_types.py`
- Test: `tests/unit/core/run/test_run_types.py`

- [ ] **Step 1: Write the failing tests.** Append to `test_run_types.py`:

```python
_A3B_LEGAL_PAIRS = {
    ("running", "suspended"),
    ("suspended", "woken"),
    ("suspended", "refused"),
    ("suspended", "failed"),
    ("woken", "completed"),
    ("woken", "failed"),
}

# Reserved AFTER A3b — pairs the A3b runtime cannot produce (no re-loop, no
# re-suspend, no direct suspended->completed, no post-wake refusal/pending,
# cancelled still deferred). The doctrine pin: these refuse today.
_RESERVED_PAIRS_A3B = {
    ("woken", "running"),
    ("woken", "suspended"),
    ("suspended", "completed"),
    ("suspended", "pending_approval"),
    ("running", "cancelled"),
    ("pending", "cancelled"),
    ("suspended", "cancelled"),
}


@pytest.mark.parametrize("pair", sorted(_A3B_LEGAL_PAIRS))
def test_a3b_suspend_wake_pairs_are_legal(pair: tuple[str, str]) -> None:
    validate_transition(from_state=pair[0], to_state=pair[1])  # type: ignore[arg-type]  # no raise


@pytest.mark.parametrize("pair", sorted(_RESERVED_PAIRS_A3B))
def test_reserved_pairs_refuse_after_a3b(pair: tuple[str, str]) -> None:
    with pytest.raises(RunTransitionRefused) as exc:
        validate_transition(from_state=pair[0], to_state=pair[1])  # type: ignore[arg-type]
    assert exc.value.reason == "run_transition_invalid_state_pair"


def test_run_state_vocabulary_still_exactly_nine_after_a3b() -> None:
    # A3b EXPANDS the matrix, never the vocabulary.
    assert len(get_args(RunState)) == 9
```

Also **delete** the A3a `test_reserved_pairs_refuse_until_expanded` test (it asserted `running→suspended`/`suspended→woken` refuse — now legal). Its successor is `test_reserved_pairs_refuse_after_a3b`.

- [ ] **Step 2: Run, watch fail.** `uv run pytest tests/unit/core/run/test_run_types.py -q`. Expected: `test_a3b_suspend_wake_pairs_are_legal` FAILS (those pairs raise today).

- [ ] **Step 3: Implement.** In `_types.py`, after `_A3A_VALID_TRANSITIONS`, add the A3b delta + union, and point `validate_transition` at the union:

```python
#: Sprint 14A-A3b — EXPAND ONLY (vocab unchanged): the suspend/wake pairs the
#: A3b runtime can actually produce. No woken->refused (no post-wake refusal
#: source); no woken->running / woken->suspended (no re-loop / re-suspend); no
#: cancelled pairs (still reserved).
_A3B_VALID_TRANSITIONS: Final[frozenset[tuple[RunState, RunState]]] = frozenset(
    {
        ("running", "suspended"),
        ("suspended", "woken"),
        ("suspended", "refused"),
        ("suspended", "failed"),
        ("woken", "completed"),
        ("woken", "failed"),
    }
)

#: The full legal matrix consumed by validate_transition (12 pairs).
_VALID_TRANSITIONS: Final[frozenset[tuple[RunState, RunState]]] = (
    _A3A_VALID_TRANSITIONS | _A3B_VALID_TRANSITIONS
)
```

Change the validator body:

```python
    if (from_state, to_state) not in _VALID_TRANSITIONS:
        raise RunTransitionRefused("run_transition_invalid_state_pair")
```

Update the module DOCTRINE docstring: the example pin is now `test_reserved_pairs_refuse_after_a3b`; note A3b expanded `_A3B_VALID_TRANSITIONS` over the fixed 9-value vocab.

- [ ] **Step 4: Run, watch pass.** `uv run pytest tests/unit/core/run/test_run_types.py -q`. Expected: all pass.

- [ ] **Step 5: Gate ladder.** Focused + `tests/unit/core/run/` + ruff check + ruff format --check + `uv run mypy src tests`.

- [ ] **Step 6: Halt-before-commit.** Watchpoints: (a) vocab unchanged at 9 — pinned by `test_run_state_vocabulary_still_exactly_nine_after_a3b`; (b) only the 6 producible pairs legal — `test_a3b_suspend_wake_pairs_are_legal`; (c) still-reserved refuse — `test_reserved_pairs_refuse_after_a3b`. Present fresh evidence + files modified. Await token.

- [ ] **Step 7: Commit** (on token). Stage `src/cognic_agentos/core/run/_types.py tests/unit/core/run/test_run_types.py`. Message: `feat(run): A3b expand run-transition matrix with suspend/wake pairs (ADR-022)`.

---

## Task 2: `storage.py` — new transition targets (CC)

**Files:**
- Modify: `src/cognic_agentos/core/run/storage.py`
- Test: `tests/unit/core/run/test_run_storage.py`

- [ ] **Step 1: Write the failing tests.** Mirror the A3a fixture in `test_run_storage.py` (in-memory sqlite engine + `_metadata.create_all`, build a `RunRecordStore`, `create_run` a genesis row, `transition` pending→running). Add:

```python
@pytest.mark.asyncio
async def test_running_to_suspended_persists_session_and_checkpoint(run_store) -> None:
    store, engine = run_store
    run_id = uuid.uuid4()
    await store.create_run(run_id=run_id, tenant_id="t1", pack_id="p", pack_uuid=uuid.uuid4(),
                           pack_version="1", request_id="rq")
    await store.transition(run_id=run_id, tenant_id="t1", from_state="pending", to_state="running",
                           actor_id="alice", request_id="rq", task_id=uuid.uuid4())
    cid = uuid.uuid4().hex  # CheckpointId hex (32 chars)
    await store.transition(run_id=run_id, tenant_id="t1", from_state="running", to_state="suspended",
                           actor_id="alice", request_id="rq", session_id="sess-1", checkpoint_id=cid)
    rec = await store.load(run_id, tenant_id="t1")
    assert rec is not None and rec.state == "suspended"
    assert rec.session_id == "sess-1" and rec.checkpoint_id == cid


@pytest.mark.asyncio
async def test_suspended_to_woken_to_completed(run_store) -> None:
    store, _ = run_store
    run_id = uuid.uuid4()
    await store.create_run(run_id=run_id, tenant_id="t1", pack_id="p", pack_uuid=uuid.uuid4(),
                           pack_version="1", request_id="rq")
    for frm, to, kw in [("pending", "running", {"task_id": uuid.uuid4()}),
                        ("running", "suspended", {"session_id": "s", "checkpoint_id": uuid.uuid4().hex}),
                        ("suspended", "woken", {}), ("woken", "completed", {})]:
        await store.transition(run_id=run_id, tenant_id="t1", from_state=frm, to_state=to,
                               actor_id="alice", request_id="rq", **kw)
    rec = await store.load(run_id, tenant_id="t1")
    assert rec is not None and rec.state == "completed"


@pytest.mark.asyncio
async def test_suspended_decision_type_is_run_lifecycle_suspended(run_store) -> None:
    from cognic_agentos.core.run.storage import _STATE_TO_DECISION_TYPE
    assert _STATE_TO_DECISION_TYPE["suspended"] == "run.lifecycle.suspended"
    assert _STATE_TO_DECISION_TYPE["woken"] == "run.lifecycle.woken"


@pytest.mark.asyncio
async def test_stale_read_on_suspend_pair_refuses(run_store) -> None:
    store, _ = run_store
    run_id = uuid.uuid4()
    await store.create_run(run_id=run_id, tenant_id="t1", pack_id="p", pack_uuid=uuid.uuid4(),
                           pack_version="1", request_id="rq")
    # row is 'pending'; claim from_state='running' -> stale -> refused
    with pytest.raises(RunTransitionRefused) as exc:
        await store.transition(run_id=run_id, tenant_id="t1", from_state="running",
                               to_state="suspended", actor_id="a", request_id="rq",
                               session_id="s", checkpoint_id=uuid.uuid4().hex)
    assert exc.value.reason == "run_transition_invalid_state_pair"
```

- [ ] **Step 2: Run, watch fail.** `uv run pytest tests/unit/core/run/test_run_storage.py -q`. Expected: `test_running_to_suspended_*` FAIL — the `to_state="suspended"` preflight `to_state not in _STATE_TO_DECISION_TYPE` raises `run_transition_invalid_state_pair` today.

- [ ] **Step 3: Implement.** In `storage.py`, extend `_STATE_TO_DECISION_TYPE`:

```python
_STATE_TO_DECISION_TYPE: Final[dict[RunState, str]] = {
    "running": "run.lifecycle.running",
    "completed": "run.lifecycle.completed",
    "failed": "run.lifecycle.failed",
    "refused": "run.lifecycle.refused",
    "pending_approval": "run.lifecycle.pending_approval",
    "suspended": "run.lifecycle.suspended",  # A3b
    "woken": "run.lifecycle.woken",          # A3b
}
```

Update the map's docstring comment from "A3a subset (5 reachable …)" to note A3b added suspended/woken alongside `_A3B_VALID_TRANSITIONS`. No other change — the nullable column kwargs + the `validate_transition` call already handle the new pairs (T1 made them legal).

- [ ] **Step 4: Run, watch pass.** `uv run pytest tests/unit/core/run/test_run_storage.py -q`. Expected: all pass.

- [ ] **Step 5: Gate ladder + verify-at-promotion.** Gate ladder, then full suite with `--cov-branch`, `uv run coverage json -o coverage.json`, `uv run python tools/check_critical_coverage.py`. `core/run/storage.py` must stay ≥95/90 (the two new map entries are data, not branches — coverage holds; if the new transition-target paths dipped branch coverage, the four tests above cover them).

- [ ] **Step 6: Halt-before-commit.** Watchpoints: suspended/woken targets emit the right `decision_type` + persist session_id/checkpoint_id (the four tests); CC coverage ≥95/90 on fresh data; count still 131. Present evidence + files modified. Await token.

- [ ] **Step 7: Commit** (on token). Stage `src/cognic_agentos/core/run/storage.py tests/unit/core/run/test_run_storage.py`. Message: `feat(run): A3b storage suspended/woken lifecycle decision-types (ADR-022)`.

---

## Task 3: `executor.py` run-record wiring + suspend path + composition (CC + off-gate)

**Files:**
- Modify: `src/cognic_agentos/core/run/executor.py`
- Modify: `src/cognic_agentos/portal/api/app.py`
- Modify: `src/cognic_agentos/harness/sandbox.py`
- Test: `tests/unit/core/run/test_executor.py`, `tests/unit/portal/api/test_app_sandbox_state.py`, `tests/unit/architecture/test_run_no_sdk_import.py`

This task bundles the executor constructor change with its sole production call site (`app.py`) so mypy + the suite stay green in one commit. `resume()` is T4.

- [ ] **Step 1: Write failing executor tests.** In `test_executor.py` extend the existing stub-backend orchestration suite (real scheduler + real `RunRecordStore` + real `DecisionHistoryStore` on in-memory sqlite; stub backend + stub checkpoint-store). Add a stub session that records `destroy`/`suspend` calls and a stub checkpoint-store returning a `CheckpointMetadata`-shaped object with a `checkpoint_id`. Key tests:

```python
async def test_run_mints_run_id_and_genesis_on_every_path(...):
    # a refused run (e.g. pack_not_installed) still returns a non-empty run_id
    result = await executor.run(req_refused)
    assert result.run_id  # non-empty
    # and a run.lifecycle.pending row exists for it
    assert await _count_lifecycle(engine, result.run_id, "run.lifecycle.pending") == 1

async def test_suspend_after_exec_suspends_and_skips_destroy(...):
    stub_session = StubSession(exit_code=0)
    result = await executor.run(replace(req_ok, suspend_after_exec=True))
    assert result.terminal_state == "suspended"
    assert stub_session.suspend_calls == 1
    assert stub_session.destroy_calls == 0           # conditional teardown skipped
    rec = await run_store.load(uuid.UUID(result.run_id), tenant_id="t1")
    assert rec.state == "suspended" and rec.session_id and rec.checkpoint_id
    # direct run.suspended evidence carries run_id + session_id + checkpoint_id
    payload = await _latest_payload(engine, "run.suspended")
    assert payload["run_id"] == result.run_id and payload["checkpoint_id"]

async def test_run_without_suspend_completes_and_destroys(...):
    result = await executor.run(req_ok)
    assert result.terminal_state == "completed"
    assert stub_session.destroy_calls == 1

async def test_direct_run_events_carry_run_id(...):
    result = await executor.run(req_ok)
    payload = await _latest_payload(engine, "run.completed")
    assert payload["run_id"] == result.run_id and payload["task_id"] is not None
```

- [ ] **Step 2: Run, watch fail.** `uv run pytest tests/unit/core/run/test_executor.py -q`. Expected: fail — `RunResult` has no `run_id`; `suspend_after_exec` not a field; constructor missing `run_record_store`/`checkpoint_store`.

- [ ] **Step 3a: Implement shapes + emitter contract.** In `executor.py`:

```python
RunTerminalState = Literal["completed", "failed", "refused", "pending_approval", "suspended"]  # +suspended

@dataclass(frozen=True)
class RunRequest:
    tenant_id: str
    pack_id: str
    pack_uuid: uuid.UUID
    pack_version: str
    argv: tuple[str, ...]
    actor: Actor
    approval_request_id: uuid.UUID | None = None
    suspend_after_exec: bool = False           # A3b — F2

@dataclass(frozen=True)
class RunResult:
    run_id: str                                 # A3b — F1, populated on every path
    task_id: str | None
    terminal_state: RunTerminalState
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    refusal_reason: str | None
    approval_request_id: str | None = None
```

Add `RunRecordStore`/`RunNotFound` import and the `CheckpointStore` TYPE_CHECKING import:

```python
from cognic_agentos.core.run.storage import RunNotFound, RunRecordStore  # core->core, SDK-free
if TYPE_CHECKING:
    ...
    from cognic_agentos.sandbox.checkpoint_store import CheckpointStore
```

Constructor adds the two deps:

```python
    def __init__(self, *, scheduler, sandbox_backend, pack_loader,
                 decision_history_store, settings,
                 run_record_store: RunRecordStore,
                 checkpoint_store: CheckpointStore) -> None:
        ...
        self._runs = run_record_store
        self._checkpoints = checkpoint_store
```

Rework the five emitters to the P1b contract — keyword-only `run_id: str` (always) + `task_id: str | None` (nullable), payloading both; add `_emit_suspended`:

```python
    async def _emit_completed(self, request, request_id, *, run_id: str, task_id: str | None,
                              result: SandboxExecResult) -> None:
        await self._dh.append(DecisionRecord(
            decision_type="run.completed", request_id=request_id,
            payload={"run_id": run_id, "task_id": task_id, "exit_code": result.exit_code,
                     "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                     "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
                     "stdout_bytes": len(result.stdout), "stderr_bytes": len(result.stderr)},
            actor_id=request.actor.subject, tenant_id=request.tenant_id,
            iso_controls=_RUN_EVIDENCE_ISO_CONTROLS))

    async def _emit_failed(self, request, request_id, *, run_id: str, task_id: str | None,
                           reason: RunFailedReason) -> None:
        await self._dh.append(DecisionRecord(
            decision_type="run.failed", request_id=request_id,
            payload={"run_id": run_id, "task_id": task_id, "reason": reason},
            actor_id=request.actor.subject, tenant_id=request.tenant_id,
            iso_controls=_RUN_EVIDENCE_ISO_CONTROLS))

    async def _emit_pending(self, request, request_id, *, run_id: str, task_id: str | None,
                            approval_request_id: str | None) -> None:
        await self._dh.append(DecisionRecord(
            decision_type="run.pending_approval", request_id=request_id,
            payload={"run_id": run_id, "task_id": task_id,
                     "approval_reason": _SANDBOX_APPROVAL_PENDING_REASON,
                     "approval_request_id": approval_request_id},
            actor_id=request.actor.subject, tenant_id=request.tenant_id,
            iso_controls=_RUN_EVIDENCE_ISO_CONTROLS))

    async def _emit_refused(self, request, request_id, *, run_id: str, task_id: str | None,
                            reason: str) -> None:
        # P1b: run.refused ALSO carries run_id + nullable task_id (join key). task_id
        # is None for pack/preflight/resume refusals, the scheduler task id otherwise.
        await self._dh.append(DecisionRecord(
            decision_type="run.refused", request_id=request_id,
            payload={"run_id": run_id, "task_id": task_id, "reason": reason,
                     "pack_id": request.pack_id},
            actor_id=request.actor.subject, tenant_id=request.tenant_id,
            iso_controls=_RUN_EVIDENCE_ISO_CONTROLS))

    async def _emit_suspended(self, request, request_id, *, run_id: str, task_id: str | None,
                              result: SandboxExecResult, session_id: str, checkpoint_id: str) -> None:
        await self._dh.append(DecisionRecord(
            decision_type="run.suspended", request_id=request_id,
            payload={"run_id": run_id, "task_id": task_id, "exit_code": result.exit_code,
                     "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                     "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
                     "stdout_bytes": len(result.stdout), "stderr_bytes": len(result.stderr),
                     "session_id": session_id, "checkpoint_id": checkpoint_id},
            actor_id=request.actor.subject, tenant_id=request.tenant_id,
            iso_controls=_RUN_EVIDENCE_ISO_CONTROLS))
```

- [ ] **Step 3b: Implement `run()` rework.** Keep the confused-deputy guard first. After it: mint `run_id` + genesis, then thread a run-record transition into **every** terminal path, update every `RunResult(...)` to include `run_id`, and add the suspend branch + conditional teardown. The exact insertions (call them with the grounded `transition` signature — `from_state`/`to_state`/`actor_id`/`request_id` keyword):

```python
        run_id = uuid.uuid4()
        await self._runs.create_run(
            run_id=run_id, tenant_id=request.tenant_id, pack_id=request.pack_id,
            pack_uuid=request.pack_uuid, pack_version=request.pack_version, request_id=request_id)
        rid = str(run_id)

        # pack refusal:
        if refusal is not None:
            await self._runs.transition(run_id=run_id, tenant_id=request.tenant_id,
                from_state="pending", to_state="refused", actor_id=request.actor.subject,
                request_id=request_id)
            await self._emit_refused(request, request_id, run_id=rid, task_id=None, reason=refusal)
            return RunResult(run_id=rid, task_id=None, terminal_state="refused", exit_code=None,
                             stdout=b"", stderr=b"", refusal_reason=refusal)

        # queued -> cancel + pending->refused:
        # non-immediate -> pending->refused:
        #   (both mirror the pack-refusal block: transition pending->refused, then
        #    _emit_refused(request, request_id, run_id=rid, task_id=decision.task_id,
        #    reason=<reason>), then return RunResult(run_id=rid, task_id=decision.task_id,
        #    terminal_state="refused", ...) — task_id is the scheduler task id here, not None)

        # after mark_running:
        await self._scheduler.mark_running(task_id, request_id=request_id)
        await self._runs.transition(run_id=run_id, tenant_id=request.tenant_id,
            from_state="pending", to_state="running", actor_id=request.actor.subject,
            request_id=request_id, task_id=task_id)

        session = None
        skip_destroy = False
        try:
            try:
                session = await self._sandbox_backend.create(policy, actor=request.actor,
                    tenant_id=request.tenant_id, pack_context=ctx, requires_credentials=(),
                    approval_request_id=request.approval_request_id)
            except SandboxLifecycleRefused as exc:
                if exc.reason == _SANDBOX_APPROVAL_PENDING_REASON:
                    await self._scheduler.cancel(task_id, actor=task_actor,
                        reason="actor_cancelled", request_id=request_id)
                    await self._runs.transition(run_id=run_id, tenant_id=request.tenant_id,
                        from_state="running", to_state="pending_approval",
                        actor_id=request.actor.subject, request_id=request_id,
                        approval_request_id=(uuid.UUID(exc.approval_request_id)
                                             if exc.approval_request_id else None))
                    await self._emit_pending(request, request_id, run_id=rid, task_id=decision.task_id,
                        approval_request_id=exc.approval_request_id)
                    return RunResult(run_id=rid, task_id=decision.task_id,
                        terminal_state="pending_approval", exit_code=None, stdout=b"", stderr=b"",
                        refusal_reason=None, approval_request_id=exc.approval_request_id)
                await self._scheduler.cancel(task_id, actor=task_actor,
                    reason="actor_cancelled", request_id=request_id)
                await self._runs.transition(run_id=run_id, tenant_id=request.tenant_id,
                    from_state="running", to_state="refused", actor_id=request.actor.subject,
                    request_id=request_id)
                await self._emit_refused(request, request_id, run_id=rid, task_id=decision.task_id,
                    reason=str(exc.reason))
                return RunResult(run_id=rid, task_id=decision.task_id, terminal_state="refused",
                    exit_code=None, stdout=b"", stderr=b"", refusal_reason=str(exc.reason))
            except Exception as exc:
                await self._scheduler.fail(task_id, payload=TaskFailedPayload(
                    reason="scheduler_task_failed_sandbox_create_refused",
                    sandbox_refusal_reason=_refusal_detail(exc)), request_id=request_id)
                await self._runs.transition(run_id=run_id, tenant_id=request.tenant_id,
                    from_state="running", to_state="failed", actor_id=request.actor.subject,
                    request_id=request_id)
                await self._emit_failed(request, request_id, run_id=rid, task_id=decision.task_id,
                    reason="sandbox_create_refused")
                return RunResult(run_id=rid, task_id=decision.task_id, terminal_state="failed",
                    exit_code=None, stdout=b"", stderr=b"", refusal_reason=None)

            try:
                exec_result = await session.exec(list(request.argv), timeout_s=policy.walltime_s)
            except Exception:
                await self._scheduler.fail(task_id, payload=TaskFailedPayload(
                    reason="scheduler_task_failed_workload_runtime_error"), request_id=request_id)
                await self._runs.transition(run_id=run_id, tenant_id=request.tenant_id,
                    from_state="running", to_state="failed", actor_id=request.actor.subject,
                    request_id=request_id)
                await self._emit_failed(request, request_id, run_id=rid, task_id=decision.task_id,
                    reason="workload_runtime_error")
                return RunResult(run_id=rid, task_id=decision.task_id, terminal_state="failed",
                    exit_code=None, stdout=b"", stderr=b"", refusal_reason=None)

            if request.suspend_after_exec:
                await session.suspend()
                skip_destroy = True   # IMMEDIATELY — irrevocable; no destroy after this point
                meta, _ = await self._checkpoints.load_latest(
                    session_id=session.session_id, tenant_id=request.tenant_id)
                await self._runs.transition(run_id=run_id, tenant_id=request.tenant_id,
                    from_state="running", to_state="suspended", actor_id=request.actor.subject,
                    request_id=request_id, session_id=session.session_id,
                    checkpoint_id=meta.checkpoint_id)
                await self._scheduler.complete(task_id, request_id=request_id)
                await self._emit_suspended(request, request_id, run_id=rid, task_id=decision.task_id,
                    result=exec_result, session_id=session.session_id, checkpoint_id=meta.checkpoint_id)
                return RunResult(run_id=rid, task_id=decision.task_id, terminal_state="suspended",
                    exit_code=exec_result.exit_code, stdout=exec_result.stdout,
                    stderr=exec_result.stderr, refusal_reason=None)

            await self._scheduler.complete(task_id, request_id=request_id)
            await self._runs.transition(run_id=run_id, tenant_id=request.tenant_id,
                from_state="running", to_state="completed", actor_id=request.actor.subject,
                request_id=request_id)
            await self._emit_completed(request, request_id, run_id=rid, task_id=decision.task_id,
                result=exec_result)
            return RunResult(run_id=rid, task_id=decision.task_id, terminal_state="completed",
                exit_code=exec_result.exit_code, stdout=exec_result.stdout,
                stderr=exec_result.stderr, refusal_reason=None)
        finally:
            if session is not None and not skip_destroy:
                try:
                    await session.destroy()
                except Exception:
                    logger.warning("run.session_destroy_failed",
                        extra={"request_id": request_id, "run_id": rid,
                               "session_id": session.session_id})
```

(Post-suspend failure posture per spec: `skip_destroy=True` is set the instant `suspend()` returns, so a failure in `load_latest`/`transition`/`complete`/`_emit_suspended` propagates without ever destroying the session.)

- [ ] **Step 3c: Composition (app.py + harness).** In `app.py`, replace the sandbox-block body so the checkpoint store is resolved **inside** the try and threaded into both the backend and the executor (per spec §7):

```python
            if (is_sandbox_available(settings) and settings.sandbox_runtime_enabled
                    and runtime.scheduler is not None):
                from cognic_agentos.core.run.executor import ManagedRunExecutor
                from cognic_agentos.core.run.storage import RunRecordStore
                from cognic_agentos.harness.sandbox import PackRecordStoreLoader, build_sandbox_backend
                try:
                    checkpoint_store = (app.state.checkpoint_store
                        or _build_checkpoint_store_from_adapters(adapters, settings))
                    # Share the resolved store with the reaper block below (the
                    # early injected_store capture at app.py:551 predates this block,
                    # so the reaper re-reads app.state.checkpoint_store at build time).
                    app.state.checkpoint_store = checkpoint_store
                    backend, sandbox_docker_client = await build_sandbox_backend(
                        settings=settings, runtime=runtime, checkpoint_store=checkpoint_store)
                    app.state.sandbox_backend = backend
                    app.state.managed_run_executor = ManagedRunExecutor(
                        scheduler=runtime.scheduler, sandbox_backend=backend,
                        pack_loader=PackRecordStoreLoader(
                            store=PackRecordStore(adapters.relational.engine)),
                        decision_history_store=runtime.decision_history_store, settings=settings,
                        run_record_store=RunRecordStore(adapters.relational.engine),
                        checkpoint_store=checkpoint_store)
                except Exception:
                    logger.error("sandbox.runtime_construction_failed", exc_info=True)
                    if sandbox_docker_client is not None:
                        await sandbox_docker_client.close()
                    sandbox_docker_client = None
                    app.state.sandbox_backend = None
                    app.state.managed_run_executor = None
```

Patch the existing setting-driven reaper block at `app.py:714-715` to reuse the resolved store instead of unconditionally building a second one — change `store = _build_checkpoint_store_from_adapters(adapters, settings)` to:

```python
                if setting_driven_reaper:
                    store = (app.state.checkpoint_store
                        or _build_checkpoint_store_from_adapters(adapters, settings))
                    reaper_task = _start_checkpoint_reaper(store)
                    ...
```

This keeps ONE `CheckpointStore` across the sandbox runtime + reaper. (The `setting_driven_reaper` precedence is unchanged — a `create_app(checkpoint_store=...)` injection still wins via the explicit-injection path at `app.py:545`; the setting-driven path now reuses the sandbox-resolved store when present, else builds its own and still fail-louds per #489 §4.3.2 if the build raises.) In `harness/sandbox.py`, update only the docstring note: "`checkpoint_store=None` in 14A-A; **wired in A3b** (14A-A2 wired the route + approval, not the checkpoint store)".

- [ ] **Step 3d: Architecture fence.** In `tests/unit/architecture/test_run_no_sdk_import.py`, confirm the expected-imports assertion still holds: `executor.py` adds only the `core.run.storage` runtime import (core→core) + a TYPE_CHECKING `CheckpointStore` — no `aiodocker`/`kubernetes_asyncio`/runtime `portal`. If the test enumerates allowed runtime imports, add `cognic_agentos.core.run.storage`. Run `uv run pytest tests/unit/architecture/test_run_no_sdk_import.py -q` and confirm green.

- [ ] **Step 4: Run, watch pass.** `uv run pytest tests/unit/core/run/test_executor.py tests/unit/portal/api/test_app_sandbox_state.py -q`. Update the lifespan composition tests so the executor-construction path passes the two new deps (and the fail-soft test still nulls both slots). Watch pass.

- [ ] **Step 5: Gate ladder + verify-at-promotion + boundary.** Gate ladder (incl. architecture fence). Then full suite `--cov-branch` → `uv run coverage json -o coverage.json` → `uv run python tools/check_critical_coverage.py` (executor.py ≥95/90; count 131). This is a **boundary checkpoint** — full suite green.

- [ ] **Step 6: Halt-before-commit.** Watchpoints: (a) run_id on every path + genesis pending — `test_run_mints_run_id_and_genesis_on_every_path`; (b) suspend skips destroy + persists session/checkpoint + run.suspended — `test_suspend_after_exec_suspends_and_skips_destroy`; (c) non-suspend still destroys — `test_run_without_suspend_completes_and_destroys`; (d) direct events carry run_id — `test_direct_run_events_carry_run_id`; (e) composition fail-soft when checkpoint store unbuildable — lifespan test; (f) arch fence green; (g) executor ≥95/90, count 131. Present evidence + files modified. Await token.

- [ ] **Step 7: Commit** (on token). Stage `src/cognic_agentos/core/run/executor.py src/cognic_agentos/portal/api/app.py src/cognic_agentos/harness/sandbox.py tests/unit/core/run/test_executor.py tests/unit/portal/api/test_app_sandbox_state.py tests/unit/architecture/test_run_no_sdk_import.py`. Message: `feat(run): A3b executor run-record wiring + suspend path + checkpoint-store composition (ADR-022/004)`.

---

## Task 4: `executor.py` — `resume()` + `RunNotResumable`/`RunResumeConflict` (CC)

**Files:**
- Modify: `src/cognic_agentos/core/run/executor.py`
- Test: `tests/unit/core/run/test_executor.py`

- [ ] **Step 1: Write failing tests.** Add a stub backend `wake()` (returns a stub session / raises `SandboxLifecycleRefused` / raises generic). Tests:

```python
async def test_resume_happy_path_wakes_execs_completes(...):
    # suspend a run first, then resume it
    s = await executor.run(replace(req_ok, suspend_after_exec=True))
    res = await executor.resume(run_id=uuid.UUID(s.run_id), actor=actor, argv=("echo", "go"))
    assert res.terminal_state == "completed" and res.run_id == s.run_id and res.task_id is None
    assert stub_backend.wake_calls == 1 and woken_session.destroy_calls == 1
    rec = await run_store.load(uuid.UUID(s.run_id), tenant_id="t1")
    assert rec.state == "completed"   # suspended->woken->completed

async def test_resume_wake_refused_transitions_suspended_to_refused(...):
    stub_backend.wake_raises = SandboxLifecycleRefused("sandbox_wake_checkpoint_corrupt")
    res = await executor.resume(run_id=..., actor=actor, argv=("x",))
    assert res.terminal_state == "refused" and res.refusal_reason == "sandbox_wake_checkpoint_corrupt"
    assert (await run_store.load(...)).state == "refused"

async def test_resume_wake_infra_transitions_suspended_to_failed(...):
    stub_backend.wake_raises = RuntimeError("boom")
    res = await executor.resume(...); assert res.terminal_state == "failed"
    assert (await run_store.load(...)).state == "failed"

async def test_resume_resumed_exec_infra_transitions_woken_to_failed(...):
    woken_session.exec_raises = RuntimeError("boom")
    res = await executor.resume(...); assert res.terminal_state == "failed"
    assert (await run_store.load(...)).state == "failed" and woken_session.destroy_calls == 1

async def test_resume_unknown_run_raises_run_not_found(...):
    with pytest.raises(RunNotFound):
        await executor.resume(run_id=uuid.uuid4(), actor=actor, argv=("x",))

async def test_resume_non_suspended_raises_run_not_resumable(...):
    done = await executor.run(req_ok)  # completed, not suspended
    with pytest.raises(RunNotResumable) as exc:
        await executor.resume(run_id=uuid.UUID(done.run_id), actor=actor, argv=("x",))
    assert exc.value.current_state == "completed"

# --- the wake/tombstone edge (resume-side teardown posture) ---

async def test_resume_claim_failure_does_not_destroy_and_run_stays_suspended(...):
    # wake() ok, but the suspended->woken claim raises a (non-stale) DB error:
    # claimed_woken stays False -> finally must NOT destroy -> no tombstone ->
    # the rolled-back run record is still 'suspended' (resumable). Mechanism:
    # wrap the run store so transition(to_state="woken") raises RuntimeError once.
    s = await executor.run(replace(req_ok, suspend_after_exec=True))
    woken_session = StubSession(exit_code=0)
    stub_backend.wake_returns = woken_session
    failing_runs.fail_woken_transition = True   # store wrapper raises on suspended->woken
    with pytest.raises(RuntimeError):
        await executor.resume(run_id=uuid.UUID(s.run_id), actor=actor, argv=("x",))
    assert woken_session.destroy_calls == 0
    rec = await run_store.load(uuid.UUID(s.run_id), tenant_id="t1")
    assert rec.state == "suspended"            # still resumable, NOT tombstoned

async def test_resume_concurrent_conflict_returns_conflict_without_destroy(...):
    # Two resumes both load 'suspended' and both wake. The stub wake commits the
    # winning request's suspended->woken claim as a side-effect, so THIS request's
    # claim stale-refuses -> RunResumeConflict, and its woken session is NOT
    # destroyed (the winner owns the session_id; destroying would tombstone it).
    s = await executor.run(replace(req_ok, suspend_after_exec=True))
    loser_session = StubSession(exit_code=0)
    async def _wake_then_winner_claims(session_id, *, actor, tenant_id):
        await run_store.transition(run_id=uuid.UUID(s.run_id), tenant_id="t1",
            from_state="suspended", to_state="woken", actor_id="winner", request_id="w")
        return loser_session
    stub_backend.wake = _wake_then_winner_claims
    with pytest.raises(RunResumeConflict):
        await executor.resume(run_id=uuid.UUID(s.run_id), actor=actor, argv=("x",))
    assert loser_session.destroy_calls == 0
```

- [ ] **Step 2: Run, watch fail.** `uv run pytest tests/unit/core/run/test_executor.py -k resume -q`. Expected: fail — no `resume`/`RunNotResumable`.

- [ ] **Step 3: Implement.** Add the `RunNotResumable` exception at module scope, then add `resume()` as a method of `ManagedRunExecutor`:

```python
class RunNotResumable(Exception):
    """Raised by resume() when the run record exists but is not in 'suspended'.
    The route maps it to 409 run_not_suspended."""
    def __init__(self, current_state: str) -> None:
        self.current_state = current_state
        super().__init__(f"run_not_suspended: state={current_state}")


class RunResumeConflict(Exception):
    """Raised by resume() when wake() succeeded but the atomic suspended->woken
    claim lost the race to a concurrent resume (the row already moved out of
    suspended). The route maps it to 409 run_resume_conflict; resume() leaves
    claimed_woken=False so the woken session is NOT destroyed (the winning
    request owns it — destroying would tombstone the session it is executing)."""
    def __init__(self, run_id: uuid.UUID) -> None:
        self.run_id = run_id
        super().__init__(f"run_resume_conflict: {run_id}")
```

`resume()` is a method of **`ManagedRunExecutor`** (indented one level inside that class — it is NOT a method of `RunNotResumable`):

```python
    async def resume(self, *, run_id: uuid.UUID, actor: Actor, argv: tuple[str, ...]) -> RunResult:
        request_id = f"run-resume-{uuid.uuid4().hex}"
        record = await self._runs.load(run_id, tenant_id=actor.tenant_id)
        if record is None:
            raise RunNotFound(run_id)                      # -> route 404
        if record.state != "suspended":
            raise RunNotResumable(record.state)            # -> route 409
        if record.session_id is None:                      # invariant: suspended => session_id set
            raise RuntimeError(f"run_suspended_without_session_id: {run_id}")
        rid = str(run_id)
        from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused
        # RunTransitionRefused is imported at MODULE scope (core->core, SDK-free):
        #   from cognic_agentos.core.run._types import RunTransitionRefused

        session = None
        claimed_woken = False
        try:
            try:
                session = await self._sandbox_backend.wake(
                    record.session_id, actor=actor, tenant_id=actor.tenant_id)
            except SandboxLifecycleRefused as exc:
                await self._runs.transition(run_id=run_id, tenant_id=actor.tenant_id,
                    from_state="suspended", to_state="refused", actor_id=actor.subject,
                    request_id=request_id)
                await self._emit_refused(_resume_req(actor, record), request_id, run_id=rid,
                    task_id=None, reason=str(exc.reason))
                return RunResult(run_id=rid, task_id=None, terminal_state="refused", exit_code=None,
                    stdout=b"", stderr=b"", refusal_reason=str(exc.reason))
            except Exception:
                await self._runs.transition(run_id=run_id, tenant_id=actor.tenant_id,
                    from_state="suspended", to_state="failed", actor_id=actor.subject,
                    request_id=request_id)
                await self._emit_failed(_resume_req(actor, record), request_id, run_id=rid,
                    task_id=None, reason="workload_runtime_error")
                return RunResult(run_id=rid, task_id=None, terminal_state="failed", exit_code=None,
                    stdout=b"", stderr=b"", refusal_reason=None)

            # Atomic claim + mutex: exactly one concurrent resume commits
            # suspended->woken. A loser sees the row already moved -> stale ->
            # RunTransitionRefused -> RunResumeConflict (409); claimed_woken stays
            # False so the finally does NOT destroy. A non-RunTransitionRefused
            # (DB) error here also propagates with claimed_woken=False -> no destroy
            # -> the rolled-back run stays suspended/resumable (no tombstone).
            try:
                await self._runs.transition(run_id=run_id, tenant_id=actor.tenant_id,
                    from_state="suspended", to_state="woken", actor_id=actor.subject,
                    request_id=request_id)
            except RunTransitionRefused:
                raise RunResumeConflict(run_id)
            claimed_woken = True
            try:
                exec_result = await session.exec(list(argv), timeout_s=self._build_policy().walltime_s)
            except Exception:
                await self._runs.transition(run_id=run_id, tenant_id=actor.tenant_id,
                    from_state="woken", to_state="failed", actor_id=actor.subject,
                    request_id=request_id)
                await self._emit_failed(_resume_req(actor, record), request_id, run_id=rid,
                    task_id=None, reason="workload_runtime_error")
                return RunResult(run_id=rid, task_id=None, terminal_state="failed", exit_code=None,
                    stdout=b"", stderr=b"", refusal_reason=None)

            await self._runs.transition(run_id=run_id, tenant_id=actor.tenant_id,
                from_state="woken", to_state="completed", actor_id=actor.subject,
                request_id=request_id)
            await self._emit_completed(_resume_req(actor, record), request_id, run_id=rid,
                task_id=None, result=exec_result)
            return RunResult(run_id=rid, task_id=None, terminal_state="completed",
                exit_code=exec_result.exit_code, stdout=exec_result.stdout,
                stderr=exec_result.stderr, refusal_reason=None)
        finally:
            # Destroy ONLY a session we own (claimed suspended->woken). If wake()
            # succeeded but the claim failed (concurrent loser, or a DB error),
            # destroying would tombstone a session the winner is executing / a run
            # that is still suspended+resumable -> sandbox_wake_session_tombstoned.
            # TRADE-OFF: a claim-failure/loser therefore LEAVES a live woken
            # container/pod orphaned. The CheckpointReaper purges only object-store
            # checkpoints, NOT backend resources, so this is NOT auto-reclaimed today
            # -> leaked-backend-resource cleanup is a forward item (resource leak,
            # not data-loss).
            if session is not None and claimed_woken:
                try:
                    await session.destroy()
                except Exception:
                    logger.warning("run.session_destroy_failed",
                        extra={"request_id": request_id, "run_id": rid,
                               "session_id": session.session_id})
```

The `_emit_*` helpers take a `RunRequest` (for `actor.subject`/`tenant_id`/`pack_id`). resume has no `RunRequest`; add a tiny module-private `_resume_req(actor, record) -> RunRequest` that builds a minimal `RunRequest` from the loaded record (`tenant_id=record.tenant_id`, `pack_id=record.pack_id`, `pack_uuid=record.pack_uuid`, `pack_version=record.pack_version`, `argv=()`, `actor=actor`) purely so the emitters read `actor.subject`/`tenant_id`/`pack_id`. (Alternative: refactor the emitters to take `actor`+`tenant_id`+`pack_id` directly — pick whichever keeps the diff smaller; the `_resume_req` shim is the minimal change.)

- [ ] **Step 4: Run, watch pass.** `uv run pytest tests/unit/core/run/test_executor.py -q`. Watch all pass.

- [ ] **Step 5: Gate ladder + verify-at-promotion.** Gate ladder; full suite `--cov-branch` → coverage json → `check_critical_coverage.py` (executor ≥95/90, count 131).

- [ ] **Step 6: Halt-before-commit.** Watchpoints: resume happy/refused/failed/exec-failed/not-found/not-suspended (the six tests); **claim-failure leaves the run `suspended` and does NOT destroy** + **concurrent-conflict → `RunResumeConflict` (409) and does NOT destroy** (the two wake/tombstone-edge tests); the woken session is destroyed ONLY on a successfully-claimed terminal (not on suspend, claim-failure, or conflict); resume keeps `task_id=None`; executor ≥95/90. Present evidence + files modified. Await token.

- [ ] **Step 7: Commit** (on token). Stage `src/cognic_agentos/core/run/executor.py tests/unit/core/run/test_executor.py`. Message: `feat(run): A3b executor resume() — run->session resolver + wake dispatch + claim-gated teardown (ADR-022/004)`.

---

## Task 5: `scopes.py` — `run.resume` (CC, 1-file)

**Files:**
- Modify: `src/cognic_agentos/portal/rbac/scopes.py`
- Test: `tests/unit/portal/rbac/test_run_scopes.py`

- [ ] **Step 1: Write failing test.** Update `test_run_scopes.py`:

```python
def test_run_scopes_has_exactly_two_values() -> None:
    assert set(get_args(RunRBACScope)) == {"run.submit", "run.resume"}
    assert RUN_SCOPES == frozenset({"run.submit", "run.resume"})

def test_run_scopes_namespace_disjoint_from_other_families() -> None:
    assert all(s.startswith("run.") for s in get_args(RunRBACScope))
```

- [ ] **Step 2: Run, watch fail.** `uv run pytest tests/unit/portal/rbac/test_run_scopes.py -q`. Expected: fail (only `run.submit` today).

- [ ] **Step 3: Implement.** In `scopes.py`:

```python
RunRBACScope = Literal["run.submit", "run.resume"]   # A3b — +run.resume
RUN_SCOPES: frozenset[RunRBACScope] = frozenset({"run.submit", "run.resume"})
```

Update the doc comment to "2 run scopes". `actor.py:143` + `enforcement.py:259` reference the type (`| RunRBACScope`) — **no change needed there** (the new value flows automatically); confirm via mypy.

- [ ] **Step 4: Run, watch pass.** `uv run pytest tests/unit/portal/rbac/test_run_scopes.py -q`.

- [ ] **Step 5: Gate ladder + verify-at-promotion.** Gate ladder; full suite `--cov-branch` → coverage json → `check_critical_coverage.py` (scopes.py ≥95/90, count 131).

- [ ] **Step 6: Halt-before-commit.** Watchpoints: 2-value RunRBACScope + frozenset — the two tests; mypy clean (the union sites auto-include the value); scopes.py ≥95/90. Present evidence + files modified. Await token.

- [ ] **Step 7: Commit** (on token). Stage `src/cognic_agentos/portal/rbac/scopes.py tests/unit/portal/rbac/test_run_scopes.py`. Message: `feat(rbac): A3b add run.resume scope (ADR-022)`.

---

## Task 6: `dto.py` + `routes.py` — resume route (off-gate)

**Files:**
- Modify: `src/cognic_agentos/portal/api/runs/dto.py`
- Modify: `src/cognic_agentos/portal/api/runs/routes.py`
- Test: `tests/unit/portal/api/runs/test_run_routes.py` (+ dto tests)

- [ ] **Step 1: Write failing tests.** Add resume-route tests via FastAPI `TestClient` over a `build_run_routes()` app with a stub executor on `app.state.managed_run_executor` (mirror the existing submit-route tests). Cover: 200 (resume completed), 502 (failed), 409 (wake refused), 404 (RunNotFound → `run_not_found`), 409 (RunNotResumable → `run_not_suspended` + `current_state`), 409 (RunResumeConflict → `run_resume_conflict`), 403 (no `run.resume` scope), 503 (no executor), and `RunResponse.run_id` present on submit + resume.

- [ ] **Step 2: Run, watch fail.** `uv run pytest tests/unit/portal/api/runs/ -q`. Expected: fail (no resume route / no `run_id` field).

- [ ] **Step 3a: Implement dto.py.** Extract the shared validator + add the resume request + grow `RunResponse`:

```python
def _validate_argv_bounds(v: list[str]) -> list[str]:
    if not v:
        raise ValueError("argv_must_be_non_empty")
    if len(v) > _MAX_ARGV_ITEMS:
        raise ValueError(f"argv_too_many_items_max_{_MAX_ARGV_ITEMS}")
    for item in v:
        if len(item) > _MAX_ARGV_ITEM_LEN:
            raise ValueError(f"argv_item_too_long_max_{_MAX_ARGV_ITEM_LEN}")
    return v

class RunSubmitRequest(BaseModel):
    ...
    @field_validator("argv")
    @classmethod
    def _argv_bounded(cls, v: list[str]) -> list[str]:
        return _validate_argv_bounds(v)

class RunResumeRequest(BaseModel):
    """Body for POST /api/v1/runs/{run_id}/resume. run_id is the path param;
    tenant/actor come from the bound Actor (extra='forbid')."""
    model_config = ConfigDict(frozen=True, extra="forbid")
    argv: list[str]

    @field_validator("argv")
    @classmethod
    def _argv_bounded(cls, v: list[str]) -> list[str]:
        return _validate_argv_bounds(v)

class RunResponse(BaseModel):
    model_config = ConfigDict(frozen=True)
    run_id: str                                  # A3b
    task_id: str | None
    terminal_state: Literal["completed", "failed", "refused", "pending_approval", "suspended"]
    exit_code: int | None
    stdout_b64: str
    stderr_b64: str
    stdout_bytes: int
    stderr_bytes: int
    refusal_reason: str | None
    approval_request_id: str | None
```

- [ ] **Step 3b: Implement routes.py.** Add the shared projector, refactor submit, add the resume route + status + pre-flight:

```python
from cognic_agentos.core.run.executor import (
    ManagedRunExecutor, RunNotResumable, RunRequest, RunResult, RunResumeConflict)
from cognic_agentos.core.run.storage import RunNotFound
from cognic_agentos.portal.api.runs.dto import RunResponse, RunResumeRequest, RunSubmitRequest

_STATUS_BY_TERMINAL: dict[str, int] = {
    "completed": 200, "pending_approval": 202, "refused": 409, "failed": 502,
    "suspended": 202,                                   # A3b
}

def _run_response_from_result(result: RunResult) -> RunResponse:
    return RunResponse(
        run_id=result.run_id, task_id=result.task_id, terminal_state=result.terminal_state,
        exit_code=result.exit_code,
        stdout_b64=base64.b64encode(result.stdout).decode("ascii"),
        stderr_b64=base64.b64encode(result.stderr).decode("ascii"),
        stdout_bytes=len(result.stdout), stderr_bytes=len(result.stderr),
        refusal_reason=result.refusal_reason, approval_request_id=result.approval_request_id)
```

In `build_run_routes()`: refactor `submit_run` to `return _run_response_from_result(result)`, then add:

```python
    _require_resume = RequireScope("run.resume")

    @router.post("/{run_id}/resume", response_model=RunResponse)
    async def resume_run(
        run_id: uuid.UUID,
        body: RunResumeRequest,
        response: Response,
        actor: Annotated[Actor, Depends(_require_resume)],
        executor: Annotated[ManagedRunExecutor, Depends(_require_managed_run_executor)],
    ) -> RunResponse:
        try:
            result = await executor.resume(run_id=run_id, actor=actor, argv=tuple(body.argv))
        except RunNotFound:
            raise HTTPException(status_code=404, detail={"reason": "run_not_found"})
        except RunNotResumable as exc:
            raise HTTPException(status_code=409,
                detail={"reason": "run_not_suspended", "current_state": exc.current_state})
        except RunResumeConflict:
            raise HTTPException(status_code=409, detail={"reason": "run_resume_conflict"})
        response.status_code = _STATUS_BY_TERMINAL[result.terminal_state]
        return _run_response_from_result(result)
```

Add `import uuid` to `routes.py`. Keep `from __future__ import annotations` OMITTED.

- [ ] **Step 4: Run, watch pass.** `uv run pytest tests/unit/portal/api/runs/ -q`.

- [ ] **Step 5: Gate ladder + boundary.** Gate ladder; full suite + `check_critical_coverage.py` (count 131 — no on-gate file changed in this task, but run it as the second boundary checkpoint to confirm nothing regressed).

- [ ] **Step 6: Halt-before-commit.** Watchpoints: resume 200/502/409/404/409/403/503 + run_id on both responses + suspended→202 — the route tests. Present evidence + files modified. Await token.

- [ ] **Step 7: Commit** (on token). Stage `src/cognic_agentos/portal/api/runs/dto.py src/cognic_agentos/portal/api/runs/routes.py tests/unit/portal/api/runs/test_run_routes.py` (+ any dto test file). Message: `feat(api): A3b POST /runs/{run_id}/resume route + run_id on RunResponse (ADR-022/004)`.

---

## Task 7: env-gated real-docker e2e (off-gate)

**Files:**
- Create: `tests/integration/run/test_managed_run_resume_e2e.py`

- [ ] **Step 1: Write the e2e.** Mirror the 14A-A e2e at `tests/integration/run/test_managed_run_e2e.py` (real `DockerSiblingSandboxBackend` + real `RunRecordStore` + real `CheckpointStore` + canonical runtime image). Gate on `COGNIC_RUN_DOCKER_SANDBOX=1` (default-skip; fail-loud when opted in). Body: `submit(suspend_after_exec=True)` → assert `terminal_state == "suspended"` + a `run_id`; then `resume(run_id, argv=[deterministic])` → assert `terminal_state == "completed"` + the expected `exit_code`/`stdout`; assert the `runs` row walks `pending→running→suspended→woken→completed` and the `run.lifecycle.*` + `run.suspended`/`run.completed` chain rows exist.

- [ ] **Step 2: Verify skip-by-default.** `uv run pytest tests/integration/run/test_managed_run_resume_e2e.py -q` → SKIPPED (no env var). Confirm it does not error on collection.

- [ ] **Step 3: Gate ladder (paths touched).** ruff check + ruff format --check + `uv run mypy src tests` for the new file.

- [ ] **Step 4: Halt-before-commit.** Watchpoints: default-skip clean; fail-loud-when-opted-in structure; no gated source touched. Present evidence + files modified. Await token.

- [ ] **Step 5: Commit** (on token). Stage `tests/integration/run/test_managed_run_resume_e2e.py`. Message: `test(run): A3b env-gated suspend->resume docker e2e (ADR-022/004)`.

---

## Task 8: docs (off-gate)

**Files:**
- Modify: `docs/adrs/ADR-022-runtime-scheduler.md`, `docs/adrs/ADR-004-sandbox-primitive.md`, `AGENTS.md`, `docs/AS_BUILT_CAPABILITY_MAP.md`

- [ ] **Step 1: ADR amendments.** ADR-022 + ADR-004 Sprint-14A-A3b amendment: the run→session resolver + resume route; the explicit `suspend_after_exec` trigger; `suspend()`-then-`load_latest` mechanic; conditional teardown (tombstone-on-destroy rationale); the resume-side claim-gated teardown (the wake/tombstone race) — and its **leaked-orphaned-backend-resource cleanup as a forward item** (the `CheckpointReaper` purges object-store checkpoints, NOT live containers/pods); resume-no-scheduler + quota-on-resume as a forward item; the A3c fence (no CheckpointMetadata approval fields, no wake-path approval threading) still pending.

- [ ] **Step 2: AGENTS.md.** Under `*Run-persistence foundation (Sprint 14A-A3a)*` add an A3b note: the executor (`core/run/executor.py`) now drives the run record + the suspend/resume lane; `storage.py` gained `suspended`/`woken` lifecycle decision-types; `scopes.py` gained `run.resume`; `run.lifecycle.*` (store) stays distinct from direct `run.*` (executor); the resume route unblocks the deferred `resume` UI action; **no new on-gate module — CC count stays 131**.

- [ ] **Step 3: Capability map.** Pillar 2: A3b done (first exercised run→session resolver + `backend.wake()` first production caller); A3c (wake approval correlator) next.

- [ ] **Step 4: Gate ladder.** ruff format --check on the docs is N/A; just confirm no stray staging. (No code/tests changed.)

- [ ] **Step 5: Halt-before-commit.** Watchpoints: honesty (resume-no-scheduler forward item stated; A3c fence stated; count 131); no protected docs staged. Present files modified. Await token.

- [ ] **Step 6: Commit** (on token). Stage the four docs only. Message: `docs: A3b run-resume resolver — ADR-022/004 + AGENTS.md + capability map`.

---

## Self-review

**Spec coverage:** every spec component maps to a task — `_types` matrix (T1), storage decision-types (T2), executor run-record+suspend+composition (T3), executor resume (T4), `run.resume` scope (T5), dto+routes (T6), e2e (T7), docs (T8). The five locks (F1 uniform run_id, F2 corrected suspend mechanic, F3 run.resume + continuation argv, F4 conditional teardown + persist both, F5 +6 producible pairs) and the four review patches (P1 skip_destroy-immediate, P1 run_id-keyed emitters, P2 checkpoint-store fail-soft, P3 concrete helpers) are all present.

**Placeholder scan:** the run() rework (T3.3b) shows the new code with the queued/non-immediate refusal blocks described by reference to the shown pack-refusal block (same shape) — the engineer reproduces that one block twice; every other path is shown in full. No "TBD"/"add error handling".

**Type consistency:** `RunResult.run_id: str` is the first field everywhere; `RunTerminalState` (executor, 5 values) and `RunResponse.terminal_state` (dto, 5 values) match; the emitters' `run_id: str` + `task_id: str | None` are consistent across T3/T4; `transition(...)` calls use the grounded keyword signature (`from_state`/`to_state`/`actor_id`/`request_id` + nullable columns); `_STATE_TO_DECISION_TYPE` (T2) + `_VALID_TRANSITIONS` (T1) are both prerequisites for the new transitions (T3/T4) and land first.

**Ordering:** T1→T2 (foundation) → T3 (executor run + composition, keeps mypy/suite green by updating app.py in the same commit) → T4 (resume) → T5 (scope) → T6 (route) → T7 (e2e) → T8 (docs). Boundary full-suite + CC-gate after T3 and T6.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-15-sprint-14a-a3b-run-resume-resolver.md`. Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task + two-stage review (spec-compliance then code-quality), with the halt-before-commit reviewer gate on every task.
2. **Inline Execution** — execute tasks in this session with checkpoints.

Which approach?
