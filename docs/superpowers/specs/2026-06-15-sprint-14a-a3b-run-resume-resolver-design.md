# Sprint 14A-A3b — Run→Session Resolver + Resume Route (Design)

**Status:** LOCKED source of truth. The implementation plan mirrors this exactly.
**Date:** 2026-06-15
**ADRs:** ADR-022 (runtime scheduler), ADR-004 (sandbox primitive — resumable session API §73-93)
**Slice:** 2 of 3 in the checkpoint→wake / run-persistence arc (A3a foundation → **A3b resolver/resume** → A3c wake approval correlator).

---

## Goal

Wire the A3a-dormant `RunRecordStore` into the managed-run lane, add an explicit-suspend path to the executor, and add a `POST /api/v1/runs/{run_id}/resume` route that resolves `run_id → session_id` and dispatches `backend.wake()` — proving the resumable-session vertical end-to-end (`submit → exec → suspend → [new request] → wake → exec → complete`) while keeping the synchronous `POST /api/v1/runs` contract additively-stable and the A3c approval correlator fully out.

**Success criterion:** a correct, durable, resumable run substrate proven by tests — not "resume is feature-complete." This is the slice that turns the dormant A3a store into the first *exercised* run→session resolver and lights up `backend.wake()` (which has zero production callers today).

## Architecture

The executor (`core/run/executor.py`, already on the CC gate) becomes the run-record authority: it mints a `run_id`, writes a genesis `run.lifecycle.pending` row, drives the run record through its lifecycle via `RunRecordStore.transition`, and on an explicit `suspend_after_exec` request calls `session.suspend()` instead of `session.destroy()`, persisting `session_id` + the latest `checkpoint_id` on the `running→suspended` transition. A new `executor.resume()` method + `POST /api/v1/runs/{run_id}/resume` route resolves the run record (tenant-scoped), wakes the session by `session_id`, runs a continuation `argv`, and completes. The `RunState` vocabulary is unchanged (fixed at A3a); A3b only **expands the legal-transition matrix** with the suspend/wake pairs.

## Tech stack

Python 3.12, SQLAlchemy async (`runs` table from A3a migration `0011` — no new migration), FastAPI, the existing sandbox resumable-session API (`SandboxSession.suspend()`, `SandboxBackend.wake()`, `CheckpointStore.load_latest()`), `RunRecordStore` (A3a). uv; pytest (`asyncio_mode=auto`); mypy strict (`tests.*` untyped allowed); 100-char lines.

---

## Scope

### In scope
- **Run-record wiring** into the executor: mint `run_id`, genesis `run.lifecycle.pending`, drive `pending→running→{terminal}` via `RunRecordStore`.
- **Uniform additive `run_id`**: `RunResult` + `RunResponse` gain `run_id` populated on every path (F1-A). Existing response fields + status semantics unchanged.
- **Explicit suspend trigger**: `RunRequest.suspend_after_exec: bool = False` (F2-B). On suspend: `exec → session.suspend() → checkpoint_store.load_latest → transition running→suspended (session_id + checkpoint_id) → skip destroy`.
- **Conditional teardown** (F4): the unconditional `session.destroy()` becomes conditional; the suspend path skips it (resumability-critical — see below).
- **Run→session resolver + resume route**: `POST /api/v1/runs/{run_id}/resume` (new `run.resume` scope; continuation `argv` with submit's bounds; tenant/actor from bound `Actor`); `executor.resume()` resolves `run_id → session_id`, dispatches `backend.wake()`, execs, completes.
- **Transition-matrix expansion** (F5): add exactly the 6 pairs the A3b runtime can produce; `RunState` vocab unchanged.
- **Composition root**: build one `CheckpointStore`, thread it into the backend + executor + reaper; add `run_record_store` to the executor construction.

### Out of scope — A3c fence (hard)
- **No `CheckpointMetadata` approval fields.** No `approval_request_id`/`approval_verified` on the checkpoint metadata.
- **No wake-path `admit_policy` approval threading.** `wake()`'s intrinsic Wave-1 policy revalidation (docker:2559 / k8s:2429) fires unchanged when we call `wake()`; we add nothing to it.
- **No high-risk pending-approval proof.** The run shape stays `read_only` / `requires_credentials=()`.

### Out of scope — other deferrals (forward items, not A3c)
- **Resume does NOT re-admit through the scheduler.** `executor.resume()` has no `scheduler.submit`/`mark_running`/`complete` calls — it resolves, wakes, execs, and transitions the run record directly. Whether resumed compute should re-consume a scheduler slot / re-charge quota (an ADR-018 quota-accounting decision) is a deliberate later-slice call. Rationale: the scheduler slot was freed at suspend (`scheduler.complete`), and `wake()` re-validates sandbox policy; baking quota-on-resume semantics in here would over-scope the substrate proof.
- **No UI resume-action wiring.** The route is the primitive that *unblocks* the deferred `resume` UI action (`action_backend_deferred_no_run_primitive`); lifting the UI stub to call it is a later slice.
- **No re-suspend loop** (`woken→suspended`) and **no `woken→running`** — resume runs to a terminal in one continuous span.
- **No workload-signalled suspend protocol** — suspend is the explicit `suspend_after_exec` flag only.
- **No `cancelled` transitions** — the `cancelled` state stays in the vocab but unreachable (still refused).

---

## Design basis — the locked forks

| Fork | Lock |
|---|---|
| **F1** | **A** — uniform additive `run_id`; every run mints `run_id` + writes `run.lifecycle.pending`; `RunResponse` gains additive `run_id` on every path; existing fields/status stable; dual evidence (store `run.lifecycle.*` + executor direct `run.*`). |
| **F2** | **B (corrected mechanic)** — explicit `suspend_after_exec: bool = False`; on suspend: `exec → session.suspend() → checkpoint_store.load_latest(session_id, tenant_id) → transition running→suspended with session_id + latest checkpoint_id → skip destroy`. **No explicit `checkpoint(label)`** — `suspend()` already takes the final `__suspend__` checkpoint; `checkpoint_id` is read back from `load_latest` as evidence/resolver context (wake resolves latest internally). |
| **F3** | **new `run.resume` scope** — `POST /api/v1/runs/{run_id}/resume`; same 503 executor guard; continuation `argv` with submit's bounds; tenant/actor from bound `Actor` only; payload deferred; route is the primitive (no UI wiring). |
| **F4** | **conditional teardown** — replace unconditional `destroy()` with conditional; persist `session_id` + `checkpoint_id` on the `running→suspended` transition (on suspend, not create). |
| **F5** | **matrix expansion** — add only producible pairs: `running→suspended`, `suspended→woken`, `suspended→refused`, `suspended→failed`, `woken→completed`, `woken→failed`. No `woken→refused`. `cancelled` pairs stay refused. `RunTerminalState` gains `suspended`; route maps `suspended → 202`. |

**F2 grounding (the correction):** `suspend()` (`protocol.py:623-627`) takes its own final checkpoint (`label='__suspend__'`) and releases the container; `wake()`→`load_latest` restores the **latest by `created_at`** (`checkpoint_store.py:998`). So an explicit `checkpoint(label)` before `suspend()` would write a redundant snapshot whose id is *not* the one wake restores. The locked mechanic drops it and reads the real resumable id via `load_latest`. `Q5` lock confirmed safe: checkpoint/suspend raise `NotImplementedError` only on non-empty `active_leases`; our shape is `requires_credentials=()` → no leases.

**F5 grounding (why no `woken→refused`):** after a successful `wake()`, the resumed `exec()` yields a `SandboxExecResult` (→ `woken→completed`, any exit code) or raises — including `SandboxPolicyViolated` (OOM/walltime), which maps to a failure (→ `woken→failed`). There is no refusal source after a successful wake. Wake's own refusals fire *before* the state leaves `suspended` (→ `suspended→refused`); a wake-time container-create infra exception → `suspended→failed`.

---

## Component design

### 1. `core/run/_types.py` (off-gate) — matrix expansion + doctrine pin

The 9-value `RunState` Literal is **unchanged** (`pending`/`running`/`completed`/`failed`/`refused`/`pending_approval`/`suspended`/`woken`/`cancelled`). The expand-only doctrine: A3b produces transitions to `suspended` + `woken` (already in the vocab); `cancelled` stays unreachable.

Keep the A3a frozenset and add an auditable A3b delta, then union:

```python
_A3A_VALID_TRANSITIONS: frozenset[tuple[RunState, RunState]] = frozenset({
    ("pending", "running"), ("pending", "refused"),
    ("running", "completed"), ("running", "failed"),
    ("running", "refused"), ("running", "pending_approval"),
})

# Sprint 14A-A3b — EXPAND ONLY (vocab unchanged): the suspend/wake pairs the
# A3b runtime can actually produce. No woken->refused (no post-wake refusal
# source); no woken->running / woken->suspended (no re-loop / re-suspend);
# no cancelled pairs (still reserved).
_A3B_VALID_TRANSITIONS: frozenset[tuple[RunState, RunState]] = frozenset({
    ("running", "suspended"),
    ("suspended", "woken"),
    ("suspended", "refused"),
    ("suspended", "failed"),
    ("woken", "completed"),
    ("woken", "failed"),
})

_VALID_TRANSITIONS = _A3A_VALID_TRANSITIONS | _A3B_VALID_TRANSITIONS  # 12 pairs
```

`validate_transition(*, from_state, to_state)` and `RunTransitionRefused(reason="run_transition_invalid_state_pair")` are otherwise unchanged.

**Doctrine pin update** (`tests/unit/core/run/test_run_types.py`): the still-reserved set shrinks to pairs the A3b runtime cannot produce — `("woken","running")`, `("woken","suspended")`, `("suspended","completed")`, `("suspended","pending_approval")`, `("running","cancelled")`, `("pending","cancelled")`, `("suspended","cancelled")`. `test_reserved_pairs_refuse_until_expanded` asserts these refuse; a positive parametrized test asserts all 12 legal pairs pass; the vocab test still asserts exactly 9 values.

### 2. `core/run/storage.py` (CC, on-gate) — new transition targets

The only change: extend `_STATE_TO_DECISION_TYPE` with the two new transition targets so the preflight guard (`to_state in _STATE_TO_DECISION_TYPE`) admits them and they emit the right chain `decision_type`:

```python
_STATE_TO_DECISION_TYPE: dict[RunState, str] = {
    "running": "run.lifecycle.running",
    "completed": "run.lifecycle.completed",
    "failed": "run.lifecycle.failed",
    "refused": "run.lifecycle.refused",
    "pending_approval": "run.lifecycle.pending_approval",
    "suspended": "run.lifecycle.suspended",   # A3b
    "woken": "run.lifecycle.woken",           # A3b
}
```

No new method, no new column (A3a's `runs` table already carries nullable `session_id`/`task_id`/`checkpoint_id`/`approval_request_id`; the `transition()` optional-column kwargs already exist). `create_run` (genesis) and `transition` (Doctrine Lock D atomicity) are otherwise unchanged. **Verify-at-promotion**: storage.py stays on-gate; the commit re-runs `check_critical_coverage.py` on fresh `--cov-branch` data; new tests cover both new transition targets (`running→suspended` persisting `session_id`+`checkpoint_id`; `suspended→woken→completed`) so coverage holds ≥95/90.

### 3. `core/run/executor.py` (CC, on-gate) — the rework

**New constructor deps** (the executor is now the run-record authority + needs `load_latest`):

```python
def __init__(self, *, scheduler, sandbox_backend, pack_loader,
             decision_history_store, settings,
             run_record_store: RunRecordStore,        # A3b — new
             checkpoint_store: CheckpointStore) -> None:  # A3b — new
```

`run_record_store` is a runtime import (`core.run.storage`, core→core, SDK-free); `RunNotFound` is also imported from there (raised by `resume`). `checkpoint_store` is typed via `TYPE_CHECKING` (the concrete instance is injected; the executor only calls `load_latest`, duck-typed) — the architecture fence (`tests/unit/architecture/test_run_no_sdk_import.py`: no `aiodocker`/`kubernetes_asyncio`, no runtime `portal` import) stays green.

**New / changed shapes:**

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

class RunNotResumable(Exception):               # A3b — carries the current state for the 409
    def __init__(self, current_state: str) -> None:
        self.current_state = current_state
        super().__init__(f"run_not_suspended: state={current_state}")
```

**Direct `run.*` emitter contract (P1b — `task_id` may be absent on resume):** all direct emitters (`_emit_completed` / `_emit_failed` / `_emit_refused` / `_emit_pending` / `_emit_suspended`) take `*, run_id: str, task_id: str | None, …` and write **both** into the value-free payload — `run_id` always present, `task_id` nullable. The submit path passes the scheduler `task_id`; the resume path (no scheduler) passes `task_id=None`. `run_id` is therefore the stable join key between the store's `run.lifecycle.*` rows and the executor's direct `run.*` rows — dual evidence correlates by `run_id`, never relying solely on `request_id`. (This is the change from 14A-A2's `task_id`-keyed emitters, which required a UUID and payloaded it.)

**`run()` lifecycle** (the genesis + suspend additions; everything else mirrors 14A-A2):

0. `run_id = uuid.uuid4()`; `await run_record_store.create_run(run_id=, tenant_id=, pack_id=, pack_uuid=, pack_version=)` → genesis `run.lifecycle.pending`. **Before any refusal**, so every path carries a `run_id` (F1). (A genesis-write DB failure is fail-loud / 500 — a substrate outage, not a `RunResult`.)
1. Load+validate pack → on refusal: `transition(run_id, from_state="pending", to_state="refused", …)` + direct `_emit_refused` (`run.refused`) + `return RunResult(run_id=…, terminal_state="refused", …)`.
2. `scheduler.submit` → `accepted_queued` (cancel + `pending→refused` + `run.refused` + refused) / non-`accepted_immediate` (`pending→refused` + refused).
3. `scheduler.mark_running`; then `transition(run_id, from_state="pending", to_state="running", task_id=<scheduler task_id>)` → `run.lifecycle.running` (persists the scheduler `task_id` on the run row, linking run↔task).
4. `session = None`; `skip_destroy = False`; `session = await backend.create(policy, actor=, tenant_id=, pack_context=, requires_credentials=(), approval_request_id=request.approval_request_id)` inside the nested try:
   - `SandboxLifecycleRefused`, reason == `sandbox_approval_pending` → `scheduler.cancel` + `running→pending_approval` + `run.pending_approval` + `return RunResult(terminal_state="pending_approval", …)` (202). *(Seam-capable but not exercised by the read_only run shape.)*
   - other `SandboxLifecycleRefused` → `scheduler.cancel` + `running→refused` + `run.refused` (409).
   - generic `Exception` → `scheduler.fail(sandbox_create_refused)` + `running→failed` + `run.failed` (502).
5. `exec_result = await session.exec(list(argv), timeout_s=policy.walltime_s)` inside the nested try:
   - `Exception` → `scheduler.fail(workload_runtime_error)` + `running→failed` + `run.failed` (502). *(Falls through to `finally` → destroy; session exists.)*
6. **A3b branch — `if request.suspend_after_exec:`** (ordered so the no-destroy guard flips the instant suspend succeeds):
   - `await session.suspend()` (takes the `__suspend__` checkpoint + releases the container). **On success → set `skip_destroy = True` immediately, before any further `await`.** This is irrevocable for the request: a suspended session is never destroyed here, because `destroy()` tombstones it and `wake()` would then refuse `sandbox_wake_session_tombstoned`.
   - `meta, _ = await checkpoint_store.load_latest(session_id=session.session_id, tenant_id=request.tenant_id)` (the snapshot bytes are discarded — only `meta.checkpoint_id` is needed; a metadata-only read is a future optimization).
   - `transition(run_id, from_state="running", to_state="suspended", session_id=session.session_id, checkpoint_id=meta.checkpoint_id)` → `run.lifecycle.suspended` (the atomic "this run is now suspended + resumable" commit).
   - `scheduler.complete(task_id, …)` — the scheduler task's exec leg is done; the slot is freed (the *run* is suspended, recorded on the run record, not the scheduler).
   - `_emit_suspended(run_id=, task_id=<scheduler task_id str>, exit_code=, stdout_sha256=, stderr_sha256=, stdout_bytes=, stderr_bytes=, session_id=, checkpoint_id=)` → new direct `run.suspended`. **Value-free** (sha256, never raw output); `session_id`+`checkpoint_id` are the resume handle.
   - `return RunResult(run_id=str(run_id), task_id=task_id, terminal_state="suspended", exit_code=exec_result.exit_code, stdout=exec_result.stdout, stderr=exec_result.stderr, refusal_reason=None)`.

   **Post-suspend failure posture (P1):** once `session.suspend()` succeeds and `skip_destroy=True` is set, *no* failure in `load_latest`/`transition`/`scheduler.complete`/`_emit_suspended` destroys the session — the `finally` is gated on `skip_destroy`. Such a failure propagates (the request surfaces a 500) **without** tombstoning: the `__suspend__` checkpoint survives and self-heals via the retention reaper. The run record reflects whatever committed — if `running→suspended` committed, the run is resumable; if it failed before committing, the run stays `running` with a live suspended session (a benign orphan the reaper's retention purge reclaims; a reconcile sweep is a forward item). The invariant: **suspend success ⇒ no destroy in this request**, at most degraded run-record consistency, never data loss.
7. **Else (no suspend):** `scheduler.complete` + `running→completed` + `run.completed` + `return RunResult(terminal_state="completed", exit_code=…, …)`.
8. **`finally` — conditional teardown (F4):**
   ```python
   finally:
       if session is not None and not skip_destroy:
           try:
               await session.destroy()
           except Exception:
               logger.warning("run.session_destroy_failed",
                              extra={"request_id": request_id, "run_id": str(run_id),
                                     "session_id": session.session_id})
   ```
   `skip_destroy` starts `False` and flips to `True` the instant `session.suspend()` succeeds (step 6), so every post-suspend code path — success *or* exception — leaves the session intact. **Why this is correctness-critical, not hygiene:** `session.destroy()` is the unconditional teardown that **tombstones** the session, and `wake()` refuses a tombstoned session (`sandbox_wake_session_tombstoned`). Destroying a suspended session would make its checkpoint permanently un-wakeable. `suspend()` has already released the underlying container, so there is nothing to clean up on the suspend path — and there must not be.

**`resume()` method** (no scheduler involvement — see forward items):

```python
async def resume(self, *, run_id: uuid.UUID, actor: Actor, argv: tuple[str, ...]) -> RunResult:
```

1. `record = await run_record_store.load(run_id, tenant_id=actor.tenant_id)`; `if record is None: raise RunNotFound(run_id)` → route 404 (cross-tenant + unknown both invisible).
2. `if record.state != "suspended": raise RunNotResumable(record.state)` → route 409 `run_not_suspended`.
3. `session_id = record.session_id` (invariant: a `suspended` record always has `session_id` persisted per F4; a `None` here is a data-integrity error → fail-loud 500).
4. `session = None`; `claimed_woken = False`; teardown `finally: if session is not None and claimed_woken: await session.destroy()` — the woken session is destroyed **only after** the `suspended→woken` claim commits (see the resume-side teardown posture below; this closes the post-wake tombstone race).
5. `session = await backend.wake(session_id, actor=actor, tenant_id=actor.tenant_id)` inside the nested try:
   - `SandboxLifecycleRefused` (wake refusal — terminal) → `transition(run_id, from_state="suspended", to_state="refused")` + `_emit_refused` (`run.refused`) + `return RunResult(run_id=…, task_id=None, terminal_state="refused", refusal_reason=exc.reason, …)` (409). *(`exc.reason` is the sandbox wake reason — `sandbox_wake_checkpoint_corrupt`, `…_tombstoned`, etc.)*
   - generic `Exception` (wake infra) → `transition(suspended→failed)` + `_emit_failed` + `return RunResult(terminal_state="failed", …)` (502).
6. wake succeeded → **atomically claim the run** via `transition(run_id, from_state="suspended", to_state="woken")` → `run.lifecycle.woken`; on success set `claimed_woken = True`. **On `RunTransitionRefused`** from this claim (a concurrent resume won the race, or the row moved out of `suspended`) → `raise RunResumeConflict(run_id)` → route 409 `run_resume_conflict`; `claimed_woken` stays `False` so the `finally` does **not** destroy (the session is owned by the winning request — destroying it would tombstone the session that request is executing). *(No direct executor event for `woken` — it is a mid-resume transition, not a request terminal; the store's lifecycle row captures it.)*
7. `exec_result = await session.exec(list(argv), timeout_s=self._build_policy().walltime_s)` inside the nested try:
   - `Exception` (resumed exec infra) → `transition(woken→failed)` + `_emit_failed` + `return RunResult(terminal_state="failed", …)` (502).
8. `transition(run_id, from_state="woken", to_state="completed")` + `_emit_completed` + `return RunResult(terminal_state="completed", exit_code=exec_result.exit_code, …)` (200).

**Resume-side teardown posture (the wake/tombstone edge).** `session.destroy()` tombstones the session and `wake()` refuses a tombstoned session (`sandbox_wake_session_tombstoned`), so resume must never destroy a session it does not own. The `suspended→woken` transition is the atomic claim + mutex; the woken session is destroyed **only** when `claimed_woken` is `True`. This closes two shapes: (i) **single-request claim failure** — `wake()` succeeds but `suspended→woken` fails (a DB error, not a `RunTransitionRefused`): the exception propagates (500), `claimed_woken` stays `False`, the `finally` skips destroy, the rolled-back run record stays `suspended` and **resumable**, and the woken backend resource (the container/pod `wake()` created) is left **live and orphaned** — A3b deliberately does NOT destroy it, since destroying would tombstone the session and block future resume; (ii) **concurrent resume** — two requests both load `suspended` and both `wake()` (the realistic race: both read the same valid checkpoint so both wakes succeed; the loser's woken resource is likewise left live and orphaned), but the atomic claim admits exactly one — the winner sets `claimed_woken=True`, execs, and destroys; the loser's claim raises `RunTransitionRefused` → `RunResumeConflict` (409) and does **not** destroy, so it cannot tombstone the session the winner is executing. This is the inverse-polarity twin of the submit-side guard (submit flips `skip_destroy` ON at suspend success; resume flips `claimed_woken` ON at claim success). **The F5 matrix is unchanged** — the claim-failure path commits no transition (only the 409); wake refusal/infra still fire BEFORE the claim as `suspended→refused`/`suspended→failed`. **Honesty note:** the orphaned woken backend resource is a *resource leak, not data-loss*. The existing `CheckpointReaper` (`sandbox/reaper.py`) delegates to `CheckpointStore.purge_expired()`, which purges only object-store checkpoint/tombstone artifacts — it does **not** reap live Docker containers or Kubernetes pods. So this leaked resource is **not** auto-reclaimed today; a tombstone-safe wake-failure teardown / a real backend-resource reaper / reconcile sweep is an explicit **forward item**.

Resume's `RunResult.terminal_state` is always one of `{completed, failed, refused}` (never `suspended`/`pending_approval`). No pack re-load (the run validated its pack at submit; the woken session already carries the checkpointed pack context). The pre-flight 404/409 are HTTP errors, not run outcomes — no `run.*` chain row and no run-record transition (mirrors the submit route's 503/403 guards; auditing failed resume *attempts* is a forward item).

### 4. `portal/api/runs/dto.py` (off-gate)

```python
class RunResumeRequest(BaseModel):
    """Body for POST /api/v1/runs/{run_id}/resume. run_id is the path param;
    tenant/actor come from the bound Actor (extra='forbid')."""
    model_config = ConfigDict(frozen=True, extra="forbid")
    argv: list[str]                              # continuation; submit's bounds

    # argv reuses RunSubmitRequest's bounds via a shared module-private helper:
    # non-empty, <=64 items, each <=4096 UTF-8 bytes; else 422.
    @field_validator("argv")
    @classmethod
    def _argv_bounded(cls, v: list[str]) -> list[str]:
        return _validate_argv_bounds(v)          # shared with RunSubmitRequest (DRY)

class RunResponse(BaseModel):
    model_config = ConfigDict(frozen=True)
    run_id: str                                  # A3b — F1, additive, on every path
    task_id: str | None
    terminal_state: Literal["completed", "failed", "refused", "pending_approval", "suspended"]  # +suspended
    exit_code: int | None
    stdout_b64: str
    stderr_b64: str
    stdout_bytes: int
    stderr_bytes: int
    refusal_reason: str | None
    approval_request_id: str | None
```

The `argv` bound validator is shared with `RunSubmitRequest` (extract a module-private helper to keep DRY).

### 5. `portal/api/runs/routes.py` (off-gate) — the resume route

Add to `build_run_routes()` (same router, prefix `/api/v1/runs`):

```python
_require_resume = RequireScope("run.resume")
_STATUS_BY_TERMINAL["suspended"] = 202          # mirrors pending_approval

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
    return _run_response_from_result(result)     # shared projector (see below)
```

`_run_response_from_result(result)` is a new module-private projector that builds `RunResponse` from a `RunResult` — `run_id` + base64-encoded `stdout`/`stderr` + byte counts + `task_id`/`terminal_state`/`exit_code`/`refusal_reason`/`approval_request_id`. The **submit handler is refactored to use the same projector** (DRY; `run_id` lands on both responses through one shape). `_require_managed_run_executor` (the existing 503 `sandbox_runtime_unavailable` guard) is reused. `from __future__ import annotations` stays OMITTED (FastAPI `Annotated[..., Depends(...)]` invariant).

### 6. `portal/rbac/scopes.py` (CC) — the `run.resume` value (1-file)

```python
RunRBACScope = Literal["run.submit", "run.resume"]   # A3b — +run.resume
RUN_SCOPES: frozenset[RunRBACScope] = frozenset({"run.submit", "run.resume"})
```

`actor.py:143` and `enforcement.py:259` reference the type (`| RunRBACScope`) and need no change. `tests/unit/portal/rbac/test_run_scopes.py` updates to pin 2 values. **Verify-at-promotion**: scopes.py is on-gate; the commit re-runs `check_critical_coverage.py` on fresh data.

### 7. Composition root (off-gate) — `app.py` + `harness/sandbox.py`

**Checkpoint-store failure posture (P2):** A3b promotes the checkpoint store from *reaper-only-if-enabled* to **required** for the managed-run executor/backend (the executor's suspend path calls `load_latest`; the backend's suspend/wake persist + restore). The lifespan resolves exactly one store — an injected `create_app(checkpoint_store=...)` wins, else `_build_checkpoint_store_from_adapters(adapters, settings)` — **inside** the sandbox-construction try, so a store-build failure routes to the existing fail-soft. If sandbox runtime is enabled but the store cannot be built, both slots go `None` and the sandbox runtime is disabled; we **never** construct a resumable executor without a checkpoint store. The reaper reuses the same resolved store.

```python
if is_sandbox_available(settings) and settings.sandbox_runtime_enabled and runtime.scheduler is not None:
    try:
        # Resolve exactly one store INSIDE the try → a build failure fail-softs the runtime.
        checkpoint_store = app.state.checkpoint_store or _build_checkpoint_store_from_adapters(adapters, settings)
        backend, sandbox_docker_client = await build_sandbox_backend(
            settings=settings, runtime=runtime, checkpoint_store=checkpoint_store)   # A3b — real store
        app.state.sandbox_backend = backend
        app.state.managed_run_executor = ManagedRunExecutor(
            scheduler=runtime.scheduler, sandbox_backend=backend,
            pack_loader=PackRecordStoreLoader(store=PackRecordStore(adapters.relational.engine)),
            decision_history_store=runtime.decision_history_store, settings=settings,
            run_record_store=RunRecordStore(adapters.relational.engine),   # A3b
            checkpoint_store=checkpoint_store)                             # A3b — required, never None here
    except Exception:
        logger.error("sandbox.runtime_construction_failed", exc_info=True)
        if sandbox_docker_client is not None:
            await sandbox_docker_client.close()
        sandbox_docker_client = None
        app.state.sandbox_backend = None
        app.state.managed_run_executor = None
# The reaper wiring (below, unchanged) reuses the resolved app.state.checkpoint_store.
```

`harness/sandbox.py`: no signature change (`build_sandbox_backend` already accepts `checkpoint_store`); update the docstring note from "`checkpoint_store=None` in 14A-A (14A-A2 wires it)" to "wired in A3b (14A-A2 wired the route + approval, not the checkpoint store)". **No migration** — A3a's `runs` table already has every column A3b uses.

---

## Lifecycle + status maps (consolidated)

**Submit — `POST /api/v1/runs`:**

| Outcome | Run-record transition(s) | Direct event | `terminal_state` | HTTP |
|---|---|---|---|---|
| pack/admission refusal | `pending→refused` | `run.refused` | refused | 409 |
| sandbox approval pending | `running→pending_approval` | `run.pending_approval` | pending_approval | 202 |
| create infra / exec infra | `running→failed` | `run.failed` | failed | 502 |
| exec returns, no suspend | `running→completed` | `run.completed` | completed | 200 |
| exec returns, `suspend_after_exec` | `running→suspended` (+session_id, checkpoint_id) | `run.suspended` | suspended | **202** |

**Resume — `POST /api/v1/runs/{run_id}/resume`:**

| Outcome | Run-record transition(s) | Direct event | Result | HTTP |
|---|---|---|---|---|
| run not found / cross-tenant | — (none) | — | — | 404 |
| run not `suspended` | — (none) | — | — | 409 |
| resume conflict (concurrent claim lost) | — (none; no destroy) | — | `RunResumeConflict` | 409 |
| wake refusal | `suspended→refused` | `run.refused` | refused | 409 |
| wake infra | `suspended→failed` | `run.failed` | failed | 502 |
| resumed exec infra | `suspended→woken`, `woken→failed` | `run.failed` | failed | 502 |
| resumed exec returns | `suspended→woken`, `woken→completed` | `run.completed` | completed | 200 |

**Evidence model (dual, per F1):** the store emits `run.lifecycle.<state>` at **every** transition (`pending`/`running`/`suspended`/`woken`/`completed`/`failed`/`refused`/`pending_approval`); the executor emits **direct** value-free `run.<terminal>` at request terminals (`completed`/`failed`/`refused`/`pending_approval`/**`suspended`**). The two are intentionally distinct granularities (lifecycle markers vs output-evidence). `woken` has a store lifecycle row but no direct executor event (it is not a request terminal).

---

## Transition matrix (after A3b)

**Legal (12):** `pending→running`, `pending→refused`, `running→completed`, `running→failed`, `running→refused`, `running→pending_approval` (A3a) · `running→suspended`, `suspended→woken`, `suspended→refused`, `suspended→failed`, `woken→completed`, `woken→failed` (A3b).

**Still refused** (vocab present, runtime cannot produce): `woken→running`, `woken→suspended`, `suspended→completed`, `suspended→pending_approval`, all `*→cancelled`. `RunState` vocab unchanged at 9 values.

---

## CC surface + count

| Module | Gate | A3b change |
|---|---|---|
| `core/run/executor.py` | **CC** | run-record wiring, suspend path, conditional teardown, `resume()` (claim-gated teardown), `RunRequest.suspend_after_exec`, `RunResult.run_id`, `RunTerminalState +suspended`, `RunNotResumable`, `RunResumeConflict` |
| `core/run/storage.py` | **CC** | `_STATE_TO_DECISION_TYPE += {suspended, woken}` |
| `portal/rbac/scopes.py` | **CC** | `RunRBACScope += "run.resume"` |
| `core/run/_types.py` | off-gate | matrix expansion + doctrine pin |
| `portal/api/runs/dto.py` | off-gate | `RunResumeRequest`, `RunResponse.run_id` |
| `portal/api/runs/routes.py` | off-gate | resume route + `run.resume` + 404/409 |
| `harness/sandbox.py` | off-gate | docstring only |
| `portal/api/app.py` | off-gate | checkpoint_store threading + `run_record_store` + reorder |

**CC count stays 131** — no new on-gate module. The three on-gate edits run `check_critical_coverage.py` on fresh `--cov-branch` data in their commit (verify-at-promotion). Full suite + CC gate at the boundary.

---

## Test strategy (TDD — watch-it-fail first)

- **`_types`**: 12 legal pairs pass (parametrized); the still-refused set refuses (updated `test_reserved_pairs_refuse_until_expanded`); vocab still exactly 9.
- **`storage`**: `running→suspended` persists + snapshots `session_id`+`checkpoint_id`; `suspended→woken→completed` chain; `decision_type` strings `run.lifecycle.suspended`/`woken`; stale-read on the new pairs refuses `run_transition_invalid_state_pair`. (+ coverage to hold ≥95/90.)
- **`executor`** (real scheduler + real `DecisionHistoryStore` on in-memory sqlite + real `RunRecordStore` + stub backend/checkpoint-store, mirroring 14A-A's orchestration tests): genesis `run.lifecycle.pending` + `run_id` on every path; suspend path (`suspend_after_exec=True` → `suspend()` called → `load_latest` → `running→suspended` with session_id+checkpoint_id → `run.suspended` → **destroy NOT called** → `RunResult(suspended)`); non-suspend path unchanged (completes + destroys); `resume()` happy path (resolve→wake→exec→`woken→completed`→destroy); resume wake-refused (`suspended→refused`, `exc.reason` surfaced); resume wake-infra (`suspended→failed`); resume not-found (`RunNotFound`); resume not-suspended (`RunNotResumable(state)`); **resume claim-failure** (`wake()` ok but `suspended→woken` raises a DB error → propagates, **`destroy` NOT called**, run record stays `suspended`/resumable); **resume concurrent-conflict** (stub `wake()` commits `suspended→woken` as a side-effect so this request's claim stale-refuses → `RunResumeConflict`, **`destroy` NOT called**); conditional-teardown assertion (stub session records `destroy` calls — 0 on suspend, 0 on a resume claim-failure/conflict, 1 on complete and on a successfully-claimed resume terminal).
- **`routes`**: resume 200/502/409 terminal mapping + 404/409 pre-flight; `run.resume` 403 on scope miss; 503 when executor absent; `RunResponse.run_id` present on submit + resume.
- **`rbac`**: `test_run_scopes.py` pins 2 values + `run.*` namespace disjointness.
- **architecture fence**: `test_run_no_sdk_import.py` stays green (executor adds only `core.run.storage` runtime import + TYPE_CHECKING `CheckpointStore`; no `aiodocker`/`kubernetes_asyncio`/runtime `portal`).
- **env-gated e2e** (`tests/integration/run/`, `COGNIC_RUN_DOCKER_SANDBOX=1`): real DockerSibling `submit(suspend_after_exec=True) → 202 suspended → resume → 200 completed`; default-skip; fail-loud when opted in.

---

## Self-review

- **Placeholders:** none — the two illustrative `...` snippets were replaced with concrete shared helpers (`_validate_argv_bounds`, `_run_response_from_result`) per review P3.
- **Consistency:** `RunTerminalState` (executor, 5 values incl. `suspended`) vs `RunState` (store column, 9 values, unchanged) are distinct by design and used consistently; resume's terminal subset `{completed, failed, refused}` is a strict subset of `RunTerminalState`; the F3 status map and the resume map agree on 409/502/200; the matrix's 12 legal pairs are exactly the union used by the executor's transitions.
- **Scope:** single slice; no A3c approval surface; resume-no-scheduler + UI-stub-not-wired are explicit forward items, not silent omissions.
- **Ambiguity:** the F2 mechanic is the re-locked `suspend()`-then-`load_latest` form (no explicit `checkpoint(label)`); `checkpoint_id` is evidence/resolver context, not a wake input; conditional teardown is justified by the tombstone-on-destroy correctness point.
- **Failure posture (review P1 + P2):** the suspend no-destroy guard `skip_destroy` flips the instant `session.suspend()` succeeds, *before any further await*, so a post-suspend failure never tombstones (data-loss-free; at most a degraded `running`-with-live-suspended-session orphan the reaper reclaims). Direct `run.*` emitters carry `run_id` + nullable `task_id`, so resume evidence (no scheduler task) still correlates and dual evidence joins on `run_id`. The checkpoint store is resolved *inside* the sandbox-construction try, so a build failure fail-softs the runtime (`sandbox_backend=None`, `managed_run_executor=None`) rather than yielding a checkpoint-less resumable executor. On the resume side (the wake/tombstone edge), `claimed_woken` is the inverse-polarity guard — the woken session is destroyed ONLY after the atomic `suspended→woken` claim commits, so a claim failure (DB error) leaves the run `suspended`/resumable and a concurrent loser returns `RunResumeConflict` (409); neither tombstones a session it does not own.
