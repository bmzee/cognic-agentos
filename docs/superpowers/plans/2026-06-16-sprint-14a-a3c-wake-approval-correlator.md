# Sprint 14A-A3c — Wake Approval Correlator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Thread the 13.5c1 sandbox approval engine into the wake-path `admit_policy` so a resume that re-admits a session can pend for a human grant — completing the checkpoint→wake arc (the wake mirror of the 14A-A2 cold-create approval seam).

**Architecture:** The seam is ~90% pre-built. A3c is bounded wiring: extend `wake()` with `approval_request_id` (Protocol + both backends), pass `approval_engine`+`approval_request_id` into the wake `admit_policy`, stop the wake refusal-collapse wrapper from swallowing the `sandbox_approval_*` family, add a `pending_approval` arm + a no-re-mint guard to `executor.resume()`, expand the run-transition matrix by 4 pairs, carry `approval_request_id` on `RunResumeRequest`, and flip the `test_approval_threading.py` fence. **No `CheckpointMetadata` change** (the grant binds the already-persisted immutable `metadata.policy`/`pack_context`). **CC count stays 131.**

**Tech Stack:** Python 3.12, uv, pytest (`asyncio_mode=auto`), SQLAlchemy async (in-memory sqlite unit DB), FastAPI, the resumable-session API, the `core/approval` engine.

**Source of truth:** `docs/superpowers/specs/2026-06-16-sprint-14a-a3c-wake-approval-correlator-design.md` (committed `582f88d`). This plan mirrors it exactly.

---

## File structure

| File | Gate | Change |
|---|---|---|
| `src/cognic_agentos/core/run/_types.py` | off | `_A3C_VALID_TRANSITIONS` (+4 pairs) ∪ `_VALID_TRANSITIONS`; doctrine docstring |
| `src/cognic_agentos/sandbox/protocol.py` | **CC** | `wake()` Protocol += `approval_request_id`; the closed `sandbox_approval_*` wake-exemption constant `_APPROVAL_WAKE_PASSTHROUGH_REASONS` (single source, next to `SandboxRefusalReason`; imported by both backends) |
| `src/cognic_agentos/sandbox/backends/docker_sibling.py` | **CC** | `wake()` sig += param; wake `admit_policy` += `approval_engine`/`approval_request_id`; F3 wrapper exemption (imports the constant from `protocol.py`) |
| `src/cognic_agentos/sandbox/backends/kubernetes_pod.py` | **CC** | byte-identical to docker_sibling |
| `src/cognic_agentos/core/run/executor.py` | **CC** | `resume()` += `approval_request_id`; widen guard; `from_state=record.state`; no-re-mint guard; pending arm; `RunResumePendingApprovalRequired` + `RunResumeApprovalMismatch` |
| `src/cognic_agentos/portal/api/runs/dto.py` | off | `RunResumeRequest.approval_request_id` |
| `src/cognic_agentos/portal/api/runs/routes.py` | off | thread `approval_request_id`; map the 2 new refusals |
| docs | — | ADR-022, ADR-004, ADR-014, AGENTS.md, capability map |

**Tests:** `tests/unit/core/run/test_run_types.py`, `tests/unit/sandbox/backends/test_approval_threading.py`, `tests/unit/core/run/test_executor.py`, `tests/unit/portal/api/runs/test_run_routes.py` (+ dto), `tests/integration/run/test_managed_run_resume_approval_e2e.py`.

**CC count stays 131** — A3c edits only modules already on the gate (`protocol.py`, both backends, `executor.py`); no new on-gate module. `tools/check_critical_coverage.py` `_CRITICAL_FILES` + the self-test `_EXPECTED_ENTRY_COUNT` are **UNCHANGED**. `sandbox/admission.py`, `sandbox/checkpoint_store.py`, `core/run/storage.py` are **consumed, not edited**.

---

## Standing execution discipline (every task)

- **TDD:** write the failing test first, run it, watch it fail for the right reason, then the minimal implementation, then watch it pass.
- **Halt-before-commit reviewer gate (EVERY task):** after the gate ladder, STOP and present the watchpoint→pin mapping, fresh gate-ladder evidence (commands + output), and "files modified" (not staged). Wait for an explicit full-word commit token. Stage by explicit path; commit footer `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- **Gate ladder (per task):** focused pytest → neighborhood pytest (incl. `tests/unit/architecture/`) → `uv run ruff check .` → `uv run ruff format --check .` → full-tree `uv run mypy src tests`.
- **Verify-at-promotion (CC tasks T2/T3):** in the SAME commit, full suite with `--cov-branch`, then `uv run coverage json -o coverage.json` (NOT `--cov-report=json`), then `uv run python tools/check_critical_coverage.py`. The touched on-gate file must be ≥95% line / ≥90% branch; if below, add coverage; if a defensive branch is uncovered, cover it.
- **Boundary checkpoint (after T2 and T3):** full suite + `check_critical_coverage.py` (count must read 131). The full `--cov-branch` suite is ~13 min — run it as a background command and WAIT for it.
- **NEVER stage** `docs/reviews/` or `docs/superpowers/specs/2026-05-26-agentos-local-managed-agents-gap-analysis.md`.
- One `uv run` at a time (venv lock). No src edits during a background `--cov` run.
- Branch is `feat/sprint-14a-a3c-wake-approval-correlator` (already created; spec `582f88d` on it).

---

## Task 1: `_types.py` — wake-pending matrix pairs (off-gate)

**Files:**
- Modify: `src/cognic_agentos/core/run/_types.py`
- Test: `tests/unit/core/run/test_run_types.py`

- [ ] **Step 1: Write the failing tests.** Append to `test_run_types.py`:

```python
_A3C_LEGAL_PAIRS = {
    ("suspended", "pending_approval"),
    ("pending_approval", "woken"),
    ("pending_approval", "refused"),
    ("pending_approval", "failed"),
}

# Reserved AFTER A3c — pairs no runtime path produces (pending_approval only
# leaves to woken/refused/failed; cancelled still deferred; no re-loop/re-suspend).
_RESERVED_PAIRS_A3C = {
    ("woken", "running"),
    ("woken", "suspended"),
    ("woken", "pending_approval"),
    ("suspended", "completed"),
    ("pending_approval", "running"),
    ("pending_approval", "suspended"),
    ("pending_approval", "completed"),
    ("running", "cancelled"),
    ("pending", "cancelled"),
    ("suspended", "cancelled"),
    ("pending_approval", "cancelled"),
}


@pytest.mark.parametrize("pair", sorted(_A3C_LEGAL_PAIRS))
def test_a3c_pending_approval_pairs_are_legal(pair: tuple[str, str]) -> None:
    validate_transition(from_state=pair[0], to_state=pair[1])  # type: ignore[arg-type]  # no raise


@pytest.mark.parametrize("pair", sorted(_RESERVED_PAIRS_A3C))
def test_reserved_pairs_refuse_after_a3c(pair: tuple[str, str]) -> None:
    with pytest.raises(RunTransitionRefused) as exc:
        validate_transition(from_state=pair[0], to_state=pair[1])  # type: ignore[arg-type]
    assert exc.value.reason == "run_transition_invalid_state_pair"


def test_run_state_vocabulary_still_exactly_nine_after_a3c() -> None:
    assert len(get_args(RunState)) == 9
```

Also **delete** `test_reserved_pairs_refuse_after_a3c`'s predecessor logic that asserted `("suspended", "pending_approval")` refuses: find the A3b `_RESERVED_PAIRS_A3B` set + `test_reserved_pairs_refuse_after_a3b` and **remove the now-legal `("suspended", "pending_approval")` entry** (it is now in `_A3C_LEGAL_PAIRS`). Leave the rest of the A3b reserved test intact, or supersede it with `test_reserved_pairs_refuse_after_a3c` (which is its strict successor — the A3c reserved set above already covers every still-reserved A3b pair except the promoted one). Prefer: delete `_RESERVED_PAIRS_A3B` + `test_reserved_pairs_refuse_after_a3b` and rely on `test_reserved_pairs_refuse_after_a3c` (mirrors how A3b replaced the A3a reserved test).

- [ ] **Step 2: Run, watch fail.** `uv run pytest tests/unit/core/run/test_run_types.py -q`. Expected: `test_a3c_pending_approval_pairs_are_legal` FAILS (those 4 pairs raise today).

- [ ] **Step 3: Implement.** In `_types.py`, after `_A3B_VALID_TRANSITIONS`, add the A3c delta + fold it into the union:

```python
#: Sprint 14A-A3c — EXPAND ONLY (vocab unchanged): the wake-approval pairs.
#: First resume from `suspended` that hits a wake-pending -> pending_approval;
#: the granted re-resume claims pending_approval -> woken; a denied/expired grant
#: or a non-approval wake-revalidation refusal -> pending_approval -> refused; a
#: wake/exec infra-fail on re-resume -> pending_approval -> failed. No
#: pending_approval -> pending_approval self-loop (a still-pending re-resume is a
#: no-op, no transition).
_A3C_VALID_TRANSITIONS: Final[frozenset[tuple[RunState, RunState]]] = frozenset(
    {
        ("suspended", "pending_approval"),
        ("pending_approval", "woken"),
        ("pending_approval", "refused"),
        ("pending_approval", "failed"),
    }
)

#: The full legal matrix consumed by validate_transition (16 pairs).
_VALID_TRANSITIONS: Final[frozenset[tuple[RunState, RunState]]] = (
    _A3A_VALID_TRANSITIONS | _A3B_VALID_TRANSITIONS | _A3C_VALID_TRANSITIONS
)
```

Update the module DOCTRINE docstring (lines 8-15): note A3c expanded `_A3C_VALID_TRANSITIONS` (the wake-approval pairs) over the fixed 9-value vocab; the example pin is now `test_reserved_pairs_refuse_after_a3c`.

- [ ] **Step 4: Run, watch pass.** `uv run pytest tests/unit/core/run/test_run_types.py -q`. Expected: all pass.

- [ ] **Step 5: Gate ladder.** Focused + `tests/unit/core/run/` + ruff check + ruff format --check + `uv run mypy src tests`.

- [ ] **Step 6: Halt-before-commit.** Watchpoints: (a) the 4 wake-approval pairs legal — `test_a3c_pending_approval_pairs_are_legal`; (b) still-reserved refuse — `test_reserved_pairs_refuse_after_a3c`; (c) vocab unchanged at 9 — `test_run_state_vocabulary_still_exactly_nine_after_a3c`. Present evidence + files modified. Await token.

- [ ] **Step 7: Commit** (on token). Stage `src/cognic_agentos/core/run/_types.py tests/unit/core/run/test_run_types.py`. Message: `feat(run): A3c expand run-transition matrix with wake-approval pairs (ADR-022)`.

---

## Task 2: wake-path approval threading + wrapper exemption (CC, both backends)

**Files:**
- Modify: `src/cognic_agentos/sandbox/protocol.py` (`wake()` Protocol + the `_APPROVAL_WAKE_PASSTHROUGH_REASONS` constant)
- Modify: `src/cognic_agentos/sandbox/backends/docker_sibling.py` (`wake()` ~`:2382`; admit_policy ~`:2559-2573`)
- Modify: `src/cognic_agentos/sandbox/backends/kubernetes_pod.py` (`wake()` ~`:2250`; admit_policy ~`:2429-2443`)
- Test: `tests/unit/sandbox/backends/test_approval_threading.py`

**READ FIRST:** the cold-create `admit_policy` call (docker `:1120-1132`, k8s `:1150-1162`) is the threading template; both backends are byte-identical at the wake seam. `self._approval_engine` already exists (docker `:972`, k8s `:994`). The `SandboxLifecycleRefused` reason vocabulary lives on the `SandboxRefusalReason` Literal (`protocol.py:171-176` for wake reasons; the `sandbox_approval_*` reasons are defined alongside the approval seam).

- [ ] **Step 1: Write the failing tests.** In `test_approval_threading.py`, the existing fence asserts the wake path is un-threaded — **invert it**. Add (parametrize over both backends; use the existing test harness that constructs a backend with a recording stub `admit_policy` / a stub approval engine):

```python
_APPROVAL_REASONS = [
    "sandbox_approval_pending",
    "sandbox_approval_denied",
    "sandbox_approval_expired",
    "sandbox_approval_request_not_found",
    "sandbox_approval_binding_mismatch",
]


async def test_wake_threads_approval_engine_and_request_id(backend_with_recording_admit):
    backend, calls = backend_with_recording_admit  # admit_policy records its kwargs
    req_id = uuid.uuid4()
    await _drive_wake(backend, session_id="s", approval_request_id=req_id)
    kw = calls[-1]
    assert kw["approval_engine"] is backend._approval_engine
    assert kw["approval_request_id"] == req_id


@pytest.mark.parametrize("reason", _APPROVAL_REASONS)
async def test_wake_approval_refusal_passes_through_uncollapsed(backend_factory, reason):
    # admit_policy raises SandboxLifecycleRefused(reason, approval_request_id=R);
    # the wake wrapper must re-raise it un-rewrapped (reason + approval_request_id intact).
    backend = backend_factory(admit_raises=SandboxLifecycleRefused(reason, approval_request_id="R"))
    with pytest.raises(SandboxLifecycleRefused) as exc:
        await _drive_wake(backend, session_id="s", approval_request_id=uuid.uuid4())
    assert exc.value.reason == reason          # NOT collapsed
    assert exc.value.approval_request_id == "R"


async def test_wake_nonapproval_refusal_still_collapses(backend_factory):
    backend = backend_factory(admit_raises=SandboxLifecycleRefused("sandbox_admission_catalog_image_unknown"))
    with pytest.raises(SandboxLifecycleRefused) as exc:
        await _drive_wake(backend, session_id="s", approval_request_id=None)
    assert exc.value.reason == "sandbox_wake_policy_revalidation_failed"  # still collapsed
```

Plus a cross-backend lockstep test asserting both backends import the SAME exemption-set constant.

- [ ] **Step 2: Run, watch fail.** `uv run pytest tests/unit/sandbox/backends/test_approval_threading.py -q`. Expected: the threading + passthrough tests fail (wake doesn't thread / collapses everything today).

- [ ] **Step 3a: Implement the exemption constant.** In `sandbox/protocol.py`, next to the `SandboxRefusalReason` Literal (single source of truth — it is a subset of that closed vocabulary; CC-gated; both backends already import from `protocol.py`, so no new dependency), add:

```python
#: Sprint 14A-A3c — the wake refusal-collapse wrapper must let the approval
#: family pass through un-rewrapped so the executor sees sandbox_approval_pending
#: (and the approval_request_id). Single source of truth (no per-backend drift).
_APPROVAL_WAKE_PASSTHROUGH_REASONS: frozenset[str] = frozenset(
    {
        "sandbox_approval_pending",
        "sandbox_approval_denied",
        "sandbox_approval_expired",
        "sandbox_approval_request_not_found",
        "sandbox_approval_binding_mismatch",
    }
)
```

- [ ] **Step 3b: Implement `protocol.py` wake().** Extend the `SandboxBackend.wake` Protocol (`:730`) with a trailing keyword-only `approval_request_id: uuid.UUID | None = None` (mirror `create()`'s param at `:651-660`). Add `import uuid` if absent.

- [ ] **Step 3c: Implement both backends (byte-identical).** In each `wake()` signature, add `approval_request_id: uuid.UUID | None = None`. Replace the wake `admit_policy` call + its wrapper. Current (docker `:2558-2573`):

```python
        try:
            await admit_policy(
                metadata.policy,
                tenant_id=tenant_id,
                actor=actor,
                pack_context=metadata.pack_context,
                catalog=self._catalog,
                credential_adapter=self._credential_adapter,
                rego_engine=self._rego,
                settings=self._settings,
            )
        except SandboxLifecycleRefused as original:
            raise SandboxLifecycleRefused(
                "sandbox_wake_policy_revalidation_failed",
                detail=f"original={original.reason}: {original.detail}",
            ) from original
```

becomes:

```python
        try:
            await admit_policy(
                metadata.policy,
                tenant_id=tenant_id,
                actor=actor,
                pack_context=metadata.pack_context,
                catalog=self._catalog,
                credential_adapter=self._credential_adapter,
                rego_engine=self._rego,
                settings=self._settings,
                approval_engine=self._approval_engine,        # A3c — wake approval seam
                approval_request_id=approval_request_id,       # A3c — request-time correlator
            )
        except SandboxLifecycleRefused as original:
            # A3c — let the approval family pass through un-rewrapped so the
            # executor sees sandbox_approval_pending + the approval_request_id;
            # only genuine revalidation refusals collapse.
            if original.reason in _APPROVAL_WAKE_PASSTHROUGH_REASONS:
                raise
            raise SandboxLifecycleRefused(
                "sandbox_wake_policy_revalidation_failed",
                detail=f"original={original.reason}: {original.detail}",
            ) from original
```

Apply the identical change to `kubernetes_pod.py` (`:2429-2443`). Import `_APPROVAL_WAKE_PASSTHROUGH_REASONS` from `cognic_agentos.sandbox.protocol` in both backends. (Do NOT thread `requires_credentials` — out of approval scope.)

- [ ] **Step 4: Run, watch pass.** `uv run pytest tests/unit/sandbox/backends/test_approval_threading.py -q`. Watch pass.

- [ ] **Step 5: Gate ladder + verify-at-promotion + boundary.** Gate ladder. Then full `--cov-branch` (background) → `uv run coverage json -o coverage.json` → `uv run python tools/check_critical_coverage.py` (both backends + protocol.py ≥95/90; count 131). Boundary checkpoint — full suite green.

- [ ] **Step 6: Halt-before-commit.** Watchpoints: (a) wake threads `approval_engine`+`approval_request_id` (both backends) — `test_wake_threads_*`; (b) approval family passes through with `approval_request_id` — `test_wake_approval_refusal_passes_through_uncollapsed`; (c) non-approval still collapses — `test_wake_nonapproval_refusal_still_collapses`; (d) single exemption constant — lockstep test; (e) backends/protocol ≥95/90, count 131. Present evidence + files modified. Await token.

- [ ] **Step 7: Commit** (on token). Stage `src/cognic_agentos/sandbox/protocol.py src/cognic_agentos/sandbox/backends/docker_sibling.py src/cognic_agentos/sandbox/backends/kubernetes_pod.py tests/unit/sandbox/backends/test_approval_threading.py`. Message: `feat(sandbox): A3c thread approval engine into wake admit_policy + exempt approval family from the wake wrapper (ADR-004/014)`.

---

## Task 3: `executor.resume()` — pending arm + no-re-mint guard (CC)

**Files:**
- Modify: `src/cognic_agentos/core/run/executor.py` (`resume()` `:656-851`; add 2 exception classes near `RunNotResumable`/`RunResumeConflict`)
- Test: `tests/unit/core/run/test_executor.py`

**READ FIRST:** the current `resume()` (`:656-851`) hardcodes `from_state="suspended"` at `:712`, `:739`, `:771`; `RunRecord.approval_request_id` already exists (`_types.py:108`); the cold-create pending branch (`:439-476`) is the run.pending_approval/transition template; `_SANDBOX_APPROVAL_PENDING_REASON = "sandbox_approval_pending"` already exists in `executor.py`.

- [ ] **Step 1: Write the failing tests.** Extend the stub backend so `wake()` can be driven to: return a session, raise `SandboxLifecycleRefused("sandbox_approval_pending", approval_request_id=R)`, raise `SandboxLifecycleRefused("sandbox_approval_denied", ...)`, raise a generic exc. Tests:

A `uuid.UUID` correlator is used end-to-end: `SandboxLifecycleRefused.approval_request_id` is a **str** (mirrors the cold-create path's `str(request.request_id)`); the executor parses it via `uuid.UUID(...)` to store on the run row (`RunRecord.approval_request_id: uuid.UUID | None`, `_types.py:108`) and returns it as the str on `RunResult.approval_request_id`; the re-resume caller supplies a `uuid.UUID` (`RunResumeRequest.approval_request_id: uuid.UUID | None`). A small test helper drives a run to `pending_approval`:

```python
async def _drive_to_pending_approval(executor, stub_backend, run_store, actor, req_ok, arid_str):
    """First resume: run -> suspended -> wake-pending. Returns the run_id (uuid.UUID)."""
    s = await executor.run(replace(req_ok, suspend_after_exec=True))   # run row: suspended
    stub_backend.wake_raises = SandboxLifecycleRefused(
        "sandbox_approval_pending", approval_request_id=arid_str)
    await executor.resume(run_id=uuid.UUID(s.run_id), actor=actor, argv=("x",))
    return uuid.UUID(s.run_id)


async def test_resume_first_pending_transitions_suspended_to_pending_approval(...):
    arid = uuid.uuid4()
    s = await executor.run(replace(req_ok, suspend_after_exec=True))   # run row: suspended
    stub_backend.wake_raises = SandboxLifecycleRefused(
        "sandbox_approval_pending", approval_request_id=str(arid))
    res = await executor.resume(run_id=uuid.UUID(s.run_id), actor=actor, argv=("x",))
    assert res.terminal_state == "pending_approval" and res.approval_request_id == str(arid)
    rec = await run_store.load(uuid.UUID(s.run_id), tenant_id="t1")
    assert rec.state == "pending_approval" and rec.approval_request_id == arid   # stored as UUID
    assert stub_session.destroy_calls == 0   # pending arm never claims -> never destroys


async def test_resume_reresume_requires_approval_id(...):
    arid = uuid.uuid4()
    run_id = await _drive_to_pending_approval(executor, stub_backend, run_store, actor, req_ok, str(arid))
    wake_before = stub_backend.wake_calls
    with pytest.raises(RunResumePendingApprovalRequired):
        await executor.resume(run_id=run_id, actor=actor, argv=("x",))   # no approval_request_id
    assert stub_backend.wake_calls == wake_before   # wake NOT called again (no Arm-A re-mint)


async def test_resume_reresume_mismatched_id_refuses(...):
    arid = uuid.uuid4()
    run_id = await _drive_to_pending_approval(executor, stub_backend, run_store, actor, req_ok, str(arid))
    wake_before = stub_backend.wake_calls
    with pytest.raises(RunResumeApprovalMismatch):
        await executor.resume(run_id=run_id, actor=actor, argv=("x",), approval_request_id=uuid.uuid4())
    assert stub_backend.wake_calls == wake_before   # wake NOT called


async def test_resume_reresume_still_pending_no_transition(...):
    arid = uuid.uuid4()
    run_id = await _drive_to_pending_approval(executor, stub_backend, run_store, actor, req_ok, str(arid))
    # re-resume with matching id, wake STILL pending (awaiting_second) -> no transition.
    stub_backend.wake_raises = SandboxLifecycleRefused(
        "sandbox_approval_pending", approval_request_id=str(arid))
    res = await executor.resume(run_id=run_id, actor=actor, argv=("x",), approval_request_id=arid)
    assert res.terminal_state == "pending_approval" and res.approval_request_id == str(arid)
    assert (await run_store.load(run_id, tenant_id="t1")).state == "pending_approval"


async def test_resume_reresume_granted_completes(...):
    arid = uuid.uuid4()
    run_id = await _drive_to_pending_approval(executor, stub_backend, run_store, actor, req_ok, str(arid))
    stub_backend.wake_raises = None
    stub_backend.wake_returns = StubSession(exit_code=0)   # grant verified in admission -> wake returns
    res = await executor.resume(run_id=run_id, actor=actor, argv=("echo",), approval_request_id=arid)
    assert res.terminal_state == "completed"
    assert (await run_store.load(run_id, tenant_id="t1")).state == "completed"   # pending_approval->woken->completed


async def test_resume_reresume_denied_refuses(...):
    arid = uuid.uuid4()
    run_id = await _drive_to_pending_approval(executor, stub_backend, run_store, actor, req_ok, str(arid))
    stub_backend.wake_raises = SandboxLifecycleRefused("sandbox_approval_denied", approval_request_id=str(arid))
    res = await executor.resume(run_id=run_id, actor=actor, argv=("x",), approval_request_id=arid)
    assert res.terminal_state == "refused" and res.refusal_reason == "sandbox_approval_denied"
    assert (await run_store.load(run_id, tenant_id="t1")).state == "refused"   # pending_approval->refused
```

- [ ] **Step 2: Run, watch fail.** `uv run pytest tests/unit/core/run/test_executor.py -k "pending or approval or reresume" -q`. Expected: fail — no `approval_request_id` param / no `RunResumePendingApprovalRequired`.

- [ ] **Step 3a: Add the two exceptions** (near `RunNotResumable`/`RunResumeConflict`):

```python
class RunResumePendingApprovalRequired(Exception):
    """resume() of a run already in 'pending_approval' WITHOUT an approval_request_id.
    The route maps it to 409 run_resume_approval_id_required. Raised BEFORE wake() so
    admission Arm A (mint) is never reached — no silent new-pending loop."""
    def __init__(self, run_id: uuid.UUID) -> None:
        self.run_id = run_id
        super().__init__(f"run_resume_approval_id_required: {run_id}")


class RunResumeApprovalMismatch(Exception):
    """resume() of a 'pending_approval' run with an approval_request_id that does not
    match the run row's stored one. Route -> 409 run_resume_approval_id_mismatch."""
    def __init__(self, run_id: uuid.UUID) -> None:
        self.run_id = run_id
        super().__init__(f"run_resume_approval_id_mismatch: {run_id}")
```

- [ ] **Step 3b: Rework `resume()`.** Signature: `async def resume(self, *, run_id, actor, argv, approval_request_id: uuid.UUID | None = None) -> RunResult`. After `record = await self._runs.load(...)`:

```python
        if record is None:
            raise RunNotFound(run_id)
        if record.state not in ("suspended", "pending_approval"):   # A3c — widen
            raise RunNotResumable(record.state)
        if record.session_id is None:
            raise RuntimeError(f"run_suspended_without_session_id: {run_id}")
        from_state = record.state   # A3c — suspended (first) OR pending_approval (re-resume)

        # A3c no-re-mint guard: a pending_approval run MUST supply its stored id and
        # never re-enters admission Arm A (mint).
        if record.state == "pending_approval":
            if approval_request_id is None:
                raise RunResumePendingApprovalRequired(run_id)
            if record.approval_request_id is None or approval_request_id != record.approval_request_id:
                raise RunResumeApprovalMismatch(run_id)
```

Thread the correlator into wake:

```python
                session = await self._sandbox_backend.wake(
                    record.session_id, actor=actor, tenant_id=actor.tenant_id,
                    approval_request_id=approval_request_id,   # A3c
                )
```

Replace the `except SandboxLifecycleRefused as exc:` arm (`:706-732`) with the dispatch (note `from_state` everywhere, not the hardcoded `"suspended"`):

```python
            except SandboxLifecycleRefused as exc:
                if exc.reason == _SANDBOX_APPROVAL_PENDING_REASON:
                    # A3c wake-pending. First resume (suspended): transition to
                    # pending_approval + store the minted id. Re-resume already in
                    # pending_approval (still awaiting): NO transition (no self-loop).
                    if from_state != "pending_approval":
                        await self._runs.transition(
                            run_id=run_id, tenant_id=actor.tenant_id,
                            from_state=from_state, to_state="pending_approval",
                            actor_id=actor.subject, request_id=request_id,
                            approval_request_id=(uuid.UUID(exc.approval_request_id)
                                                 if exc.approval_request_id else None),
                        )
                    await self._emit_pending(
                        _resume_req(actor, record), request_id, run_id=rid,
                        task_id=None, approval_request_id=exc.approval_request_id,
                    )
                    return RunResult(
                        run_id=rid, task_id=None, terminal_state="pending_approval",
                        exit_code=None, stdout=b"", stderr=b"", refusal_reason=None,
                        approval_request_id=exc.approval_request_id,
                    )
                # any other SandboxLifecycleRefused (sandbox_approval_denied/expired/
                # not_found/binding_mismatch OR sandbox_wake_*) -> refused.
                await self._runs.transition(
                    run_id=run_id, tenant_id=actor.tenant_id,
                    from_state=from_state, to_state="refused",
                    actor_id=actor.subject, request_id=request_id,
                )
                await self._emit_refused(
                    _resume_req(actor, record), request_id, run_id=rid,
                    task_id=None, reason=str(exc.reason),
                )
                return RunResult(
                    run_id=rid, task_id=None, terminal_state="refused", exit_code=None,
                    stdout=b"", stderr=b"", refusal_reason=str(exc.reason),
                )
```

In the `except Exception:` wake-infra arm (`:733-759`) and the atomic claim (`:767-778`), replace `from_state="suspended"` with `from_state=from_state`. (The post-claim `woken→failed`/`woken→completed` transitions stay `"woken"`.) The claim becomes `from_state→woken` (suspended→woken or pending_approval→woken — both legal per T1). The `_emit_pending` helper already exists (the cold-create path uses it); confirm its signature matches the call.

- [ ] **Step 4: Run, watch pass.** `uv run pytest tests/unit/core/run/test_executor.py -q`. Watch pass.

- [ ] **Step 5: Gate ladder + verify-at-promotion + boundary.** Gate ladder; full `--cov-branch` (background) → coverage json → `check_critical_coverage.py` (executor.py ≥95/90; count 131). Boundary — full suite green.

- [ ] **Step 6: Halt-before-commit.** Watchpoints: first-pending → suspended→pending_approval + id stored + no destroy; re-resume-no-id → `RunResumePendingApprovalRequired` + **wake NOT called** (no re-mint); re-resume-mismatch → `RunResumeApprovalMismatch` + wake NOT called; still-pending → no transition + same id; granted → pending_approval→woken→completed; denied → pending_approval→refused; the claim-gated teardown unbroken (pending/refused arms never destroy); executor ≥95/90, count 131. Present evidence + files modified. Await token.

- [ ] **Step 7: Commit** (on token). Stage `src/cognic_agentos/core/run/executor.py tests/unit/core/run/test_executor.py`. Message: `feat(run): A3c executor resume() wake-approval pending arm + no-re-mint guard (ADR-022/014)`.

---

## Task 4: `dto.py` + `routes.py` — resume correlator + refusal mappings (off-gate)

**Files:**
- Modify: `src/cognic_agentos/portal/api/runs/dto.py` (`RunResumeRequest`)
- Modify: `src/cognic_agentos/portal/api/runs/routes.py` (`resume_run` + imports)
- Test: `tests/unit/portal/api/runs/test_run_routes.py`

- [ ] **Step 1: Write the failing tests.** Add resume-route tests (stub executor on `app.state.managed_run_executor`): 202 + `approval_request_id` echoed when `executor.resume` returns `pending_approval`; 200 when it returns `completed`; 409 `run_resume_approval_id_required` when `executor.resume` raises `RunResumePendingApprovalRequired`; 409 `run_resume_approval_id_mismatch` when it raises `RunResumeApprovalMismatch`; the request body accepts an optional `approval_request_id` and threads it to `executor.resume`.

- [ ] **Step 2: Run, watch fail.** `uv run pytest tests/unit/portal/api/runs/ -q`. Expected: fail (no `approval_request_id` field / no refusal mapping).

- [ ] **Step 3a: Implement `dto.py`.** Add the optional correlator to `RunResumeRequest` (mirror `RunSubmitRequest.approval_request_id`):

```python
class RunResumeRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    argv: list[str]
    approval_request_id: uuid.UUID | None = None   # A3c — re-resume after grant

    @field_validator("argv")
    @classmethod
    def _argv_bounded(cls, v: list[str]) -> list[str]:
        return _validate_argv_bounds(v)
```

Add `import uuid` if absent.

- [ ] **Step 3b: Implement `routes.py`.** Extend the resume import + the handler:

```python
from cognic_agentos.core.run.executor import (
    ManagedRunExecutor, RunNotResumable, RunRequest, RunResult,
    RunResumeApprovalMismatch, RunResumeConflict, RunResumePendingApprovalRequired,
)
```

In `resume_run`, thread the correlator + map the two new refusals:

```python
        try:
            result = await executor.resume(
                run_id=run_id, actor=actor, argv=tuple(body.argv),
                approval_request_id=body.approval_request_id,   # A3c
            )
        except RunNotFound:
            raise HTTPException(status_code=404, detail={"reason": "run_not_found"}) from None
        except RunNotResumable as exc:
            raise HTTPException(status_code=409,
                detail={"reason": "run_not_suspended", "current_state": exc.current_state}) from None
        except RunResumePendingApprovalRequired:
            raise HTTPException(status_code=409,
                detail={"reason": "run_resume_approval_id_required"}) from None
        except RunResumeApprovalMismatch:
            raise HTTPException(status_code=409,
                detail={"reason": "run_resume_approval_id_mismatch"}) from None
        except RunResumeConflict:
            raise HTTPException(status_code=409, detail={"reason": "run_resume_conflict"}) from None
        response.status_code = _STATUS_BY_TERMINAL[result.terminal_state]
        return _run_response_from_result(result)
```

`pending_approval → 202` already exists in `_STATUS_BY_TERMINAL`; `_run_response_from_result` already carries `approval_request_id` — no other route change. Keep `from __future__ import annotations` OMITTED.

- [ ] **Step 4: Run, watch pass.** `uv run pytest tests/unit/portal/api/runs/ -q`.

- [ ] **Step 5: Gate ladder + boundary.** Gate ladder; full suite + `check_critical_coverage.py` (count 131 — no on-gate file changed here; run as the regression check).

- [ ] **Step 6: Halt-before-commit.** Watchpoints: 202 + correlator on pending; 200 on completed; 409 `run_resume_approval_id_required` / `run_resume_approval_id_mismatch`; the body threads `approval_request_id`. Present evidence + files modified. Await token.

- [ ] **Step 7: Commit** (on token). Stage `src/cognic_agentos/portal/api/runs/dto.py src/cognic_agentos/portal/api/runs/routes.py tests/unit/portal/api/runs/test_run_routes.py`. Message: `feat(api): A3c resume route approval_request_id correlator + pending-guard refusals (ADR-022/014)`.

---

## Task 5: env-gated docker e2e — wake-approval cycle (off-gate)

**Files:**
- Create: `tests/integration/run/test_managed_run_resume_approval_e2e.py`

- [ ] **Step 1: Write the e2e.** Mirror `tests/integration/run/test_managed_run_resume_e2e.py` (real `DockerSiblingSandboxBackend` + real `RunRecordStore` + real shared `CheckpointStore`), gated on `COGNIC_RUN_DOCKER_SANDBOX=1`. **Drive the pending→grant cycle with a stub/conformer approval engine** (NOT a real `ApprovalEngine` — the read_only shape auto-tiers under a real engine and never pends). Construct the backend with `approval_engine=<conformer that returns pending on the first admit then granted after an out-of-band "grant" flip>`. Body: `run(suspend_after_exec=True)` → `suspended`; `resume()` (no id) → `pending_approval` + 202-shaped result + `approval_request_id`; flip the conformer to "granted"; `resume(approval_request_id=<id>)` → `completed`; assert the runs row walks `pending→running→suspended→pending_approval→woken→completed` and the `run.lifecycle.*` + `run.pending_approval`/`run.completed` chain rows exist. Default-skip; fail-loud when opted in. Document inline that this proves the **wake/resume mechanics + threading**, not real-approval-engine live behaviour (high-risk run shape deferred per F4).

- [ ] **Step 2: Verify skip-by-default.** This e2e mirrors the existing one's module-level `pytest.skip(..., allow_module_level=True)` (the repo pattern at `test_managed_run_resume_e2e.py:47`), so the **single-file** command `uv run pytest tests/integration/run/test_managed_run_resume_approval_e2e.py -q` exits **5** with `1 skipped` (no tests ran — module-level skip; this is expected, the same behaviour accepted at A3b T7, not a collection error). For the **exit-0 clean-collection** check, run the package: `uv run pytest tests/integration/run/ -q` → all skipped, exit 0, no collection/import error.

- [ ] **Step 3: Gate ladder (paths touched).** ruff check + ruff format --check + `uv run mypy src tests` for the new file.

- [ ] **Step 4: Halt-before-commit.** Watchpoints: default-skip clean; stub/conformer (not real engine) drives the pending→grant cycle; the 6-state walk asserted; no gated source touched. Present evidence + files modified. Await token.

- [ ] **Step 5: Commit** (on token). Stage `tests/integration/run/test_managed_run_resume_approval_e2e.py`. Message: `test(run): A3c env-gated wake-approval suspend->pending->grant->resume docker e2e (ADR-022/004/014)`.

---

## Task 6: docs (off-gate)

**Files:**
- Modify: `docs/adrs/ADR-022-runtime-scheduler.md`, `docs/adrs/ADR-004-sandbox-primitive.md`, `docs/adrs/ADR-014-runtime-tool-approval.md`, `AGENTS.md`, `docs/AS_BUILT_CAPABILITY_MAP.md`

- [ ] **Step 1: ADR amendments.** ADR-004 (sandbox): the wake-path `admit_policy` now threads the approval engine (cold-create mirror); the wrapper exempts the `sandbox_approval_*` family; **no `CheckpointMetadata` change** (the grant binds the already-persisted immutable `metadata.policy`/`pack_context`). ADR-014 (approval): the wake-approval seam is the 5th `admit_policy` consumer (after cold-create); the no-re-mint guard. ADR-022 (run): the run-record wake-pending lifecycle (`suspended→pending_approval→woken`), the no-re-mint contract, resume-no-scheduler still holds. State HONESTLY: wired + unit-proven; **high-risk live exercise deferred (F4)** — the read_only shape never pends under a real engine; orphaned-resource + quota-on-resume still deferred.

- [ ] **Step 2: AGENTS.md.** Under the Run-persistence section, add an A3c note: the wake-path approval correlator landed; `protocol.py` wake() gained `approval_request_id`; both backends thread the engine + exempt the approval family; `executor.resume()` gained the pending arm + no-re-mint guard; matrix +4 pairs; **CC count stays 131** (no new on-gate module). The A3c fence A3b held is now crossed; the checkpoint→wake arc's wiring is complete.

- [ ] **Step 3: Capability map.** Pillar 2 + pillar 6 (approval seams): A3c done (wake-approval seam wired + unit-proven); update the approval-seams count (the sandbox WAKE seam now wired alongside cold-create). High-risk live exercise + the remaining forward items stay listed.

- [ ] **Step 4: Halt-before-commit.** Watchpoints: honesty (wired-not-live-exercised; high-risk deferred; no CheckpointMetadata change; count 131; arc-wiring-complete-not-fully-live); no protected docs staged. Present files modified. Await token.

- [ ] **Step 5: Commit** (on token). Stage the docs only. Message: `docs: A3c wake approval correlator — ADR-022/004/014 + AGENTS.md + capability map`.

---

## Self-review

**Spec coverage:** every spec component maps to a task — `_types` matrix (T1), wake threading + wrapper exemption (T2), executor pending arm + no-re-mint guard (T3), dto+route correlator (T4), e2e (T5), docs (T6). F1 (no CheckpointMetadata change — nothing edits it), F2 (durable pending_approval + the no-re-mint pin — T1 matrix + T3 guard/arm), F3 (wrapper exemption — T2), F4 (stub-engine e2e, high-risk deferred — T5 + T6 honesty) all present.

**Placeholder scan:** the `_drive_wake` / `backend_with_recording_admit` / `backend_factory` test helpers in T2 are described by behaviour because they bind to the existing `test_approval_threading.py` harness the implementer reads first; every production code block is shown in full. No "TBD"/"add error handling".

**Type consistency:** `approval_request_id: uuid.UUID | None` is consistent across `wake()` (Protocol + backends), `resume()`, and `RunResumeRequest`; the `sandbox_approval_*` exemption set is defined once in `sandbox/protocol.py` (`_APPROVAL_WAKE_PASSTHROUGH_REASONS`, imported by both backends in T2) and is the same 5 reasons T3's dispatch keys on (the executor matches `_SANDBOX_APPROVAL_PENDING_REASON` for the pending arm and treats the other 4 as `refused`); `from_state = record.state` in T3 is consistent with the T1 matrix pairs (`suspended→pending_approval`, `pending_approval→{woken,refused,failed}`); the two new exceptions (`RunResumePendingApprovalRequired`, `RunResumeApprovalMismatch`) are defined in T3 and consumed in T4.

**Ordering:** T1 (matrix) → T2 (sandbox wake, boundary) → T3 (executor, boundary) → T4 (route) → T5 (e2e) → T6 (docs). T2's wake-pending output feeds T3's pending arm; T3's new exceptions feed T4's mappings. CC count stays 131 throughout.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-16-sprint-14a-a3c-wake-approval-correlator.md`. Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task + two-stage review (spec-compliance then code-quality), halt-before-commit on every task.
2. **Inline Execution** — execute tasks in this session with checkpoints.

Which approach?
