# Sprint 14A-A2 Run Route + Sandbox Approval Threading Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. (This arc is executed INLINE per the operator's standing discipline — halt-before-commit reviewer gate on every task, separate full-word commit tokens.)

**Goal:** Make the managed-run path LIVE-exercised through a production `POST /api/v1/runs` caller, and wire the sandbox approval-engine branch so the run→pending→grant→re-POST contract becomes real.

**Architecture:** `POST /api/v1/runs` (new off-gate route) binds the authenticated `Actor`, gates on a new `run.submit` RBAC scope, and drives `app.state.managed_run_executor.run(RunRequest)`. The executor (CC) gains a `pending_approval` terminal state: when `backend.create()` raises `SandboxLifecycleRefused("sandbox_approval_pending")`, the executor cancels the running scheduler task (releasing quota), emits value-free `run.pending_approval` evidence, and returns `202` + the approval-request id. 14A-A2b threads `approval_engine` + `approval_request_id` through both sandbox backends → `admit_policy` so that pending path becomes reachable via the real backend.

**Tech Stack:** Python 3.12, uv, pytest (asyncio_mode=auto), FastAPI (lifespan + `Annotated[..., Depends(...)]`), SQLAlchemy async (in-memory sqlite for unit DB), Pydantic v2, OPA/Rego, Vault transport. mypy strict (`tests.*` untyped allowed); 100-char lines; value-free chain posture.

---

## Decisions locked from the committed spec (`docs/superpowers/specs/2026-06-14-sprint-14a-a2-run-route-sandbox-approval-design.md`)

- **Valve:** 14A-A2a (T1 scope + T2 route/executor) → 14A-A2b (T3 sandbox threading). The committed spec's §8 had route+RBAC+executor as one task; this plan splits the RBAC vocab (T1) from the route surface (T2) for tighter on-gate halts. Valve checkpoint = after T2.
- **Mount (spec finding 1):** the run router mounts UNCONDITIONALLY at construction time (eval-router pattern, app.py:1294); the request-time `_require_managed_run_executor` dep is the sole gate → `503 sandbox_runtime_unavailable` when the lifespan did not populate `app.state.managed_run_executor`. No `decision_history_store` mount dep (the executor owns DH).
- **Import-boundary pin (spec finding 2):** the executor catches `SandboxLifecycleRefused` via a FUNCTION-LOCAL import inside `run()` — never a module-level sandbox import. `tests/unit/architecture/test_run_no_sdk_import.py::test_core_run_imports_without_hvac` stays green + a new AST assertion pins no module-level sandbox import.
- **Pending-reason precision + classification (F3 status map):** only `sandbox_approval_pending` maps to the `202` pending path. The other `sandbox_approval_*` reasons (`_denied` / `_expired` / `_binding_mismatch` / `_request_not_found`) — and every non-approval `SandboxLifecycleRefused` (`high_risk_tier_refused`, catalog/egress) — are terminal governance refusals → **`refused`/409** (cancel + `run.refused` carrying the sandbox reason); in 14A-A2a the approval ones are UNREACHABLE via the real backend (`approval_engine=None`), reachable in 14A-A2b. A generic `create()` exception OR any `exec()` exception → **`failed`/502** (`scheduler.fail` + `run.failed`). Policy/admission refusal is a governance conflict (409), not infrastructure failure (502).
- **create() param type (plan-time precision over spec §3):** `SandboxBackend.create` gains `approval_request_id: uuid.UUID | None = None` (matching `admit_policy`'s `uuid.UUID | None`), NOT `str`. Only the OUTPUT correlator is `str | None`: `SandboxLifecycleRefused.approval_request_id` (str) → `RunResult.approval_request_id` (str) → `RunResponse.approval_request_id` (str).
- **Wake-path deferral (review finding):** 14A-A2b threads approval through the COLD `create()` `admit_policy` ONLY. The wake-revalidation `admit_policy` (docker ~:2547, k8s ~:2417) is LEFT UNCHANGED — checkpoint→wake (incl. its approval-correlator threading) is a separate deferred slice; half-wiring `approval_engine` onto a dormant surface is avoided. T3 threads `approval_request_id` into the route→executor→cold-create path; T2 adds a route→executor threading pin (`test_body_approval_request_id_and_actor_reach_executor`).
- **CC-posture correction (plan-time over spec §7):** `portal/rbac/scopes.py`, `portal/rbac/actor.py`, `portal/rbac/enforcement.py` are ALL on the coverage gate (gate file lines 487/491/495). T1's three scope-plumbing edits are on-gate (verify-at-promotion each). `core/run/executor.py` (T2 + T3), `sandbox/protocol.py` + `sandbox/backends/docker_sibling.py` + `sandbox/backends/kubernetes_pod.py` (T3) are on the gate. The route/dto (`portal/api/runs/`), `harness/sandbox.py`, `portal/api/app.py` are off-gate. **No NEW gate module → count stays 130; do NOT touch the `_EXPECTED_ENTRY_COUNT` pin.**

## File structure

| File | Task | On gate? | Change |
|---|---|---|---|
| `src/cognic_agentos/portal/rbac/scopes.py` | T1 | YES | add `RunRBACScope` + `RUN_SCOPES` |
| `src/cognic_agentos/portal/rbac/actor.py` | T1 | YES | widen `Actor.scopes` union with `RunRBACScope` |
| `src/cognic_agentos/portal/rbac/enforcement.py` | T1 | YES | widen `RequireScope` param union with `RunRBACScope` |
| `tests/unit/portal/rbac/test_run_scopes.py` | T1 | — | NEW |
| `src/cognic_agentos/core/run/executor.py` | T2,T3 | YES | T2: `RunRequest.approval_request_id`, `RunResult.pending_approval`+field, `_emit_pending`, pending branch. T3: thread `approval_request_id` into `backend.create` |
| `src/cognic_agentos/portal/api/runs/__init__.py` | T2 | no | NEW (package marker) |
| `src/cognic_agentos/portal/api/runs/dto.py` | T2 | no | NEW |
| `src/cognic_agentos/portal/api/runs/routes.py` | T2 | no | NEW |
| `src/cognic_agentos/portal/api/app.py` | T2 | no | mount run router unconditionally |
| `tests/unit/architecture/test_run_no_sdk_import.py` | T2 | — | add no-module-level-sandbox-import assertion |
| `tests/unit/core/run/test_executor.py` | T2,T3 | — | T2: pending path + RunResult field. T3: backend.create threads approval_request_id |
| `tests/unit/portal/api/runs/test_run_routes.py` | T2 | — | NEW |
| `src/cognic_agentos/sandbox/protocol.py` | T3 | YES | `create` += `approval_request_id`; `import uuid` |
| `src/cognic_agentos/sandbox/backends/docker_sibling.py` | T3 | YES | `__init__` += `approval_engine`; `create` += `approval_request_id`; thread both into the **cold-create** `admit_policy` (wake path unchanged) |
| `src/cognic_agentos/sandbox/backends/kubernetes_pod.py` | T3 | YES | same as docker_sibling |
| `src/cognic_agentos/harness/sandbox.py` | T3 | no | thread `approval_engine=runtime.approval_engine` into `get_backend` |
| `tests/unit/sandbox/backends/test_approval_threading.py` | T3 | — | NEW (cross-backend lockstep) |
| `tests/unit/harness/test_sandbox.py` | T3 | — | assert approval_engine threaded |
| ADRs + AGENTS.md + capability map | T4 | — | amendments |

---

## Task 1: `run.submit` RBAC scope (3 on-gate edits)

**Files:**
- Modify: `src/cognic_agentos/portal/rbac/scopes.py`
- Modify: `src/cognic_agentos/portal/rbac/actor.py`
- Modify: `src/cognic_agentos/portal/rbac/enforcement.py`
- Test: `tests/unit/portal/rbac/test_run_scopes.py` (NEW)

- [ ] **Step 1: Write the failing test**

Create `tests/unit/portal/rbac/test_run_scopes.py`:

```python
"""Sprint 14A-A2a — run.submit RBAC scope (ADR-022). Mirrors the
ToolApprovalRBACScope additive-widening pattern (13.5b1)."""

from __future__ import annotations

from typing import get_args

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.scopes import (
    RUN_SCOPES,
    ComplianceRBACScope,
    ConfigOverlayRBACScope,
    EmergencyRBACScope,
    EvalRBACScope,
    MemoryRBACScope,
    ModelRBACScope,
    PackRBACScope,
    QuotaRBACScope,
    RunRBACScope,
    ToolApprovalRBACScope,
    UIRBACScope,
)


def test_run_rbac_scope_has_exactly_one_value() -> None:
    assert set(get_args(RunRBACScope)) == {"run.submit"}


def test_run_scopes_frozenset_matches_literal() -> None:
    assert RUN_SCOPES == frozenset(get_args(RunRBACScope))


def test_run_scope_namespace_disjoint_from_every_other_family() -> None:
    run = set(get_args(RunRBACScope))
    others: set[str] = set()
    for fam in (
        PackRBACScope,
        UIRBACScope,
        ComplianceRBACScope,
        ModelRBACScope,
        MemoryRBACScope,
        EmergencyRBACScope,
        QuotaRBACScope,
        EvalRBACScope,
        ConfigOverlayRBACScope,
        ToolApprovalRBACScope,
    ):
        others |= set(get_args(fam))
    assert run.isdisjoint(others)
    assert all(s.startswith("run.") for s in run)


def test_actor_accepts_run_submit_scope() -> None:
    actor = Actor(
        subject="svc", tenant_id="t", scopes=frozenset({"run.submit"}), actor_type="service"
    )
    assert "run.submit" in actor.scopes


def test_require_scope_accepts_run_submit() -> None:
    # mypy: RequireScope's param union must admit RunRBACScope. Runtime: returns
    # a callable dependency without raising.
    dep = RequireScope("run.submit")
    assert callable(dep)
```

- [ ] **Step 2: Run the test — verify it fails**

Run: `uv run pytest tests/unit/portal/rbac/test_run_scopes.py -q`
Expected: FAIL — `ImportError: cannot import name 'RunRBACScope'` (and `RUN_SCOPES`).

- [ ] **Step 3: Add `RunRBACScope` + `RUN_SCOPES` to `scopes.py`**

In `src/cognic_agentos/portal/rbac/scopes.py`, after the `ToolApprovalRBACScope` block (after `TOOL_APPROVAL_SCOPES`, ~line 319) and before the `ConfigOverlayRBACScope` block, insert:

```python
#: Sprint 14A-A2a (ADR-022) — managed-run submission RBAC family. Single value
#: ``run.submit`` consumed by ``POST /api/v1/runs``; NOT a Human-only decision
#: (the sandbox approval seam owns the per-tier human checkpoint, so the run
#: route does NOT also gate on :class:`RequireHumanActor`). Value-disjoint from
#: every other family by the ``run.*`` namespace. Wire-protocol-public — the 403
#: ``scope_not_held`` body carries it. Pinned by
#: ``tests/unit/portal/rbac/test_run_scopes.py``.
#:
#: Style note: plain ``= Literal[...]`` (no ``TypeAlias`` annotation) per the
#: repo convention at ``packs/lifecycle.py:111`` + the families above.
RunRBACScope = Literal["run.submit"]

#: All 1 run scope as a frozenset (1:1 with :data:`RunRBACScope`) for
#: bank-overlay binders. Pinned by ``tests/unit/portal/rbac/test_run_scopes.py``.
RUN_SCOPES: frozenset[RunRBACScope] = frozenset({"run.submit"})
```

- [ ] **Step 4: Widen `Actor.scopes` in `actor.py`**

In `src/cognic_agentos/portal/rbac/actor.py`, add `RunRBACScope` to the scopes import block (the `from cognic_agentos.portal.rbac.scopes import (...)` at line 37) and add `| RunRBACScope` to the `scopes` field union (after `ToolApprovalRBACScope`, line 136):

```python
    scopes: frozenset[
        PackRBACScope
        | UIRBACScope
        | ComplianceRBACScope
        | ModelRBACScope
        | MemoryRBACScope
        | EmergencyRBACScope
        | QuotaRBACScope
        | EvalRBACScope
        | ConfigOverlayRBACScope
        | ToolApprovalRBACScope
        | RunRBACScope  # Sprint 14A-A2a (ADR-022) — managed-run submission
    ]
```

Add a one-line comment above the field mirroring the 13.5b1 note: `#: Sprint 14A-A2a (ADR-022) — widened with RunRBACScope so a run-capable actor carries run.submit for POST /api/v1/runs. Additive — pre-14A-A2a actors construct cleanly.`

- [ ] **Step 5: Widen the `RequireScope` param union in `enforcement.py`**

In `src/cognic_agentos/portal/rbac/enforcement.py`, add `RunRBACScope` to the scopes import and to the `RequireScope(scope: ...)` parameter union (after `ToolApprovalRBACScope`):

```python
def RequireScope(
    scope: PackRBACScope
    | UIRBACScope
    | ComplianceRBACScope
    | ModelRBACScope
    | MemoryRBACScope
    | EmergencyRBACScope
    | QuotaRBACScope
    | EvalRBACScope
    | ConfigOverlayRBACScope
    | ToolApprovalRBACScope
    | RunRBACScope,
) -> Callable[..., Awaitable[Actor]]:
```

- [ ] **Step 6: Run the test — verify it passes**

Run: `uv run pytest tests/unit/portal/rbac/test_run_scopes.py -q`
Expected: PASS (5 tests).

- [ ] **Step 7: Neighbourhood + RBAC regression**

Run: `uv run pytest tests/unit/portal/rbac/ -q`
Expected: PASS — the existing scope-family disjointness + partition tests still green (RunRBACScope is namespace-disjoint).

- [ ] **Step 8: HALT — reviewer gate (CC; 3 on-gate edits)**

- Gate ladder: `uv run pytest tests/unit/portal/rbac/ -q` → `uv run ruff check .` → `uv run ruff format --check .` → `uv run mypy src tests`.
- Verify-at-promotion (3 on-gate modules): `uv run pytest --cov=cognic_agentos --cov-branch -q` then `uv run coverage json -o coverage.json` then `uv run python tools/check_critical_coverage.py` — confirm `scopes.py`, `actor.py`, `enforcement.py` ≥ 95/90 on FRESH data; gate PASSES at 130.
- Watchpoint→pin: namespace-disjointness → `test_run_scope_namespace_disjoint_from_every_other_family`; Actor carries scope → `test_actor_accepts_run_submit_scope`; RequireScope admits scope (mypy + runtime) → `test_require_scope_accepts_run_submit` + the mypy run.
- Report files MODIFIED + fresh gate evidence. Await commit token.

- [ ] **Step 9: Commit (on token)**

```bash
git add src/cognic_agentos/portal/rbac/scopes.py src/cognic_agentos/portal/rbac/actor.py src/cognic_agentos/portal/rbac/enforcement.py tests/unit/portal/rbac/test_run_scopes.py
git commit -m "feat(run): run.submit RBAC scope wired into Actor + RequireScope unions (ADR-022)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: `POST /api/v1/runs` route + executor pending-approval contract (VALVE after this task)

**Files:**
- Modify: `src/cognic_agentos/core/run/executor.py` (CC)
- Create: `src/cognic_agentos/portal/api/runs/__init__.py`
- Create: `src/cognic_agentos/portal/api/runs/dto.py`
- Create: `src/cognic_agentos/portal/api/runs/routes.py`
- Modify: `src/cognic_agentos/portal/api/app.py`
- Modify: `tests/unit/architecture/test_run_no_sdk_import.py`
- Modify: `tests/unit/core/run/test_executor.py`
- Create: `tests/unit/portal/api/runs/__init__.py` + `tests/unit/portal/api/runs/test_run_routes.py`

### 2a — executor pending-approval contract (CC)

- [ ] **Step 1: Write the failing executor test (pending path)**

In `tests/unit/core/run/test_executor.py`, the existing suite uses a stub backend + real scheduler + real DH over in-memory sqlite. Add a pending-raising stub backend and the pending-path test. First update the existing stub backend's `create()` to accept the forward-compat `approval_request_id` kwarg (added to the Protocol in T3) so T3's executor change does not break it:

```python
# In the existing stub backend class create() signature, add the kwarg:
#     async def create(self, policy, *, actor, tenant_id, pack_context,
#                      use_warm_pool=True, requires_credentials=(),
#                      approval_request_id=None):
# (the stub ignores it; T3 wires the executor to pass it)
```

Add the new pending stub + test:

```python
class _ApprovalPendingBackend:
    """create() raises sandbox_approval_pending (the 14A-A2b real-backend
    behaviour, stub-pinned here in 14A-A2a where approval_engine=None)."""

    def __init__(self, *, approval_request_id: str) -> None:
        self._arid = approval_request_id
        self.destroyed = False

    async def create(self, policy, *, actor, tenant_id, pack_context,  # type: ignore[no-untyped-def]
                     use_warm_pool=True, requires_credentials=(), approval_request_id=None):
        from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

        raise SandboxLifecycleRefused(
            "sandbox_approval_pending",
            detail="approval pending",
            approval_request_id=self._arid,
        )


async def test_run_pending_approval_cancels_task_and_returns_pending(make_scheduler_and_dh) -> None:  # type: ignore[no-untyped-def]
    scheduler, dh, engine = make_scheduler_and_dh
    loader = _StubLoader(_installed_record())  # existing helper from the suite
    backend = _ApprovalPendingBackend(approval_request_id="arid-123")
    executor = ManagedRunExecutor(
        scheduler=scheduler,
        sandbox_backend=backend,  # type: ignore[arg-type]
        pack_loader=loader,  # type: ignore[arg-type]
        decision_history_store=dh,
        settings=_settings(),  # existing helper
    )
    result = await executor.run(_run_request())  # existing helper builds a read_only run

    assert result.terminal_state == "pending_approval"
    assert result.approval_request_id == "arid-123"
    assert result.exit_code is None
    assert result.refusal_reason is None
    # value-free evidence: a run.pending_approval row exists, NO run.completed/failed
    types = await _decision_types(engine)  # existing helper -> list[str] of event_type
    assert "run.pending_approval" in types
    assert "run.completed" not in types and "run.failed" not in types
    # the scheduler task was cancelled (running -> cancelled), not left dangling
    assert "scheduler.task_cancelled" in types


async def test_run_sandbox_governance_refusal_returns_refused(make_scheduler_and_dh) -> None:  # type: ignore[no-untyped-def]
    """A non-pending SandboxLifecycleRefused (governance/admission refusal) ->
    refused/409: cancel the running task, emit run.refused carrying the sandbox
    reason; NO scheduler.fail / run.failed (F3 status map)."""
    scheduler, dh, engine = make_scheduler_and_dh

    class _GovRefusalBackend:
        async def create(self, policy, *, actor, tenant_id, pack_context,  # type: ignore[no-untyped-def]
                         use_warm_pool=True, requires_credentials=(), approval_request_id=None):
            from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

            raise SandboxLifecycleRefused(
                "sandbox_high_risk_tier_refused_pre_13_5", detail="governance refusal"
            )

    executor = ManagedRunExecutor(
        scheduler=scheduler, sandbox_backend=_GovRefusalBackend(),  # type: ignore[arg-type]
        pack_loader=_StubLoader(_installed_record()),  # type: ignore[arg-type]
        decision_history_store=dh, settings=_settings(),
    )
    result = await executor.run(_run_request())

    assert result.terminal_state == "refused"
    assert result.refusal_reason == "sandbox_high_risk_tier_refused_pre_13_5"
    assert result.exit_code is None
    types = await _decision_types(engine)
    assert "run.refused" in types
    assert "run.failed" not in types and "run.completed" not in types
    # governance refusal CANCELS the running task (not scheduler.fail)
    assert "scheduler.task_cancelled" in types and "scheduler.task_failed" not in types
```

(Reuse the suite's existing fixtures/helpers — `make_scheduler_and_dh`, `_StubLoader`, `_installed_record`, `_settings`, `_run_request`, `_decision_types`. If a helper name differs, match the landed 14A-A suite.) **Keep the existing 14A-A generic-create-exception infra test** proving `failed`/502 — it must raise a *generic* `Exception` (e.g. `RuntimeError`), NOT a `SandboxLifecycleRefused` (which now routes to `refused`/409); if it currently raises a `SandboxLifecycleRefused`, change it to a generic `Exception`.

- [ ] **Step 2: Run — verify it fails**

Run: `uv run pytest tests/unit/core/run/test_executor.py::test_run_pending_approval_cancels_task_and_returns_pending -q`
Expected: FAIL — `RunResult` has no `approval_request_id`; `terminal_state` Literal has no `pending_approval`; the executor does not branch on `sandbox_approval_pending`.

- [ ] **Step 3: Extend `RunTerminalState`, `RunRequest`, `RunResult` + add the pending constant**

In `src/cognic_agentos/core/run/executor.py`:

```python
RunTerminalState = Literal["completed", "failed", "refused", "pending_approval"]

#: The single sandbox approval reason that means "pending — go approve". The
#: other sandbox_approval_* reasons (_denied/_expired/_binding_mismatch/
#: _request_not_found) — and every non-approval SandboxLifecycleRefused — are
#: terminal governance refusals -> refused/409 (cancel + run.refused),
#: unreachable in 14A-A2a (approval_engine=None), reachable in 14A-A2b.
_SANDBOX_APPROVAL_PENDING_REASON = "sandbox_approval_pending"
```

Add `approval_request_id` to `RunRequest` (after `actor`):

```python
@dataclass(frozen=True)
class RunRequest:
    ...
    actor: Actor
    #: Sprint 14A-A2a (ADR-014): re-POST correlator for a previously-pending
    #: sandbox approval. Threaded to backend.create -> admit_policy grant
    #: verification in 14A-A2b. None on a fresh run.
    approval_request_id: uuid.UUID | None = None
```

Add `approval_request_id` to `RunResult` (after `refusal_reason`, with default for additive back-compat):

```python
@dataclass(frozen=True)
class RunResult:
    ...
    refusal_reason: str | None
    #: Set ONLY when terminal_state == "pending_approval"; the sandbox approval
    #: correlator the caller re-POSTs after granting. str (the OUTPUT side;
    #: SandboxLifecycleRefused carries it as str).
    approval_request_id: str | None = None
```

- [ ] **Step 4: Add the pending branch + `_emit_pending`**

In `ManagedRunExecutor.run`, add the function-local import at the top of the method (before the create try — kernel-boot-clean, mirrors `_build_policy`):

```python
        # Function-local import for the except-clause class at runtime;
        # sandbox.protocol is NOT a module-level import (kernel-boot-clean).
        from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused
```

Change the create try/except to catch `SandboxLifecycleRefused` FIRST (symmetric exception ordering — domain-specific before generic):

```python
            try:
                session = await self._sandbox_backend.create(
                    policy,
                    actor=request.actor,
                    tenant_id=request.tenant_id,
                    pack_context=ctx,
                    requires_credentials=(),
                )
            except SandboxLifecycleRefused as exc:
                if exc.reason == _SANDBOX_APPROVAL_PENDING_REASON:
                    # pending sandbox approval is NOT an infra failure: cancel the
                    # running task (running -> cancelled releases quota + counters),
                    # emit value-free pending evidence, return 202-shaped result.
                    await self._scheduler.cancel(
                        task_id, actor=task_actor, reason="actor_cancelled", request_id=request_id
                    )
                    await self._emit_pending(
                        request, request_id, task_id, approval_request_id=exc.approval_request_id
                    )
                    return RunResult(
                        decision.task_id, "pending_approval", None, b"", b"", None,
                        exc.approval_request_id,
                    )
                # any OTHER SandboxLifecycleRefused is a governance/admission
                # REFUSAL (high_risk_tier_refused, approval_denied/expired,
                # catalog/egress) -> refused/409, NOT an infra failure (F3 status
                # map). Cancel the running task (running -> cancelled releases
                # quota + counters) + emit run.refused carrying the sandbox reason.
                await self._scheduler.cancel(
                    task_id, actor=task_actor, reason="actor_cancelled", request_id=request_id
                )
                await self._emit_refused(request, request_id, str(exc.reason))
                return RunResult(decision.task_id, "refused", None, b"", b"", str(exc.reason))
            except Exception as exc:
                await self._scheduler.fail(
                    task_id,
                    payload=TaskFailedPayload(
                        reason="scheduler_task_failed_sandbox_create_refused",
                        sandbox_refusal_reason=_refusal_detail(exc),
                    ),
                    request_id=request_id,
                )
                await self._emit_failed(request, request_id, task_id, "sandbox_create_refused")
                return RunResult(decision.task_id, "failed", None, b"", b"", None)
```

Add `_emit_pending` alongside the other `_emit_*` methods:

```python
    async def _emit_pending(
        self,
        request: RunRequest,
        request_id: str,
        task_id: uuid.UUID,
        *,
        approval_request_id: str | None,
    ) -> None:
        await self._dh.append(
            DecisionRecord(
                decision_type="run.pending_approval",
                request_id=request_id,
                payload={
                    "task_id": str(task_id),
                    "approval_reason": _SANDBOX_APPROVAL_PENDING_REASON,
                    "approval_request_id": approval_request_id,
                },
                actor_id=request.actor.subject,
                tenant_id=request.tenant_id,
                iso_controls=_RUN_EVIDENCE_ISO_CONTROLS,
            )
        )
```

- [ ] **Step 5: Run — verify pending test + full executor suite pass**

Run: `uv run pytest tests/unit/core/run/test_executor.py -q`
Expected: PASS (14 tests — the existing 12 stay green via the additive `RunResult` default; the new pending + governance-refusal tests pass).

### 2b — import-boundary pin

- [ ] **Step 6: Add the no-module-level-sandbox-import assertion**

Read `tests/unit/architecture/test_run_no_sdk_import.py` first. Add this test (keep the existing `test_core_run_imports_without_hvac` unchanged):

```python
def test_executor_has_no_module_level_sandbox_import() -> None:
    """The pending-approval handler catches SandboxLifecycleRefused via a
    FUNCTION-LOCAL import. Assert NO module-level (non-TYPE_CHECKING) sandbox
    import exists in executor.py — a module-level import would pull hvac
    transitively and break kernel boot (see the 14A-A hvac regression)."""
    import ast
    import pathlib

    src = pathlib.Path("src/cognic_agentos/core/run/executor.py").read_text()
    tree = ast.parse(src)
    offenders: list[str] = []
    for node in tree.body:  # MODULE-LEVEL statements only — excludes the
        # `if TYPE_CHECKING:` ast.If block + function-body imports.
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod.startswith("cognic_agentos.sandbox"):
                offenders.append(mod)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("cognic_agentos.sandbox"):
                    offenders.append(alias.name)
    assert offenders == [], f"module-level sandbox import(s) break kernel boot: {offenders}"
```

- [ ] **Step 7: Run — verify the import-boundary pins pass**

Run: `uv run pytest tests/unit/architecture/test_run_no_sdk_import.py -q`
Expected: PASS — the new assertion + the existing hvac subprocess probe both green (the function-local import does not fire at module load).

### 2c — DTO + route + mount

- [ ] **Step 8: Write the failing route test**

Create `tests/unit/portal/api/runs/__init__.py` (empty) and `tests/unit/portal/api/runs/test_run_routes.py`:

```python
"""Sprint 14A-A2a — POST /api/v1/runs route. Stub executor + stub binder on
app.state; the route is mounted at construction (unconditional)."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from cognic_agentos.core.run.executor import RunResult
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Any) -> Actor:
        return self._actor


class _StubExecutor:
    def __init__(self, result: RunResult) -> None:
        self._result = result
        self.calls: list[Any] = []

    async def run(self, request: Any) -> RunResult:
        self.calls.append(request)
        return self._result


def _app(memory_settings: Any, memory_registry: Any, tmp_path: Any, *, executor: Any) -> Any:
    cfg = tmp_path / "litellm.yaml"
    cfg.write_text(
        "model_list:\n  - model_name: cognic-tier1-dev\n"
        "    litellm_params:\n      model: ollama/qwen\n"
        "      api_base: http://localhost:11434\n"
    )
    app = create_app(
        memory_settings.model_copy(update={"litellm_config_path": cfg}),
        adapter_registry=memory_registry,
    )
    app.state.actor_binder = _StubBinder(
        Actor(subject="svc", tenant_id="t", scopes=frozenset({"run.submit"}), actor_type="service")
    )
    app.state.managed_run_executor = executor
    return app


def _body() -> dict[str, Any]:
    return {
        "pack_id": "cognic-tool-foo",
        "pack_uuid": "11111111-1111-1111-1111-111111111111",
        "pack_version": "1.0.0",
        "argv": ["echo", "hi"],
    }


@pytest.mark.parametrize(
    "result,expected_status",
    [
        (RunResult("tid", "completed", 0, b"out", b"", None, None), 200),
        (RunResult("tid", "pending_approval", None, b"", b"", None, "arid-9"), 202),
        (RunResult("tid", "refused", None, b"", b"", "run_admission_queued_unsupported", None), 409),
        (RunResult("tid", "failed", None, b"", b"", None, None), 502),
    ],
)
def test_terminal_state_maps_to_status(
    memory_settings: Any, memory_registry: Any, tmp_path: Any, result: RunResult, expected_status: int
) -> None:
    app = _app(memory_settings, memory_registry, tmp_path, executor=_StubExecutor(result))
    with TestClient(app) as client:
        resp = client.post("/api/v1/runs", json=_body())
    assert resp.status_code == expected_status
    payload = resp.json()
    assert payload["terminal_state"] == result.terminal_state
    assert payload["approval_request_id"] == result.approval_request_id


def test_completed_run_base64_encodes_raw_output(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    import base64

    app = _app(
        memory_settings, memory_registry, tmp_path,
        executor=_StubExecutor(RunResult("tid", "completed", 0, b"hello\x00", b"err", None, None)),
    )
    with TestClient(app) as client:
        resp = client.post("/api/v1/runs", json=_body())
    assert resp.status_code == 200
    body = resp.json()
    assert base64.b64decode(body["stdout_b64"]) == b"hello\x00"
    assert body["stdout_bytes"] == 6
    assert base64.b64decode(body["stderr_b64"]) == b"err"
    assert body["stderr_bytes"] == 3


def test_body_approval_request_id_and_actor_reach_executor(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    import uuid as _uuid

    executor = _StubExecutor(RunResult("tid", "completed", 0, b"", b"", None, None))
    app = _app(memory_settings, memory_registry, tmp_path, executor=executor)
    arid = "22222222-2222-2222-2222-222222222222"
    body = _body()
    body["approval_request_id"] = arid
    with TestClient(app) as client:
        resp = client.post("/api/v1/runs", json=body)
    assert resp.status_code == 200
    # route -> executor threading: body correlator + bound actor + tenant-from-actor
    # (closes the re-POST drop-the-correlator-at-the-API-boundary gap).
    assert len(executor.calls) == 1
    run_request = executor.calls[0]
    assert run_request.approval_request_id == _uuid.UUID(arid)
    assert run_request.tenant_id == "t"  # the bound actor's tenant, NOT from body
    assert run_request.actor.subject == "svc"  # the bound actor reaches the executor
    assert run_request.argv == ("echo", "hi")  # tuple, verbatim (no shell concat)


def test_503_when_executor_not_populated(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    app = _app(memory_settings, memory_registry, tmp_path, executor=None)
    with TestClient(app) as client:
        resp = client.post("/api/v1/runs", json=_body())
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "sandbox_runtime_unavailable"


def test_422_on_empty_argv(memory_settings: Any, memory_registry: Any, tmp_path: Any) -> None:
    app = _app(
        memory_settings, memory_registry, tmp_path,
        executor=_StubExecutor(RunResult("tid", "completed", 0, b"", b"", None, None)),
    )
    body = _body()
    body["argv"] = []
    with TestClient(app) as client:
        resp = client.post("/api/v1/runs", json=body)
    assert resp.status_code == 422


def test_422_on_extra_tenant_field(memory_settings: Any, memory_registry: Any, tmp_path: Any) -> None:
    app = _app(
        memory_settings, memory_registry, tmp_path,
        executor=_StubExecutor(RunResult("tid", "completed", 0, b"", b"", None, None)),
    )
    body = _body()
    body["tenant_id"] = "attacker"
    with TestClient(app) as client:
        resp = client.post("/api/v1/runs", json=body)
    assert resp.status_code == 422
```

- [ ] **Step 9: Run — verify it fails**

Run: `uv run pytest tests/unit/portal/api/runs/test_run_routes.py -q`
Expected: FAIL — `portal.api.runs` does not exist; route 404.

- [ ] **Step 10: Create the DTO module**

Create `src/cognic_agentos/portal/api/runs/__init__.py` (empty) and `src/cognic_agentos/portal/api/runs/dto.py`:

```python
"""Sprint 14A-A2a — POST /api/v1/runs request/response DTOs (ADR-022)."""

from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

#: argv bounds — non-empty + bounded per-item + bounded count (no shell concat;
#: argv is passed verbatim to session.exec). Empty/oversized -> 422.
_MAX_ARGV_ITEMS = 64
_MAX_ARGV_ITEM_LEN = 4096


class RunSubmitRequest(BaseModel):
    """Body for POST /api/v1/runs. tenant_id + actor come ONLY from the bound
    Actor — this DTO has NO tenant/actor field (extra='forbid' rejects them)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    pack_id: str
    pack_uuid: uuid.UUID
    pack_version: str
    argv: list[str]
    approval_request_id: uuid.UUID | None = None

    @field_validator("argv")
    @classmethod
    def _argv_bounded(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("argv_must_be_non_empty")
        if len(v) > _MAX_ARGV_ITEMS:
            raise ValueError(f"argv_too_many_items_max_{_MAX_ARGV_ITEMS}")
        for item in v:
            if len(item) > _MAX_ARGV_ITEM_LEN:
                raise ValueError(f"argv_item_too_long_max_{_MAX_ARGV_ITEM_LEN}")
        return v


class RunResponse(BaseModel):
    """Returned for every terminal state. Raw stdout/stderr are base64-encoded
    (bytes are not an accidental wire ambiguity); *_bytes are the decoded sizes."""

    model_config = ConfigDict(frozen=True)

    task_id: str | None
    terminal_state: Literal["completed", "failed", "refused", "pending_approval"]
    exit_code: int | None
    stdout_b64: str
    stderr_b64: str
    stdout_bytes: int
    stderr_bytes: int
    refusal_reason: str | None
    approval_request_id: str | None
```

- [ ] **Step 11: Create the route module**

Create `src/cognic_agentos/portal/api/runs/routes.py`. `from __future__ import annotations` is INTENTIONALLY OMITTED (FastAPI must resolve `Annotated[..., Depends(<closure-local>)]` against the closure-local `_require_submit`):

```python
"""Sprint 14A-A2a — POST /api/v1/runs managed-run caller (ADR-022 + ADR-004).

The production caller that LIVE-exercises ManagedRunExecutor + (via
scheduler.submit) the scheduler approval seam. Mounted UNCONDITIONALLY at
construction; the request-time _require_managed_run_executor dep returns 503
when the lifespan did not populate app.state.managed_run_executor.

`from __future__ import annotations` is INTENTIONALLY OMITTED so FastAPI can
resolve the closure-local Depends() annotations.
"""

import base64
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from cognic_agentos.core.run.executor import ManagedRunExecutor, RunRequest, RunResult
from cognic_agentos.portal.api.runs.dto import RunResponse, RunSubmitRequest
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope

#: terminal_state -> HTTP status. completed (incl. non-zero exit) is a run
#: result (200); pending_approval is 202; refused is 409; infra-failed is 502.
_STATUS_BY_TERMINAL: dict[str, int] = {
    "completed": 200,
    "pending_approval": 202,
    "refused": 409,
    "failed": 502,
}


def _require_managed_run_executor(request: Request) -> ManagedRunExecutor:
    executor = getattr(request.app.state, "managed_run_executor", None)
    if executor is None:
        raise HTTPException(
            status_code=503, detail={"reason": "sandbox_runtime_unavailable"}
        )
    return executor


def build_run_routes() -> APIRouter:
    router = APIRouter()
    _require_submit = RequireScope("run.submit")

    @router.post("", response_model=RunResponse)
    async def submit_run(
        body: RunSubmitRequest,
        response: Response,
        actor: Annotated[Actor, Depends(_require_submit)],
        executor: Annotated[ManagedRunExecutor, Depends(_require_managed_run_executor)],
    ) -> RunResponse:
        run_request = RunRequest(
            tenant_id=actor.tenant_id,
            pack_id=body.pack_id,
            pack_uuid=body.pack_uuid,
            pack_version=body.pack_version,
            argv=tuple(body.argv),
            actor=actor,
            approval_request_id=body.approval_request_id,
        )
        result: RunResult = await executor.run(run_request)
        # One consistent body shape across all outcomes; the status varies. A
        # programmatic caller always gets task_id + terminal_state +
        # refusal_reason + approval_request_id without parsing a {"detail": ...}
        # envelope.
        response.status_code = _STATUS_BY_TERMINAL[result.terminal_state]
        return RunResponse(
            task_id=result.task_id,
            terminal_state=result.terminal_state,
            exit_code=result.exit_code,
            stdout_b64=base64.b64encode(result.stdout).decode("ascii"),
            stderr_b64=base64.b64encode(result.stderr).decode("ascii"),
            stdout_bytes=len(result.stdout),
            stderr_bytes=len(result.stderr),
            refusal_reason=result.refusal_reason,
            approval_request_id=result.approval_request_id,
        )

    return router
```

- [ ] **Step 12: Mount the router unconditionally in `app.py`**

In `src/cognic_agentos/portal/api/app.py`, near the eval-router mount (~line 1292-1298), add the unconditional run-router mount:

```python
        from cognic_agentos.portal.api.runs.routes import build_run_routes

        app.include_router(
            build_run_routes(),
            prefix="/api/v1/runs",
            tags=["runs"],
        )
```

Place it OUTSIDE any conditional block (always mounted, mirroring the eval router; the request-time dep is the gate).

- [ ] **Step 13: Run — verify the route suite passes**

Run: `uv run pytest tests/unit/portal/api/runs/test_run_routes.py -q`
Expected: PASS (status mapping ×4, base64, 503, 422 ×2).

- [ ] **Step 14: VALVE checkpoint + HALT — reviewer gate (CC; executor on-gate)**

- Full suite + gate (14A-A2a boundary): `uv run pytest -q` → `uv run coverage json -o coverage.json` (after a `--cov-branch` run) → `uv run python tools/check_critical_coverage.py` — confirm `core/run/executor.py` ≥ 95/90 on FRESH data; gate PASSES at 130.
- Gate ladder: `uv run ruff check .` → `uv run ruff format --check .` → `uv run mypy src tests`.
- Watchpoint→pin: unconditional mount + 503 dep → `test_503_when_executor_not_populated` + the eval-pattern mount; pending→202 + cancel + value-free evidence → `test_run_pending_approval_...` + `test_terminal_state_maps_to_status[202]`; sandbox governance refusal→409 (not 502) + cancel → `test_run_sandbox_governance_refusal_returns_refused`; route→executor threading (correlator + bound actor + tenant-from-actor) → `test_body_approval_request_id_and_actor_reach_executor`; base64 bounds → `test_completed_run_base64_encodes_raw_output`; body validation (no tenant/actor, non-empty argv) → `test_422_on_extra_tenant_field` + `test_422_on_empty_argv`; kernel-boot cleanliness → `test_executor_has_no_module_level_sandbox_import` + `test_core_run_imports_without_hvac`.
- **VALVE:** if 14A-A2a (T1+T2) is reviewable as-is, proceed to T3 (14A-A2b). If it crossed reviewable size, T3 is the natural split — confirm before continuing.
- Report files MODIFIED + fresh gate evidence. Await commit token.

- [ ] **Step 15: Commit (on token)**

```bash
git add src/cognic_agentos/core/run/executor.py src/cognic_agentos/portal/api/runs/__init__.py src/cognic_agentos/portal/api/runs/dto.py src/cognic_agentos/portal/api/runs/routes.py src/cognic_agentos/portal/api/app.py tests/unit/architecture/test_run_no_sdk_import.py tests/unit/core/run/test_executor.py tests/unit/portal/api/runs/__init__.py tests/unit/portal/api/runs/test_run_routes.py
git commit -m "feat(run): POST /api/v1/runs caller + executor pending-approval contract (ADR-022)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: 14A-A2b — sandbox approval_engine + approval_request_id threading (CC; protocol + both backends + executor)

**Files:**
- Modify: `src/cognic_agentos/sandbox/protocol.py` (CC)
- Modify: `src/cognic_agentos/sandbox/backends/docker_sibling.py` (CC)
- Modify: `src/cognic_agentos/sandbox/backends/kubernetes_pod.py` (CC)
- Modify: `src/cognic_agentos/core/run/executor.py` (CC)
- Modify: `src/cognic_agentos/harness/sandbox.py`
- Test: `tests/unit/sandbox/backends/test_approval_threading.py` (NEW)
- Test: `tests/unit/harness/test_sandbox.py` + `tests/unit/core/run/test_executor.py`

- [ ] **Step 1: Write the failing cross-backend threading test**

Create `tests/unit/sandbox/backends/test_approval_threading.py`:

```python
"""Sprint 14A-A2b — both backends thread approval_engine + approval_request_id
into admit_policy (cross-backend lockstep)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest


@pytest.mark.parametrize("backend_module", ["docker_sibling", "kubernetes_pod"])
async def test_create_threads_approval_into_admit_policy(
    backend_module: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import importlib

    mod = importlib.import_module(f"cognic_agentos.sandbox.backends.{backend_module}")
    captured: dict[str, Any] = {}

    async def _fake_admit(policy: Any, **kwargs: Any) -> None:
        captured.update(kwargs)
        raise _StopCreate()  # short-circuit after admission (no real container)

    class _StopCreate(Exception):
        pass

    monkeypatch.setattr(mod, "admit_policy", _fake_admit)

    sentinel_engine = object()
    backend = _build_backend_with_approval_engine(mod, backend_module, sentinel_engine)
    arid = uuid.uuid4()
    with pytest.raises(_StopCreate):
        await backend.create(
            _policy(), actor=_actor(), tenant_id="t", pack_context=_ctx(),
            approval_request_id=arid,
        )
    assert captured["approval_engine"] is sentinel_engine
    assert captured["approval_request_id"] == arid
```

(Provide `_build_backend_with_approval_engine`, `_policy`, `_actor`, `_ctx` helpers in the test module — construct each backend with stub catalog/rego/audit/dh/credential adapter + the sentinel `approval_engine`. Mirror the existing `tests/unit/sandbox/backends/` construction helpers for each backend's required kwargs.)

- [ ] **Step 2: Run — verify it fails**

Run: `uv run pytest tests/unit/sandbox/backends/test_approval_threading.py -q`
Expected: FAIL — `create()` rejects `approval_request_id` (unexpected kwarg); `__init__` rejects `approval_engine`.

- [ ] **Step 3: Extend the `SandboxBackend.create` Protocol**

In `src/cognic_agentos/sandbox/protocol.py`: add `import uuid` to the imports, and add `approval_request_id` to the Protocol `create` signature (after `requires_credentials`):

```python
    async def create(
        self,
        policy: SandboxPolicy,
        *,
        actor: Actor,
        tenant_id: str,
        pack_context: PackAdmissionContext,
        use_warm_pool: bool = True,
        requires_credentials: Sequence[VaultLeaseRequest] = (),
        approval_request_id: uuid.UUID | None = None,
    ) -> SandboxSession: ...
```

- [ ] **Step 4: Thread through `docker_sibling.py`**

In `src/cognic_agentos/sandbox/backends/docker_sibling.py`:
- Add the import: `from cognic_agentos.core.approval.engine import ApprovalEngine` (mirrors `admission.py:57`).
- Add `approval_engine: ApprovalEngine | None = None` to `__init__` (after `egress_proxy_image`) and store `self._approval_engine = approval_engine`.
- Add `approval_request_id: uuid.UUID | None = None` to `create` (after `expected_workload_gid`). Ensure `import uuid` exists.
- Cold-create `admit_policy` call (~line 1110) — add the two kwargs:

```python
        await admit_policy(
            policy,
            tenant_id=tenant_id,
            actor=actor,
            pack_context=pack_context,
            catalog=self._catalog,
            credential_adapter=self._credential_adapter,
            rego_engine=self._rego,
            settings=self._settings,
            requires_credentials=requires_credentials,
            approval_engine=self._approval_engine,
            approval_request_id=approval_request_id,
        )
```

- Wake-path `admit_policy` call (~line 2547) — **LEAVE UNCHANGED**. Checkpoint→wake is explicitly deferred in 14A-A2 (no run-persistence / run→session resolver); threading only `approval_engine` without an approval correlator would half-wire approval on a dormant surface. 14A-A2 threads the **COLD-CREATE path ONLY**; the wake `admit_policy` keeps `approval_engine` defaulting to `None` (current pre-13.5 behaviour). `self._approval_engine` is stored for the cold-create path only.

- [ ] **Step 5: Thread through `kubernetes_pod.py` (lockstep)**

Apply the IDENTICAL changes to `src/cognic_agentos/sandbox/backends/kubernetes_pod.py`: `ApprovalEngine` import; `__init__` += `approval_engine` + `self._approval_engine`; `create` += `approval_request_id`; cold-create `admit_policy` (~line 1140) += `approval_engine=self._approval_engine, approval_request_id=approval_request_id`. The wake `admit_policy` (~line 2417) is **LEFT UNCHANGED** (cold-create only — see Step 4).

- [ ] **Step 6: Run — verify the cross-backend test passes**

Run: `uv run pytest tests/unit/sandbox/backends/test_approval_threading.py -q`
Expected: PASS (both backends thread `approval_engine` + `approval_request_id`).

- [ ] **Step 7: Thread `approval_engine` in `build_sandbox_backend`**

In `src/cognic_agentos/harness/sandbox.py`, add `approval_engine=runtime.approval_engine` to the `get_backend(...)` call (it forwards `**kwargs` to the backend `__init__`):

```python
        backend = get_backend(
            settings,
            docker_client=docker_client,
            credential_adapter=credential_adapter,
            rego_engine=rego_engine,
            audit_store=runtime.audit_store,
            decision_history_store=runtime.decision_history_store,
            checkpoint_store=checkpoint_store,
            warm_pool=None,
            approval_engine=runtime.approval_engine,
        )
```

Add a harness test (`tests/unit/harness/test_sandbox.py`) asserting the threaded kwarg — extend `test_build_sandbox_backend_closes_client_on_internal_failure` style: monkeypatch `get_backend` to capture kwargs and assert `kwargs["approval_engine"] is runtime.approval_engine`:

```python
async def test_build_sandbox_backend_threads_approval_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from unittest.mock import AsyncMock

    captured: dict[str, Any] = {}

    class _FakeClient:
        async def close(self) -> None:
            pass

    monkeypatch.setattr("aiodocker.Docker", lambda *a, **k: _FakeClient())
    monkeypatch.setattr(
        "cognic_agentos.core.policy.engine.OPAEngine.create", AsyncMock(return_value=object())
    )

    def _fake_get_backend(settings: Any, /, **kwargs: Any) -> Any:
        captured.update(kwargs)
        return object()

    # build_sandbox_backend imports get_backend function-locally from
    # backend_factory, so the name resolves from the SOURCE module at call
    # time — patch the source, not harness.sandbox (which has no such global).
    monkeypatch.setattr("cognic_agentos.sandbox.backend_factory.get_backend", _fake_get_backend)

    class _Runtime:
        audit_store = object()
        decision_history_store = object()
        approval_engine = object()

    s = Settings(sandbox_backend="docker_sibling", vault_addr="http://vault:8200")
    backend, _client = await build_sandbox_backend(settings=s, runtime=_Runtime())  # type: ignore[arg-type]
    assert captured["approval_engine"] is _Runtime.approval_engine
```

(Source-confirmed: `build_sandbox_backend` imports `get_backend` function-locally from `cognic_agentos.sandbox.backend_factory`, so the function-local import resolves the name from the SOURCE module at call time — monkeypatch `cognic_agentos.sandbox.backend_factory.get_backend`, NOT `harness.sandbox.get_backend` which has no such module global.)

- [ ] **Step 8: Thread `approval_request_id` from the executor into `backend.create`**

In `src/cognic_agentos/core/run/executor.py`, add `approval_request_id=request.approval_request_id` to the `backend.create(...)` call in `run()`:

```python
                session = await self._sandbox_backend.create(
                    policy,
                    actor=request.actor,
                    tenant_id=request.tenant_id,
                    pack_context=ctx,
                    requires_credentials=(),
                    approval_request_id=request.approval_request_id,
                )
```

Add an executor test asserting the thread (the stub backend captures the kwarg):

```python
async def test_run_threads_approval_request_id_into_backend_create(make_scheduler_and_dh) -> None:  # type: ignore[no-untyped-def]
    scheduler, dh, _engine = make_scheduler_and_dh
    captured: dict[str, Any] = {}

    class _CaptureBackend:
        async def create(self, policy, *, actor, tenant_id, pack_context,  # type: ignore[no-untyped-def]
                         use_warm_pool=True, requires_credentials=(), approval_request_id=None):
            captured["arid"] = approval_request_id
            return _StubSession()  # existing helper returning a session with exec/destroy

    import uuid as _uuid

    arid = _uuid.uuid4()
    executor = ManagedRunExecutor(
        scheduler=scheduler, sandbox_backend=_CaptureBackend(),  # type: ignore[arg-type]
        pack_loader=_StubLoader(_installed_record()),  # type: ignore[arg-type]
        decision_history_store=dh, settings=_settings(),
    )
    await executor.run(_run_request(approval_request_id=arid))  # extend helper to accept arid
    assert captured["arid"] == arid
```

(Extend the `_run_request` helper to accept an optional `approval_request_id`; `_StubSession.exec` returns a `SandboxExecResult(b"", b"", 0)` and `destroy()` is a no-op.)

- [ ] **Step 9: Run — verify executor + backend + harness suites pass**

Run: `uv run pytest tests/unit/core/run/test_executor.py tests/unit/sandbox/backends/test_approval_threading.py tests/unit/harness/test_sandbox.py -q`
Expected: PASS.

- [ ] **Step 10: HALT — reviewer gate (CC; protocol + both backends + executor on-gate)**

- Full suite + gate: `uv run pytest -q` → `uv run coverage json -o coverage.json` (after `--cov-branch`) → `uv run python tools/check_critical_coverage.py` — confirm `sandbox/protocol.py`, `sandbox/backends/docker_sibling.py`, `sandbox/backends/kubernetes_pod.py`, `core/run/executor.py` ≥ 95/90 on FRESH data; gate PASSES at 130.
- Gate ladder: `uv run ruff check .` → `uv run ruff format --check .` → `uv run mypy src tests`.
- Watchpoint→pin: cross-backend lockstep → `test_create_threads_approval_into_admit_policy[docker_sibling]` + `[kubernetes_pod]`; additive Protocol param (existing backend tests green) → full sandbox suite; harness threads runtime.approval_engine → `test_build_sandbox_backend_threads_approval_engine`; executor threads request.approval_request_id → `test_run_threads_approval_request_id_into_backend_create`.
- Report files MODIFIED + fresh gate evidence. Await commit token.

- [ ] **Step 11: Commit (on token)**

```bash
git add src/cognic_agentos/sandbox/protocol.py src/cognic_agentos/sandbox/backends/docker_sibling.py src/cognic_agentos/sandbox/backends/kubernetes_pod.py src/cognic_agentos/core/run/executor.py src/cognic_agentos/harness/sandbox.py tests/unit/sandbox/backends/test_approval_threading.py tests/unit/harness/test_sandbox.py tests/unit/core/run/test_executor.py
git commit -m "feat(run): thread approval_engine + approval_request_id through sandbox backends to admit_policy (ADR-014/004/022)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: docs

**Files:**
- Modify: `docs/adrs/ADR-022-runtime-scheduler.md`
- Modify: `docs/adrs/ADR-004-sandbox-primitive.md`
- Modify: `docs/adrs/ADR-014-runtime-tool-approval.md`
- Modify: `AGENTS.md`
- Modify: `docs/AS_BUILT_CAPABILITY_MAP.md`

- [ ] **Step 1: ADR-022 — Sprint 14A-A2 amendment**

Document: `POST /api/v1/runs` is the production caller that LIVE-exercises `ManagedRunExecutor` + (via `scheduler.submit`) the scheduler approval seam (auto-tier for read_only — no high-risk pending in 14A-A2a). `RunResult` gains `pending_approval`; queued-cancel + value-free `run.pending_approval`/`run.completed`/`run.failed`/`run.refused` evidence.

- [ ] **Step 2: ADR-004 + ADR-014 — sandbox approval seam now LIVE**

Document: the sandbox approval-engine branch is now WIRED — `build_sandbox_backend` threads `runtime.approval_engine` into both backends; `backend.create(approval_request_id=...)` → `admit_policy` grant verification. The run→`202 sandbox_approval_pending`→grant→re-POST contract is real. Note the deferrals: checkpoint→wake approval-correlator threading, MCP `call_tool`, `LocalParentBudgetResolver`/sub-agent dispatch.

- [ ] **Step 3: AGENTS.md — managed-run route + sandbox seam**

Update the `*Managed-run executor*` CC section: add the `pending_approval` contract + the on-gate `sandbox/protocol.py`/`docker_sibling.py`/`kubernetes_pod.py` approval threading; note `portal/api/runs/` route + dto are off-gate; the run route is the first LIVE consumer of `app.state.managed_run_executor`.

- [ ] **Step 4: AS_BUILT_CAPABILITY_MAP.md — 14A-A2 DONE**

Mark pillar 2 (`POST /api/v1/runs` route DONE) + pillar 6 (sandbox approval seam LIVE) + the forward sequence (14A-A2 DONE; the 3 deferrals as forward items).

- [ ] **Step 5: HALT — docs reviewer gate**

- Confirm no source/test drift (docs-only): `git status --porcelain` shows only the 4 doc files staged (NEVER `docs/reviews/` or the 2026-05-26 gap-analysis spec).
- Confirm every doc claim matches the landed code (no overstatement — the sandbox seam is LIVE only when `sandbox_runtime_enabled` + `approval_engine` present; the route is WIRED).
- Report files MODIFIED. Await commit token.

- [ ] **Step 6: Commit (on token)**

```bash
git add docs/adrs/ADR-022-runtime-scheduler.md docs/adrs/ADR-004-sandbox-primitive.md docs/adrs/ADR-014-runtime-tool-approval.md AGENTS.md docs/AS_BUILT_CAPABILITY_MAP.md
git commit -m "docs(run): Sprint 14A-A2 run route + LIVE sandbox approval seam (ADR-022/004/014)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-review notes (author)

- **Spec coverage:** F1 (RunSubmitRequest shape + validation + tenant/actor-from-Actor) → T2 dto + route; F2 (RunRBACScope + RequireScope, no RequireHumanActor) → T1 + T2 route; F3 (pending_approval + 202/200/409/502 + base64 bounds) → T2 executor + route + dto; F4 (re-POST + threading, no idempotency) → T2 RunRequest field + T3 backend threading. Valve (a/b) → T2/T3 split. Spec finding 1 (mount) → T2 Step 12 unconditional. Spec finding 2 (import boundary) → T2 Step 6.
- **Plan-time deltas to flag to the operator (spec amendments):** (1) §7 CC-posture — scopes/actor/enforcement are ON the gate, not off; (2) §3 — `create` param is `uuid.UUID | None` not `str`; (3) §3/§4 — only `sandbox_approval_pending` → 202 (the family-wide "∈ sandbox_approval_*" is narrowed). All three are precision corrections; the plan implements the corrected behaviour.
- **Placeholder scan:** none — every test body + impl is complete; helper-reuse notes name the exact landed-suite helpers to match.
- **Type consistency:** `RunResult` 7th field defaulted (additive); `RunRequest.approval_request_id: uuid.UUID|None`; `RunResult.approval_request_id: str|None`; `SandboxBackend.create approval_request_id: uuid.UUID|None`; `_STATUS_BY_TERMINAL` keys 1:1 with `RunTerminalState`.
- **Count:** stays 130 — no NEW gate module; do NOT touch `_EXPECTED_ENTRY_COUNT`.
