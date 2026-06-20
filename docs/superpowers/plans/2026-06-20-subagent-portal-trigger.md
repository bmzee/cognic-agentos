# Sub-Agent Portal Trigger — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `app.state.subagent_spawner` LIVE via `POST /api/v1/subagents` — an RBAC-gated portal route that spawns a child sub-agent (which runs as a governed managed run).

**Architecture:** Thin off-gate route mirroring `portal/api/runs/`. Resolves `parent_run_id` → `task_id` (tenant-scoped), maps the body onto the existing `SubAgentSpawnRequest`/`ManagedRunChildSpec`, calls the existing `SubAgentSpawner.spawn(...)`, and returns the existing `SubAgentResult` coarsely (200 + `spawn_record_id` + `child_result`). No `subagent/` change. CC stays 133.

**Tech stack:** FastAPI (`Annotated`/`Depends`, no `from __future__` in routes), Pydantic v2 (`extra="forbid"`), the existing `SubAgentSpawner` + `RunRecordStore`.

**Source of truth:** `docs/superpowers/specs/2026-06-20-subagent-portal-trigger-design.md`.

---

## File structure

| File | Responsibility | Gate |
|---|---|---|
| `portal/rbac/scopes.py` | `SubAgentRBACScope` + `SUBAGENT_SCOPES` (additive) | on-gate (additive) |
| `portal/rbac/actor.py` | widen `Actor.scopes` union | on-gate (additive) |
| `portal/rbac/enforcement.py` | widen `RequireScope` param union | on-gate (additive) |
| `portal/api/app.py` | P2 run-store wiring + mount the route | off-gate |
| `portal/api/subagents/dto.py` | request/response DTOs | off-gate (new) |
| `portal/api/subagents/routes.py` | `build_subagent_routes` + dep + handler | off-gate (new) |
| `portal/api/subagents/__init__.py` | `build_subagent_routes` export | off-gate (new) |

**Grounded shapes (verified on `main` @ `270cf53`):**
- `SubAgentSpawner.spawn(*, request: SubAgentSpawnRequest, managed_run: ManagedRunChildSpec, actor: Actor, parent_trace_id: str) -> SubAgentResult` (`subagent/spawn.py:59`).
- `SubAgentResult{spawn_record_id: uuid.UUID, child_result: ChildResult}` (`subagent/_types.py:143`); `ChildResult{summary, tokens_used, wall_time_used_s, ok}`.
- `SubAgentSpawnRequest{prompt, parent_tool_allow_list: frozenset[str], requested_tool_allow_list: frozenset[str], current_depth: int, requested_estimated_tokens: int, tenant_id: str, parent_task_id: str | None}` (`subagent/_types.py:76`).
- `ManagedRunChildSpec{pack_id: str, pack_version: str, argv: tuple[str, ...]}`.
- `SubAgentPrivilegeEscalation(*, extra_tools: frozenset[str])` + `.extra_tools` — re-exported `from cognic_agentos.subagent import SubAgentPrivilegeEscalation` (`subagent/__init__.py:16,32`).
- `RunRecordStore.load(run_id: uuid.UUID, *, tenant_id: str) -> RunRecord | None` (`core/run/storage.py:378`); `RunRecord.task_id: uuid.UUID | None` (`core/run/_types.py:123`).
- RBAC pattern: `RunRBACScope = Literal["run.submit", "run.resume"]` + `RUN_SCOPES: frozenset[RunRBACScope]` (`scopes.py:337,341`); `Actor.scopes` union (`actor.py:138-150`); `RequireScope` param union (`enforcement.py:250-261`).
- app.py lifespan: the inline `run_record_store=RunRecordStore(adapters.relational.engine)` at `app.py:711`; the except path at `:726-733`; `app.state.subagent_spawner = None` pre-seed at `:942`.

---

## Task 1: RBAC scope `subagent.spawn`

**Files:**
- Modify: `src/cognic_agentos/portal/rbac/scopes.py`
- Modify: `src/cognic_agentos/portal/rbac/actor.py`
- Modify: `src/cognic_agentos/portal/rbac/enforcement.py`
- Test: `tests/unit/portal/rbac/test_subagent_scopes.py` (new)

- [ ] **Step 1: Write the failing scope test**

Create `tests/unit/portal/rbac/test_subagent_scopes.py`:

```python
"""Sub-agent portal-trigger RBAC scope (ADR-005 + ADR-012 §40)."""

import typing

from cognic_agentos.portal.rbac.scopes import SUBAGENT_SCOPES, SubAgentRBACScope


def test_subagent_scope_has_exactly_one_value() -> None:
    assert set(typing.get_args(SubAgentRBACScope)) == {"subagent.spawn"}


def test_subagent_scopes_frozenset_matches_literal() -> None:
    # non-Yoda operand order (ruff SIM300); mirrors test_scopes.py:187.
    assert frozenset(typing.get_args(SubAgentRBACScope)) == SUBAGENT_SCOPES
    assert isinstance(SUBAGENT_SCOPES, frozenset)


def test_subagent_scope_namespace_disjoint_from_other_scopes() -> None:
    # subagent.* must not collide with any existing scope namespace.
    from cognic_agentos.portal.rbac.scopes import (
        MCP_SCOPES,
        RUN_SCOPES,
    )

    assert SUBAGENT_SCOPES.isdisjoint(RUN_SCOPES)
    assert SUBAGENT_SCOPES.isdisjoint(MCP_SCOPES)
    assert all(s.startswith("subagent.") for s in SUBAGENT_SCOPES)


def test_actor_accepts_subagent_scope() -> None:
    from cognic_agentos.portal.rbac.actor import Actor

    actor = Actor(
        subject="svc-a",
        tenant_id="tenant-a",
        scopes=frozenset({"subagent.spawn"}),
        actor_type="service",
    )
    assert "subagent.spawn" in actor.scopes


def test_require_scope_accepts_subagent_scope() -> None:
    from cognic_agentos.portal.rbac.enforcement import RequireScope

    dep = RequireScope("subagent.spawn")  # must type-check + construct
    assert dep is not None
```

- [ ] **Step 2: Run it — verify it fails**

Run: `uv run pytest tests/unit/portal/rbac/test_subagent_scopes.py -q`
Expected: FAIL (`ImportError: cannot import name 'SUBAGENT_SCOPES'`).

- [ ] **Step 3: Add the scope to `scopes.py`**

After the `MCP_SCOPES` block (`scopes.py:364`), add:

```python
#: Sub-agent portal-trigger scope (ADR-005, "Fork B" portal seam). Spawning is
#: operational orchestration, not a Human-only decision; a high-risk child still
#: pends for a human downstream at sandbox cold-create admission.
SubAgentRBACScope = Literal["subagent.spawn"]

#: The 1 sub-agent scope as a frozenset (1:1 with :data:`SubAgentRBACScope`).
SUBAGENT_SCOPES: frozenset[SubAgentRBACScope] = frozenset({"subagent.spawn"})
```

- [ ] **Step 4: Widen the `Actor.scopes` union in `actor.py`**

Add `SubAgentRBACScope` to the scopes import block (`actor.py:42-47` region) and to the union (`actor.py:149-150`):

```python
# in the `from cognic_agentos.portal.rbac.scopes import (...)` block:
    SubAgentRBACScope,
```
```python
# append to the Actor.scopes union (after `| MCPRBACScope`):
        | SubAgentRBACScope
```
Add an inline note mirroring the existing `:129`/`:134` comments:
```python
    #: 2026-06-20 (ADR-005, Fork B) — further widened with ``SubAgentRBACScope``
    #: so a single Actor can carry a sub-agent-spawn grant.
```

- [ ] **Step 5: Widen the `RequireScope` param union in `enforcement.py`**

Add `SubAgentRBACScope` to the scopes import (`enforcement.py:45-50` region) and to the `RequireScope` `scope` param union (`enforcement.py:260-261`):

```python
    SubAgentRBACScope,
```
```python
    | RequireScope-union... | MCPRBACScope,
    | SubAgentRBACScope,
```
(Append `| SubAgentRBACScope` as the last arm of the existing union, matching the file's formatting.)

- [ ] **Step 6: Run the test + the broader RBAC suite + mypy**

Run: `uv run pytest tests/unit/portal/rbac/ -q`
Expected: PASS (the new 5 + all existing).
Run: `uv run ruff check src/cognic_agentos/portal/rbac/ tests/unit/portal/rbac/test_subagent_scopes.py && uv run ruff format --check src/cognic_agentos/portal/rbac/ tests/unit/portal/rbac/test_subagent_scopes.py`
Expected: clean.
Run: `uv run mypy src tests`
Expected: Success.

- [ ] **Step 7: Commit (controller token-gated)**

```bash
git add src/cognic_agentos/portal/rbac/scopes.py src/cognic_agentos/portal/rbac/actor.py src/cognic_agentos/portal/rbac/enforcement.py tests/unit/portal/rbac/test_subagent_scopes.py
git commit -m "feat(rbac): subagent.spawn scope (ADR-005/ADR-012)"
```

---

## Task 2: P2 — `app.state.run_record_store` lifespan wiring

The route's parent-resolution dep needs `app.state.run_record_store`, which `app.py` does not set today (it builds `RunRecordStore` inline in the executor call at `:711`). Lift it to a named local + an `app.state` assignment, co-populated with the spawner.

**Files:**
- Modify: `src/cognic_agentos/portal/api/app.py`
- Test: `tests/unit/portal/api/test_app_run_record_store_state.py` (new)

- [ ] **Step 1: Write the failing app-state test**

Create `tests/unit/portal/api/test_app_run_record_store_state.py`:

```python
"""P2 — the lifespan must publish app.state.run_record_store (2026-06-20, ADR-005)."""

from cognic_agentos.portal.api.app import create_app


def test_app_state_preseeds_run_record_store_to_none() -> None:
    # Before any lifespan runs, the attribute exists and is None (so the
    # request-time dep can `getattr(..., None)` without AttributeError).
    app = create_app()
    assert getattr(app.state, "run_record_store", "MISSING") is None
```

(Construction-only: `create_app()` does not enter the lifespan, so the pre-seed is what's asserted. The on-the-SDK-path assignment + the exception-path clear are covered by the route's 503 tests in Task 4 and by manual/integration verification; a full lifespan-entered test needs the adapter pool and is out of this unit's scope.)

- [ ] **Step 2: Run it — verify it fails**

Run: `uv run pytest tests/unit/portal/api/test_app_run_record_store_state.py -q`
Expected: FAIL (`assert 'MISSING' is None`).

- [ ] **Step 3: Pre-seed `app.state.run_record_store = None`**

In `app.py`, next to the existing `app.state.subagent_spawner = None` pre-seed (`:942`), add:

```python
    app.state.run_record_store = None  # 2026-06-20 (ADR-005) — lifespan publishes; route resolves.
```

- [ ] **Step 4: Lift the inline `RunRecordStore` + publish to `app.state`**

In the SDK-gated lifespan block (`app.py:703-713`), replace the inline construction with a named local and publish it. Change:

```python
                        app.state.managed_run_executor = ManagedRunExecutor(
                            scheduler=runtime.scheduler,
                            sandbox_backend=backend,
                            pack_loader=PackRecordStoreLoader(
                                store=PackRecordStore(adapters.relational.engine)
                            ),
                            decision_history_store=runtime.decision_history_store,
                            settings=settings,
                            run_record_store=RunRecordStore(adapters.relational.engine),
                            checkpoint_store=checkpoint_store,
                        )
```
to:
```python
                        run_record_store = RunRecordStore(adapters.relational.engine)
                        app.state.managed_run_executor = ManagedRunExecutor(
                            scheduler=runtime.scheduler,
                            sandbox_backend=backend,
                            pack_loader=PackRecordStoreLoader(
                                store=PackRecordStore(adapters.relational.engine)
                            ),
                            decision_history_store=runtime.decision_history_store,
                            settings=settings,
                            run_record_store=run_record_store,
                            checkpoint_store=checkpoint_store,
                        )
                        # 2026-06-20 (ADR-005, Fork B) — publish the SAME run-record
                        # store the executor uses so POST /api/v1/subagents can
                        # resolve parent_run_id -> task_id (tenant-scoped). Co-populated
                        # with the spawner; the route's combined 503 dep covers either.
                        app.state.run_record_store = run_record_store
```

- [ ] **Step 5: Clear it on the exception path**

In the `except Exception:` block (`app.py:726-733`), next to `app.state.subagent_spawner = None`, add:

```python
                        app.state.run_record_store = None
```

- [ ] **Step 6: Run the test + mypy**

Run: `uv run pytest tests/unit/portal/api/test_app_run_record_store_state.py -q`
Expected: PASS.
Run: `uv run mypy src tests`
Expected: Success.

- [ ] **Step 7: Commit**

```bash
git add src/cognic_agentos/portal/api/app.py tests/unit/portal/api/test_app_run_record_store_state.py
git commit -m "feat(portal): publish app.state.run_record_store for the subagent route (ADR-005)"
```

---

## Task 3: the request/response DTOs

**Files:**
- Create: `src/cognic_agentos/portal/api/subagents/__init__.py`
- Create: `src/cognic_agentos/portal/api/subagents/dto.py`
- Test: `tests/unit/portal/api/subagents/test_dto.py` (new)

- [ ] **Step 1: Write the failing DTO test**

Create `tests/unit/portal/api/subagents/__init__.py` (empty) and `tests/unit/portal/api/subagents/test_dto.py`:

```python
"""POST /api/v1/subagents DTOs (ADR-005)."""

import uuid
from typing import Any

import pytest
from pydantic import ValidationError

from cognic_agentos.portal.api.subagents.dto import (
    ManagedRunChildSpecBody,
    SubAgentSpawnRequestBody,
)


def _valid_body() -> dict[str, Any]:
    return {
        "parent_run_id": str(uuid.uuid4()),
        "managed_run": {"pack_id": "cognic-tool-x", "pack_version": "1.0.0", "argv": ["--run"]},
        "prompt": "do the thing",
        "parent_tool_allow_list": ["a", "b", "b"],  # dupe is fine — frozenset dedupes
        "requested_tool_allow_list": ["a"],
        "requested_estimated_tokens": 100,
    }


def test_request_body_parses_and_uuid_typed() -> None:
    body = SubAgentSpawnRequestBody.model_validate(_valid_body())
    assert isinstance(body.parent_run_id, uuid.UUID)
    assert body.managed_run.pack_id == "cognic-tool-x"


def test_request_body_forbids_extra_fields() -> None:
    bad = _valid_body() | {"tenant_id": "tenant-evil"}  # tenant comes from the Actor only
    with pytest.raises(ValidationError):
        SubAgentSpawnRequestBody.model_validate(bad)


def test_request_body_forbids_current_depth() -> None:
    bad = _valid_body() | {"current_depth": 5}  # route-set to 0; never a body field
    with pytest.raises(ValidationError):
        SubAgentSpawnRequestBody.model_validate(bad)


def test_malformed_parent_run_id_is_422() -> None:
    bad = _valid_body() | {"parent_run_id": "not-a-uuid"}
    with pytest.raises(ValidationError):
        SubAgentSpawnRequestBody.model_validate(bad)


def test_managed_run_argv_must_be_non_empty() -> None:
    bad = _valid_body()
    bad["managed_run"] = {"pack_id": "p", "pack_version": "1.0.0", "argv": []}
    with pytest.raises(ValidationError):
        SubAgentSpawnRequestBody.model_validate(bad)


def test_managed_run_child_spec_body_standalone() -> None:
    spec = ManagedRunChildSpecBody.model_validate(
        {"pack_id": "p", "pack_version": "1.0.0", "argv": ["x"]}
    )
    assert spec.argv == ["x"]
```

- [ ] **Step 2: Run it — verify it fails**

Run: `uv run pytest tests/unit/portal/api/subagents/test_dto.py -q`
Expected: FAIL (`ModuleNotFoundError: cognic_agentos.portal.api.subagents`).

- [ ] **Step 3: Create the package + DTOs**

Create `src/cognic_agentos/portal/api/subagents/__init__.py` — **docstring-only in Task 3** (the `build_subagent_routes` re-export is added in Task 4, after `routes.py` exists, so each task's `mypy src tests` stays green):

```python
"""POST /api/v1/subagents — the portal-trigger surface for the live SubAgentSpawner (ADR-005).

The ``build_subagent_routes`` re-export is added in Task 4 (after ``routes.py``
lands) to keep ``mypy src tests`` green at every task boundary.
"""
```

Create `src/cognic_agentos/portal/api/subagents/dto.py`:

```python
"""POST /api/v1/subagents request/response DTOs (ADR-005)."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, field_validator

#: argv bounds — mirror the run route (non-empty, bounded count + per-item length).
_MAX_ARGV_ITEMS = 64
_MAX_ARGV_ITEM_LEN = 4096
#: tool-list bounds — defensive caps on the body-supplied allow-lists.
_MAX_TOOLS = 512
_MAX_TOOL_ID_LEN = 512


def _validate_argv_bounds(v: list[str]) -> list[str]:
    if not v:
        raise ValueError("argv_must_be_non_empty")
    if len(v) > _MAX_ARGV_ITEMS:
        raise ValueError(f"argv_too_many_items_max_{_MAX_ARGV_ITEMS}")
    for item in v:
        if len(item) > _MAX_ARGV_ITEM_LEN:
            raise ValueError(f"argv_item_too_long_max_{_MAX_ARGV_ITEM_LEN}")
    return v


def _validate_tool_list(v: list[str]) -> list[str]:
    if len(v) > _MAX_TOOLS:
        raise ValueError(f"tool_list_too_many_max_{_MAX_TOOLS}")
    for item in v:
        if len(item) > _MAX_TOOL_ID_LEN:
            raise ValueError(f"tool_id_too_long_max_{_MAX_TOOL_ID_LEN}")
    return v


class ManagedRunChildSpecBody(BaseModel):
    """The child's managed-run identity (maps to ManagedRunChildSpec)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    pack_id: str
    pack_version: str
    argv: list[str]

    @field_validator("argv")
    @classmethod
    def _argv_bounded(cls, v: list[str]) -> list[str]:
        return _validate_argv_bounds(v)


class SubAgentSpawnRequestBody(BaseModel):
    """Body for POST /api/v1/subagents. tenant_id + actor come ONLY from the bound
    Actor; current_depth is route-set to 0 (never a body field). Tool lists are
    list[str] for JSON ergonomics (deduped to frozenset when building the spawn
    request); ordering is not semantically meaningful."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    parent_run_id: uuid.UUID
    managed_run: ManagedRunChildSpecBody
    prompt: str
    parent_tool_allow_list: list[str]
    requested_tool_allow_list: list[str]
    requested_estimated_tokens: int

    @field_validator("parent_tool_allow_list", "requested_tool_allow_list")
    @classmethod
    def _tool_list_bounded(cls, v: list[str]) -> list[str]:
        return _validate_tool_list(v)


class ChildResultBody(BaseModel):
    """The coarse child outcome (maps from ChildResult)."""

    model_config = ConfigDict(frozen=True)

    ok: bool
    summary: str
    tokens_used: int
    wall_time_used_s: float


class SubAgentSpawnResponse(BaseModel):
    """200 body. spawn_record_id is str(result.spawn_record_id) — the
    audit-correlatable subagent.spawn chain-event id. A pending/failed/refused
    child is represented inside the 200 as child_result.ok=false + summary."""

    model_config = ConfigDict(frozen=True)

    spawn_record_id: str
    child_result: ChildResultBody
```

(The Task 3 `__init__.py` is docstring-only — no `routes` import — so importing `cognic_agentos.portal.api.subagents.dto` works now; the `build_subagent_routes` re-export + the full package import land in Task 4.)

- [ ] **Step 4: Run the DTO test + ruff + mypy**

Run: `uv run pytest tests/unit/portal/api/subagents/test_dto.py -q`
Expected: PASS.
Run: `uv run ruff check src/cognic_agentos/portal/api/subagents/dto.py tests/unit/portal/api/subagents/test_dto.py && uv run ruff format --check src/cognic_agentos/portal/api/subagents/dto.py tests/unit/portal/api/subagents/test_dto.py`
Expected: clean.
Run: `uv run mypy src tests`
Expected: Success.

(The Task 3 `__init__.py` is **docstring-only** — no `routes` import — so `mypy src tests` is green at the Task 3 boundary even though `routes.py` does not exist yet. The `build_subagent_routes` re-export is added in Task 4 Step 3.)

- [ ] **Step 5: Commit**

```bash
git add src/cognic_agentos/portal/api/subagents/__init__.py src/cognic_agentos/portal/api/subagents/dto.py tests/unit/portal/api/subagents/__init__.py tests/unit/portal/api/subagents/test_dto.py
git commit -m "feat(portal): subagents request/response DTOs (ADR-005)"
```

---

## Task 4: the route

**Files:**
- Create: `src/cognic_agentos/portal/api/subagents/routes.py`
- Modify: `src/cognic_agentos/portal/api/subagents/__init__.py` (add the export)
- Test: `tests/unit/portal/api/subagents/test_routes.py` (new)

- [ ] **Step 1: Write the failing route tests**

Create `tests/unit/portal/api/subagents/test_routes.py`:

```python
"""POST /api/v1/subagents route (ADR-005). Stub spawner + stub RunRecordStore +
stub actor binder on app.state — the route mounts on a bare FastAPI app (the real
app.py mount lands in Task 5). RequireScope runs NORMALLY (no dependency override):
it resolves the actor via app.state.actor_binder, mirroring the run-route tests."""

import uuid
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from cognic_agentos.portal.api.subagents.routes import build_subagent_routes
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.subagent import SubAgentPrivilegeEscalation
from cognic_agentos.subagent._types import ChildResult, SubAgentResult


class _StubBinder:
    """Mirrors the run-route test binder (tests/unit/portal/api/runs/test_run_routes.py:26):
    the route's RequireScope resolves the actor via app.state.actor_binder.bind(request=...),
    then runs its REAL scope check against actor.scopes."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Any) -> Actor:
        return self._actor


class _StubRecord:
    def __init__(self, task_id: uuid.UUID | None) -> None:
        self.task_id = task_id


class _StubRunStore:
    def __init__(self, record: _StubRecord | None) -> None:
        self._record = record
        self.seen: tuple[uuid.UUID, str] | None = None

    async def load(self, run_id: uuid.UUID, *, tenant_id: str) -> _StubRecord | None:
        self.seen = (run_id, tenant_id)
        return self._record


class _StubSpawner:
    def __init__(self, result: SubAgentResult | None = None, raise_escalation: bool = False) -> None:
        self._result = result
        self._raise = raise_escalation
        self.seen: dict[str, Any] | None = None

    async def spawn(self, *, request: Any, managed_run: Any, actor: Any, parent_trace_id: str) -> Any:
        self.seen = {
            "request": request,
            "managed_run": managed_run,
            "actor": actor,
            "parent_trace_id": parent_trace_id,
        }
        if self._raise:
            raise SubAgentPrivilegeEscalation(extra_tools=frozenset({"danger"}))
        assert self._result is not None
        return self._result


_ACTOR = Actor(
    subject="svc-a",
    tenant_id="tenant-a",
    scopes=frozenset({"subagent.spawn"}),
    actor_type="service",
)
#: An actor WITHOUT subagent.spawn — drives the scope_not_held 403 path.
_ACTOR_NO_SCOPE = Actor(
    subject="svc-b",
    tenant_id="tenant-a",
    scopes=frozenset(),
    actor_type="service",
)


def _result(ok: bool = True) -> SubAgentResult:
    return SubAgentResult(
        spawn_record_id=uuid.uuid4(),
        child_result=ChildResult(summary="done", tokens_used=10, wall_time_used_s=0.5, ok=ok),
    )


def _client(
    *,
    spawner: Any = "DEFAULT",
    run_store: Any = "DEFAULT",
    actor: Actor = _ACTOR,
) -> TestClient:
    app = FastAPI()
    if spawner == "DEFAULT":
        spawner = _StubSpawner(result=_result())
    if run_store == "DEFAULT":
        run_store = _StubRunStore(_StubRecord(task_id=uuid.uuid4()))
    app.state.subagent_spawner = spawner
    app.state.run_record_store = run_store
    # RequireScope runs normally; it resolves the actor via app.state.actor_binder
    # (the run-route test pattern). NO dependency_overrides — a fresh RequireScope
    # callable would not match the route's dependency key.
    app.state.actor_binder = _StubBinder(actor)
    app.include_router(build_subagent_routes(), prefix="/api/v1/subagents")
    return TestClient(app)


def _body(**over: Any) -> dict[str, Any]:
    base = {
        "parent_run_id": str(uuid.uuid4()),
        "managed_run": {"pack_id": "p", "pack_version": "1.0.0", "argv": ["--run"]},
        "prompt": "go",
        "parent_tool_allow_list": ["a", "b"],
        "requested_tool_allow_list": ["a"],
        "requested_estimated_tokens": 100,
    }
    base.update(over)
    return base


def test_spawn_200_returns_record_id_and_child_result() -> None:
    spawner = _StubSpawner(result=_result(ok=True))
    client = _client(spawner=spawner)
    resp = client.post("/api/v1/subagents", json=_body())
    assert resp.status_code == 200
    payload = resp.json()
    assert spawner._result is not None  # narrows Optional for mypy (set by construction)
    assert payload["spawn_record_id"] == str(spawner._result.spawn_record_id)
    assert payload["child_result"] == {
        "ok": True,
        "summary": "done",
        "tokens_used": 10,
        "wall_time_used_s": 0.5,
    }


def test_spawn_threads_route_derived_fields() -> None:
    parent_run = uuid.uuid4()
    task_id = uuid.uuid4()
    spawner = _StubSpawner(result=_result())
    run_store = _StubRunStore(_StubRecord(task_id=task_id))
    client = _client(spawner=spawner, run_store=run_store)
    resp = client.post("/api/v1/subagents", json=_body(parent_run_id=str(parent_run)))
    assert resp.status_code == 200
    # route-derived: current_depth=0, parent_task_id=str(task_id), tenant from actor,
    # parent_trace_id=run:<parent_run_id>; tool lists -> frozenset.
    assert spawner.seen is not None  # narrows Optional for mypy (set by the spawn call)
    req = spawner.seen["request"]
    assert req.current_depth == 0
    assert req.parent_task_id == str(task_id)
    assert req.tenant_id == "tenant-a"
    assert req.parent_tool_allow_list == frozenset({"a", "b"})
    assert spawner.seen["parent_trace_id"] == f"run:{parent_run}"
    assert run_store.seen == (parent_run, "tenant-a")


def test_child_not_ok_still_200() -> None:
    client = _client(spawner=_StubSpawner(result=_result(ok=False)))
    resp = client.post("/api/v1/subagents", json=_body())
    assert resp.status_code == 200
    assert resp.json()["child_result"]["ok"] is False


def test_parent_run_not_found_404() -> None:
    client = _client(run_store=_StubRunStore(None))
    resp = client.post("/api/v1/subagents", json=_body())
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "parent_run_not_found"


def test_parent_run_not_admitted_409() -> None:
    client = _client(run_store=_StubRunStore(_StubRecord(task_id=None)))
    resp = client.post("/api/v1/subagents", json=_body())
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "parent_run_not_admitted"


def test_privilege_escalation_403_with_extra_tools() -> None:
    client = _client(spawner=_StubSpawner(raise_escalation=True))
    resp = client.post("/api/v1/subagents", json=_body())
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert detail["reason"] == "subagent_privilege_escalation"
    assert detail["extra_tools"] == ["danger"]


def test_scope_not_held_403() -> None:
    # An actor lacking subagent.spawn -> RequireScope refuses BEFORE the handler.
    client = _client(actor=_ACTOR_NO_SCOPE)
    resp = client.post("/api/v1/subagents", json=_body())
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "scope_not_held"


def test_503_when_spawner_dormant() -> None:
    app = FastAPI()
    app.state.subagent_spawner = None
    app.state.run_record_store = _StubRunStore(_StubRecord(task_id=uuid.uuid4()))
    app.state.actor_binder = _StubBinder(_ACTOR)
    app.include_router(build_subagent_routes(), prefix="/api/v1/subagents")
    resp = TestClient(app).post("/api/v1/subagents", json=_body())
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "subagent_spawner_unavailable"


def test_503_when_run_store_dormant() -> None:
    app = FastAPI()
    app.state.subagent_spawner = _StubSpawner(result=_result())
    app.state.run_record_store = None
    app.state.actor_binder = _StubBinder(_ACTOR)
    app.include_router(build_subagent_routes(), prefix="/api/v1/subagents")
    resp = TestClient(app).post("/api/v1/subagents", json=_body())
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "subagent_spawner_unavailable"
```

> **RBAC test harness (grounded):** the tests set `app.state.actor_binder = _StubBinder(actor)` and let `RequireScope` run normally (it resolves the actor via the binder, then checks `actor.scopes`) — mirroring `tests/unit/portal/api/runs/test_run_routes.py:26,114`. Do NOT use `app.dependency_overrides[RequireScope(...)]`: a fresh `RequireScope` callable per call won't match the route's dependency key. The `scope_not_held` 403 path is driven by binding `_ACTOR_NO_SCOPE` (empty scopes).

- [ ] **Step 2: Run the tests — verify they fail**

Run: `uv run pytest tests/unit/portal/api/subagents/test_routes.py -q`
Expected: FAIL (`ImportError: build_subagent_routes`).

- [ ] **Step 3: Implement the route**

Create `src/cognic_agentos/portal/api/subagents/routes.py` (NO `from __future__ import annotations` — the FastAPI `Annotated`/`Depends` resolution invariant):

```python
"""POST /api/v1/subagents — the production caller of the live SubAgentSpawner
(ADR-005, Fork B). Mounted UNCONDITIONALLY; the request-time combined dep returns
503 when the SDK-gated lifespan did not populate the spawner + run-record store.

``from __future__ import annotations`` is INTENTIONALLY OMITTED so FastAPI can
resolve the closure-local ``Depends(...)`` annotations eagerly.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request

from cognic_agentos.core.run.storage import RunRecordStore
from cognic_agentos.portal.api.subagents.dto import (
    ChildResultBody,
    SubAgentSpawnRequestBody,
    SubAgentSpawnResponse,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.subagent import SubAgentPrivilegeEscalation
from cognic_agentos.subagent._types import ManagedRunChildSpec, SubAgentSpawnRequest
from cognic_agentos.subagent.spawn import SubAgentSpawner  # NOT re-exported from the package root


def _require_subagent_runtime(request: Request) -> tuple[SubAgentSpawner, RunRecordStore]:
    """Co-populated in one SDK-gated lifespan block; a single 503 covers either
    being absent (the dormant-lifespan pattern, mirroring the run route)."""
    spawner: SubAgentSpawner | None = getattr(request.app.state, "subagent_spawner", None)
    run_store: RunRecordStore | None = getattr(request.app.state, "run_record_store", None)
    if spawner is None or run_store is None:
        raise HTTPException(status_code=503, detail={"reason": "subagent_spawner_unavailable"})
    return spawner, run_store


def build_subagent_routes() -> APIRouter:
    router = APIRouter()
    _require_spawn = RequireScope("subagent.spawn")

    @router.post("", response_model=SubAgentSpawnResponse)
    async def spawn_subagent_route(
        body: SubAgentSpawnRequestBody,
        actor: Annotated[Actor, Depends(_require_spawn)],
        runtime: Annotated[
            tuple[SubAgentSpawner, RunRecordStore], Depends(_require_subagent_runtime)
        ],
    ) -> SubAgentSpawnResponse:
        spawner, run_store = runtime
        # 1. Resolve parent_run_id -> task_id, tenant-scoped (cross-tenant -> None -> 404).
        record = await run_store.load(body.parent_run_id, tenant_id=actor.tenant_id)
        if record is None:
            raise HTTPException(status_code=404, detail={"reason": "parent_run_not_found"})
        if record.task_id is None:
            raise HTTPException(status_code=409, detail={"reason": "parent_run_not_admitted"})
        # 2. Build the spawn request (route-derived: current_depth=0, parent_task_id,
        #    tenant, parent_trace_id) + the child spec.
        spawn_request = SubAgentSpawnRequest(
            prompt=body.prompt,
            parent_tool_allow_list=frozenset(body.parent_tool_allow_list),
            requested_tool_allow_list=frozenset(body.requested_tool_allow_list),
            current_depth=0,
            requested_estimated_tokens=body.requested_estimated_tokens,
            tenant_id=actor.tenant_id,
            parent_task_id=str(record.task_id),
        )
        managed_run = ManagedRunChildSpec(
            pack_id=body.managed_run.pack_id,
            pack_version=body.managed_run.pack_version,
            argv=tuple(body.managed_run.argv),
        )
        # 3. Spawn (privilege escalation -> 403).
        try:
            result = await spawner.spawn(
                request=spawn_request,
                managed_run=managed_run,
                actor=actor,
                parent_trace_id=f"run:{body.parent_run_id}",
            )
        except SubAgentPrivilegeEscalation as exc:
            raise HTTPException(
                status_code=403,
                detail={
                    "reason": "subagent_privilege_escalation",
                    "extra_tools": sorted(exc.extra_tools),
                },
            ) from None
        # 4. Coarse 200 (a pending/failed child rides child_result.ok=false; §6).
        return SubAgentSpawnResponse(
            spawn_record_id=str(result.spawn_record_id),
            child_result=ChildResultBody(
                ok=result.child_result.ok,
                summary=result.child_result.summary,
                tokens_used=result.child_result.tokens_used,
                wall_time_used_s=result.child_result.wall_time_used_s,
            ),
        )

    return router
```

Update `src/cognic_agentos/portal/api/subagents/__init__.py` to add the export (deferred from Task 3):

```python
"""POST /api/v1/subagents — the portal-trigger surface for the live SubAgentSpawner (ADR-005)."""

from cognic_agentos.portal.api.subagents.routes import build_subagent_routes

__all__ = ["build_subagent_routes"]
```

- [ ] **Step 4: Run the route tests + ruff + mypy**

Run: `uv run pytest tests/unit/portal/api/subagents/ -q`
Expected: PASS (the DTO + route suites).
Run: `uv run ruff check src/cognic_agentos/portal/api/subagents/ tests/unit/portal/api/subagents/ && uv run ruff format --check src/cognic_agentos/portal/api/subagents/ tests/unit/portal/api/subagents/`
Expected: clean.
Run: `uv run mypy src tests`
Expected: Success.

- [ ] **Step 5: Commit**

```bash
git add src/cognic_agentos/portal/api/subagents/routes.py src/cognic_agentos/portal/api/subagents/__init__.py tests/unit/portal/api/subagents/test_routes.py
git commit -m "feat(portal): POST /api/v1/subagents — live SubAgentSpawner trigger (ADR-005)"
```

---

## Task 5: mount the route in app.py

**Files:**
- Modify: `src/cognic_agentos/portal/api/app.py`
- Test: `tests/unit/portal/api/test_app_subagent_route_mounted.py` (new)

- [ ] **Step 1: Write the failing mount test**

Create `tests/unit/portal/api/test_app_subagent_route_mounted.py`:

```python
"""The subagent route mounts UNCONDITIONALLY at /api/v1/subagents (ADR-005)."""

from cognic_agentos.portal.api.app import create_app


def test_subagent_route_is_registered() -> None:
    app = create_app()
    paths = {route.path for route in app.routes}  # type: ignore[attr-defined]
    assert "/api/v1/subagents" in paths
```

- [ ] **Step 2: Run it — verify it fails**

Run: `uv run pytest tests/unit/portal/api/test_app_subagent_route_mounted.py -q`
Expected: FAIL (`/api/v1/subagents` not in paths).

- [ ] **Step 3: Mount the route**

Find where `build_run_routes()` is mounted in `app.py` (the unconditional `create_app` route-registration region at **`app.py:1346-1361`**, alongside `build_run_routes` `:1346-1349` + `build_mcp_routes` `:1358-1361`) and add the subagent router alongside it:

```python
    from cognic_agentos.portal.api.subagents import build_subagent_routes

    app.include_router(
        build_subagent_routes(),
        prefix="/api/v1/subagents",
        tags=["subagents"],
    )
```

(Mount it next to the existing `build_run_routes()` mount — the REAL mounts use the multi-line `app.include_router(..., prefix=..., tags=[...])` form, so include `tags=["subagents"]` to match runs/mcp/eval. Same unconditional posture; plain `app.include_router(...)`, no helper.)

- [ ] **Step 4: Run the mount test + the broad portal-api suite + mypy**

Run: `uv run pytest tests/unit/portal/api/test_app_subagent_route_mounted.py tests/unit/portal/api/subagents/ -q`
Expected: PASS.
Run: `uv run mypy src tests`
Expected: Success.

- [ ] **Step 5: Commit**

```bash
git add src/cognic_agentos/portal/api/app.py tests/unit/portal/api/test_app_subagent_route_mounted.py
git commit -m "feat(portal): mount POST /api/v1/subagents in create_app (ADR-005)"
```

---

## Task 6: closeout — full gates + CC

**Files:** none (verification + the AS_BUILT/ADR doc updates if the slice requires them — see Step 4).

- [ ] **Step 1: Full quality gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy src tests`
Expected: all clean.

- [ ] **Step 2: Full suite on fresh coverage**

Run: `uv run pytest -q --cov=cognic_agentos --cov-branch --cov-report=json:coverage.json`
Expected: all pass (no new skips beyond the env-gated Docker/K8s ones).

- [ ] **Step 3: CC gate stays 133/133**

Run: `uv run python tools/check_critical_coverage.py`
Expected: `passed`. **No new gate module** — the route + DTOs are off-gate; the only on-gate edits are the additive `portal/rbac/*` ones. If the `portal/rbac/*` additive edits dropped any on-gate module below floor on fresh data, add focused tests in the SAME commit (the meets-floor-at-promotion-time rule).

- [ ] **Step 4: Docs**

ADR-005 already covers the sub-agent primitive + the Fork-B portal seam was designed in this slice's spec. Add an ADR-005 amendment note (the portal-trigger surface is now LIVE) + an AS_BUILT bullet if the repo's AS_BUILT tracker expects one. No new ADR. Update the spec's status from DRAFT to LANDED if that is the repo convention.

- [ ] **Step 5: Commit (if Step 4 produced doc changes)**

```bash
git add docs/adrs/ADR-005-subagent-primitive.md docs/AS_BUILT_CAPABILITY_MAP.md
git commit -m "docs(subagent): ADR-005 + AS_BUILT — portal-trigger surface LIVE (ADR-005)"
```

---

## Self-review checklist (run before execution)

- **Spec coverage:** every spec §1-7 lock + the module table maps to a task — §2 parent-identity (T4), §3 RBAC (T1), §4 body (T3+T4), §5 tool-list (T3+T4), §6 status (T4), §7 `SubAgentResult` mapping (T4), P2 wiring (T2), mount (T5). ✓
- **No `subagent/` edits** — confirmed; the slice consumes `SubAgentResult`/`spawn()`/`SubAgentPrivilegeEscalation` unchanged. ✓
- **The one harness-verify point:** the RBAC dep override in the route tests (Task 4 Step 1 note) — confirm the working mechanism against an existing route test, do NOT invent an auth bypass.
- **CC stays 133, no migration.** ✓
