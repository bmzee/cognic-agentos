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
    def __init__(
        self, result: SubAgentResult | None = None, raise_escalation: bool = False
    ) -> None:
        self._result = result
        self._raise = raise_escalation
        self.seen: dict[str, Any] | None = None

    async def spawn(
        self, *, request: Any, managed_run: Any, actor: Any, parent_trace_id: str
    ) -> Any:
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
    assert spawner._result is not None
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
    assert spawner.seen is not None
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
