"""M6 Task A6 (ADR-025) — POST /api/v1/skills/{skill_id}/invoke route. Stub
executor + stub actor binder on app.state (bare FastAPI app, mirroring the
subagents route test). RequireScope runs NORMALLY (resolves the actor via
app.state.actor_binder); the request-time dep returns 503 when the executor is
absent."""

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cognic_agentos.core.skill._types import SkillInvokeResult
from cognic_agentos.portal.api.skills.routes import build_skill_routes
from cognic_agentos.portal.rbac.actor import Actor


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Any) -> Actor:
        return self._actor


class _StubExecutor:
    def __init__(self, result: SkillInvokeResult) -> None:
        self._result = result
        self.calls: list[dict[str, Any]] = []

    async def invoke(
        self, *, skill_id: str, arguments: dict[str, Any], actor: Any
    ) -> SkillInvokeResult:
        self.calls.append({"skill_id": skill_id, "arguments": arguments, "actor": actor})
        return self._result


_ACTOR = Actor(
    subject="agent-x",
    tenant_id="tenant-a",
    scopes=frozenset({"skill.invoke"}),
    actor_type="service",
)
_ACTOR_NO_SCOPE = Actor(
    subject="agent-y",
    tenant_id="tenant-a",
    scopes=frozenset(),
    actor_type="service",
)


def _client(*, executor: Any = "DEFAULT", actor: Actor = _ACTOR) -> TestClient:
    app = FastAPI()
    if executor == "DEFAULT":
        executor = _StubExecutor(
            SkillInvokeResult(terminal_state="completed", result={"ok": 1}, refusal_reason=None)
        )
    app.state.skill_executor = executor
    app.state.actor_binder = _StubBinder(actor)
    app.include_router(build_skill_routes(), prefix="/api/v1/skills")
    return TestClient(app)


def _post(client: TestClient, *, skill_id: str = "schema-summary", body: Any = None) -> Any:
    return client.post(
        f"/api/v1/skills/{skill_id}/invoke",
        json=body if body is not None else {"arguments": {"owner": "COGNIC"}},
    )


def test_completed_returns_200_with_result() -> None:
    ex = _StubExecutor(
        SkillInvokeResult(
            terminal_state="completed", result={"schema": "COGNIC"}, refusal_reason=None
        )
    )
    resp = _post(_client(executor=ex))
    assert resp.status_code == 200
    body = resp.json()
    assert body["skill_id"] == "schema-summary"
    assert body["terminal_state"] == "completed"
    assert body["result"] == {"schema": "COGNIC"}
    assert body["refusal_reason"] is None


def test_forbidden_tool_returns_403() -> None:
    ex = _StubExecutor(
        SkillInvokeResult(
            terminal_state="refused", result=None, refusal_reason="skill_tool_not_declared"
        )
    )
    resp = _post(_client(executor=ex))
    assert resp.status_code == 403
    assert resp.json()["refusal_reason"] == "skill_tool_not_declared"


def test_skill_not_found_returns_404() -> None:
    ex = _StubExecutor(
        SkillInvokeResult(terminal_state="refused", result=None, refusal_reason="skill_not_found")
    )
    resp = _post(_client(executor=ex), skill_id="ghost")
    assert resp.status_code == 404
    assert resp.json()["refusal_reason"] == "skill_not_found"


def test_skill_not_registered_returns_409() -> None:
    ex = _StubExecutor(
        SkillInvokeResult(
            terminal_state="refused", result=None, refusal_reason="skill_not_registered"
        )
    )
    resp = _post(_client(executor=ex))
    assert resp.status_code == 409
    assert resp.json()["refusal_reason"] == "skill_not_registered"


def test_skill_not_executable_returns_409_with_reason() -> None:
    """A7 (ADR-027): an instruction-mode skill refused by the executor's mode
    guard surfaces 409 with the closed-enum reason in the body — present but
    not invokable, mirroring ``skill_not_registered``'s 409 semantics."""
    ex = _StubExecutor(
        SkillInvokeResult(
            terminal_state="refused", result=None, refusal_reason="skill_not_executable"
        )
    )
    resp = _post(_client(executor=ex))
    assert resp.status_code == 409
    body = resp.json()
    assert body["refusal_reason"] == "skill_not_executable"
    assert body["terminal_state"] == "refused"


def test_runtime_error_returns_502() -> None:
    ex = _StubExecutor(
        SkillInvokeResult(
            terminal_state="failed", result=None, refusal_reason="skill_runtime_error"
        )
    )
    resp = _post(_client(executor=ex))
    assert resp.status_code == 502
    assert resp.json()["refusal_reason"] == "skill_runtime_error"


def test_503_when_executor_absent() -> None:
    resp = _post(_client(executor=None))
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "skill_executor_unavailable"


def test_scope_miss_returns_403_scope_not_held() -> None:
    resp = _post(_client(actor=_ACTOR_NO_SCOPE))
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "scope_not_held"
    assert resp.json()["detail"]["required_scope"] == "skill.invoke"


def test_extra_body_field_rejected_422() -> None:
    resp = _post(_client(), body={"arguments": {}, "tenant_id": "attacker"})
    assert resp.status_code == 422


def test_body_and_path_reach_executor_tenant_from_actor() -> None:
    ex = _StubExecutor(
        SkillInvokeResult(terminal_state="completed", result={}, refusal_reason=None)
    )
    resp = _post(
        _client(executor=ex), skill_id="schema-summary", body={"arguments": {"owner": "X"}}
    )
    assert resp.status_code == 200
    assert len(ex.calls) == 1
    call = ex.calls[0]
    assert call["skill_id"] == "schema-summary"
    assert call["arguments"] == {"owner": "X"}
    # the bound actor (tenant-a / agent-x) reaches the executor; no tenant from body.
    assert call["actor"].tenant_id == "tenant-a"
    assert call["actor"].subject == "agent-x"


def test_arguments_defaults_to_empty_dict() -> None:
    ex = _StubExecutor(
        SkillInvokeResult(terminal_state="completed", result={}, refusal_reason=None)
    )
    resp = _client(executor=ex).post("/api/v1/skills/schema-summary/invoke", json={})
    assert resp.status_code == 200
    assert ex.calls[0]["arguments"] == {}


@pytest.mark.parametrize(
    "reason,status",
    [
        ("skill_tool_not_declared", 403),
        ("skill_not_found", 404),
        ("skill_not_registered", 409),
        ("skill_not_executable", 409),
    ],
)
def test_refused_status_map(reason: str, status: int) -> None:
    ex = _StubExecutor(
        SkillInvokeResult(terminal_state="refused", result=None, refusal_reason=reason)
    )
    assert _post(_client(executor=ex)).status_code == status
