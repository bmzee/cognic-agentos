"""M8 A13 (ADR-027) — POST /api/v1/agents/{agent_id}/ask route. Stub loop +
stub actor binder on app.state (bare FastAPI app, mirroring the skills route
test). RequireScope runs NORMALLY (resolves the actor via
app.state.actor_binder); the request-time dep returns 503 when the loop is
absent."""

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cognic_agentos.core.agent._types import AgentAskResult, AgentGrantNotRequested
from cognic_agentos.portal.api.agents.routes import build_agent_routes
from cognic_agentos.portal.rbac.actor import Actor


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Any) -> Actor:
        return self._actor


class _StubLoop:
    def __init__(
        self, result: AgentAskResult | None = None, raises: Exception | None = None
    ) -> None:
        self._result = result
        self._raises = raises
        self.calls: list[dict[str, Any]] = []

    async def ask(
        self, *, agent_id: str, question: str, actor_tenant_id: str, actor_subject: str
    ) -> AgentAskResult:
        self.calls.append(
            {
                "agent_id": agent_id,
                "question": question,
                "actor_tenant_id": actor_tenant_id,
                "actor_subject": actor_subject,
            }
        )
        if self._raises is not None:
            raise self._raises
        assert self._result is not None
        return self._result


_ACTOR = Actor(
    subject="analyst@bank",
    tenant_id="tenant-a",
    scopes=frozenset({"agent.ask"}),
    actor_type="human",
)
_ACTOR_NO_SCOPE = Actor(
    subject="svc-x",
    tenant_id="tenant-a",
    scopes=frozenset(),
    actor_type="service",
)

_RUN_ID = "agent-run-" + "ab" * 16


def _completed(answer: str = "the schema has 3 tables") -> AgentAskResult:
    return AgentAskResult(
        run_id=_RUN_ID,
        terminal_state="completed",
        answer=answer,
        steps_used=2,
        refusal_reason=None,
        prompt_tokens=11,
        completion_tokens=7,
    )


def _client(*, loop: Any = "DEFAULT", actor: Actor = _ACTOR) -> TestClient:
    app = FastAPI()
    if loop == "DEFAULT":
        loop = _StubLoop(result=_completed())
    app.state.agent_loop = loop
    app.state.actor_binder = _StubBinder(actor)
    app.include_router(build_agent_routes(), prefix="/api/v1/agents")
    return TestClient(app)


def _post(client: TestClient, *, agent_id: str = "schema-advisor", body: Any = None) -> Any:
    return client.post(
        f"/api/v1/agents/{agent_id}/ask",
        json=body if body is not None else {"question": "how many tables?"},
    )


def test_completed_returns_200_with_projected_fields() -> None:
    loop = _StubLoop(result=_completed(answer="42 tables"))
    resp = _post(_client(loop=loop))
    assert resp.status_code == 200
    body = resp.json()
    assert body["run_id"] == _RUN_ID
    assert body["terminal_state"] == "completed"
    assert body["answer"] == "42 tables"
    assert body["steps_used"] == 2
    assert body["refusal_reason"] is None


def test_refused_returns_200_with_refusal_reason() -> None:
    """A governed refusal IS a successful governed answer (the agent.run.refused
    evidence row carries it) — 200, never an error status."""
    loop = _StubLoop(
        result=AgentAskResult(
            run_id=_RUN_ID,
            terminal_state="refused",
            answer="the agent run stopped before producing an answer",
            steps_used=6,
            refusal_reason="agent_max_steps_exceeded",
            prompt_tokens=24,
            completion_tokens=9,
        )
    )
    resp = _post(_client(loop=loop))
    assert resp.status_code == 200
    body = resp.json()
    assert body["terminal_state"] == "refused"
    assert body["refusal_reason"] == "agent_max_steps_exceeded"


def test_failed_returns_502() -> None:
    loop = _StubLoop(
        result=AgentAskResult(
            run_id=_RUN_ID,
            terminal_state="failed",
            answer="the agent run failed before producing an answer",
            steps_used=1,
            refusal_reason=None,
            prompt_tokens=3,
            completion_tokens=0,
        )
    )
    resp = _post(_client(loop=loop))
    assert resp.status_code == 502
    assert resp.json()["terminal_state"] == "failed"


def test_unknown_agent_returns_404_agent_not_found() -> None:
    """LookupError → 404 wire-collapse: unknown and unregistered agents read
    identically (no enumeration axis)."""
    loop = _StubLoop(raises=LookupError("agent 'ghost' is not registered"))
    resp = _post(_client(loop=loop), agent_id="ghost")
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "agent_not_found"


def test_503_when_loop_absent() -> None:
    resp = _post(_client(loop=None))
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "agent_loop_unavailable"


def test_scope_miss_returns_403_scope_not_held() -> None:
    resp = _post(_client(actor=_ACTOR_NO_SCOPE))
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "scope_not_held"
    assert resp.json()["detail"]["required_scope"] == "agent.ask"


def test_extra_body_field_rejected_422() -> None:
    resp = _post(_client(), body={"question": "q", "tenant_id": "attacker"})
    assert resp.status_code == 422


def test_empty_question_rejected_422() -> None:
    resp = _post(_client(), body={"question": ""})
    assert resp.status_code == 422


def test_oversized_question_rejected_422() -> None:
    resp = _post(_client(), body={"question": "x" * 4097})
    assert resp.status_code == 422


def test_max_length_question_accepted() -> None:
    loop = _StubLoop(result=_completed())
    resp = _post(_client(loop=loop), body={"question": "x" * 4096})
    assert resp.status_code == 200


def test_missing_question_rejected_422() -> None:
    resp = _post(_client(), body={})
    assert resp.status_code == 422


def test_tenant_and_originator_threaded_from_actor_only() -> None:
    loop = _StubLoop(result=_completed())
    resp = _post(_client(loop=loop), agent_id="schema-advisor")
    assert resp.status_code == 200
    assert len(loop.calls) == 1
    call = loop.calls[0]
    assert call["agent_id"] == "schema-advisor"
    assert call["question"] == "how many tables?"
    # tenant + originator come from the bound Actor ONLY (never the body).
    assert call["actor_tenant_id"] == "tenant-a"
    assert call["actor_subject"] == "analyst@bank"


def test_grant_not_requested_propagates_uncollapsed() -> None:
    """AgentGrantNotRequested (config-drift emergency) is NOT collapsed to a
    governed status — it propagates to the generic 500 handler (fail loud)."""
    loop = _StubLoop(raises=AgentGrantNotRequested(capability_ref="x/y", capability_kind="tool"))
    with pytest.raises(AgentGrantNotRequested):
        _post(_client(loop=loop))


def test_runtime_error_propagates_uncollapsed() -> None:
    """The dispatcher's fail-loud missing-signing-key RuntimeError (a
    DEPLOYMENT error) propagates — never collapsed to a governed status."""
    loop = _StubLoop(raises=RuntimeError("query_context_signing_key_pem is not configured"))
    with pytest.raises(RuntimeError):
        _post(_client(loop=loop))


def test_ask_route_is_mounted_by_create_app() -> None:
    """create_app mounts the agents router UNCONDITIONALLY (the skills-mount
    posture) — the path is present even when no loop was built."""
    from cognic_agentos.portal.api.app import create_app

    app = create_app()
    paths = {route.path for route in app.routes}  # type: ignore[attr-defined]
    assert "/api/v1/agents/{agent_id}/ask" in paths
