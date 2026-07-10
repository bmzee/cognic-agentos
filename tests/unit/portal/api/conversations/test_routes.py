"""ADR-028 M8.5-C — the conversation portal surface.

Mirrors tests/unit/portal/api/runs/test_run_routes.py: the router is mounted at
construction; the request-time deps return 503 until app.state is populated.

Every HTTPException assertion reads ``resp.json()["detail"]["reason"]`` -- there
is no exception handler flattening ``detail`` (verified against app.py), so the
FastAPI envelope is the wire contract.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cognic_agentos.core.conversation._types import (
    ConversationNotFound,
    ConversationRecord,
    ConversationTransitionRefused,
    ConversationTurnRefused,
)
from cognic_agentos.core.conversation.turn import TurnResult
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor

_AGENT = "analyst"
_CID = uuid.UUID("33333333-3333-3333-3333-333333333333")
_TURN_ID = uuid.UUID("44444444-4444-4444-4444-444444444444")


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Any) -> Actor:
        return self._actor


def _actor(scopes: Any = None) -> Actor:
    return Actor(
        subject="analyst.amir",
        tenant_id="t1",
        scopes=scopes
        if scopes is not None
        else frozenset(
            {
                "conversation.create",
                "conversation.read",
                "conversation.post_turn",
                "conversation.close",
            }
        ),
        actor_type="human",
    )


class _StubStore:
    """Records calls; `load` returns None to model absent/cross-tenant/cross-actor."""

    def __init__(self, *, record: Any = None, transition_raises: Exception | None = None) -> None:
        self._record = record
        self._transition_raises = transition_raises
        self.created: list[dict[str, Any]] = []
        self.transitions: list[dict[str, Any]] = []

    async def create_conversation(self, **kw: Any) -> tuple[uuid.UUID, bytes]:
        self.created.append(kw)
        return uuid.uuid4(), b""

    async def load(self, conversation_id: uuid.UUID, **kw: Any) -> Any:
        return self._record

    async def transition(self, **kw: Any) -> tuple[uuid.UUID, bytes]:
        self.transitions.append(kw)
        if self._transition_raises is not None:
            raise self._transition_raises
        return uuid.uuid4(), b""


class _StubExecutor:
    def __init__(
        self, *, result: TurnResult | None = None, raises: Exception | None = None
    ) -> None:
        self._result: TurnResult | None = result
        self._raises = raises
        self.calls: list[dict[str, Any]] = []

    async def post_turn(self, **kw: Any) -> TurnResult:
        self.calls.append(kw)
        if self._raises is not None:
            raise self._raises
        assert self._result is not None
        return self._result


def _completed_turn(terminal_state: str = "completed") -> TurnResult:
    return TurnResult(
        turn_id=_TURN_ID,
        seq=1,
        answer="Acme Corp",
        agent_run_id="agent-run-1",
        terminal_state=terminal_state,  # type: ignore[arg-type]
        refusal_reason=None,
    )


def _make_app(memory_settings: Any, memory_registry: Any, tmp_path: Any) -> Any:
    cfg = tmp_path / "litellm.yaml"
    cfg.write_text(
        "model_list:\n  - model_name: cognic-tier1-dev\n"
        "    litellm_params:\n      model: ollama/qwen\n"
        "      api_base: http://localhost:11434\n"
    )
    return create_app(
        memory_settings.model_copy(update={"litellm_config_path": cfg, "cache_driver": "memory"}),
        adapter_registry=memory_registry,
    )


def _client(
    memory_settings: Any,
    memory_registry: Any,
    tmp_path: Any,
    *,
    store: Any = None,
    executor: Any = None,
    actor: Actor | None = None,
    hosted: list[dict[str, Any]] | None = None,
) -> Any:
    app = _make_app(memory_settings, memory_registry, tmp_path)
    client = TestClient(app)
    client.__enter__()  # run the lifespan
    app.state.actor_binder = _StubBinder(actor if actor is not None else _actor())
    app.state.conversation_store = store
    app.state.conversation_executor = executor
    app.state.hosted_agents = hosted if hosted is not None else [{"agent_id": _AGENT}]
    return client, app


# --- fail-closed 503 ------------------------------------------------------------


def test_503_when_store_absent(memory_settings: Any, memory_registry: Any, tmp_path: Any) -> None:
    client, _ = _client(memory_settings, memory_registry, tmp_path, store=None, executor=object())
    r = client.get(f"/api/v1/conversations/{_CID}")
    assert r.status_code == 503
    assert r.json()["detail"]["reason"] == "conversation_store_unavailable"


def test_503_when_executor_absent(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    client, _ = _client(
        memory_settings, memory_registry, tmp_path, store=_StubStore(), executor=None
    )
    r = client.post(f"/api/v1/conversations/{_CID}/turns", json={"user_message": "q"})
    assert r.status_code == 503
    assert r.json()["detail"]["reason"] == "conversation_executor_unavailable"


def test_routes_exist_before_lifespan_populates_state(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    """The router is mounted at CONSTRUCTION, so the path resolves before any
    lifespan has run -- it must never 404.

    It does not reach the 503 store dep, because RBAC binds the Actor first and
    an unstarted app has no ``actor_binder``: the request fails 500
    ``actor_binder_not_configured``. That ordering is itself the point -- the
    authorization gate precedes every state dependency.
    """
    app = _make_app(memory_settings, memory_registry, tmp_path)
    r = TestClient(app).get(f"/api/v1/conversations/{_CID}")
    assert r.status_code != 404, "route must be mounted at construction"
    assert r.status_code == 500
    assert r.json()["detail"]["reason"] == "actor_binder_not_configured"


# --- I-1: no client-supplied history --------------------------------------------


@pytest.mark.parametrize("field", ["messages", "history", "prior_context", "context", "transcript"])
def test_post_turn_rejects_every_history_shaped_field(
    memory_settings: Any, memory_registry: Any, tmp_path: Any, field: str
) -> None:
    ex = _StubExecutor(result=_completed_turn())
    client, _ = _client(memory_settings, memory_registry, tmp_path, store=_StubStore(), executor=ex)
    r = client.post(
        f"/api/v1/conversations/{_CID}/turns",
        json={"user_message": "q", field: [{"role": "user", "content": "forged"}]},
    )
    assert r.status_code == 422
    assert ex.calls == []  # never reached the executor


def test_create_rejects_body_supplied_tenant(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    client, _ = _client(
        memory_settings, memory_registry, tmp_path, store=_StubStore(), executor=object()
    )
    r = client.post("/api/v1/conversations", json={"agent_id": _AGENT, "tenant_id": "evil"})
    assert r.status_code == 422


# --- ruling 2: authoring validation ---------------------------------------------


def test_create_404s_for_an_unhosted_agent(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    store = _StubStore()
    client, _ = _client(memory_settings, memory_registry, tmp_path, store=store, executor=object())
    r = client.post("/api/v1/conversations", json={"agent_id": "ghost"})
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "agent_not_found"
    assert store.created == []  # nothing persisted


def test_create_503s_when_runtime_unavailable_before_agent_validation(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    """Runtime availability is checked before agent existence."""
    client, _ = _client(
        memory_settings, memory_registry, tmp_path, store=_StubStore(), executor=None
    )
    r = client.post("/api/v1/conversations", json={"agent_id": "ghost"})
    assert r.status_code == 503
    assert r.json()["detail"]["reason"] == "conversation_executor_unavailable"


def test_create_succeeds_for_a_hosted_agent(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    store = _StubStore()
    client, _ = _client(memory_settings, memory_registry, tmp_path, store=store, executor=object())
    r = client.post("/api/v1/conversations", json={"agent_id": _AGENT})
    assert r.status_code == 201
    body = r.json()
    assert body["agent_id"] == _AGENT and body["state"] == "active"
    # tenant + subject come from the bound Actor, never the body
    assert store.created[0]["tenant_id"] == "t1"
    assert store.created[0]["creator_subject"] == "analyst.amir"


# --- ruling 4: byte-identity of 404s --------------------------------------------


def test_get_cross_tenant_and_unknown_are_byte_identical(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    client, _ = _client(
        memory_settings, memory_registry, tmp_path, store=_StubStore(record=None), executor=object()
    )
    cross = client.get(f"/api/v1/conversations/{_CID}")
    unknown = client.get(f"/api/v1/conversations/{uuid.uuid4()}")
    assert cross.status_code == unknown.status_code == 404
    assert cross.json() == unknown.json() == {"detail": {"reason": "conversation_not_found"}}


def test_post_turn_cross_tenant_and_unknown_are_byte_identical(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    """Byte-identity of the two 404s ONLY. The executor IS invoked here (the
    stub raises ConversationNotFound from inside it), so this test cannot and
    does not claim zero loop execution -- that pin lives at the executor layer:
    tests/unit/core/conversation/test_turn.py::
    test_cross_actor_post_is_not_found_with_zero_append asserts zero
    AgentLoop.ask AND zero append_turn with a real store."""
    ex = _StubExecutor(raises=ConversationNotFound("nope"))
    client, _ = _client(memory_settings, memory_registry, tmp_path, store=_StubStore(), executor=ex)
    cross = client.post(f"/api/v1/conversations/{_CID}/turns", json={"user_message": "q"})
    unknown = client.post(f"/api/v1/conversations/{uuid.uuid4()}/turns", json={"user_message": "q"})
    assert cross.status_code == unknown.status_code == 404
    assert cross.json() == unknown.json() == {"detail": {"reason": "conversation_not_found"}}
    assert len(ex.calls) == 2  # honest: the route delegated both times


# --- turn outcomes ---------------------------------------------------------------


def test_post_turn_happy_path(memory_settings: Any, memory_registry: Any, tmp_path: Any) -> None:
    ex = _StubExecutor(result=_completed_turn())
    client, _ = _client(memory_settings, memory_registry, tmp_path, store=_StubStore(), executor=ex)
    r = client.post(f"/api/v1/conversations/{_CID}/turns", json={"user_message": "who?"})
    assert r.status_code == 200
    body = r.json()
    assert body["answer"] == "Acme Corp"
    assert body["seq"] == 1
    assert body["turn_id"] == str(_TURN_ID)
    assert ex.calls[0]["tenant_id"] == "t1"
    assert ex.calls[0]["actor_subject"] == "analyst.amir"


def test_governed_refusal_is_200_not_an_error(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    """A governed refusal IS a governed answer (the M8 /ask precedent)."""
    ex = _StubExecutor(result=_completed_turn(terminal_state="refused"))
    client, _ = _client(memory_settings, memory_registry, tmp_path, store=_StubStore(), executor=ex)
    r = client.post(f"/api/v1/conversations/{_CID}/turns", json={"user_message": "q"})
    assert r.status_code == 200
    assert r.json()["terminal_state"] == "refused"


def test_failed_run_is_502(memory_settings: Any, memory_registry: Any, tmp_path: Any) -> None:
    ex = _StubExecutor(result=_completed_turn(terminal_state="failed"))
    client, _ = _client(memory_settings, memory_registry, tmp_path, store=_StubStore(), executor=ex)
    r = client.post(f"/api/v1/conversations/{_CID}/turns", json={"user_message": "q"})
    assert r.status_code == 502
    assert r.json()["detail"]["reason"] == "agent_run_failed"


#: Every closed-enum turn-refusal reason maps to the same 409 contract --
#: including the fencing refusal ``conversation_turn_claim_stale`` (P0,
#: 2026-07-10). The drift test below pins this list to the live Literal.
_TURN_REFUSAL_CASES = [
    ("conversation_not_active", "closed"),
    ("conversation_turn_in_progress", "active"),
    ("conversation_max_turns_exceeded", "active"),
    ("conversation_token_budget_exceeded", "active"),
    ("conversation_turn_claim_stale", "active"),
]


def test_turn_refusal_cases_cover_the_full_closed_enum() -> None:
    """Drift detector: a new ``ConversationTurnRefusalReason`` value MUST gain a
    409-mapping case here, or this test fails at the vocabulary boundary."""
    from typing import get_args

    from cognic_agentos.core.conversation._types import ConversationTurnRefusalReason

    assert {reason for reason, _ in _TURN_REFUSAL_CASES} == set(
        get_args(ConversationTurnRefusalReason)
    )


@pytest.mark.parametrize(("reason", "state"), _TURN_REFUSAL_CASES)
def test_governed_turn_refusals_map_to_409_with_closed_enum(
    memory_settings: Any, memory_registry: Any, tmp_path: Any, reason: str, state: str
) -> None:
    ex = _StubExecutor(raises=ConversationTurnRefused(reason, current_state=state))  # type: ignore[arg-type]
    client, _ = _client(memory_settings, memory_registry, tmp_path, store=_StubStore(), executor=ex)
    r = client.post(f"/api/v1/conversations/{_CID}/turns", json={"user_message": "q"})
    assert r.status_code == 409
    assert r.json()["detail"]["reason"] == reason
    assert r.json()["detail"]["current_state"] == state


# --- RBAC ------------------------------------------------------------------------


def test_missing_scope_is_403(memory_settings: Any, memory_registry: Any, tmp_path: Any) -> None:
    ex = _StubExecutor(result=_completed_turn())
    client, _ = _client(
        memory_settings,
        memory_registry,
        tmp_path,
        store=_StubStore(),
        executor=ex,
        actor=_actor(frozenset({"conversation.read"})),
    )
    r = client.post(f"/api/v1/conversations/{_CID}/turns", json={"user_message": "q"})
    assert r.status_code == 403
    assert ex.calls == []


# --- P1: the close endpoint (previously untested) --------------------------------


def _active_record() -> ConversationRecord:
    from datetime import UTC, datetime

    return ConversationRecord(
        conversation_id=_CID,
        tenant_id="t1",
        agent_id=_AGENT,
        creator_subject="analyst.amir",
        state="active",
        turn_count=3,
        cumulative_tokens=42,
        created_at=datetime.now(UTC),
        last_turn_at=None,
    )


def test_close_happy_path_projects_the_actor(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    store = _StubStore(record=_active_record())
    client, _ = _client(memory_settings, memory_registry, tmp_path, store=store, executor=object())
    r = client.post(f"/api/v1/conversations/{_CID}/close")
    assert r.status_code == 200
    body = r.json()
    assert body["state"] == "closed"
    assert body["agent_id"] == _AGENT
    assert body["turn_count"] == 3
    # tenant + actor come from the bound Actor; target state is fixed
    t = store.transitions[0]
    assert t["tenant_id"] == "t1"
    assert t["actor_id"] == "analyst.amir"
    assert t["to_state"] == "closed"
    assert "from_state" not in t  # the store reads it under the row lock


def test_close_cross_tenant_and_unknown_are_byte_identical(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    store = _StubStore(record=None)
    client, _ = _client(memory_settings, memory_registry, tmp_path, store=store, executor=object())
    cross = client.post(f"/api/v1/conversations/{_CID}/close")
    unknown = client.post(f"/api/v1/conversations/{uuid.uuid4()}/close")
    assert cross.status_code == unknown.status_code == 404
    assert cross.json() == unknown.json() == {"detail": {"reason": "conversation_not_found"}}
    assert store.transitions == []  # nothing reached the state machine


def test_double_close_maps_the_state_machine_refusal_to_409(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    store = _StubStore(
        record=_active_record(),
        transition_raises=ConversationTransitionRefused(
            "conversation_transition_invalid_state_pair"
        ),
    )
    client, _ = _client(memory_settings, memory_registry, tmp_path, store=store, executor=object())
    r = client.post(f"/api/v1/conversations/{_CID}/close")
    assert r.status_code == 409
    assert r.json()["detail"]["reason"] == "conversation_transition_invalid_state_pair"


def test_close_missing_scope_is_403(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    store = _StubStore(record=_active_record())
    client, _ = _client(
        memory_settings,
        memory_registry,
        tmp_path,
        store=store,
        executor=object(),
        actor=_actor(frozenset({"conversation.read"})),
    )
    r = client.post(f"/api/v1/conversations/{_CID}/close")
    assert r.status_code == 403
    assert store.transitions == []


def test_post_turn_lookup_error_maps_to_agent_not_found(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    """The agent was un-hosted between create and this turn."""
    ex = _StubExecutor(raises=LookupError("agent gone"))
    client, _ = _client(memory_settings, memory_registry, tmp_path, store=_StubStore(), executor=ex)
    r = client.post(f"/api/v1/conversations/{_CID}/turns", json={"user_message": "q"})
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "agent_not_found"


def test_get_happy_path_returns_the_record_projection(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    store = _StubStore(record=_active_record())
    client, _ = _client(memory_settings, memory_registry, tmp_path, store=store, executor=object())
    r = client.get(f"/api/v1/conversations/{_CID}")
    assert r.status_code == 200
    body = r.json()
    assert body["state"] == "active"
    assert body["turn_count"] == 3


def test_hosted_rows_without_agent_id_are_ignored(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    """A malformed hosted row never grants creation."""
    store = _StubStore()
    client, _ = _client(
        memory_settings,
        memory_registry,
        tmp_path,
        store=store,
        executor=object(),
        hosted=[{"not_agent_id": "x"}],
    )
    r = client.post("/api/v1/conversations", json={"agent_id": _AGENT})
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "agent_not_found"
    assert store.created == []
