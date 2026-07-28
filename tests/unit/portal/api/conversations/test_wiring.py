"""ADR-028 M8.5-C — lifespan wiring for the conversation substrate (P1, ruled
2026-07-10).

Behavioral pins over the REAL create_app + lifespan, not source inspection:

  * the ConversationStore is built from ``adapters.relational.engine``
  * a build_agent_loop_with_records() failure is contained -- no
    UnboundLocalError, the
    store still constructs, the executor stays None, POST-turn fails closed 503
  * an invalid executor configuration (claim_ttl lacks declared-budget
    headroom) is contained -- the whole conversation surface fails closed 503
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from cognic_agentos.core.conversation.storage import ConversationStore
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor


class _Binder:
    def __init__(self) -> None:
        self._actor = Actor(
            subject="s1",
            tenant_id="t1",
            scopes=frozenset({"conversation.read", "conversation.post_turn"}),
            actor_type="human",
        )

    def bind(self, *, request: Any) -> Actor:
        return self._actor


def _app(memory_settings: Any, memory_registry: Any, tmp_path: Any, **overrides: Any) -> Any:
    cfg = tmp_path / "litellm.yaml"
    cfg.write_text(
        "model_list:\n  - model_name: cognic-tier1-dev\n"
        "    litellm_params:\n      model: ollama/qwen\n"
        "      api_base: http://localhost:11434\n"
    )
    return create_app(
        memory_settings.model_copy(
            update={"litellm_config_path": cfg, "cache_driver": "memory", **overrides}
        ),
        adapter_registry=memory_registry,
    )


def test_store_is_built_from_the_relational_adapter_engine(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    app = _app(memory_settings, memory_registry, tmp_path)
    with TestClient(app):
        store = app.state.conversation_store
        assert isinstance(store, ConversationStore)
        adapters = app.state.adapters
        assert store._engine is adapters.relational.engine


def test_read_model_is_built_from_the_engine_with_the_ruled_candidate_cap(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    """M8.5-B: the read model is built from ``adapters.relational.engine`` with
    ``Settings.conversation_chain_candidate_limit`` threaded into the candidate
    cap. (Its independence from the agent loop is pinned separately by
    test_build_agent_loop_failure_is_contained, where the loop fails and the
    read model still constructs.)"""
    from cognic_agentos.core.conversation.read_model import ConversationReadModel

    app = _app(memory_settings, memory_registry, tmp_path)
    with TestClient(app):
        rm = app.state.conversation_read_model
        assert isinstance(rm, ConversationReadModel)
        assert rm._engine is app.state.adapters.relational.engine
        # The ruled Setting threads into the reader's candidate cap.
        assert rm._chain_candidate_limit == memory_settings.conversation_chain_candidate_limit


def test_executor_requires_agent_loop_and_both_admitted_hook_phases(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    """An empty dispatcher is not a ready conversation safety boundary."""
    app = _app(memory_settings, memory_registry, tmp_path)
    with TestClient(app) as client:
        loop_present = app.state.agent_loop is not None
        dispatcher = app.state.hook_dispatcher
        hooks_ready = dispatcher is not None and all(
            dispatcher.has_phase_hooks(phase)
            for phase in ("conversation_input", "conversation_output")
        )
        executor_present = app.state.conversation_executor is not None
        assert executor_present == (loop_present and hooks_ready)
        if executor_present:
            assert app.state.conversation_hook_guard is not None
            assert app.state.conversation_hook_guard._dispatcher is app.state.hook_dispatcher
            assert app.state.conversation_executor._hook_guard is app.state.conversation_hook_guard
        if not executor_present:
            app.state.actor_binder = _Binder()
            r = client.post(
                "/api/v1/conversations/33333333-3333-3333-3333-333333333333/turns",
                json={"user_message": "q"},
            )
            assert r.status_code == 503
            assert r.json()["detail"]["reason"] == "conversation_executor_unavailable"


def test_hook_runtime_failure_keeps_turn_surface_fail_closed(
    memory_settings: Any,
    memory_registry: Any,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import cognic_agentos.harness.hook_registry as hook_registry

    def _boom(**kwargs: Any) -> Any:
        raise RuntimeError("hook runtime construction exploded")

    monkeypatch.setattr(hook_registry, "build_hook_runtime", _boom)
    app = _app(memory_settings, memory_registry, tmp_path)
    with TestClient(app):
        assert app.state.hook_dispatcher is None
        assert app.state.conversation_hook_guard is None
        assert app.state.conversation_executor is None
        assert app.state.conversation_store is not None
        assert app.state.conversation_read_model is not None


def test_build_agent_loop_failure_is_contained(
    memory_settings: Any, memory_registry: Any, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If build_agent_loop_with_records() raises, the fail-soft arm remains safe.

    The conversation block reads app.state.agent_loop -- never the local, which
    is genuinely unbound on this path. The proof that no UnboundLocalError fires
    is that the lifespan completes and the store still constructs."""
    import cognic_agentos.harness.agent_host as agent_host

    async def _boom(**kwargs: Any) -> Any:
        raise RuntimeError("agent loop construction exploded")

    monkeypatch.setattr(agent_host, "build_agent_loop_with_records", _boom)
    app = _app(memory_settings, memory_registry, tmp_path)
    with TestClient(app) as client:  # lifespan completing IS the assertion
        assert app.state.agent_loop is None
        assert isinstance(app.state.conversation_store, ConversationStore)
        assert app.state.conversation_executor is None
        assert app.state.conversation_read_model is not None  # reads survive loop failure
        app.state.actor_binder = _Binder()
        r = client.post(
            "/api/v1/conversations/33333333-3333-3333-3333-333333333333/turns",
            json={"user_message": "q"},
        )
        assert r.status_code == 503
        assert r.json()["detail"]["reason"] == "conversation_executor_unavailable"


def test_invalid_executor_configuration_fails_the_surface_closed(
    memory_settings: Any,
    memory_registry: Any,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Insufficient declared-budget headroom trips executor construction.

    The lifespan contains the ValueError and nulls the whole surface, so every
    conversation route fails closed 503. This does not claim a hard end-to-end
    lease deadline; the executor docstring records that R20 limitation.
    """
    import cognic_agentos.harness.hook_registry as hook_registry

    class _ReadyGuard:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def turn_timeout_budget_s(self) -> float:
            # The adapter's own unit test pins this as the exact input+output
            # phase sum. This wiring pin proves the lifespan cannot drop the
            # returned budget before executor construction.
            return 60.0

    # This regression isolates the TTL constructor guard. Empty phase-chain
    # refusal is pinned independently and would otherwise short-circuit first.
    monkeypatch.setattr(hook_registry, "ConversationHookGuardAdapter", _ReadyGuard)

    app = _app(
        memory_settings,
        memory_registry,
        tmp_path,
        # Greater than the 120s loop budget, but equal to loop + hook headroom.
        conversation_claim_ttl_s=180.0,
    )
    with TestClient(app) as client:
        assert app.state.conversation_store is None
        assert app.state.conversation_executor is None
        assert app.state.conversation_read_model is None  # fail-soft nulls ALL THREE
        app.state.actor_binder = _Binder()
        r = client.get("/api/v1/conversations/33333333-3333-3333-3333-333333333333")
        assert r.status_code == 503
        assert r.json()["detail"]["reason"] == "conversation_store_unavailable"
        r = client.get("/api/v1/conversations")
        assert r.status_code == 503
        assert r.json()["detail"]["reason"] == "conversation_read_model_unavailable"
