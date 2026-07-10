"""ADR-028 M8.5-C — lifespan wiring for the conversation substrate (P1, ruled
2026-07-10).

Behavioral pins over the REAL create_app + lifespan, not source inspection:

  * the ConversationStore is built from ``adapters.relational.engine``
  * a build_agent_loop() failure is contained -- no UnboundLocalError, the
    store still constructs, the executor stays None, POST-turn fails closed 503
  * an invalid executor configuration (claim_ttl <= wall clock) is contained --
    the whole conversation surface fails closed 503
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


def test_executor_presence_tracks_agent_loop_presence(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    """The executor exists iff the agent loop was built. With the memory
    fixtures (no packs, no MCP host) the loop is absent, so the executor must
    be too -- and the surface fails closed at the route."""
    app = _app(memory_settings, memory_registry, tmp_path)
    with TestClient(app) as client:
        loop_present = app.state.agent_loop is not None
        executor_present = app.state.conversation_executor is not None
        assert executor_present == loop_present
        if not executor_present:
            app.state.actor_binder = _Binder()
            r = client.post(
                "/api/v1/conversations/33333333-3333-3333-3333-333333333333/turns",
                json={"user_message": "q"},
            )
            assert r.status_code == 503
            assert r.json()["detail"]["reason"] == "conversation_executor_unavailable"


def test_build_agent_loop_failure_is_contained(
    memory_settings: Any, memory_registry: Any, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If build_agent_loop() raises, the except arm sets ONLY app.state.agent_loop.

    The conversation block reads app.state.agent_loop -- never the local, which
    is genuinely unbound on this path. The proof that no UnboundLocalError fires
    is that the lifespan completes and the store still constructs."""
    import cognic_agentos.harness.agent_host as agent_host

    async def _boom(**kwargs: Any) -> Any:
        raise RuntimeError("agent loop construction exploded")

    monkeypatch.setattr(agent_host, "build_agent_loop", _boom)
    app = _app(memory_settings, memory_registry, tmp_path)
    with TestClient(app) as client:  # lifespan completing IS the assertion
        assert app.state.agent_loop is None
        assert isinstance(app.state.conversation_store, ConversationStore)
        assert app.state.conversation_executor is None
        app.state.actor_binder = _Binder()
        r = client.post(
            "/api/v1/conversations/33333333-3333-3333-3333-333333333333/turns",
            json={"user_message": "q"},
        )
        assert r.status_code == 503
        assert r.json()["detail"]["reason"] == "conversation_executor_unavailable"


def test_invalid_executor_configuration_fails_the_surface_closed(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    """claim_ttl_s <= agent_run_wall_clock_s trips the executor's construction
    guard; the lifespan contains the ValueError and nulls the WHOLE surface, so
    every conversation route fails closed 503 rather than serving a store whose
    executor could double-run slow turns."""
    app = _app(
        memory_settings,
        memory_registry,
        tmp_path,
        conversation_claim_ttl_s=60.0,  # < agent_run_wall_clock_s default 120.0
    )
    with TestClient(app) as client:
        assert app.state.conversation_store is None
        assert app.state.conversation_executor is None
        app.state.actor_binder = _Binder()
        r = client.get("/api/v1/conversations/33333333-3333-3333-3333-333333333333")
        assert r.status_code == 503
        assert r.json()["detail"]["reason"] == "conversation_store_unavailable"
