"""Live eval-judge proof — real LLM + real gateway + recording observability.

Env-gated on COGNIC_RUN_GATEWAY_OBSERVABILITY_INTEGRATION=1. Per the
integration-test discipline (mirrors the Sprint-10.1 Z2 fail-loud contract):
opted-in but misconfigured (no reachable LiteLLM proxy / model) FAILS LOUD
(AssertionError), NOT skip. NOT opted in -> skip (casual local `uv run pytest`).

What this proves: the real-LLM call + the gateway emitting the
`llm.gateway.completion` span THROUGH the adapter seam + the
`eval.judge_verdict` chain row — end-to-end. It does NOT prove real Langfuse
INGESTION (the recording adapter is in-process); that stays a deferred
operational check.

Env contract (all required when opted in; each asserted fail-loud):
- COGNIC_LITELLM_BASE_URL — a reachable LiteLLM proxy base URL (the gateway
  POSTs ``{base}/chat/completions`` at gateway.py:354).
- COGNIC_LITELLM_MODEL — the model string the proxy serves for the tier1
  alias (written into the litellm YAML below; also drives preflight
  classification — see the policy note in the test).
Optional:
- COGNIC_LITELLM_MASTER_KEY — bearer key for the proxy (None if unsecured).
"""

from __future__ import annotations

import os

import httpx
import pytest
from sqlalchemy import select

from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.db.adapters.protocols import AdapterHealth
from cognic_agentos.portal.rbac.actor import Actor

_OPTED_IN = os.environ.get("COGNIC_RUN_GATEWAY_OBSERVABILITY_INTEGRATION") == "1"

pytestmark = pytest.mark.skipif(
    not _OPTED_IN,
    reason="set COGNIC_RUN_GATEWAY_OBSERVABILITY_INTEGRATION=1 (+ COGNIC_LITELLM_BASE_URL "
    "+ COGNIC_LITELLM_MODEL pointing at a reachable LiteLLM proxy) to run the live proof",
)


class _RecordingObservability:
    def __init__(self) -> None:
        self.captured: list[tuple[str, dict[str, object]]] = []

    async def emit_trace(self, name: str, attributes: dict[str, object]) -> None:
        self.captured.append((name, attributes))

    async def emit_metric(self, name: str, value: float, attributes: dict[str, object]) -> None: ...
    async def flush(self) -> None: ...
    async def health_check(self) -> AdapterHealth:
        return AdapterHealth(status="ok", driver="recording", latency_ms=0.0)


class _StubBinder:
    """Mirror tests/unit/portal/api/evaluation/test_routes.py::_StubBinder."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: object) -> Actor:
        return self._actor


def _actor() -> Actor:
    return Actor(
        subject="svc",
        tenant_id="t1",
        scopes=frozenset({"eval.judge.run"}),
        actor_type="service",
    )


async def test_live_eval_judge_emits_gateway_span_and_chain_row(
    memory_settings, memory_registry, tmp_path
):
    from fastapi import FastAPI

    from cognic_agentos.db.adapters.factory import build_adapters
    from cognic_agentos.harness import build_runtime
    from cognic_agentos.portal.api.evaluation.routes import build_eval_routes

    # --- fail-loud config preconditions (opted in => prove it or fail) ----
    base_url = os.environ.get("COGNIC_LITELLM_BASE_URL")
    model = os.environ.get("COGNIC_LITELLM_MODEL")
    assert base_url, "opted in but COGNIC_LITELLM_BASE_URL unset — fail loud (NOT skip)"
    assert model, "opted in but COGNIC_LITELLM_MODEL unset — fail loud (NOT skip)"

    # Minimal litellm YAML mapping the tier1 alias -> the proxy's model.
    cfg = tmp_path / "litellm.yaml"
    cfg.write_text(
        "model_list:\n"
        "  - model_name: cognic-tier1-dev\n"
        "    litellm_params:\n"
        f"      model: {model}\n"
    )
    # Reuse the proven in-memory DB config (memory_settings: db_driver='memory' etc.),
    # point the LLM at the real proxy. cache_driver='none' keeps the memory branch out
    # (gateway-only path). NOTE: if the proxy model classifies as EXTERNAL (preflight
    # via gateway.py:211 _is_external), the live operator must also set the matching
    # policy env (e.g. allow_external_llm + allowed_providers) so the pre-call cloud-
    # policy gate passes — otherwise the span outcome is "policy_denied", not "ok".
    settings = memory_settings.model_copy(
        update={
            "litellm_config_path": cfg,
            "litellm_base_url": base_url,
            "tier1_alias": "cognic-tier1-dev",
            "litellm_master_key": os.environ.get("COGNIC_LITELLM_MASTER_KEY"),
            "cache_driver": "none",
        }
    )

    adapters = build_adapters(settings, registry=memory_registry)
    recording = _RecordingObservability()
    adapters.observability = recording  # Adapters is @dataclass(slots=True), NOT frozen
    await adapters.open_all()
    runtime = None
    try:
        # Chain tables + chain heads come from InMemoryRelationalAdapter.connect()
        # (Sprint 13.5b1 — build_runtime's unconditional approval OPAEngine.create
        # needs them on EVERY path), so no test-local seeding here.
        eng = adapters.relational.engine
        runtime = await build_runtime(settings, adapters)
        assert runtime.llm_gateway._observability is recording  # the seam under test

        # Mirror test_routes.py::_build_app, but with the REAL gateway + runtime.
        app = FastAPI()
        app.state.actor_binder = _StubBinder(_actor())
        app.state.ui_event_broker = None
        app.state.llm_gateway = runtime.llm_gateway
        app.state.decision_history_store = None  # resolved runtime-first from app.state.runtime
        app.state.runtime = runtime
        app.include_router(build_eval_routes(eval_judge_tier="tier1"), prefix="/api/v1/eval")

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            resp = await client.post(
                "/api/v1/eval/judge",
                json={
                    "candidate_output": "2 + 2 = 4",
                    "criteria": [{"name": "correct", "description": "is the arithmetic correct"}],
                },
            )
        assert resp.status_code == 200, resp.text

        # (a) the gateway emitted the span THROUGH the adapter seam.
        spans = [a for n, a in recording.captured if n == "llm.gateway.completion"]
        assert len(spans) == 1
        assert spans[0]["llm.gateway.outcome"] in {"ok", "drift"}
        assert "content" not in repr(spans[0]).lower()  # value-free even live

        # (b) the eval.judge_verdict chain row was written. The persisted column is
        # `event_type` (DecisionRecord.decision_type maps to it — decision_history.py:195
        # + the docstring at :220-222), NOT `decision_type`.
        async with eng.connect() as conn:
            rows = list(
                (
                    await conn.execute(
                        select(_decision_history).where(
                            _decision_history.c.event_type == "eval.judge_verdict"
                        )
                    )
                ).fetchall()
            )
        assert len(rows) == 1
    finally:
        if runtime is not None:
            await runtime.aclose()
        await adapters.close_all()
