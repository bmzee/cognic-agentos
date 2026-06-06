from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.llm.concurrency import LLMConcurrencyExceeded
from cognic_agentos.llm.gateway import GatewayResponse
from cognic_agentos.llm.policy import CloudPolicyViolationError, PolicyDecision
from cognic_agentos.llm.preflight import ResolvedUpstream
from cognic_agentos.portal.api.evaluation.routes import build_eval_routes
from cognic_agentos.portal.rbac.actor import Actor

_GOOD = json.dumps(
    {
        "verdict": "pass",
        "score": 1.0,
        "rationale": "right",
        "criteria_results": [{"name": "correct", "passed": True, "note": "ok"}],
    }
)


def _cloud_policy_violation() -> CloudPolicyViolationError:
    """Construct a real ``CloudPolicyViolationError``.

    Its ``__init__(self, message, decision)`` requires a ``PolicyDecision``
    (it is NOT a single-arg ``RuntimeError`` like ``LLMConcurrencyExceeded``),
    so the plan's one-arg ``CloudPolicyViolationError("denied")`` stand-in does
    not construct. We build a genuine denial decision here and surface it via
    ``from_decision`` — the route only cares that it is a raised gateway
    exception (Mode B), so the decision contents are immaterial.
    """
    resolved = ResolvedUpstream(
        alias="cognic-tier1-dev",
        model_string="openai/gpt-4o",
        api_base=None,
        external=True,
        provenance="resolved",
    )
    decision = PolicyDecision(
        allowed=False,
        resolved=resolved,
        reason="denied",
        policy_mode="cloud",
        post_response=False,
        audit_payload={"reason": "denied"},
    )
    return CloudPolicyViolationError.from_decision(decision)


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _actor(
    *,
    scopes: frozenset[str] = frozenset({"eval.judge.run"}),
    actor_type: str = "service",
) -> Actor:
    return Actor(subject="svc", tenant_id="t1", scopes=scopes, actor_type=actor_type)  # type: ignore[arg-type]


class _FakeGateway:
    def __init__(self, *, content: str | None = None, raise_exc: Exception | None = None) -> None:
        self._content = content
        self._raise = raise_exc
        self.calls: list[str] = []

    async def completion(
        self,
        *,
        tier: str,
        messages: list[dict[str, str]],
        request_id: str,
        tenant_id: str | None = None,
    ) -> GatewayResponse:
        self.calls.append(request_id)
        if self._raise is not None:
            raise self._raise
        assert self._content is not None
        return GatewayResponse(
            content=self._content,
            upstream_model="m",
            api_base=None,
            external=False,
            request_id=request_id,
            tier=tier,
            latency_ms=5,
        )


class _CapturingStore:
    def __init__(self) -> None:
        self.records: list[DecisionRecord] = []

    async def append(self, record: DecisionRecord) -> tuple[uuid.UUID, bytes]:
        self.records.append(record)
        return uuid.uuid4(), b"hash"


class _FakeRuntime:
    def __init__(self, store: _CapturingStore) -> None:
        self.decision_history_store = store


def _build_app(*, actor: Actor, gateway: Any, store: Any = None, runtime: Any = None) -> FastAPI:
    app = FastAPI()
    app.state.actor_binder = _StubBinder(actor)
    app.state.ui_event_broker = None
    app.state.llm_gateway = gateway
    app.state.decision_history_store = store
    app.state.runtime = runtime
    app.include_router(build_eval_routes(eval_judge_tier="tier1"), prefix="/api/v1/eval")
    return app


def _body() -> dict[str, Any]:
    return {
        "candidate_output": "2+2=4",
        "criteria": [{"name": "correct", "description": "is it correct"}],
    }


def test_succeeded_200_and_value_free_chain() -> None:
    store = _CapturingStore()
    app = _build_app(actor=_actor(), gateway=_FakeGateway(content=_GOOD), store=store)
    resp = TestClient(app).post("/api/v1/eval/judge", json=_body())
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "pass"
    assert len(store.records) == 1
    rec = store.records[0]
    assert rec.decision_type == "eval.judge_verdict"
    assert rec.payload["status"] == "succeeded"
    # value-free: the raw candidate output must NOT appear; the digest must.
    assert "2+2=4" not in json.dumps(rec.payload)
    assert rec.payload["output_digest"] is not None


def test_unparseable_502_errored_event_safe_evidence_only() -> None:
    store = _CapturingStore()
    app = _build_app(actor=_actor(), gateway=_FakeGateway(content="not json"), store=store)
    resp = TestClient(app).post("/api/v1/eval/judge", json=_body())
    assert resp.status_code == 502
    assert resp.json()["detail"]["reason"] == "judge_verdict_unparseable"
    assert len(store.records) == 1
    p = store.records[0].payload
    assert p["status"] == "errored" and p["parse_reason"] == "not_json"
    assert "verdict" not in p and p["response_digest"] is not None


def test_llm_gateway_unavailable_503() -> None:
    app = _build_app(actor=_actor(), gateway=None, store=_CapturingStore())
    resp = TestClient(app).post("/api/v1/eval/judge", json=_body())
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "llm_gateway_unavailable"


def test_decision_history_unavailable_503_zero_gateway_calls() -> None:
    gw = _FakeGateway(content=_GOOD)
    app = _build_app(actor=_actor(), gateway=gw, store=None, runtime=None)
    resp = TestClient(app).post("/api/v1/eval/judge", json=_body())
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "decision_history_unavailable"
    assert gw.calls == []  # fail-closed BEFORE dispatch


def test_scope_not_held_403() -> None:
    app = _build_app(
        actor=_actor(scopes=frozenset({"memory.read"})),
        gateway=_FakeGateway(content=_GOOD),
        store=_CapturingStore(),
    )
    resp = TestClient(app).post("/api/v1/eval/judge", json=_body())
    assert resp.status_code == 403


@pytest.mark.parametrize(
    "bad",
    [
        {"candidate_output": "", "criteria": [{"name": "a", "description": "d"}]},
        {"candidate_output": "x", "criteria": []},
        {
            "candidate_output": "x",
            "criteria": [
                {"name": "a", "description": "d"},
                {"name": "a", "description": "e"},
            ],
        },
    ],
)
def test_422_request_shape(bad: dict[str, Any]) -> None:
    app = _build_app(actor=_actor(), gateway=_FakeGateway(content=_GOOD), store=_CapturingStore())
    assert TestClient(app).post("/api/v1/eval/judge", json=bad).status_code == 422


def test_mode_b_cloud_policy_502_no_eval_event() -> None:
    store = _CapturingStore()
    gw = _FakeGateway(raise_exc=_cloud_policy_violation())
    app = _build_app(actor=_actor(), gateway=gw, store=store)
    resp = TestClient(app).post("/api/v1/eval/judge", json=_body())
    assert resp.status_code == 502
    assert resp.json()["detail"]["reason"] == "gateway_call_failed"
    assert store.records == []  # Mode B emits NO eval event


def test_mode_b_concurrency_429_no_eval_event() -> None:
    store = _CapturingStore()
    gw = _FakeGateway(raise_exc=LLMConcurrencyExceeded("busy"))
    app = _build_app(actor=_actor(), gateway=gw, store=store)
    resp = TestClient(app).post("/api/v1/eval/judge", json=_body())
    assert resp.status_code == 429
    assert store.records == []


def test_mode_b_generic_502_no_eval_event() -> None:
    store = _CapturingStore()
    gw = _FakeGateway(raise_exc=RuntimeError("httpx/SLA stand-in"))
    app = _build_app(actor=_actor(), gateway=gw, store=store)
    resp = TestClient(app).post("/api/v1/eval/judge", json=_body())
    assert resp.status_code == 502  # default — no raw 500 leak
    assert store.records == []


def test_prod_di_resolves_store_from_runtime() -> None:
    # create_prod_app does not inject decision_history_store; the real store is
    # on app.state.runtime. With store=None but runtime set, the route resolves it.
    store = _CapturingStore()
    app = _build_app(
        actor=_actor(),
        gateway=_FakeGateway(content=_GOOD),
        store=None,
        runtime=_FakeRuntime(store),
    )
    resp = TestClient(app).post("/api/v1/eval/judge", json=_body())
    assert resp.status_code == 200
    assert len(store.records) == 1
