from __future__ import annotations

from typing import Any, get_args

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.llm.gateway import GatewayResponse
from cognic_agentos.portal.api.evaluation.replay_routes import (
    EvalReplayRefusalReason,
    build_eval_replay_routes,
)
from cognic_agentos.portal.rbac.actor import Actor


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _actor(*, scopes: frozenset[str] = frozenset({"eval.replay.run"})) -> Actor:
    return Actor(subject="svc", tenant_id="t1", scopes=scopes, actor_type="service")  # type: ignore[arg-type]


class _FakeGateway:
    async def completion(
        self,
        *,
        tier: str,
        messages: list[dict[str, str]],
        request_id: str,
        tenant_id: str | None = None,
    ) -> GatewayResponse:
        return GatewayResponse(
            content="ok",
            upstream_model="m",
            api_base=None,
            external=False,
            request_id=request_id,
            tier=tier,
            latency_ms=1,
        )


def _dh_store() -> DecisionHistoryStore:
    return DecisionHistoryStore(create_async_engine("sqlite+aiosqlite://"))


def _corpus(n: int) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "corpus_id": "cp",
        "cases": [
            {
                "id": f"c{i}",
                "case_kind": "completion",
                "messages": [{"role": "user", "content": "q"}],
                "assertions": {"contains": ["ok"]},
            }
            for i in range(n)
        ],
    }


def _body(
    corpus: dict[str, Any],
    baseline_run_id: str = "11111111-1111-1111-1111-111111111111",
    **extra: Any,
) -> dict[str, Any]:
    b: dict[str, Any] = {"corpus": corpus, "baseline_run_id": baseline_run_id}
    b.update(extra)
    return b


def _app(
    *, actor: Actor, gateway: Any, store: Any, runtime: Any = None, max_cases: int = 50
) -> FastAPI:
    app = FastAPI()
    app.state.actor_binder = _StubBinder(actor)
    app.state.llm_gateway = gateway
    app.state.decision_history_store = store
    app.state.runtime = runtime
    app.include_router(
        build_eval_replay_routes(
            max_cases=max_cases,
            max_raw_output_chars=50_000,
            target_tier="tier1",
            judge_tier="tier1",
        ),
        prefix="/api/v1/eval",
    )
    return app


def test_llm_gateway_unavailable_503() -> None:
    app = _app(actor=_actor(), gateway=None, store=_dh_store())
    r = TestClient(app).post("/api/v1/eval/replay", json=_body(_corpus(1)))
    assert r.status_code == 503 and r.json()["detail"]["reason"] == "llm_gateway_unavailable"


def test_scope_not_held_403() -> None:
    app = _app(
        actor=_actor(scopes=frozenset({"eval.bulk.run"})),
        gateway=_FakeGateway(),
        store=_dh_store(),
    )
    assert TestClient(app).post("/api/v1/eval/replay", json=_body(_corpus(1))).status_code == 403


def test_over_cap_413() -> None:
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=_dh_store(), max_cases=1)
    r = TestClient(app).post("/api/v1/eval/replay", json=_body(_corpus(2)))
    assert r.status_code == 413 and r.json()["detail"]["reason"] == "eval_corpus_too_large"


def test_empty_corpus_400() -> None:
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=_dh_store())
    body = _body(_corpus(1))
    body["corpus"]["cases"] = []
    r = TestClient(app).post("/api/v1/eval/replay", json=body)
    assert r.status_code == 400 and r.json()["detail"]["reason"] == "eval_corpus_empty"


def test_malformed_baseline_uuid_422() -> None:
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=_dh_store())
    r = TestClient(app).post(
        "/api/v1/eval/replay",
        json=_body(_corpus(1), baseline_run_id="not-a-uuid"),
    )
    assert r.status_code == 422


def test_persist_raw_output_rejects_non_bool() -> None:
    # P1 pin (mirrors the bulk-run boundary): ``ReplayRequest.persist_raw_output`` is a
    # StrictBool — Pydantic must reject a COERCED value (string ``"true"`` / int ``1``)
    # with 422 so the handler never runs and nothing persists. A future downgrade to a
    # plain ``bool`` would silently opt callers into storing model output at rest.
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=_dh_store())
    body = _body(_corpus(1), persist_raw_output="true")
    assert TestClient(app).post("/api/v1/eval/replay", json=body).status_code == 422

    body = _body(_corpus(1), persist_raw_output=1)
    assert TestClient(app).post("/api/v1/eval/replay", json=body).status_code == 422


def test_replay_refusal_reason_closed_set() -> None:
    # P2 pin: ``EvalReplayRefusalReason`` is the closed vocabulary of refusals UNIQUE to
    # the replay surface (post-baseline). It deliberately does NOT include the corpus
    # refusals ``eval_corpus_empty`` / ``eval_corpus_too_large`` (owned by bulk's
    # ``EvalBulkRefusalReason`` and reused here) nor the shared DI 503 reasons. Drift in
    # this exact set is a wire-protocol change to the replay-specific refusal bodies.
    assert set(get_args(EvalReplayRefusalReason)) == {
        "baseline_run_not_found",
        "replay_corpus_digest_mismatch",
    }


def test_store_unavailable_503() -> None:
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=None)
    r = TestClient(app).post("/api/v1/eval/replay", json=_body(_corpus(1)))
    assert r.status_code == 503 and r.json()["detail"]["reason"] == "decision_history_unavailable"


def test_wrong_type_store_503() -> None:
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=object())
    r = TestClient(app).post("/api/v1/eval/replay", json=_body(_corpus(1)))
    assert r.status_code == 503 and r.json()["detail"]["reason"] == "decision_history_unavailable"


def test_replay_routes_omits_future_annotations() -> None:
    import ast
    import pathlib

    import cognic_agentos.portal.api.evaluation.replay_routes as m

    tree = ast.parse(pathlib.Path(m.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            raise AssertionError(
                "replay_routes.py must NOT import from __future__ (closure-local Depends)"
            )
