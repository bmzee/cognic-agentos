from __future__ import annotations

import ast
import pathlib
import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.llm.gateway import GatewayResponse
from cognic_agentos.portal.api.evaluation import bulk_routes
from cognic_agentos.portal.api.evaluation.bulk_routes import build_eval_bulk_routes
from cognic_agentos.portal.rbac.actor import Actor


def _dh_store() -> DecisionHistoryStore:
    # Real DecisionHistoryStore so the type guard passes; the in-memory engine is
    # never used — cap/corpus/RBAC paths return before any DB access.
    return DecisionHistoryStore(create_async_engine("sqlite+aiosqlite://"))


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _actor(*, scopes: frozenset[str] = frozenset({"eval.bulk.run"})) -> Actor:
    return Actor(subject="svc", tenant_id="t1", scopes=scopes, actor_type="service")  # type: ignore[arg-type]


class _FakeGateway:
    def __init__(self, *, content: str = "ok contains capital adequacy") -> None:
        self._content = content

    async def completion(
        self,
        *,
        tier: str,
        messages: list[dict[str, str]],
        request_id: str,
        tenant_id: str | None = None,
    ) -> GatewayResponse:
        return GatewayResponse(
            content=self._content,
            upstream_model="m",
            api_base=None,
            external=False,
            request_id=request_id,
            tier=tier,
            latency_ms=3,
        )


def _corpus_body(n_cases: int) -> dict[str, Any]:
    return {
        "corpus": {
            "schema_version": 1,
            "corpus_id": "smoke",
            "cases": [
                {
                    "id": f"c{i}",
                    "case_kind": "completion",
                    "messages": [{"role": "user", "content": "Define CAR."}],
                    "assertions": {"contains": ["capital adequacy"]},
                }
                for i in range(n_cases)
            ],
        },
        "target": "gateway",
        "persist_raw_output": False,
    }


def _app(*, actor: Actor, gateway: Any, store: Any, runtime: Any, max_cases: int = 50) -> FastAPI:
    app = FastAPI()
    app.state.actor_binder = _StubBinder(actor)
    app.state.ui_event_broker = None
    app.state.llm_gateway = gateway
    app.state.decision_history_store = store
    app.state.runtime = runtime
    app.include_router(
        build_eval_bulk_routes(
            max_cases=max_cases,
            max_raw_output_chars=50_000,
            target_tier="tier1",
            judge_tier="tier1",
        ),
        prefix="/api/v1/eval",
    )
    return app


def test_llm_gateway_unavailable_503() -> None:
    app = _app(actor=_actor(), gateway=None, store=object(), runtime=None)
    resp = TestClient(app).post("/api/v1/eval/bulk-run", json=_corpus_body(1))
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "llm_gateway_unavailable"


def test_decision_history_unavailable_503() -> None:
    # gateway present + scope held → DI resolution reaches the store dep, which
    # fails closed when no decision-history store is wired (BEFORE any execution).
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=None, runtime=None)
    resp = TestClient(app).post("/api/v1/eval/bulk-run", json=_corpus_body(1))
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "decision_history_unavailable"


def test_scope_not_held_403() -> None:
    app = _app(
        actor=_actor(scopes=frozenset({"memory.read"})),
        gateway=_FakeGateway(),
        store=_dh_store(),
        runtime=None,
    )
    resp = TestClient(app).post("/api/v1/eval/bulk-run", json=_corpus_body(1))
    assert resp.status_code == 403


def test_over_cap_413() -> None:
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=_dh_store(), runtime=None, max_cases=1)
    resp = TestClient(app).post("/api/v1/eval/bulk-run", json=_corpus_body(2))
    assert resp.status_code == 413
    assert resp.json()["detail"]["reason"] == "eval_corpus_too_large"


def test_malformed_corpus_400() -> None:
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=_dh_store(), runtime=None)
    body = _corpus_body(1)
    body["corpus"]["cases"][0]["surprise"] = 1  # unknown key
    resp = TestClient(app).post("/api/v1/eval/bulk-run", json=body)
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "corpus_unknown_key"


def test_empty_corpus_400_eval_corpus_empty() -> None:
    # Correction (A): an empty corpus must surface the dedicated
    # ``eval_corpus_empty`` reason. ``Corpus.cases`` carries Pydantic
    # ``min_length=1``, so the raw-cases length is checked BEFORE
    # ``validate_corpus_payload`` (which would otherwise reject the empty list
    # as a generic ``corpus_*`` error). This proves the branch is REACHABLE.
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=_dh_store(), runtime=None)
    body = _corpus_body(1)
    body["corpus"]["cases"] = []
    resp = TestClient(app).post("/api/v1/eval/bulk-run", json=body)
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "eval_corpus_empty"


def test_wrong_type_store_returns_503() -> None:
    # Fix 2 pin: a valid corpus body + a wrong-type store object (NOT a
    # DecisionHistoryStore) must fail closed at the DI type guard with 503 —
    # NOT reach EvalRunStore(...).persist_run() and raise a raw 500.
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=object(), runtime=None)
    resp = TestClient(app).post("/api/v1/eval/bulk-run", json=_corpus_body(1))
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "decision_history_unavailable"


def test_persist_raw_output_rejects_non_bool() -> None:
    # Fix 1 pin: ``persist_raw_output`` is a StrictBool — Pydantic must reject a
    # coerced value (string ``"true"`` / int ``1``) with 422 so the handler never
    # runs and nothing persists (raw-output persistence requires a real JSON bool).
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=_dh_store(), runtime=None)
    body = _corpus_body(1)
    body["persist_raw_output"] = "true"
    resp = TestClient(app).post("/api/v1/eval/bulk-run", json=body)
    assert resp.status_code == 422

    body["persist_raw_output"] = 1
    resp = TestClient(app).post("/api/v1/eval/bulk-run", json=body)
    assert resp.status_code == 422


def test_get_run_missing_read_scope_403() -> None:
    # The GET endpoint's read scope is ``eval.runs.read`` (T9), distinct from the
    # POST ``eval.bulk.run`` scope. An actor holding ONLY ``eval.bulk.run`` must be
    # refused at the scope check (403), not bounced by a DI 503 — so wire a real
    # store and confirm the 403 is the scope gate.
    app = _app(
        actor=_actor(scopes=frozenset({"eval.bulk.run"})),
        gateway=_FakeGateway(),
        store=_dh_store(),
        runtime=None,
    )
    resp = TestClient(app).get(f"/api/v1/eval/runs/{uuid.uuid4()}")
    assert resp.status_code == 403


def test_bulk_routes_omits_future_annotations() -> None:
    # ``bulk_routes.py`` builds closure-local ``Depends(...)`` instances; PEP 563
    # string-deferred annotations would make FastAPI silently treat handler
    # params as query params (422 at request time). Pin the no-future-import
    # invariant via AST (mirrors test_operator_routes.py).
    tree = ast.parse(pathlib.Path(bulk_routes.__file__).read_text())
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            for alias_node in node.names:
                assert alias_node.name != "annotations", (
                    "bulk_routes.py MUST OMIT `from __future__ import annotations` "
                    "(FastAPI closure-local Depends resolution)."
                )
