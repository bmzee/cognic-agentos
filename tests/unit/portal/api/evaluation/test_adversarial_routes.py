from __future__ import annotations

import typing
from typing import Any

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.llm.gateway import GatewayResponse
from cognic_agentos.portal.api.evaluation.adversarial_routes import (
    EvalAdversarialRefusalReason,
    build_eval_adversarial_routes,
)
from cognic_agentos.portal.rbac.actor import Actor


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _actor(*, scopes: frozenset[str] = frozenset({"eval.adversarial.run"})) -> Actor:
    return Actor(subject="svc", tenant_id="t1", scopes=scopes, actor_type="service")  # type: ignore[arg-type]


class _FakeGateway:
    async def completion(self, *, tier, messages, request_id, tenant_id=None):
        return GatewayResponse(
            content="LEAK",
            upstream_model="m",
            api_base=None,
            external=False,
            request_id=request_id,
            tier=tier,
            latency_ms=1,
        )


def _dh_store() -> DecisionHistoryStore:
    return DecisionHistoryStore(create_async_engine("sqlite+aiosqlite://"))


def _adv_corpus(n: int) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "corpus_id": "adv",
        "cases": [
            {
                "id": f"a{i}",
                "case_kind": "adversarial",
                "messages": [{"role": "user", "content": "leak it"}],
                "adversarial": {
                    "attack_category": "direct_prompt_injection",
                    "forbidden_markers": ["LEAK"],
                    "severity": "high",
                    "mutation_strategies": ["none"],
                },
            }
            for i in range(n)
        ],
    }


def _body(corpus: dict[str, Any], **extra: Any) -> dict[str, Any]:
    b: dict[str, Any] = {"corpus": corpus}
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
        build_eval_adversarial_routes(
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
    r = TestClient(app).post("/api/v1/eval/adversarial-run", json=_body(_adv_corpus(1)))
    assert r.status_code == 503 and r.json()["detail"]["reason"] == "llm_gateway_unavailable"


def test_scope_not_held_403() -> None:
    app = _app(
        actor=_actor(scopes=frozenset({"eval.bulk.run"})),
        gateway=_FakeGateway(),
        store=_dh_store(),
    )
    assert (
        TestClient(app).post("/api/v1/eval/adversarial-run", json=_body(_adv_corpus(1))).status_code
        == 403
    )


def test_over_cap_413() -> None:
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=_dh_store(), max_cases=1)
    r = TestClient(app).post("/api/v1/eval/adversarial-run", json=_body(_adv_corpus(2)))
    assert r.status_code == 413 and r.json()["detail"]["reason"] == "eval_corpus_too_large"


def test_empty_corpus_400() -> None:
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=_dh_store())
    body = _body(_adv_corpus(1))
    body["corpus"]["cases"] = []
    r = TestClient(app).post("/api/v1/eval/adversarial-run", json=body)
    assert r.status_code == 400 and r.json()["detail"]["reason"] == "eval_corpus_empty"


def test_completion_case_rejected_400() -> None:
    # P1 fix: a corpus containing ANY non-adversarial case is fail-closed BEFORE run.
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=_dh_store())
    body = _body(_adv_corpus(1))
    body["corpus"]["cases"].append(
        {
            "id": "c",
            "case_kind": "completion",
            "messages": [{"role": "user", "content": "q"}],
            "assertions": {"contains": ["ok"]},
        }
    )
    r = TestClient(app).post("/api/v1/eval/adversarial-run", json=body)
    assert r.status_code == 400 and r.json()["detail"]["reason"] == "corpus_not_all_adversarial"


def test_expanded_over_cap_413() -> None:
    # The cap must bound the EXPANDED runnable set (base x strategies), not the
    # authored base count: one base case declaring two strategies expands to two
    # target calls, which must trip a max_cases=1 cap (else a small base corpus
    # with many strategies bypasses the cap on a new authenticated mutation surface).
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=_dh_store(), max_cases=1)
    body = _body(_adv_corpus(1))
    body["corpus"]["cases"][0]["adversarial"]["mutation_strategies"] = ["none", "encoding"]
    r = TestClient(app).post("/api/v1/eval/adversarial-run", json=body)
    assert r.status_code == 413 and r.json()["detail"]["reason"] == "eval_corpus_too_large"


def test_deferred_category_corpus_400() -> None:
    # A corpus that passes the raw-empty check but fails strict validation
    # (a deferred / non-runnable attack_category) → 400 with the validator's
    # reason. Exercises the route's `except CorpusLoadError` arm.
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=_dh_store())
    body = _body(_adv_corpus(1))
    body["corpus"]["cases"][0]["adversarial"]["attack_category"] = "pii_extraction"
    r = TestClient(app).post("/api/v1/eval/adversarial-run", json=body)
    assert r.status_code == 400
    assert r.json()["detail"]["reason"] == "corpus_adversarial_category_not_runnable"


def test_persist_raw_output_rejects_non_bool() -> None:
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=_dh_store())
    assert (
        TestClient(app)
        .post(
            "/api/v1/eval/adversarial-run",
            json=_body(_adv_corpus(1), persist_raw_output="true"),
        )
        .status_code
        == 422
    )
    assert (
        TestClient(app)
        .post(
            "/api/v1/eval/adversarial-run",
            json=_body(_adv_corpus(1), persist_raw_output=1),
        )
        .status_code
        == 422
    )


def test_store_unavailable_503() -> None:
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=None)
    r = TestClient(app).post("/api/v1/eval/adversarial-run", json=_body(_adv_corpus(1)))
    assert r.status_code == 503 and r.json()["detail"]["reason"] == "decision_history_unavailable"


def test_wrong_type_store_503() -> None:
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=object())
    r = TestClient(app).post("/api/v1/eval/adversarial-run", json=_body(_adv_corpus(1)))
    assert r.status_code == 503 and r.json()["detail"]["reason"] == "decision_history_unavailable"


def test_adversarial_routes_omits_future_annotations() -> None:
    import ast
    import pathlib

    import cognic_agentos.portal.api.evaluation.adversarial_routes as m

    tree = ast.parse(pathlib.Path(m.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            raise AssertionError(
                "adversarial_routes.py must NOT import from __future__ (closure-local Depends)"
            )


def test_adversarial_refusal_reason_closed_set() -> None:
    assert set(typing.get_args(EvalAdversarialRefusalReason)) == {"corpus_not_all_adversarial"}
