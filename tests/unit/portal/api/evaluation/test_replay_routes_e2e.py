from __future__ import annotations

import asyncio
import uuid
from typing import Any

import sqlalchemy as sa
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.db.migrations.alembic_config import make_alembic_config
from cognic_agentos.evaluation.corpus import validate_corpus_payload
from cognic_agentos.evaluation.runner import EvalRunner
from cognic_agentos.evaluation.scorers import AssertionScorer
from cognic_agentos.evaluation.storage import EvalRunStore
from cognic_agentos.evaluation.target import GatewayTarget
from cognic_agentos.llm.gateway import GatewayResponse
from cognic_agentos.portal.api.evaluation.replay_routes import build_eval_replay_routes
from cognic_agentos.portal.rbac.actor import Actor

_CORPUS: dict[str, Any] = {
    "schema_version": 1,
    "corpus_id": "cp",
    "cases": [
        {
            "id": "c1",
            "case_kind": "completion",
            "messages": [{"role": "user", "content": "q"}],
            "assertions": {"contains": ["ok"]},
        }
    ],
}
_OTHER_CORPUS: dict[str, Any] = {
    "schema_version": 1,
    "corpus_id": "other",
    "cases": [
        {
            "id": "c1",
            "case_kind": "completion",
            "messages": [{"role": "user", "content": "different question"}],
            "assertions": {"contains": ["ok"]},
        }
    ],
}


class _Binder:
    def bind(self, *, request: Request) -> Actor:
        tenant = request.headers.get("x-tenant") or "t1"
        return Actor(
            subject="svc",
            tenant_id=tenant,
            scopes=frozenset({"eval.replay.run"}),
            actor_type="service",
        )


class _FakeGateway:
    def __init__(self, content: str) -> None:
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
            latency_ms=1,
        )


def _url(tmp_path: Any) -> str:
    return f"sqlite+aiosqlite:///{tmp_path / 'replay_route.db'}"


async def _migrate(url: str) -> None:
    from alembic import command

    await asyncio.to_thread(command.upgrade, make_alembic_config(url), "head")


async def _seed_baseline(url: str, *, content: str, tenant_id: str = "t1") -> uuid.UUID:
    eng = create_async_engine(url)
    try:
        corpus = validate_corpus_payload(_CORPUS)
        baseline = await EvalRunner().run(
            corpus,
            target=GatewayTarget(gateway=_FakeGateway(content), tier="tier1"),  # type: ignore[arg-type]
            scorers=[AssertionScorer()],
            run_id=uuid.uuid4(),
            chain_request_id="b",
            tenant_id=tenant_id,
        )
        await EvalRunStore(DecisionHistoryStore(eng)).persist_run(
            result=baseline, actor_subject="svc", tenant_id=tenant_id
        )
        return baseline.run_id
    finally:
        await eng.dispose()


def _app(url: str, *, gateway: _FakeGateway) -> FastAPI:
    app = FastAPI()
    app.state.actor_binder = _Binder()
    app.state.llm_gateway = gateway
    app.state.decision_history_store = DecisionHistoryStore(create_async_engine(url))
    app.state.runtime = None
    app.include_router(
        build_eval_replay_routes(
            max_cases=50, max_raw_output_chars=50_000, target_tier="tier1", judge_tier="tier1"
        ),
        prefix="/api/v1/eval",
    )
    return app


def _post_body(corpus: dict[str, Any], baseline_run_id: Any) -> dict[str, Any]:
    return {"corpus": corpus, "baseline_run_id": str(baseline_run_id)}


async def test_replay_200_regression_candidate_queryable_one_replay_row(tmp_path: Any) -> None:
    url = _url(tmp_path)
    await _migrate(url)
    baseline_id = await _seed_baseline(url, content="ok")  # baseline passes
    app = _app(url, gateway=_FakeGateway("no"))  # candidate fails -> regression
    with TestClient(app) as client:
        r = client.post("/api/v1/eval/replay", json=_post_body(_CORPUS, baseline_id))
    assert r.status_code == 200, r.text
    assert r.json()["has_regressions"] is True
    case0 = r.json()["cases"][0]
    assert "baseline_outcome" in case0 and "candidate_outcome" in case0  # P1 fix
    candidate_run_id = uuid.UUID(r.json()["candidate_run_id"])
    eng = create_async_engine(url)
    try:
        got = await EvalRunStore(DecisionHistoryStore(eng)).get_run(
            run_id=candidate_run_id, tenant_id="t1"
        )
        assert got is not None
        async with eng.connect() as c:
            rows = (
                await c.execute(
                    sa.text("SELECT 1 FROM decision_history WHERE event_type='eval.replay'")
                )
            ).all()
        assert len(rows) == 1
    finally:
        await eng.dispose()


async def test_unknown_and_wrong_tenant_both_404_byte_identical(tmp_path: Any) -> None:
    url = _url(tmp_path)
    await _migrate(url)
    baseline_id = await _seed_baseline(url, content="ok", tenant_id="t1")
    app = _app(url, gateway=_FakeGateway("ok"))
    with TestClient(app) as client:
        unknown = client.post("/api/v1/eval/replay", json=_post_body(_CORPUS, uuid.uuid4()))
        cross = client.post(
            "/api/v1/eval/replay", json=_post_body(_CORPUS, baseline_id), headers={"x-tenant": "t2"}
        )
    assert unknown.status_code == 404
    assert unknown.json()["detail"]["reason"] == "baseline_run_not_found"
    assert cross.status_code == 404
    assert cross.json() == unknown.json()  # wire-collapse: byte-identical


async def test_corpus_digest_mismatch_409(tmp_path: Any) -> None:
    url = _url(tmp_path)
    await _migrate(url)
    baseline_id = await _seed_baseline(url, content="ok")  # baseline corpus = _CORPUS
    app = _app(url, gateway=_FakeGateway("ok"))
    with TestClient(app) as client:
        r = client.post("/api/v1/eval/replay", json=_post_body(_OTHER_CORPUS, baseline_id))
    assert r.status_code == 409
    assert r.json()["detail"]["reason"] == "replay_corpus_digest_mismatch"


async def test_partial_failure_append_raises_after_persist_5xx(
    tmp_path: Any, monkeypatch: Any
) -> None:
    url = _url(tmp_path)
    await _migrate(url)
    baseline_id = await _seed_baseline(url, content="ok")
    app = _app(url, gateway=_FakeGateway("ok"))

    async def _boom(self: Any, **kwargs: Any) -> Any:
        raise RuntimeError("append failed after persist")

    monkeypatch.setattr(EvalRunStore, "append_replay_event", _boom)
    with TestClient(app, raise_server_exceptions=False) as client:
        r = client.post("/api/v1/eval/replay", json=_post_body(_CORPUS, baseline_id))
    assert r.status_code >= 500
    eng = create_async_engine(url)
    try:
        async with eng.connect() as c:
            eval_runs = (await c.execute(sa.text("SELECT 1 FROM eval_runs"))).all()
            replay_rows = (
                await c.execute(
                    sa.text("SELECT 1 FROM decision_history WHERE event_type='eval.replay'")
                )
            ).all()
        assert len(eval_runs) >= 2  # baseline + candidate both persisted
        assert len(replay_rows) == 0  # no eval.replay row (append failed)
    finally:
        await eng.dispose()
