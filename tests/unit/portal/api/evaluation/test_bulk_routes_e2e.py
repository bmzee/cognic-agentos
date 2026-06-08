from __future__ import annotations

import asyncio
import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.db.migrations.alembic_config import make_alembic_config
from cognic_agentos.llm.concurrency import LLMConcurrencyExceeded
from cognic_agentos.llm.gateway import GatewayResponse
from cognic_agentos.portal.api.evaluation.bulk_routes import build_eval_bulk_routes
from cognic_agentos.portal.rbac.actor import Actor


async def _migrated_engine(tmp_path: Any) -> AsyncEngine:
    # Mirrors tests/unit/evaluation/test_storage.py::_migrated_engine. The engine
    # is created but NOT used on the test loop here — its first use happens inside
    # the TestClient portal loop, so cross-loop binding is avoided.
    from alembic import command

    url = f"sqlite+aiosqlite:///{tmp_path / 'eval_route.db'}"
    await asyncio.to_thread(command.upgrade, make_alembic_config(url), "head")
    return create_async_engine(url)


class _Binder:
    """Tenant is header-driven (``x-tenant``, default ``t1``) so a single app can
    exercise own-tenant vs cross-tenant reads within one TestClient loop."""

    def bind(self, *, request: Request) -> Actor:
        tenant = request.headers.get("x-tenant") or "t1"
        return Actor(
            subject="svc",
            tenant_id=tenant,
            scopes=frozenset({"eval.bulk.run", "eval.runs.read"}),
            actor_type="service",
        )


class _FakeGateway:
    def __init__(
        self, *, content: str = "capital adequacy", raise_exc: Exception | None = None
    ) -> None:
        self._content = content
        self._raise = raise_exc

    async def completion(
        self,
        *,
        tier: str,
        messages: list[dict[str, str]],
        request_id: str,
        tenant_id: str | None = None,
    ) -> GatewayResponse:
        if self._raise is not None:
            raise self._raise
        return GatewayResponse(
            content=self._content,
            upstream_model="m",
            api_base=None,
            external=False,
            request_id=request_id,
            tier=tier,
            latency_ms=3,
        )


def _body(*, persist_raw_output: bool = False) -> dict[str, Any]:
    return {
        "corpus": {
            "schema_version": 1,
            "corpus_id": "smoke",
            "cases": [
                {
                    "id": "c1",
                    "case_kind": "completion",
                    "messages": [{"role": "user", "content": "Define CAR."}],
                    "assertions": {"contains": ["capital adequacy"]},
                }
            ],
        },
        "target": "gateway",
        "persist_raw_output": persist_raw_output,
    }


async def _app(tmp_path: Any, gateway: _FakeGateway) -> tuple[FastAPI, AsyncEngine]:
    eng = await _migrated_engine(tmp_path)
    app = FastAPI()
    app.state.actor_binder = _Binder()
    app.state.ui_event_broker = None
    app.state.llm_gateway = gateway
    app.state.decision_history_store = DecisionHistoryStore(eng)
    app.state.runtime = None
    app.include_router(
        build_eval_bulk_routes(
            max_cases=50, max_raw_output_chars=50_000, target_tier="tier1", judge_tier="tier1"
        ),
        prefix="/api/v1/eval",
    )
    return app, eng


async def test_bulk_run_success_200_persists(tmp_path: Any) -> None:
    app, eng = await _app(tmp_path, _FakeGateway())
    try:
        with TestClient(app) as client:
            resp = client.post("/api/v1/eval/bulk-run", json=_body())
        assert resp.status_code == 200
        assert resp.json()["passed"] == 1
        assert resp.json()["total"] == 1
    finally:
        await eng.dispose()


async def test_per_case_gateway_failure_returns_200_with_errored_case(tmp_path: Any) -> None:
    # Patch-2 contract: a per-case gateway failure NEVER produces a 4xx/5xx. The
    # GatewayTarget catches the known gateway exception and surfaces an ``errored``
    # case; the run completes with HTTP 200 carrying the errored case.
    app, eng = await _app(tmp_path, _FakeGateway(raise_exc=LLMConcurrencyExceeded("no slot")))
    try:
        with TestClient(app) as client:
            resp = client.post("/api/v1/eval/bulk-run", json=_body())
        assert resp.status_code == 200
        assert resp.json()["errored"] == 1
        assert resp.json()["cases"][0]["outcome"] == "errored"
    finally:
        await eng.dispose()


async def test_persist_raw_output_true_persists_candidate_text(tmp_path: Any) -> None:
    # Correction (B) b1: persist_raw_output=True → the candidate text is persisted
    # (read back through the store via the GET endpoint).
    app, eng = await _app(tmp_path, _FakeGateway(content="capital adequacy"))
    try:
        with TestClient(app) as client:
            post = client.post("/api/v1/eval/bulk-run", json=_body(persist_raw_output=True))
            assert post.status_code == 200
            assert post.json()["cases"][0]["raw_output_persisted"] is True
            assert post.json()["cases"][0]["output_truncated"] is False
            run_id = post.json()["run_id"]
            got = client.get(f"/api/v1/eval/runs/{run_id}")
        assert got.status_code == 200
        assert got.json()["cases"][0]["candidate_output_text"] == "capital adequacy"
        assert got.json()["cases"][0]["raw_output_persisted"] is True
    finally:
        await eng.dispose()


async def test_persist_raw_output_false_candidate_text_none(tmp_path: Any) -> None:
    # Correction (B) b2: persist_raw_output=False → candidate text is NOT persisted.
    app, eng = await _app(tmp_path, _FakeGateway(content="capital adequacy"))
    try:
        with TestClient(app) as client:
            post = client.post("/api/v1/eval/bulk-run", json=_body(persist_raw_output=False))
            assert post.status_code == 200
            assert post.json()["cases"][0]["raw_output_persisted"] is False
            run_id = post.json()["run_id"]
            got = client.get(f"/api/v1/eval/runs/{run_id}")
        assert got.status_code == 200
        assert got.json()["cases"][0]["candidate_output_text"] is None
    finally:
        await eng.dispose()


async def test_get_run_own_tenant_200(tmp_path: Any) -> None:
    app, eng = await _app(tmp_path, _FakeGateway())
    try:
        with TestClient(app) as client:
            post = client.post("/api/v1/eval/bulk-run", json=_body())
            run_id = post.json()["run_id"]
            got = client.get(f"/api/v1/eval/runs/{run_id}")
        assert got.status_code == 200
        assert got.json()["run"]["run_id"] == run_id
    finally:
        await eng.dispose()


async def test_get_run_cross_tenant_and_unknown_both_404(tmp_path: Any) -> None:
    app, eng = await _app(tmp_path, _FakeGateway())
    try:
        with TestClient(app) as client:
            post = client.post("/api/v1/eval/bulk-run", json=_body())  # tenant t1
            run_id = post.json()["run_id"]
            cross = client.get(f"/api/v1/eval/runs/{run_id}", headers={"x-tenant": "t2"})
            unknown = client.get(f"/api/v1/eval/runs/{uuid.uuid4()}")  # tenant t1, unknown id
        assert cross.status_code == 404
        assert cross.json()["detail"]["reason"] == "eval_run_not_found"
        assert unknown.status_code == 404
        assert unknown.json()["detail"]["reason"] == "eval_run_not_found"
    finally:
        await eng.dispose()
