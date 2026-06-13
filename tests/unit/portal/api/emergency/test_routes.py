"""Sprint 13.6 T6 — portal emergency kill-switch surface (ADR-018 §Portal API).

Flip/revert behind body-aware per-class ``EmergencyRBACScope`` + the in-handler
human gate (the lifecycle_routes promote precedent); list/audit behind
``emergency.read``. Evidence-degraded flips surface the closed-enum
``kill_switch_live_evidence_degraded`` 502 with the switch LIVE (spec review
patch 3). Uses the REAL ``KillSwitchEngine`` over a fake Redis + the REAL
migrated DH store for chain rows (mini e2e at unit level).
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.core.emergency.kill_switches import KillSwitchEngine, _switch_key
from cognic_agentos.portal.api.emergency.routes import build_emergency_routes
from cognic_agentos.portal.rbac.actor import Actor


class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def get(self, key: str) -> Any:
        return self.store.get(key)

    async def set(self, key: str, value: Any, **kwargs: Any) -> Any:
        self.store[key] = value

    def scan_iter(self, match: str) -> AsyncIterator[str]:
        prefix = match.rstrip("*")

        async def _gen() -> AsyncIterator[str]:
            for key in list(self.store):
                if key.startswith(prefix):
                    yield key

        return _gen()


class _FailingDecisionHistory:
    async def append(self, record: DecisionRecord) -> tuple[uuid.UUID, bytes]:
        raise RuntimeError("decision history down")


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _make_actor(
    *,
    subject: str = "ops@bank.example",
    tenant_id: str = "t1",
    scopes: frozenset[str] = frozenset({"emergency.kill.model", "emergency.read"}),
    actor_type: str = "human",
) -> Actor:
    return Actor(
        subject=subject,
        tenant_id=tenant_id,
        scopes=scopes,  # type: ignore[arg-type]
        actor_type=actor_type,  # type: ignore[arg-type]
    )


async def _mk_dh_store(tmp_path: Any, *, name: str = "emergency.db") -> DecisionHistoryStore:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / name}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return DecisionHistoryStore(create_async_engine(url))


def _client(actor: Actor, engine: KillSwitchEngine, dh_store: DecisionHistoryStore) -> AsyncClient:
    app = FastAPI()
    app.state.actor_binder = _StubBinder(actor)
    app.state.ui_event_broker = None
    app.include_router(build_emergency_routes(engine=engine, decision_history_store=dh_store))
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


def _flip_body(
    *, class_: str = "model", scope_key: str = "tier1", category: str = "incident_response"
) -> dict[str, str]:
    return {
        "class": class_,
        "scope_key": scope_key,
        "reason": "model hallucinating",
        "category": category,
    }


class TestFlip:
    async def test_flip_green_path_writes_redis_and_chain(self, tmp_path: Any) -> None:
        redis = _FakeRedis()
        dh = await _mk_dh_store(tmp_path)
        engine = KillSwitchEngine(redis_client=redis, cache_ttl_s=60, decision_history=dh)
        async with _client(_make_actor(), engine, dh) as client:
            resp = await client.post("/api/v1/emergency/kill-switches", json=_flip_body())
        assert resp.status_code == 200
        body = resp.json()
        assert body["class"] == "model"
        assert body["scope_key"] == "tier1"
        assert body["active"] is True
        assert body["enforcement_status"] == "live"
        assert _switch_key("model", "tier1") in redis.store

    async def test_flip_service_actor_403_human_only(self, tmp_path: Any) -> None:
        dh = await _mk_dh_store(tmp_path)
        engine = KillSwitchEngine(redis_client=_FakeRedis(), cache_ttl_s=60, decision_history=dh)
        actor = _make_actor(actor_type="service")  # holds the scope; still refused
        async with _client(actor, engine, dh) as client:
            resp = await client.post("/api/v1/emergency/kill-switches", json=_flip_body())
        assert resp.status_code == 403
        assert resp.json()["detail"]["reason"] == "actor_type_must_be_human"

    async def test_flip_wrong_class_scope_403(self, tmp_path: Any) -> None:
        dh = await _mk_dh_store(tmp_path)
        engine = KillSwitchEngine(redis_client=_FakeRedis(), cache_ttl_s=60, decision_history=dh)
        actor = _make_actor(scopes=frozenset({"emergency.kill.pack"}))
        async with _client(actor, engine, dh) as client:
            resp = await client.post("/api/v1/emergency/kill-switches", json=_flip_body())
        assert resp.status_code == 403
        assert resp.json()["detail"]["reason"] == "scope_not_held"
        assert resp.json()["detail"]["required_scope"] == "emergency.kill.model"

    async def test_flip_unknown_category_422(self, tmp_path: Any) -> None:
        dh = await _mk_dh_store(tmp_path)
        engine = KillSwitchEngine(redis_client=_FakeRedis(), cache_ttl_s=60, decision_history=dh)
        async with _client(_make_actor(), engine, dh) as client:
            resp = await client.post(
                "/api/v1/emergency/kill-switches", json=_flip_body(category="because")
            )
        assert resp.status_code == 422

    async def test_flip_unknown_feature_name_422(self, tmp_path: Any) -> None:
        dh = await _mk_dh_store(tmp_path)
        engine = KillSwitchEngine(redis_client=_FakeRedis(), cache_ttl_s=60, decision_history=dh)
        actor = _make_actor(scopes=frozenset({"emergency.kill.feature"}))
        async with _client(actor, engine, dh) as client:
            resp = await client.post(
                "/api/v1/emergency/kill-switches",
                json=_flip_body(class_="feature", scope_key="t-1:not_a_feature"),
            )
        assert resp.status_code == 422
        assert resp.json()["detail"]["reason"] == "feature_name_unknown"

    async def test_flip_evidence_degraded_502_switch_stays_live(self, tmp_path: Any) -> None:
        redis = _FakeRedis()
        engine = KillSwitchEngine(
            redis_client=redis, cache_ttl_s=60, decision_history=_FailingDecisionHistory()
        )
        dh = await _mk_dh_store(tmp_path)  # the route's audit-read store; unused here
        async with _client(_make_actor(), engine, dh) as client:
            resp = await client.post("/api/v1/emergency/kill-switches", json=_flip_body())
        assert resp.status_code == 502
        assert resp.json()["detail"] == {
            "reason": "kill_switch_live_evidence_degraded",
            "switch_live": True,
        }
        # THE BRAKE IS ON despite the evidence failure.
        assert await engine.is_class_active(class_="model", scope_key="tier1") is True


class TestRevert:
    async def test_revert_green_path(self, tmp_path: Any) -> None:
        redis = _FakeRedis()
        dh = await _mk_dh_store(tmp_path)
        engine = KillSwitchEngine(redis_client=redis, cache_ttl_s=60, decision_history=dh)
        async with _client(_make_actor(), engine, dh) as client:
            flip = await client.post("/api/v1/emergency/kill-switches", json=_flip_body())
            assert flip.status_code == 200
            resp = await client.delete(
                "/api/v1/emergency/kill-switches/model/tier1",
                params={"reason": "incident resolved", "category": "incident_response"},
            )
        assert resp.status_code == 200
        assert resp.json()["active"] is False
        assert await engine.is_class_active(class_="model", scope_key="tier1") is False

    async def test_revert_requires_reason(self, tmp_path: Any) -> None:
        dh = await _mk_dh_store(tmp_path)
        engine = KillSwitchEngine(redis_client=_FakeRedis(), cache_ttl_s=60, decision_history=dh)
        async with _client(_make_actor(), engine, dh) as client:
            resp = await client.delete(
                "/api/v1/emergency/kill-switches/model/tier1",
                params={"category": "incident_response"},
            )
        assert resp.status_code == 422

    async def test_revert_unknown_class_422(self, tmp_path: Any) -> None:
        dh = await _mk_dh_store(tmp_path)
        engine = KillSwitchEngine(redis_client=_FakeRedis(), cache_ttl_s=60, decision_history=dh)
        async with _client(_make_actor(), engine, dh) as client:
            resp = await client.delete(
                "/api/v1/emergency/kill-switches/not_a_class/x",
                params={"reason": "r", "category": "incident_response"},
            )
        assert resp.status_code == 422


class TestList:
    async def test_list_active_with_enforcement_status(self, tmp_path: Any) -> None:
        redis = _FakeRedis()
        dh = await _mk_dh_store(tmp_path)
        engine = KillSwitchEngine(redis_client=redis, cache_ttl_s=60, decision_history=dh)
        actor = _make_actor(
            scopes=frozenset({"emergency.kill.model", "emergency.kill.tool", "emergency.read"})
        )
        async with _client(actor, engine, dh) as client:
            await client.post("/api/v1/emergency/kill-switches", json=_flip_body())
            await client.post(
                "/api/v1/emergency/kill-switches",
                json=_flip_body(class_="tool", scope_key="tool-x"),
            )
            resp = await client.get("/api/v1/emergency/kill-switches")
        assert resp.status_code == 200
        entries = {(e["class"], e["scope_key"]): e for e in resp.json()}
        assert entries[("model", "tier1")]["enforcement_status"] == "live"
        assert entries[("model", "tier1")]["actor_id"] == "ops@bank.example"
        assert entries[("tool", "tool-x")]["enforcement_status"] == "armed_no_live_consumer"

    async def test_list_excludes_reverted(self, tmp_path: Any) -> None:
        redis = _FakeRedis()
        dh = await _mk_dh_store(tmp_path)
        engine = KillSwitchEngine(redis_client=redis, cache_ttl_s=60, decision_history=dh)
        async with _client(_make_actor(), engine, dh) as client:
            await client.post("/api/v1/emergency/kill-switches", json=_flip_body())
            await client.delete(
                "/api/v1/emergency/kill-switches/model/tier1",
                params={"reason": "resolved", "category": "incident_response"},
            )
            resp = await client.get("/api/v1/emergency/kill-switches")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_list_requires_read_scope(self, tmp_path: Any) -> None:
        dh = await _mk_dh_store(tmp_path)
        engine = KillSwitchEngine(redis_client=_FakeRedis(), cache_ttl_s=60, decision_history=dh)
        actor = _make_actor(scopes=frozenset({"emergency.kill.model"}))
        async with _client(actor, engine, dh) as client:
            resp = await client.get("/api/v1/emergency/kill-switches")
        assert resp.status_code == 403
        assert resp.json()["detail"]["reason"] == "scope_not_held"


class TestAudit:
    async def test_audit_returns_emergency_rows_newest_first(self, tmp_path: Any) -> None:
        redis = _FakeRedis()
        dh = await _mk_dh_store(tmp_path)
        engine = KillSwitchEngine(redis_client=redis, cache_ttl_s=60, decision_history=dh)
        # A non-emergency chain row MUST NOT surface on the audit endpoint.
        await dh.append(
            DecisionRecord(
                decision_type="other.event",
                request_id="other-1",
                payload={"k": "v"},
                tenant_id="t1",
            )
        )
        async with _client(_make_actor(), engine, dh) as client:
            await client.post("/api/v1/emergency/kill-switches", json=_flip_body())
            await client.delete(
                "/api/v1/emergency/kill-switches/model/tier1",
                params={"reason": "resolved", "category": "incident_response"},
            )
            resp = await client.get("/api/v1/emergency/audit")
        assert resp.status_code == 200
        rows = resp.json()
        assert [r["decision_type"] for r in rows] == [
            "emergency.kill_switch_reverted",
            "emergency.kill_switch_flipped",
        ]
        assert rows[1]["payload"]["class"] == "model"
        assert rows[1]["payload"]["enforcement_status"] == "live"

    async def test_audit_requires_read_scope(self, tmp_path: Any) -> None:
        dh = await _mk_dh_store(tmp_path)
        engine = KillSwitchEngine(redis_client=_FakeRedis(), cache_ttl_s=60, decision_history=dh)
        actor = _make_actor(scopes=frozenset({"emergency.kill.model"}))
        async with _client(actor, engine, dh) as client:
            resp = await client.get("/api/v1/emergency/audit")
        assert resp.status_code == 403

    async def test_audit_from_to_range_filters(self, tmp_path: Any) -> None:
        dh = await _mk_dh_store(tmp_path)
        engine = KillSwitchEngine(redis_client=_FakeRedis(), cache_ttl_s=60, decision_history=dh)
        async with _client(_make_actor(), engine, dh) as client:
            await client.post("/api/v1/emergency/kill-switches", json=_flip_body())
            # from in the future excludes everything; to in the past too.
            future = await client.get(
                "/api/v1/emergency/audit", params={"from": "2099-01-01T00:00:00Z"}
            )
            past = await client.get(
                "/api/v1/emergency/audit", params={"to": "2000-01-01T00:00:00Z"}
            )
            both = await client.get(
                "/api/v1/emergency/audit",
                params={"from": "2000-01-01T00:00:00Z", "to": "2099-01-01T00:00:00Z"},
            )
        assert future.json() == []
        assert past.json() == []
        assert [r["decision_type"] for r in both.json()] == ["emergency.kill_switch_flipped"]


class TestLogContract:
    async def test_green_flip_emits_exactly_one_flipped_log(
        self, tmp_path: Any, caplog: pytest.LogCaptureFixture
    ) -> None:
        dh = await _mk_dh_store(tmp_path)
        engine = KillSwitchEngine(redis_client=_FakeRedis(), cache_ttl_s=60, decision_history=dh)
        with caplog.at_level(logging.INFO, logger="cognic_agentos.portal.api.emergency.routes"):
            async with _client(_make_actor(), engine, dh) as client:
                resp = await client.post("/api/v1/emergency/kill-switches", json=_flip_body())
        assert resp.status_code == 200
        flipped = [r for r in caplog.records if r.message == "portal.emergency.kill_switch_flipped"]
        refused = [r for r in caplog.records if r.message == "portal.emergency.flip_refused"]
        assert len(flipped) == 1
        assert refused == []

    async def test_scope_refusal_emits_exactly_one_refused_log(
        self, tmp_path: Any, caplog: pytest.LogCaptureFixture
    ) -> None:
        dh = await _mk_dh_store(tmp_path)
        engine = KillSwitchEngine(redis_client=_FakeRedis(), cache_ttl_s=60, decision_history=dh)
        actor = _make_actor(scopes=frozenset({"emergency.kill.pack"}))
        with caplog.at_level(logging.INFO, logger="cognic_agentos.portal.api.emergency.routes"):
            async with _client(actor, engine, dh) as client:
                resp = await client.post("/api/v1/emergency/kill-switches", json=_flip_body())
        assert resp.status_code == 403
        flipped = [r for r in caplog.records if r.message == "portal.emergency.kill_switch_flipped"]
        refused = [r for r in caplog.records if r.message == "portal.emergency.flip_refused"]
        assert flipped == []
        assert len(refused) == 1


class TestRequestIdMinters:
    def test_prefixes_bounded_to_64(self) -> None:
        from cognic_agentos.portal.api.emergency.routes import (
            _EMERGENCY_AUDIT_REQUEST_ID_PREFIX,
            _EMERGENCY_FLIP_REQUEST_ID_PREFIX,
            _EMERGENCY_LIST_REQUEST_ID_PREFIX,
            _EMERGENCY_REVERT_REQUEST_ID_PREFIX,
        )

        for prefix in (
            _EMERGENCY_FLIP_REQUEST_ID_PREFIX,
            _EMERGENCY_REVERT_REQUEST_ID_PREFIX,
            _EMERGENCY_LIST_REQUEST_ID_PREFIX,
            _EMERGENCY_AUDIT_REQUEST_ID_PREFIX,
        ):
            assert len(prefix) + 32 <= 64
