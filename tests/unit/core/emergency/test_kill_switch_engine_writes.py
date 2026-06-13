"""Sprint 13.6 T2 — KillSwitchEngine write side (ADR-018; spec review patch 3).

Pins the brake-before-evidence doctrine: Redis write FIRST (the brake), THEN
the ``emergency.kill_switch_flipped`` / ``emergency.kill_switch_reverted``
chain row. Evidence-append failure leaves the switch LIVE and surfaces
``FlipResult(evidence_degraded=True)``; an idempotent re-flip performs no
Redis state change but appends the evidence row so the chain converges on
retry. Seed-class flips delegate to the seed's ``frozen`` JSON shape (F2 — no
behavioral break for memory writes).
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest

from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.core.emergency.kill_switches import (
    KillSwitchClass,
    KillSwitchEngine,
    RedisMemoryWriteFreezeKillSwitch,
    _switch_key,
)


class _RecordingRedis:
    """_AsyncRedisKVLike conformer recording set() calls into a shared event log."""

    def __init__(self, events: list[tuple[str, str]]) -> None:
        self.store: dict[str, str] = {}
        self._events = events

    async def get(self, key: str) -> Any:
        return self.store.get(key)

    async def set(self, key: str, value: Any, **kwargs: Any) -> Any:
        self._events.append(("redis_set", key))
        self.store[key] = value


class _FakeDecisionHistory:
    """Narrow append-only fake conforming to the engine's append seam."""

    def __init__(self, events: list[tuple[str, str]]) -> None:
        self.records: list[DecisionRecord] = []
        self.fail = False
        self._events = events

    async def append(self, record: DecisionRecord) -> tuple[uuid.UUID, bytes]:
        if self.fail:
            raise RuntimeError("decision history down")
        self._events.append(("chain_append", record.decision_type))
        self.records.append(record)
        return (uuid.uuid4(), b"\x00" * 32)


def _build_engine() -> tuple[
    KillSwitchEngine, _RecordingRedis, _FakeDecisionHistory, list[tuple[str, str]]
]:
    events: list[tuple[str, str]] = []
    redis = _RecordingRedis(events)
    dh = _FakeDecisionHistory(events)
    engine = KillSwitchEngine(redis_client=redis, cache_ttl_s=60, decision_history=dh)
    return engine, redis, dh, events


class TestFlipEvidence:
    async def test_flip_writes_redis_then_chain_row_in_that_order(self) -> None:
        engine, _redis, _dh, events = _build_engine()
        result = await engine.flip(
            class_="model",
            scope_key="tier1",
            actor_id="ops-1",
            reason="hallucinating",
            category="incident_response",
        )
        assert result.active is True
        assert result.evidence_degraded is False
        assert result.chain_record_id is not None
        assert events == [
            ("redis_set", _switch_key("model", "tier1")),
            ("chain_append", "emergency.kill_switch_flipped"),
        ]
        assert await engine.is_class_active(class_="model", scope_key="tier1") is True

    async def test_flip_chain_payload_keyset_iso_and_actor(self) -> None:
        engine, _redis, dh, _events = _build_engine()
        await engine.flip(
            class_="model",
            scope_key="tier1",
            actor_id="ops-1",
            reason="hallucinating",
            category="incident_response",
        )
        (record,) = dh.records
        assert record.decision_type == "emergency.kill_switch_flipped"
        # actor_id rides the DecisionRecord field (the DH store merges it into
        # the persisted payload at append) — NOT duplicated in the payload dict.
        assert record.actor_id == "ops-1"
        assert set(record.payload) == {
            "class",
            "scope_key",
            "category",
            "reason",
            "active",
            "enforcement_status",
        }
        assert record.payload["class"] == "model"
        assert record.payload["scope_key"] == "tier1"
        assert record.payload["category"] == "incident_response"
        assert record.payload["active"] is True
        assert record.payload["enforcement_status"] == "live"
        assert record.iso_controls == ("ISO42001.A.6.2.5", "ISO42001.A.9.2")

    async def test_request_id_shape_bounded(self) -> None:
        engine, _redis, dh, _events = _build_engine()
        await engine.flip(
            class_="model",
            scope_key="tier1",
            actor_id="ops-1",
            reason="r",
            category="incident_response",
        )
        (record,) = dh.records
        assert record.request_id.startswith("emrg-flip-")
        assert len(record.request_id) <= 64

    @pytest.mark.parametrize("armed_class", ["tool", "feature"])
    async def test_armed_classes_carry_armed_status_in_payload(
        self, armed_class: KillSwitchClass
    ) -> None:
        engine, _redis, dh, _events = _build_engine()
        scope_key = "tool-x" if armed_class == "tool" else "subagent_spawn"
        await engine.flip(
            class_=armed_class,
            scope_key=scope_key,
            actor_id="ops-1",
            reason="cve",
            category="security_disclosure",
        )
        (record,) = dh.records
        assert record.payload["enforcement_status"] == "armed_no_live_consumer"


class TestBrakeBeforeEvidence:
    async def test_chain_failure_leaves_switch_live_and_reports_degraded(self) -> None:
        engine, redis, dh, _events = _build_engine()
        dh.fail = True
        result = await engine.flip(
            class_="model",
            scope_key="tier1",
            actor_id="ops-1",
            reason="r",
            category="incident_response",
        )
        assert result.evidence_degraded is True
        assert result.chain_record_id is None
        # THE BRAKE STAYS ON — evidence failure never resurrects the killed path.
        assert await engine.is_class_active(class_="model", scope_key="tier1") is True
        doc = json.loads(redis.store[_switch_key("model", "tier1")])
        assert doc["active"] is True


class TestIdempotentReflip:
    async def test_same_state_flip_skips_redis_set_but_appends_evidence(self) -> None:
        engine, _redis, dh, events = _build_engine()
        await engine.flip(
            class_="model",
            scope_key="tier1",
            actor_id="ops-1",
            reason="r",
            category="incident_response",
        )
        events.clear()
        result = await engine.flip(
            class_="model",
            scope_key="tier1",
            actor_id="ops-1",
            reason="retry after degraded evidence",
            category="incident_response",
        )
        assert result.evidence_degraded is False
        # NO Redis state change; the evidence row converges the chain on retry.
        assert events == [("chain_append", "emergency.kill_switch_flipped")]
        assert len(dh.records) == 2


class TestRevert:
    async def test_revert_mirrors_flip_with_active_false(self) -> None:
        engine, _redis, dh, events = _build_engine()
        await engine.flip(
            class_="model",
            scope_key="tier1",
            actor_id="ops-1",
            reason="incident",
            category="incident_response",
        )
        events.clear()
        result = await engine.revert(
            class_="model",
            scope_key="tier1",
            actor_id="ops-2",
            reason="resolved",
            category="incident_response",
        )
        assert result.active is False
        assert events == [
            ("redis_set", _switch_key("model", "tier1")),
            ("chain_append", "emergency.kill_switch_reverted"),
        ]
        record = dh.records[-1]
        assert record.decision_type == "emergency.kill_switch_reverted"
        assert record.payload["active"] is False
        assert record.actor_id == "ops-2"
        assert await engine.is_class_active(class_="model", scope_key="tier1") is False

    async def test_revert_request_id_prefix(self) -> None:
        engine, _redis, dh, _events = _build_engine()
        await engine.revert(
            class_="model",
            scope_key="tier1",
            actor_id="ops-1",
            reason="r",
            category="incident_response",
        )
        # A revert of an already-inactive switch is the idempotent arm: no
        # Redis write, evidence row still appended.
        (record,) = dh.records
        assert record.request_id.startswith("emrg-flip-")
        assert len(record.request_id) <= 64


class TestSeedClassDelegation:
    async def test_memory_write_freeze_flip_writes_seed_frozen_shape(self) -> None:
        # F2: the seed's reader must pick up an engine-side flip — the engine
        # writes the seed's {"frozen": ...} JSON shape for this class.
        engine, redis, _dh, _events = _build_engine()
        await engine.flip(
            class_="memory_write_freeze",
            scope_key="t-1",
            actor_id="ops-1",
            reason="incident",
            category="incident_response",
        )
        seed = RedisMemoryWriteFreezeKillSwitch(redis_client=redis, cache_ttl_s=60)
        assert await seed.is_write_frozen(tenant_id="t-1") is True
        doc = json.loads(redis.store[_switch_key("memory_write_freeze", "t-1")])
        assert doc["frozen"] is True
        assert "active" not in doc

    async def test_is_class_active_parses_seed_frozen_shape(self) -> None:
        # Engine reads of the seed class are class-aware (frozen, not active)
        # so the portal list surface renders the seed switch correctly.
        engine, redis, _dh, _events = _build_engine()
        seed = RedisMemoryWriteFreezeKillSwitch(redis_client=redis, cache_ttl_s=60)
        await seed.set_write_freeze(
            tenant_id="t-1", frozen=True, actor_id="ops-1", reason="incident"
        )
        assert await engine.is_class_active(class_="memory_write_freeze", scope_key="t-1") is True


class TestTenantAttribution:
    @pytest.mark.parametrize(
        ("class_", "scope_key", "expected_tenant"),
        [
            ("memory_write_freeze", "t-1", "t-1"),
            ("tenant_packs", "t-1", "t-1"),
            ("tenant_full", "t-1", "t-1"),
            ("feature", "t-1:subagent_spawn", "t-1"),
            ("feature", "subagent_spawn", None),
            ("model", "tier1", None),
            ("pack", "pk-1", None),
            ("cloud_routing", "global", None),
        ],
    )
    async def test_chain_row_tenant_id(
        self, class_: KillSwitchClass, scope_key: str, expected_tenant: str | None
    ) -> None:
        engine, _redis, dh, _events = _build_engine()
        await engine.flip(
            class_=class_,
            scope_key=scope_key,
            actor_id="ops-1",
            reason="r",
            category="incident_response",
        )
        (record,) = dh.records
        assert record.tenant_id == expected_tenant


class TestValidation:
    async def test_unknown_feature_name_refused(self) -> None:
        engine, _redis, dh, _events = _build_engine()
        with pytest.raises(ValueError, match="feature"):
            await engine.flip(
                class_="feature",
                scope_key="t-1:not_a_feature",
                actor_id="ops-1",
                reason="r",
                category="incident_response",
            )
        assert dh.records == []  # nothing flipped, nothing appended

    async def test_flip_without_decision_history_raises(self) -> None:
        engine = KillSwitchEngine(redis_client=_RecordingRedis([]), cache_ttl_s=60)
        with pytest.raises(RuntimeError, match="decision_history"):
            await engine.flip(
                class_="model",
                scope_key="tier1",
                actor_id="ops-1",
                reason="r",
                category="incident_response",
            )
