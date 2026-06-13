"""Sprint 13.6b T4 — QuotaEngine satisfies the scheduler QuotaInterrogator seam.

Proves the ADR-022 integration contract three ways: (a) structural
``isinstance``; (b) behavioral drive THROUGH a ``QuotaInterrogator``-annotated
variable (so signature drift fails BOTH mypy + runtime); (c) a real
``SchedulerEngine`` constructed with ``quota_interrogator=QuotaEngine`` admits
under-quota work, refuses ``refused_quota_exhausted`` over-quota, and releases
the reservation on a terminal transition. NO ``core/scheduler/*`` edit — the
seam contract is already satisfied; this task PROVES it. Production DI binding
of the engine stays the composition-root sprint.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.emergency.quotas import (
    QuotaEngine,
    _reserved_tenant_key,
)
from cognic_agentos.core.scheduler._seams import QuotaInterrogator

_CLOCK = lambda: datetime(2026, 6, 13, 12, 0, tzinfo=UTC)  # noqa: E731
_WINDOW = "20260613"


class _FakeQuotaRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def get(self, key: str) -> Any:
        return self.store.get(key)

    async def set(self, key: str, value: Any, **kwargs: Any) -> Any:
        self.store[key] = value

    async def incrby(self, key: str, amount: int) -> int:
        new = int(self.store.get(key, "0")) + amount
        self.store[key] = str(new)
        return new

    async def decrby(self, key: str, amount: int) -> int:
        new = int(self.store.get(key, "0")) - amount
        self.store[key] = str(new)
        return new

    async def getdel(self, key: str) -> Any:
        return self.store.pop(key, None)

    async def expire(self, key: str, seconds: int) -> Any:
        return None


def _quota_engine(redis: _FakeQuotaRedis, *, limit: int) -> QuotaEngine:
    settings = build_settings_without_env_file().model_copy(
        update={
            "quota_tokens_per_tenant_per_day": limit,
            "quota_tokens_per_pack_per_day": limit,
        }
    )
    return QuotaEngine(redis_client=redis, settings=settings, clock=_CLOCK)


class TestStructuralConformance:
    def test_isinstance_quota_interrogator(self) -> None:
        assert isinstance(_quota_engine(_FakeQuotaRedis(), limit=1000), QuotaInterrogator)


class TestThroughTheProtocolType:
    async def test_would_admit_and_release_via_protocol_annotated_var(self) -> None:
        # The annotation forces mypy to check the call signatures against the
        # Protocol; the runtime asserts the behavior. Signature drift on
        # QuotaEngine breaks BOTH.
        redis = _FakeQuotaRedis()
        qi: QuotaInterrogator = _quota_engine(redis, limit=1000)
        tid = uuid.uuid4()
        assert (
            await qi.would_admit(task_id=tid, tenant_id="t1", pack_id="p1", estimated_tokens=400)
            is True
        )
        assert redis.store[_reserved_tenant_key("t1", _WINDOW)] == "400"
        await qi.release_reservation(tid)
        assert redis.store[_reserved_tenant_key("t1", _WINDOW)] == "0"


# ---------------------------------------------------------------------------
# (c) in-situ SchedulerEngine over a migrated DB (the ADR-022 integration).
# ---------------------------------------------------------------------------


class _InactiveKillSwitch:
    async def is_active(self, *, tenant_id: str, pack_id: str) -> bool:
        return False


class _InstalledPackState:
    async def is_installed(self, *, tenant_id: str, pack_id: str) -> bool:
        return True


async def _mk_migrated_db(tmp_path: Any) -> Any:
    import asyncio as _asyncio

    from alembic import command
    from sqlalchemy.ext.asyncio import create_async_engine

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path}/quota-seam.db"
    cfg = make_alembic_config(url)
    await _asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


def _submit_input(tokens: int) -> Any:
    from cognic_agentos.core.scheduler._types import SubmitInput, TaskActor

    return SubmitInput(
        tenant_id="t-1",
        pack_id="pack-x",
        actor=TaskActor(subject="svc-a", tenant_id="t-1", actor_type="service"),
        class_="interactive",
        pack_kind="tool",
        pack_risk_tier="internal_write",  # safe tier — no approval intercept
        requested_estimated_tokens=tokens,
    )


def _mk_engine(db: Any, quota: QuotaEngine) -> Any:
    from cognic_agentos.core.scheduler.engine import SchedulerEngine
    from cognic_agentos.core.scheduler.queue import ConcurrencyCaps
    from cognic_agentos.core.scheduler.storage import SchedulerStorage

    return SchedulerEngine(
        storage=SchedulerStorage(db),
        caps=ConcurrencyCaps(
            per_tenant_interactive=4, per_tenant_background=4, per_pack=4, per_actor=4
        ),
        class_settings={"interactive": (4, 0.200), "background": (4, 5.0)},
        quota_interrogator=quota,
        kill_switch_interrogator=_InactiveKillSwitch(),
        pack_state_interrogator=_InstalledPackState(),
    )


class TestInSituSchedulerEngine:
    async def test_under_quota_admits_over_quota_refuses(self, tmp_path: Any) -> None:
        db = await _mk_migrated_db(tmp_path)
        redis = _FakeQuotaRedis()
        engine = _mk_engine(db, _quota_engine(redis, limit=600))
        # First submit (500 ≤ 600) admits.
        d1 = await engine.submit(submit_input=_submit_input(500), request_id="req-1")
        assert d1.outcome == "accepted_immediate"
        assert redis.store[_reserved_tenant_key("t-1", _WINDOW)] == "500"
        # Second submit (500 + 500 = 1000 > 600) refuses; reservation rolled back.
        d2 = await engine.submit(submit_input=_submit_input(500), request_id="req-2")
        assert d2.outcome == "refused_quota_exhausted"
        assert d2.task_id is None
        assert redis.store[_reserved_tenant_key("t-1", _WINDOW)] == "500"  # rolled back to 500
        await db.dispose()

    async def test_terminal_transition_releases_reservation(self, tmp_path: Any) -> None:
        db = await _mk_migrated_db(tmp_path)
        redis = _FakeQuotaRedis()
        engine = _mk_engine(db, _quota_engine(redis, limit=600))
        d1 = await engine.submit(submit_input=_submit_input(500), request_id="req-1")
        assert d1.outcome == "accepted_immediate"
        # pending → running → completed; the terminal transition
        # (_transition_terminal) calls release_reservation → DECRBY.
        # AdmissionDecision.task_id is a str; the lifecycle takes a uuid.UUID.
        task_id = uuid.UUID(d1.task_id)
        await engine.mark_running(task_id, request_id="req-1-start")
        await engine.complete(task_id, request_id="req-1-complete")
        assert redis.store[_reserved_tenant_key("t-1", _WINDOW)] == "0"
        # With the reservation released, a fresh 500-token submit admits again.
        d2 = await engine.submit(submit_input=_submit_input(500), request_id="req-2")
        assert d2.outcome == "accepted_immediate"
        await db.dispose()
