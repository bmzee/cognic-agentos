"""Sprint 11.5a Z1a — RedisMemoryAdapter coverage repair.

Promoting ``core/memory/storage.py`` to the CC gate (95/90 floor) requires the
``RedisMemoryAdapter`` surfaces that ``test_storage_redis_failclosed.py`` does
not reach: the ``put()`` SUCCESS path, the non-connection-error fail-closed
branch (``_is_redis_unavailable`` import-probe fallthrough + the
``write failed: <Type>`` detail), and the four deferred-stub
``NotImplementedError`` raises (scratch recall → 11.5b; blocks are
``long_term`` → ``PostgresMemoryAdapter``). Per
``feedback_verify_promotion_meets_floor_at_promotion_time`` these negative-path
tests land in the SAME commit as the gate promotion.
"""

import sys
import uuid

import pytest

from cognic_agentos.core.memory._context import RedactionSpan, RegulatorErasureCommand
from cognic_agentos.core.memory.storage import (
    MemoryBackendUnavailable,
    RedisMemoryAdapter,
    _is_redis_unavailable,
)
from tests.unit.core.memory._builders import SUBJECT, _scratch_record


class _OkRedis:
    """A working scratch backend — records the ``set()`` call and succeeds.

    Sprint 11.5b: also implements ``get()`` so the deterministic-key read
    path can be exercised (returns ``None`` — a cache miss).
    """

    def __init__(self) -> None:
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    async def set(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return True

    async def get(self, key):
        return None  # miss — no data stored in this stub


class _NonConnRedis:
    """``set()`` raises a NON-connection, NON-redis error, so
    ``_is_redis_unavailable`` falls through to the redis import-probe and the
    ``write failed: <Type>`` detail branch (NOT the ``unreachable`` branch)."""

    async def set(self, *args, **kwargs):
        raise RuntimeError("not a connection error")

    async def get(self, key):  # pragma: no cover
        return None


async def test_scratch_put_success_returns_record_id_and_applies_ttl():
    # put() SUCCESS path: a working redis backend stores the value under a
    # TTL'd key and put() returns the generated record id.
    redis = _OkRedis()
    adapter = RedisMemoryAdapter(redis_client=redis, scratch_ttl_s=900)
    rid = await adapter.put(_scratch_record(value="ephemeral"))
    assert rid is not None
    assert len(redis.calls) == 1
    _args, kwargs = redis.calls[0]
    assert kwargs.get("ex") == 900  # the scratch TTL is applied to the redis key


async def test_scratch_put_non_connection_error_still_fails_closed():
    # A non-connection backend error ALSO fails closed — exercises the
    # _is_redis_unavailable redis-import-probe fallthrough + the "write failed"
    # detail branch (distinct from the "unreachable" connection-error branch).
    adapter = RedisMemoryAdapter(redis_client=_NonConnRedis(), scratch_ttl_s=3600)
    with pytest.raises(MemoryBackendUnavailable) as ei:
        await adapter.put(_scratch_record(value="x"))
    detail = str(ei.value)
    assert "write failed" in detail
    assert "RuntimeError" in detail


async def test_redis_block_surfaces_are_deferred_notimplemented():
    # ``upsert_block`` + ``list_blocks`` are long_term-only (blocks are
    # long_term → PostgresMemoryAdapter); ``list_for_subject`` is also deferred
    # for Redis (enumerate is always PG). ``get`` for non-scratch raises
    # NotImplementedError — task/long_term reads go to PostgresMemoryAdapter.
    adapter = RedisMemoryAdapter(redis_client=_OkRedis(), scratch_ttl_s=3600)
    # non-scratch get → NotImplementedError
    with pytest.raises(NotImplementedError):
        await adapter.get(tenant_id="t1", agent_id="kyc", subject=SUBJECT, tier="task")
    with pytest.raises(NotImplementedError):
        await adapter.list_for_subject(tenant_id="t1", agent_id="kyc", subject=SUBJECT)
    with pytest.raises(NotImplementedError):
        await adapter.upsert_block(_scratch_record(value="x"))
    with pytest.raises(NotImplementedError):
        await adapter.list_blocks(tenant_id="t1", agent_id="kyc", subject=SUBJECT)


async def test_redis_erasure_surfaces_are_deferred_notimplemented():
    # The 4 lifecycle/erasure methods are unsupported on Redis (scratch records
    # self-expire via TTL; durable erasure is PostgresMemoryAdapter): each of
    # tombstone_record / purge_record / purge_expired / redact_record raises
    # NotImplementedError at entry (Sprint 11.5b grew the Protocol to 9 methods).
    adapter = RedisMemoryAdapter(redis_client=_OkRedis(), scratch_ttl_s=3600)
    rid = uuid.uuid4()
    with pytest.raises(NotImplementedError):
        await adapter.tombstone_record(
            tenant_id="t1", agent_id="kyc", record_id=rid, reason="user_request", actor_id="svc"
        )
    with pytest.raises(NotImplementedError):
        await adapter.purge_record(
            tenant_id="t1",
            agent_id="kyc",
            record_id=rid,
            erasure_command=RegulatorErasureCommand(
                regulator_order_id="O",
                requester_scope="memory.regulator_erasure",
                subject_id="c1",
            ),
            actor_id="svc",
        )
    with pytest.raises(NotImplementedError):
        await adapter.purge_expired(tombstone_window_s=30)
    with pytest.raises(NotImplementedError):
        await adapter.redact_record(
            tenant_id="t1",
            agent_id="kyc",
            record_id=rid,
            span=RedactionSpan(path=("account", "number")),
            reason="pii_minimization",
            actor_id="svc",
        )


def test_is_redis_unavailable_returns_false_when_redis_exceptions_unimportable(monkeypatch):
    # When ``from redis.exceptions import RedisError`` raises ImportError (the
    # redis package is not installed — the [adapters] extra is absent), the
    # import-probe ImportError branch returns False for a non-builtin-connection
    # error. Setting sys.modules["redis.exceptions"] = None forces the ImportError.
    monkeypatch.setitem(sys.modules, "redis.exceptions", None)
    assert _is_redis_unavailable(RuntimeError("not a connection error")) is False
