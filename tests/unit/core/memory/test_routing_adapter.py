"""Sprint 11.5b T8 — RoutingMemoryAdapter tests.

Tests the scratch→Redis / durable→PG routing, Redis-unavailable fallback,
write-bug no-fallback, read-after-recovery, and cross-tenant/cross-agent
scratch isolation invariants.
"""

import dataclasses
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa

from cognic_agentos.core.memory._context import MemoryHit, RedactionSpan, RegulatorErasureCommand
from cognic_agentos.core.memory._routing import RoutingMemoryAdapter
from cognic_agentos.core.memory.storage import MemoryBackendUnavailable, _memory_records
from tests.unit.core.memory._builders import SUBJECT, _scratch_record, _task_record


class _RedisStub:
    """Fake MemoryAdapter conformer for the Redis adapter slot.

    unreachable=True → put/get raise MemoryBackendUnavailable(unreachable=True)
    writebug=True    → put raises MemoryBackendUnavailable(unreachable=False)
    otherwise        → stores records in-memory, get returns None (miss).
    """

    def __init__(self, *, unreachable: bool = False, writebug: bool = False) -> None:
        self.unreachable = unreachable
        self.writebug = writebug
        self.store: dict[uuid.UUID, object] = {}

    async def put(self, record):
        if self.unreachable:
            raise MemoryBackendUnavailable("unreachable", unreachable=True)
        if self.writebug:
            raise MemoryBackendUnavailable("write failed: ValueError", unreachable=False)
        rid = uuid.uuid4()
        self.store[rid] = record
        return rid

    async def get(self, *, tenant_id, agent_id, subject, tier, key=None, block_kind=None):
        if self.unreachable:
            raise MemoryBackendUnavailable("unreachable", unreachable=True)
        return None  # default: miss (real Redis read tested in storage suite)

    # Remaining MemoryAdapter methods — delegate to pg_adapter in routing, so stubs here.
    async def list_for_subject(self, *, tenant_id, agent_id, subject):
        raise NotImplementedError

    async def list_blocks(self, *, tenant_id, agent_id, subject):
        raise NotImplementedError

    async def upsert_block(self, record):
        raise NotImplementedError

    async def tombstone_record(self, **kw):
        raise NotImplementedError

    async def purge_record(self, **kw):
        raise NotImplementedError

    async def purge_expired(self, *, tombstone_window_s):
        raise NotImplementedError

    async def redact_record(self, **kw):
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Basic routing: scratch → Redis, durable → PG
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scratch_routes_to_redis_when_available(pg_adapter):
    redis = _RedisStub()
    routing = RoutingMemoryAdapter(redis_adapter=redis, pg_adapter=pg_adapter, scratch_ttl_s=3600)
    await routing.put(_scratch_record(value="v", key="k"))
    assert len(redis.store) == 1  # went to Redis, not PG


@pytest.mark.asyncio
async def test_scratch_falls_back_to_pg_when_redis_unavailable(pg_adapter, engine):
    routing = RoutingMemoryAdapter(
        redis_adapter=_RedisStub(unreachable=True),
        pg_adapter=pg_adapter,
        scratch_ttl_s=3600,
    )
    await routing.put(_scratch_record(value="v", key="k"))
    async with engine.connect() as c:
        rows = (
            await c.execute(sa.select(_memory_records).where(_memory_records.c.tier == "scratch"))
        ).all()
    assert len(rows) == 1 and rows[0].retention_until is not None  # PG fallback with retention


@pytest.mark.asyncio
async def test_redis_write_bug_does_NOT_fall_back_to_pg(pg_adapter, engine):
    routing = RoutingMemoryAdapter(
        redis_adapter=_RedisStub(writebug=True),
        pg_adapter=pg_adapter,
        scratch_ttl_s=3600,
    )
    with pytest.raises(MemoryBackendUnavailable):  # fail-closed, NOT fallback
        await routing.put(_scratch_record(value="v", key="k"))
    async with engine.connect() as c:
        rows = (
            await c.execute(sa.select(_memory_records).where(_memory_records.c.tier == "scratch"))
        ).all()
    assert rows == []  # NOTHING persisted to PG


@pytest.mark.asyncio
async def test_durable_routes_straight_to_pg(pg_adapter):
    routing = RoutingMemoryAdapter(
        redis_adapter=_RedisStub(), pg_adapter=pg_adapter, scratch_ttl_s=3600
    )
    rid = await routing.put(_task_record(value="v", key="k"))  # task → PG.put
    hit = await routing.get(
        tenant_id="t1",
        agent_id="kyc",
        subject=SUBJECT,
        tier="task",
        key="k",
    )
    assert hit is not None and hit.record_id == rid


# ---------------------------------------------------------------------------
# Scratch read: Redis-first, then PG on available-miss; Redis hit wins
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scratch_read_consults_pg_fallback_on_redis_available_miss(pg_adapter):
    """A fallback row written to PG during a PAST outage stays readable after
    Redis recovers (available but misses). This is the read-after-recovery
    stateful sequence."""
    await pg_adapter.put_scratch_fallback(
        _scratch_record(value="from-outage", key="k"),
        retention_until=datetime.now(UTC) + timedelta(hours=1),
    )
    routing = RoutingMemoryAdapter(
        redis_adapter=_RedisStub(),  # available, but returns None (miss)
        pg_adapter=pg_adapter,
        scratch_ttl_s=3600,
    )
    hit = await routing.get(
        tenant_id="t1",
        agent_id="kyc",
        subject=SUBJECT,
        tier="scratch",
        key="k",
    )
    assert hit is not None and hit.value == "from-outage"  # Redis available+miss => PG fallback


@pytest.mark.asyncio
async def test_scratch_redis_hit_preferred_over_pg_fallback(pg_adapter):
    """Both a live Redis hit AND a PG fallback row exist for the same key —
    Redis WINS (PG not consulted further). Locked routing preference."""
    await pg_adapter.put_scratch_fallback(
        _scratch_record(value="pg-stale", key="k"),
        retention_until=datetime.now(UTC) + timedelta(hours=1),
    )

    class _HitRedis:
        async def put(self, record):
            return uuid.uuid4()

        async def get(self, *, tenant_id, agent_id, subject, tier, key=None, block_kind=None):
            return MemoryHit(
                record_id=uuid.uuid4(),
                value="redis-fresh",
                tier="scratch",
                data_classes=("public",),
                purpose="customer_support",
                created_at=datetime.now(UTC),
            )

        async def list_for_subject(self, **kw):
            raise NotImplementedError

        async def list_blocks(self, **kw):
            raise NotImplementedError

        async def upsert_block(self, record):
            raise NotImplementedError

        async def tombstone_record(self, **kw):
            raise NotImplementedError

        async def purge_record(self, **kw):
            raise NotImplementedError

        async def purge_expired(self, *, tombstone_window_s):
            raise NotImplementedError

        async def redact_record(self, **kw):
            raise NotImplementedError

    routing = RoutingMemoryAdapter(
        redis_adapter=_HitRedis(), pg_adapter=pg_adapter, scratch_ttl_s=3600
    )
    hit = await routing.get(
        tenant_id="t1",
        agent_id="kyc",
        subject=SUBJECT,
        tier="scratch",
        key="k",
    )
    assert hit is not None and hit.value == "redis-fresh"  # locked: Redis hit BEFORE PG fallback


# ---------------------------------------------------------------------------
# REAL RedisMemoryAdapter get() error wrapping (P1 #1 regression)
#
# The _RedisStub above PRE-WRAPS its get() error into MemoryBackendUnavailable,
# which masks whether the *real* RedisMemoryAdapter.get() wraps a raw client
# error at all.  These two pin the production path: a raw client error from
# redis .get() MUST surface as MemoryBackendUnavailable (with the right
# `unreachable` flag) so the routing fallback works — a raw ConnectionError
# would bypass the routing layer (it only catches MemoryBackendUnavailable).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_real_redis_get_connectionerror_falls_back_to_pg(pg_adapter):
    """ConnectionError from the redis client on get() → RedisMemoryAdapter wraps
    it as MemoryBackendUnavailable(unreachable=True) → routing falls back to the
    PG scratch row written during the outage."""
    from cognic_agentos.core.memory.storage import RedisMemoryAdapter

    await pg_adapter.put_scratch_fallback(
        _scratch_record(value="from-outage", key="k"),
        retention_until=datetime.now(UTC) + timedelta(hours=1),
    )

    class _ConnErrRedis:
        async def set(self, key, value, **kw):  # pragma: no cover - not exercised
            return True

        async def get(self, key):
            raise ConnectionError("redis down")

    routing = RoutingMemoryAdapter(
        redis_adapter=RedisMemoryAdapter(redis_client=_ConnErrRedis(), scratch_ttl_s=3600),
        pg_adapter=pg_adapter,
        scratch_ttl_s=3600,
    )
    hit = await routing.get(
        tenant_id="t1",
        agent_id="kyc",
        subject=SUBJECT,
        tier="scratch",
        key="k",
    )
    # ConnectionError → unreachable=True → PG fallback consulted.
    assert hit is not None and hit.value == "from-outage"


@pytest.mark.asyncio
async def test_real_redis_get_readbug_propagates_no_fallback(pg_adapter):
    """RuntimeError from the redis client on get() is a READ BUG —
    RedisMemoryAdapter wraps it as MemoryBackendUnavailable(unreachable=False)
    and routing PROPAGATES it (does NOT silently fall back to the PG row that
    exists for the same key). A read bug must not be masked as an outage."""
    from cognic_agentos.core.memory.storage import RedisMemoryAdapter

    # A PG fallback row exists — its presence proves the propagate path does
    # NOT consult PG (otherwise this value would be returned instead of raising).
    await pg_adapter.put_scratch_fallback(
        _scratch_record(value="should-not-be-read", key="k"),
        retention_until=datetime.now(UTC) + timedelta(hours=1),
    )

    class _ReadBugRedis:
        async def set(self, key, value, **kw):  # pragma: no cover - not exercised
            return True

        async def get(self, key):
            raise RuntimeError("bad data shape")

    routing = RoutingMemoryAdapter(
        redis_adapter=RedisMemoryAdapter(redis_client=_ReadBugRedis(), scratch_ttl_s=3600),
        pg_adapter=pg_adapter,
        scratch_ttl_s=3600,
    )
    with pytest.raises(MemoryBackendUnavailable) as excinfo:
        await routing.get(
            tenant_id="t1",
            agent_id="kyc",
            subject=SUBJECT,
            tier="scratch",
            key="k",
        )
    assert excinfo.value.unreachable is False  # read bug, NOT an outage


# ---------------------------------------------------------------------------
# Cross-tenant / cross-agent scratch isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scratch_key_no_cross_tenant_collision(engine, pg_adapter):
    """Two records with the SAME logical key but DIFFERENT tenant_id must be
    stored under DIFFERENT Redis deterministic keys — no overwrite."""
    from cognic_agentos.core.memory.storage import RedisMemoryAdapter

    class _TracingRedis:
        def __init__(self) -> None:
            self.writes: list[str] = []
            self.store: dict[str, bytes] = {}

        async def set(self, key, value, **kw):
            self.writes.append(key)
            self.store[key] = value
            return True

        async def get(self, key):
            return self.store.get(key)

    redis = _TracingRedis()
    adapter = RedisMemoryAdapter(redis_client=redis, scratch_ttl_s=3600)

    rec_a = dataclasses.replace(_scratch_record(value="tenant-a", tenant_id="tenantA"), key="k")
    rec_b = dataclasses.replace(_scratch_record(value="tenant-b", tenant_id="tenantB"), key="k")
    await adapter.put(rec_a)
    await adapter.put(rec_b)

    # Two DIFFERENT keys were written — no collision.
    assert len(redis.writes) == 2
    assert redis.writes[0] != redis.writes[1], "Cross-tenant scratch keys must differ"

    # A get for tenant A never returns tenant B's value.
    hit_a = await adapter.get(
        tenant_id="tenantA",
        agent_id="kyc",
        subject=SUBJECT,
        tier="scratch",
        key="k",
    )
    hit_b = await adapter.get(
        tenant_id="tenantB",
        agent_id="kyc",
        subject=SUBJECT,
        tier="scratch",
        key="k",
    )
    assert hit_a is not None and hit_a.value == "tenant-a"
    assert hit_b is not None and hit_b.value == "tenant-b"


@pytest.mark.asyncio
async def test_scratch_key_no_cross_agent_collision(engine, pg_adapter):
    """Two records with the SAME logical key but DIFFERENT agent_id must be
    stored under DIFFERENT Redis deterministic keys — no overwrite."""
    from cognic_agentos.core.memory.storage import RedisMemoryAdapter

    class _TracingRedis:
        def __init__(self) -> None:
            self.writes: list[str] = []
            self.store: dict[str, bytes] = {}

        async def set(self, key, value, **kw):
            self.writes.append(key)
            self.store[key] = value
            return True

        async def get(self, key):
            return self.store.get(key)

    redis = _TracingRedis()
    adapter = RedisMemoryAdapter(redis_client=redis, scratch_ttl_s=3600)

    rec_agent1 = dataclasses.replace(
        _scratch_record(value="agent1-val"), key="k", agent_id="agent1"
    )
    rec_agent2 = dataclasses.replace(
        _scratch_record(value="agent2-val"), key="k", agent_id="agent2"
    )
    await adapter.put(rec_agent1)
    await adapter.put(rec_agent2)

    # Two DIFFERENT keys were written — no collision.
    assert len(redis.writes) == 2
    assert redis.writes[0] != redis.writes[1], "Cross-agent scratch keys must differ"

    # A get for agent1 never returns agent2's value.
    hit_1 = await adapter.get(
        tenant_id="t1",
        agent_id="agent1",
        subject=SUBJECT,
        tier="scratch",
        key="k",
    )
    hit_2 = await adapter.get(
        tenant_id="t1",
        agent_id="agent2",
        subject=SUBJECT,
        tier="scratch",
        key="k",
    )
    assert hit_1 is not None and hit_1.value == "agent1-val"
    assert hit_2 is not None and hit_2.value == "agent2-val"


@pytest.mark.asyncio
async def test_scratch_key_no_delimiter_collision():
    """Subject/key pairs that COLLIDE under a raw ':'-join must map to DISTINCT
    Redis entries.  (subject human:cust:7, key 'foo') and (subject human:cust,
    key '7:foo') both ':'-join to memory:scratch:t1:kyc:human:cust:7:foo — the
    hashed key schema keeps them separate so neither overwrites/reads the
    other's scratch value (cross-subject isolation)."""
    from cognic_agentos.core.memory.storage import RedisMemoryAdapter
    from cognic_agentos.core.memory.tiers import SubjectRef

    class _TracingRedis:
        def __init__(self) -> None:
            self.store: dict[str, bytes] = {}

        async def set(self, key, value, **kw):
            self.store[key] = value
            return True

        async def get(self, key):
            return self.store.get(key)

    redis = _TracingRedis()
    adapter = RedisMemoryAdapter(redis_client=redis, scratch_ttl_s=3600)

    subj_a = SubjectRef(kind="human", id="cust:7")  # canonical: human:cust:7
    subj_b = SubjectRef(kind="human", id="cust")  # canonical: human:cust
    rec_a = dataclasses.replace(_scratch_record(value="A"), subject=subj_a, key="foo")
    rec_b = dataclasses.replace(_scratch_record(value="B"), subject=subj_b, key="7:foo")
    await adapter.put(rec_a)
    await adapter.put(rec_b)

    # Two DISTINCT redis keys were written — no collision/overwrite.
    assert len(redis.store) == 2

    hit_a = await adapter.get(
        tenant_id="t1", agent_id="kyc", subject=subj_a, tier="scratch", key="foo"
    )
    hit_b = await adapter.get(
        tenant_id="t1", agent_id="kyc", subject=subj_b, tier="scratch", key="7:foo"
    )
    # Each reads back ITS OWN value — the join-collision would cross them.
    assert hit_a is not None and hit_a.value == "A"
    assert hit_b is not None and hit_b.value == "B"


@pytest.mark.asyncio
async def test_pg_fallback_cross_tenant_isolation(pg_adapter):
    """A PG fallback row for tenant A must NOT be returned when tenant B reads
    the same logical key."""
    # Write a PG fallback row for tenant A.
    await pg_adapter.put_scratch_fallback(
        dataclasses.replace(_scratch_record(value="tenant-a-secret", tenant_id="tenantA"), key="k"),
        retention_until=datetime.now(UTC) + timedelta(hours=1),
    )

    routing = RoutingMemoryAdapter(
        redis_adapter=_RedisStub(),  # available, returns None (miss)
        pg_adapter=pg_adapter,
        scratch_ttl_s=3600,
    )

    # Tenant A can read it.
    hit_a = await routing.get(
        tenant_id="tenantA",
        agent_id="kyc",
        subject=SUBJECT,
        tier="scratch",
        key="k",
    )
    assert hit_a is not None and hit_a.value == "tenant-a-secret"

    # Tenant B gets a miss — the row is invisible.
    hit_b = await routing.get(
        tenant_id="tenantB",
        agent_id="kyc",
        subject=SUBJECT,
        tier="scratch",
        key="k",
    )
    assert hit_b is None


@pytest.mark.asyncio
async def test_pg_fallback_cross_agent_isolation(pg_adapter):
    """A PG fallback row for agent1 must NOT be returned when agent2 reads
    the same logical key."""
    await pg_adapter.put_scratch_fallback(
        dataclasses.replace(_scratch_record(value="agent1-secret"), key="k", agent_id="agent1"),
        retention_until=datetime.now(UTC) + timedelta(hours=1),
    )

    routing = RoutingMemoryAdapter(
        redis_adapter=_RedisStub(),
        pg_adapter=pg_adapter,
        scratch_ttl_s=3600,
    )

    hit_1 = await routing.get(
        tenant_id="t1",
        agent_id="agent1",
        subject=SUBJECT,
        tier="scratch",
        key="k",
    )
    assert hit_1 is not None and hit_1.value == "agent1-secret"

    hit_2 = await routing.get(
        tenant_id="t1",
        agent_id="agent2",
        subject=SUBJECT,
        tier="scratch",
        key="k",
    )
    assert hit_2 is None


@pytest.mark.parametrize(
    "record",
    [
        dataclasses.replace(_scratch_record(value="v"), tier="task"),
        dataclasses.replace(_scratch_record(value="v"), block_kind="persona"),
        dataclasses.replace(_scratch_record(value="v"), key=None),
    ],
    ids=["non_scratch_tier", "block_shaped_scratch", "key_none_scratch"],
)
@pytest.mark.asyncio
async def test_put_scratch_fallback_refuses_wrong_shape_no_row_no_chain(
    record, pg_adapter, engine, decision_history_rows
):
    """put_scratch_fallback is the dedicated PG scratch primitive — a block-shaped
    or unkeyed record is refused with ValueError BEFORE any DB work: NO
    memory_records row and NO chain event (mirrors RedisMemoryAdapter.put)."""
    with pytest.raises(ValueError):
        await pg_adapter.put_scratch_fallback(
            record, retention_until=datetime.now(UTC) + timedelta(hours=1)
        )
    async with engine.connect() as c:
        rows = (await c.execute(sa.select(_memory_records))).all()
    assert rows == []  # no row inserted
    assert await decision_history_rows() == []  # no chain event emitted


@pytest.mark.asyncio
async def test_routing_delegates_passthrough_methods_to_pg():
    """The 7 non-put/get MemoryAdapter methods delegate verbatim to pg_adapter
    (durable + scratch-fallback rows live in PG; Redis self-expires via TTL).
    A spy pg records the call order; each delegator forwards its kwargs."""

    class _SpyPg:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def list_for_subject(self, **kw):
            self.calls.append("list_for_subject")
            return []

        async def list_blocks(self, **kw):
            self.calls.append("list_blocks")
            return []

        async def upsert_block(self, record):
            self.calls.append("upsert_block")
            return uuid.uuid4()

        async def tombstone_record(self, **kw):
            self.calls.append("tombstone_record")

        async def purge_record(self, **kw):
            self.calls.append("purge_record")

        async def purge_expired(self, *, tombstone_window_s):
            self.calls.append("purge_expired")
            return 3

        async def redact_record(self, **kw):
            self.calls.append("redact_record")
            return "receipt"

    spy = _SpyPg()
    routing = RoutingMemoryAdapter(
        redis_adapter=_RedisStub(),
        pg_adapter=spy,  # type: ignore[arg-type]  # duck-typed PG spy for the delegation pins
        scratch_ttl_s=3600,
    )
    rid = uuid.uuid4()
    await routing.list_for_subject(tenant_id="t1", agent_id="kyc", subject=SUBJECT)
    await routing.list_blocks(tenant_id="t1", agent_id="kyc", subject=SUBJECT)
    await routing.upsert_block(_scratch_record(value="x"))
    await routing.tombstone_record(
        tenant_id="t1", agent_id="kyc", record_id=rid, reason="user_request", actor_id="svc"
    )
    await routing.purge_record(
        tenant_id="t1",
        agent_id="kyc",
        record_id=rid,
        erasure_command=RegulatorErasureCommand(
            regulator_order_id="O", requester_scope="memory.regulator_erasure", subject_id="c1"
        ),
        actor_id="svc",
    )
    n = await routing.purge_expired(tombstone_window_s=30)
    await routing.redact_record(
        tenant_id="t1",
        agent_id="kyc",
        record_id=rid,
        span=RedactionSpan(path=("account", "number")),
        reason="pii_minimization",
        actor_id="svc",
    )
    assert spy.calls == [
        "list_for_subject",
        "list_blocks",
        "upsert_block",
        "tombstone_record",
        "purge_record",
        "purge_expired",
        "redact_record",
    ]
    assert n == 3
