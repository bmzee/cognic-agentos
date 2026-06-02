"""Sprint 11.5b T8 — RedisMemoryAdapter put→get envelope round-trip tests.

Pins that the deterministic scratch key carries the full MemoryHit envelope
so scratch recall can feed the purpose-matrix + memory.read emission.
"""

import dataclasses
import json
import uuid
from datetime import UTC, datetime

import pytest

from cognic_agentos.core.memory._context import MemoryWriteRecord
from cognic_agentos.core.memory.storage import MemoryBackendUnavailable, RedisMemoryAdapter
from cognic_agentos.core.memory.tiers import SubjectRef


class _KVRedis:
    """In-memory KV store duck-typing the redis async client used by RedisMemoryAdapter."""

    def __init__(self) -> None:
        self.store: dict[str, object] = {}

    async def set(self, key: str, value: object, **kw: object) -> bool:
        self.store[key] = value
        return True

    async def get(self, key: str) -> object:
        return self.store.get(key)


def _scratch_write(
    value: object,
    *,
    key: str,
    purpose: str = "customer_support",
    data_classes: tuple[str, ...] = ("public",),
) -> MemoryWriteRecord:
    """Build a scratch MemoryWriteRecord — avoids assuming builder signature."""
    return MemoryWriteRecord(
        tenant_id="t1",
        agent_id="kyc",
        actor_id="a1",
        subject=SubjectRef(kind="human", id="cust-7"),
        tier="scratch",
        purpose=purpose,
        data_classes=data_classes,
        value=value,
        request_id="memory-write-test",
        key=key,
    )


@pytest.mark.asyncio
async def test_redis_scratch_put_then_get_roundtrips_full_hit():
    """put() stores a JSON envelope; get() reconstructs a full MemoryHit with
    all fields needed by recall (record_id, value, tier, data_classes, purpose,
    created_at, block_kind)."""
    adapter = RedisMemoryAdapter(redis_client=_KVRedis(), scratch_ttl_s=3600)
    rid = await adapter.put(_scratch_write({"x": 1}, key="k"))
    hit = await adapter.get(
        tenant_id="t1",
        agent_id="kyc",
        subject=SubjectRef(kind="human", id="cust-7"),
        tier="scratch",
        key="k",
    )
    assert hit is not None
    # record_id is the one returned by put()
    assert hit.record_id == rid
    # value round-trips
    assert hit.value == {"x": 1}
    # tier preserved
    assert hit.tier == "scratch"
    # data_classes preserved as tuple
    assert hit.data_classes == ("public",)
    # purpose preserved — required for recall purpose-matrix
    assert hit.purpose == "customer_support"
    # created_at is a datetime instance
    assert isinstance(hit.created_at, datetime)
    # block_kind is None for keyed scratch records
    assert hit.block_kind is None


@pytest.mark.asyncio
async def test_redis_scratch_get_miss_returns_none():
    """get() for a key that was never written returns None (not an exception)."""
    adapter = RedisMemoryAdapter(redis_client=_KVRedis(), scratch_ttl_s=3600)
    hit = await adapter.get(
        tenant_id="t1",
        agent_id="kyc",
        subject=SubjectRef(kind="human", id="cust-7"),
        tier="scratch",
        key="absent",
    )
    assert hit is None


class _PlantedRedis:
    """Returns a fixed planted raw value from get() regardless of key — used to
    feed a deliberately-malformed envelope into RedisMemoryAdapter.get()."""

    def __init__(self, raw: object) -> None:
        self._raw = raw

    async def set(self, key: str, value: object, **kw: object) -> bool:  # pragma: no cover
        return True

    async def get(self, key: str) -> object:
        return self._raw


@pytest.mark.asyncio
async def test_redis_scratch_get_malformed_json_fails_closed():
    """A non-JSON envelope from redis is a READ BUG — get() raises
    MemoryBackendUnavailable(unreachable=False) so routing PROPAGATES (no raw
    json exception, no PG fallback), never an invalid MemoryHit."""
    adapter = RedisMemoryAdapter(redis_client=_PlantedRedis(b"not-json{"), scratch_ttl_s=3600)
    with pytest.raises(MemoryBackendUnavailable) as excinfo:
        await adapter.get(
            tenant_id="t1",
            agent_id="kyc",
            subject=SubjectRef(kind="human", id="cust-7"),
            tier="scratch",
            key="k",
        )
    assert excinfo.value.unreachable is False  # read bug, NOT an outage


@pytest.mark.asyncio
async def test_redis_scratch_get_wrong_tier_envelope_fails_closed():
    """A well-formed JSON envelope whose ``tier`` is NOT 'scratch' is corrupt —
    get() must NOT reconstruct a MemoryHit with the wrong tier; it fails closed
    with MemoryBackendUnavailable(unreachable=False)."""
    corrupt = json.dumps(
        {
            "record_id": str(uuid.uuid4()),
            "value": "v",
            "tier": "task",  # corrupt — scratch envelopes are always tier=scratch
            "data_classes": ["public"],
            "purpose": "customer_support",
            "block_kind": None,
            "created_at": datetime.now(UTC).isoformat(),
        }
    ).encode()
    adapter = RedisMemoryAdapter(redis_client=_PlantedRedis(corrupt), scratch_ttl_s=3600)
    with pytest.raises(MemoryBackendUnavailable) as excinfo:
        await adapter.get(
            tenant_id="t1",
            agent_id="kyc",
            subject=SubjectRef(kind="human", id="cust-7"),
            tier="scratch",
            key="k",
        )
    assert excinfo.value.unreachable is False  # corrupt shape, NOT an outage


@pytest.mark.asyncio
async def test_redis_scratch_get_non_str_bytes_raw_fails_closed() -> None:
    """A redis client returning a non-str/non-bytes raw value (e.g. an int) is a
    READ BUG — get() raises MemoryBackendUnavailable(unreachable=False), NOT a
    raw AttributeError leaking from ``.decode()`` past the typed block."""
    adapter = RedisMemoryAdapter(redis_client=_PlantedRedis(123), scratch_ttl_s=3600)
    with pytest.raises(MemoryBackendUnavailable) as excinfo:
        await adapter.get(
            tenant_id="t1",
            agent_id="kyc",
            subject=SubjectRef(kind="human", id="cust-7"),
            tier="scratch",
            key="k",
        )
    assert excinfo.value.unreachable is False  # non-str/bytes raw, NOT an outage


def _scratch_envelope(**overrides: object) -> bytes:
    """Build a well-formed scratch envelope, optionally overriding one field to
    a bad shape (used to pin per-field validation)."""
    env: dict[str, object] = {
        "record_id": str(uuid.uuid4()),
        "value": "v",
        "tier": "scratch",
        "data_classes": ["public"],
        "purpose": "customer_support",
        "block_kind": None,
        "created_at": datetime.now(UTC).isoformat(),
    }
    env.update(overrides)
    return json.dumps(env).encode()


@pytest.mark.parametrize(
    "overrides",
    [
        {"data_classes": "public"},  # a string, not a list-of-strings
        {"purpose": 123},  # non-string purpose
        {"block_kind": "persona"},  # non-None block_kind on a keyed scratch record
        {"record_id": 123},  # non-string record_id
        {"created_at": 123},  # non-string created_at
    ],
    ids=[
        "data_classes_as_string",
        "non_string_purpose",
        "non_null_block_kind",
        "non_string_record_id",
        "non_string_created_at",
    ],
)
@pytest.mark.asyncio
async def test_redis_scratch_get_invalid_field_shape_fails_closed(
    overrides: dict[str, object],
) -> None:
    """Envelope fields that survive json.loads but violate the MemoryHit shape
    fail closed as a READ BUG (unreachable=False), never an invalid MemoryHit:
    ``data_classes`` as a string would ``tuple()`` into single chars; ``purpose``
    must be a string; a keyed scratch record must carry ``block_kind is None``."""
    adapter = RedisMemoryAdapter(
        redis_client=_PlantedRedis(_scratch_envelope(**overrides)), scratch_ttl_s=3600
    )
    with pytest.raises(MemoryBackendUnavailable) as excinfo:
        await adapter.get(
            tenant_id="t1",
            agent_id="kyc",
            subject=SubjectRef(kind="human", id="cust-7"),
            tier="scratch",
            key="k",
        )
    assert excinfo.value.unreachable is False  # shape bug, NOT an outage


@pytest.mark.asyncio
async def test_redis_scratch_get_non_dict_envelope_fails_closed() -> None:
    """A well-formed JSON value that is NOT an object (e.g. a list) fails closed
    as a read bug (unreachable=False) — it is not a valid scratch envelope."""
    adapter = RedisMemoryAdapter(redis_client=_PlantedRedis(b"[1, 2, 3]"), scratch_ttl_s=3600)
    with pytest.raises(MemoryBackendUnavailable) as excinfo:
        await adapter.get(
            tenant_id="t1",
            agent_id="kyc",
            subject=SubjectRef(kind="human", id="cust-7"),
            tier="scratch",
            key="k",
        )
    assert excinfo.value.unreachable is False


@pytest.mark.asyncio
async def test_redis_scratch_get_str_raw_value_reconstructs_hit() -> None:
    """A redis client returning a str (not bytes) envelope is parsed via the str
    branch (no ``.decode()``) and reconstructs a valid MemoryHit."""

    class _StrRedis:
        async def set(self, key: str, value: object, **kw: object) -> bool:  # pragma: no cover
            return True

        async def get(self, key: str) -> object:
            return _scratch_envelope().decode()  # a str, not bytes

    adapter = RedisMemoryAdapter(redis_client=_StrRedis(), scratch_ttl_s=3600)
    hit = await adapter.get(
        tenant_id="t1",
        agent_id="kyc",
        subject=SubjectRef(kind="human", id="cust-7"),
        tier="scratch",
        key="k",
    )
    assert hit is not None and hit.tier == "scratch"


class _SetTracingRedis:
    """Records whether .set() was called — used to prove put()'s scratch-only
    guards fire BEFORE any redis write."""

    def __init__(self) -> None:
        self.set_called = False

    async def set(self, key: str, value: object, **kw: object) -> bool:
        self.set_called = True
        return True

    async def get(self, key: str) -> object:  # pragma: no cover - not exercised
        return None


@pytest.mark.parametrize(
    "record",
    [
        dataclasses.replace(_scratch_write("v", key="k"), tier="task"),
        dataclasses.replace(_scratch_write("v", key="k"), block_kind="persona"),
        dataclasses.replace(_scratch_write("v", key="k"), key=None),
    ],
    ids=["non_scratch_tier", "block_shaped_scratch", "key_none_scratch"],
)
@pytest.mark.asyncio
async def test_redis_put_refuses_wrong_shape_before_set(record: MemoryWriteRecord) -> None:
    """RedisMemoryAdapter.put() is scratch-only + keyed-only — a mis-injected
    adapter must NOT silently persist a non-scratch / block-shaped / unkeyed
    record (which would mint a record id with no PG row, no chain row, or an
    unreadable scratch envelope). The ValueError guard fires BEFORE redis .set()."""
    redis = _SetTracingRedis()
    adapter = RedisMemoryAdapter(redis_client=redis, scratch_ttl_s=3600)
    with pytest.raises(ValueError):
        await adapter.put(record)
    assert redis.set_called is False  # refused before any redis write
