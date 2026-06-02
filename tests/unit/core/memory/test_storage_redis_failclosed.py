import pytest

from cognic_agentos.core.memory.storage import MemoryBackendUnavailable, RedisMemoryAdapter
from tests.unit.core.memory._builders import _scratch_record


class _DeadRedis:
    async def set(self, *a, **k):
        raise ConnectionError("redis down")

    async def get(self, key):  # pragma: no cover
        raise ConnectionError("redis down")


async def test_scratch_write_fails_closed_when_redis_unreachable():
    adapter = RedisMemoryAdapter(redis_client=_DeadRedis(), scratch_ttl_s=3600)
    with pytest.raises(MemoryBackendUnavailable):
        await adapter.put(_scratch_record(value="ephemeral"))


def test_backend_unavailable_is_not_a_governance_refusal():
    # MemoryBackendUnavailable is an INFRA exception, NOT a MemoryRefusalReason value.
    from cognic_agentos.core.memory.tiers import MemoryOperationRefused

    assert not issubclass(MemoryBackendUnavailable, MemoryOperationRefused)
