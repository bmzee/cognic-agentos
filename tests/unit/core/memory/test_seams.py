import pytest

from cognic_agentos.core.memory._seams import (
    MemoryKillSwitchInterrogator,
    _NullMemoryKillSwitchInterrogator,
)


class _Inactive:
    async def is_write_frozen(self, *, tenant_id: str) -> bool:
        return False


def test_inactive_conformer_structurally_satisfies_protocol():
    assert isinstance(_Inactive(), MemoryKillSwitchInterrogator)


async def test_null_sentinel_fails_loud():
    with pytest.raises(NotImplementedError):
        await _NullMemoryKillSwitchInterrogator().is_write_frozen(tenant_id="t1")
