import pytest
from pydantic import ValidationError

from cognic_agentos.core.config import Settings


def test_memory_settings_have_positive_defaults():
    s = Settings()
    assert s.memory_block_max_bytes > 0
    assert s.memory_scratch_ttl_s > 0
    assert s.memory_tombstone_window_s > 0


def test_memory_reaper_interval_default_and_bounds():
    s = Settings()
    assert s.memory_reaper_interval_s == 300  # mirrors sandbox_reaper_interval_s
    assert s.memory_kill_switch_cache_ttl_s == 60  # the fail-closed grace ceiling


def test_kill_switch_cache_ttl_capped_at_60_and_reaper_positive():
    with pytest.raises(ValidationError):
        Settings(memory_kill_switch_cache_ttl_s=120)  # locked: <= 60 (le=60)
    with pytest.raises(ValidationError):
        Settings(memory_reaper_interval_s=0)  # gt=0
