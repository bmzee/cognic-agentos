from cognic_agentos.core.config import Settings


def test_memory_settings_have_positive_defaults():
    s = Settings()
    assert s.memory_block_max_bytes > 0
    assert s.memory_scratch_ttl_s > 0
    assert s.memory_tombstone_window_s > 0
