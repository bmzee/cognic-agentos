import pytest
from pydantic import ValidationError

from cognic_agentos.core.config import (
    _MEMORY_EXPORT_BUCKET_PATTERN,
    _MEMORY_EXPORT_RETENTION_FLOOR_SECONDS,
    Settings,
)


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


# --------------------------------------------------------------------------- #
# Sprint 11.5c — memory-export bucket + retention configurability
# --------------------------------------------------------------------------- #


def test_memory_export_defaults_are_bucket_and_seven_year_floor():
    s = Settings()
    assert s.memory_export_bucket == "cognic-memory-exports"
    assert s.memory_export_retention_seconds == _MEMORY_EXPORT_RETENTION_FLOOR_SECONDS
    assert _MEMORY_EXPORT_RETENTION_FLOOR_SECONDS == 7 * 365 * 24 * 3600  # 220752000


def test_memory_export_retention_floor_matches_sigstore_drift_detector():
    """The 7-year floor is an INLINE mirror of the canonical sigstore-bundle
    retention; core/ must not runtime-import protocol/* (arrow runs protocol ->
    core), so lockstep is pinned test-only here (drift-detector-test-only doctrine)."""
    from cognic_agentos.protocol.supply_chain import SIGSTORE_BUNDLE_RETENTION_SECONDS

    assert _MEMORY_EXPORT_RETENTION_FLOOR_SECONDS == SIGSTORE_BUNDLE_RETENTION_SECONDS


def test_memory_export_retention_ten_year_override_accepted():
    ten_years = 10 * 365 * 24 * 3600
    s = Settings(memory_export_retention_seconds=ten_years)
    assert s.memory_export_retention_seconds == ten_years


def test_memory_export_retention_below_floor_rejected():
    with pytest.raises(ValidationError):
        Settings(memory_export_retention_seconds=_MEMORY_EXPORT_RETENTION_FLOOR_SECONDS - 1)


def test_memory_export_retention_at_floor_accepted():
    s = Settings(memory_export_retention_seconds=_MEMORY_EXPORT_RETENTION_FLOOR_SECONDS)
    assert s.memory_export_retention_seconds == _MEMORY_EXPORT_RETENTION_FLOOR_SECONDS


def test_memory_export_bucket_override_and_empty_rejected():
    s = Settings(memory_export_bucket="acme-bank-memory-exports")
    assert s.memory_export_bucket == "acme-bank-memory-exports"
    with pytest.raises(ValidationError):
        Settings(memory_export_bucket="")  # fails the bucket-shape pattern


def test_memory_export_bucket_pattern_matches_local_fs_drift_detector():
    """The Settings bucket pattern is an INLINE mirror of the shipped local_fs
    adapter's _BUCKET_RE; core/ must not runtime-import db.adapters (config is
    consumed BY the adapters), so lockstep is pinned test-only here."""
    from cognic_agentos.db.adapters.local_object_store_adapter import _BUCKET_RE

    assert _BUCKET_RE.pattern == _MEMORY_EXPORT_BUCKET_PATTERN


@pytest.mark.parametrize(
    "bad_bucket",
    [
        "UPPER",  # uppercase
        "Bad/Bucket",  # path separator (not a single segment)
        "bad bucket",  # space
        "../x",  # traversal
        "_leading",  # must start with [a-z0-9]
        "-leading",  # must start with [a-z0-9]
        "a" * 129,  # over the 128-char cap
    ],
)
def test_memory_export_bucket_invalid_shapes_rejected_at_settings(bad_bucket):
    """Bad bucket config is rejected at Settings construction (startup), not on
    the first export put() against the local_fs adapter."""
    with pytest.raises(ValidationError):
        Settings(memory_export_bucket=bad_bucket)


# --------------------------------------------------------------------------- #
# Sprint 11.5c T7 — memory_vector_collection setting
# --------------------------------------------------------------------------- #


def test_memory_vector_collection_default():
    """``memory_vector_collection`` defaults to ``cognic-memory-episodes``."""
    s = Settings()
    assert s.memory_vector_collection == "cognic-memory-episodes"


def test_memory_vector_collection_override_accepted():
    """A custom collection name is accepted."""
    s = Settings(memory_vector_collection="bank-memory-episodes")
    assert s.memory_vector_collection == "bank-memory-episodes"


def test_memory_vector_collection_empty_rejected():
    """An empty string is rejected at Settings construction (min_length=1)."""
    with pytest.raises(ValidationError):
        Settings(memory_vector_collection="")
