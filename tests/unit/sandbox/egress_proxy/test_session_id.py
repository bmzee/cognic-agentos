import pytest
from cognic_egress_shim import ShimStartupError, resolve_policy_id  # type: ignore[import-not-found]


def test_session_id_becomes_policy_id():
    assert resolve_policy_id({"SESSION_ID": "abc123"}) == "abc123"


def test_missing_session_id_raises():
    with pytest.raises(ShimStartupError):
        resolve_policy_id({})


def test_empty_session_id_raises():
    with pytest.raises(ShimStartupError):
        resolve_policy_id({"SESSION_ID": ""})
