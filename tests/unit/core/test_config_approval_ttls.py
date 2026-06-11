from __future__ import annotations

import pydantic
import pytest

from cognic_agentos.core.config import Settings, build_settings_without_env_file


def test_approval_ttl_defaults() -> None:
    s = build_settings_without_env_file()
    assert s.approval_single_ttl_s == 300
    assert s.approval_four_eyes_ttl_s == 60


def test_approval_single_ttl_gt_zero() -> None:
    with pytest.raises(pydantic.ValidationError):
        Settings(approval_single_ttl_s=0)


def test_approval_four_eyes_ttl_gt_zero() -> None:
    with pytest.raises(pydantic.ValidationError):
        Settings(approval_four_eyes_ttl_s=0)
