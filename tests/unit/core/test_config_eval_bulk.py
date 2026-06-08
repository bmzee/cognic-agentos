# tests/unit/core/test_config_eval_bulk.py
from __future__ import annotations

import pytest
from pydantic import ValidationError

from cognic_agentos.core.config import Settings


def test_eval_bulk_settings_defaults() -> None:
    s = Settings()
    assert s.eval_bulk_max_cases == 50
    assert s.eval_bulk_max_raw_output_chars == 50_000
    assert s.eval_bulk_target_tier == "tier1"


def test_eval_bulk_max_cases_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        Settings(eval_bulk_max_cases=0)


def test_eval_bulk_max_raw_output_chars_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        Settings(eval_bulk_max_raw_output_chars=0)


def test_eval_bulk_target_tier_is_closed_enum() -> None:
    with pytest.raises(ValidationError):
        Settings(eval_bulk_target_tier="tier3")  # type: ignore[arg-type]
