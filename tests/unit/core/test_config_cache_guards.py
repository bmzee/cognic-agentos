"""Harness Injection T4 — cache/gateway/memory Settings + strict-profile cache guards (G9/G10)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from cognic_agentos.core.config import Settings


def _settings(**overrides: Any) -> Settings:
    # Fresh construction RUNS the model validators. Pydantic v2 model_copy(update=...)
    # does NOT re-validate — NEVER use it for validator tests. _env_file=None suppresses .env.
    # (_env_file is a runtime pydantic-settings kwarg mypy doesn't model — same
    # ``# type: ignore[call-arg]`` convention as tests/unit/core/test_vault.py.)
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def _prod_compliant(**overrides: Any) -> Settings:
    # Strict (prod) Settings that passes G1-G8 so only the cache guard is exercised.
    # prod_compliant_settings_kwargs is a real module-level helper extracted in
    # test_config_wave1_guards.py (Harness Injection T4).
    from tests.unit.core.test_config_wave1_guards import prod_compliant_settings_kwargs

    return Settings(  # type: ignore[call-arg]
        _env_file=None, **{**prod_compliant_settings_kwargs(), **overrides}
    )


def test_cache_driver_defaults_to_none() -> None:
    assert _settings().cache_driver == "none"


def test_new_gateway_memory_setting_defaults() -> None:
    s = _settings()
    assert s.litellm_config_path == Path("infra/litellm/config.yaml")
    assert s.llm_sla_total_budget_s == 30.0
    assert s.llm_sla_warning_threshold_s == 20.0
    assert s.memory_policy_bundle == Path("policies/_default/memory.rego")
    assert s.memory_purpose_matrix_policy_bundle == Path(
        "policies/_default/memory_purpose_matrix.rego"
    )
    assert s.memory_vector_recall_enabled is False


def test_redis_without_url_fails_loud_any_profile() -> None:
    with pytest.raises(ValidationError, match="redis_url_unset_for_redis_cache_driver"):
        _settings(cache_driver="redis", redis_url=None)


def test_dev_allows_memory_cache_driver() -> None:
    assert _settings(cache_driver="memory").cache_driver == "memory"


def test_strict_forbids_memory_cache_driver() -> None:
    with pytest.raises(ValidationError, match="cache_driver_memory_forbidden_in_strict_profile"):
        _prod_compliant(cache_driver="memory")


def test_strict_allows_redis_with_url() -> None:
    s = _prod_compliant(cache_driver="redis", redis_url="redis://r:6379/0")
    assert s.cache_driver == "redis"


def test_strict_allows_none() -> None:
    assert _prod_compliant(cache_driver="none").cache_driver == "none"
