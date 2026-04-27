"""Settings loader contract — including prod-profile .env suppression."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from cognic_agentos.core import config as config_module
from cognic_agentos.core.config import (
    Settings,
    build_settings_without_env_file,
    get_settings,
)


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> Iterator[None]:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _write_env(tmp_path: Path, body: str) -> Path:
    env_file = tmp_path / ".env"
    env_file.write_text(body, encoding="utf-8")
    return env_file


def test_dev_profile_reads_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_env(tmp_path, "COGNIC_PORT=9001\nCOGNIC_LOG_LEVEL=DEBUG\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "dev")
    monkeypatch.delenv("COGNIC_PORT", raising=False)
    monkeypatch.delenv("COGNIC_LOG_LEVEL", raising=False)

    settings = get_settings()

    assert settings.port == 9001
    assert settings.log_level == "DEBUG"
    assert settings.runtime_profile == "dev"


def test_prod_profile_ignores_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The Settings docstring promises .env is not read in prod — enforce it."""

    _write_env(tmp_path, "COGNIC_PORT=9001\nCOGNIC_LOG_LEVEL=DEBUG\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
    monkeypatch.delenv("COGNIC_PORT", raising=False)
    monkeypatch.delenv("COGNIC_LOG_LEVEL", raising=False)

    settings = get_settings()

    # .env values must NOT have leaked through; class defaults win.
    assert settings.port == 8000
    assert settings.log_level == "INFO"
    assert settings.runtime_profile == "prod"


def test_env_var_always_overrides_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_env(tmp_path, "COGNIC_PORT=9001\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "dev")
    monkeypatch.setenv("COGNIC_PORT", "9999")

    settings = get_settings()
    assert settings.port == 9999  # env wins over .env


def test_settings_class_constants() -> None:
    """The settings module exposes the prod-profile env var name as a constant."""

    assert config_module._PROD_PROFILE_ENV_VAR == "COGNIC_RUNTIME_PROFILE"


def test_build_settings_without_env_file_helper_skips_dotenv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The escape hatch used by get_settings() in prod must work in isolation.

    Test routes through ``build_settings_without_env_file`` so the narrow
    ``# type: ignore[call-arg]`` lives in exactly one place (the helper).
    """

    _write_env(tmp_path, "COGNIC_PORT=9001\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("COGNIC_PORT", raising=False)

    settings = build_settings_without_env_file()
    assert isinstance(settings, Settings)
    assert settings.port == 8000
