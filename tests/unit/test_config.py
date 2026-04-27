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


# --- Sprint 1B observability settings -------------------------------------


def test_cors_allowlist_rejects_wildcard() -> None:
    """Phase-1 'CORS allow-list-only' principle: refuse ``*`` outright."""

    with pytest.raises(ValueError, match="CORS allow-list rejects"):
        Settings(cors_allowed_origins=["*"])


def test_cors_allowlist_rejects_wildcard_amongst_real_origins() -> None:
    with pytest.raises(ValueError, match="CORS allow-list rejects"):
        Settings(cors_allowed_origins=["https://bank.example", "*"])


def test_cors_allowlist_accepts_explicit_origins() -> None:
    settings = Settings(
        cors_allowed_origins=["https://bank.example", "https://reviewer.bank.example"]
    )
    assert settings.cors_allowed_origins == [
        "https://bank.example",
        "https://reviewer.bank.example",
    ]


def test_cors_allowlist_env_accepts_comma_separated_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Most operator-friendly env shape: comma-separated origins."""

    monkeypatch.setenv(
        "COGNIC_CORS_ALLOWED_ORIGINS",
        "https://a.example, https://b.example , https://c.example",
    )
    settings = Settings()
    assert settings.cors_allowed_origins == [
        "https://a.example",
        "https://b.example",
        "https://c.example",
    ]


def test_cors_allowlist_env_accepts_empty_string(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty value (e.g. ``COGNIC_CORS_ALLOWED_ORIGINS=``) → empty list, no startup error."""

    monkeypatch.setenv("COGNIC_CORS_ALLOWED_ORIGINS", "")
    settings = Settings()
    assert settings.cors_allowed_origins == []


def test_cors_allowlist_env_accepts_json_array_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("COGNIC_CORS_ALLOWED_ORIGINS", '["https://a.example","https://b.example"]')
    settings = Settings()
    assert settings.cors_allowed_origins == ["https://a.example", "https://b.example"]


def test_cors_allowlist_env_rejects_wildcard_in_comma_separated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The wildcard refusal must still fire after the comma-split normalisation."""

    monkeypatch.setenv("COGNIC_CORS_ALLOWED_ORIGINS", "https://a.example, *")
    with pytest.raises(ValueError, match="CORS allow-list rejects"):
        Settings()


def test_observability_defaults_match_phase1_principles() -> None:
    settings = Settings()
    assert settings.log_format == "json"  # JSON from request 1
    assert settings.cors_allowed_origins == []  # default-deny
    assert settings.otel_exporter_endpoint is None  # set in stage/prod overlay
    assert settings.prometheus_metrics_path == "/metrics"
    assert settings.otel_exporter_insecure is False  # default secure


def test_otel_mtls_pair_must_be_set_together() -> None:
    """Half-set client cert/key is a misconfiguration; reject it loudly."""

    with pytest.raises(ValueError, match="must be set together"):
        Settings(otel_exporter_client_cert_path=Path("/tmp/cert.pem"))

    with pytest.raises(ValueError, match="must be set together"):
        Settings(otel_exporter_client_key_path=Path("/tmp/key.pem"))


def test_otel_mtls_pair_accepted_when_both_set() -> None:
    settings = Settings(
        otel_exporter_client_cert_path=Path("/tmp/cert.pem"),
        otel_exporter_client_key_path=Path("/tmp/key.pem"),
    )
    assert settings.otel_exporter_client_cert_path == Path("/tmp/cert.pem")
    assert settings.otel_exporter_client_key_path == Path("/tmp/key.pem")
