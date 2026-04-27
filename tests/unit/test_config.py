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


# ---------------------------------------------------------------------------
# Sprint 1C — adapter settings (per ADR-009)
# ---------------------------------------------------------------------------


class TestAdapterSettings:
    """Adapter driver fields + per-driver paths (Sprint 1C, ADR-009).

    Drivers are typed as plain ``str`` so an unknown value (e.g.
    ``COGNIC_DB_DRIVER=mssql`` — a planned plugin pack, not bundled in
    Sprint 1C) flows past Pydantic and surfaces at the factory as
    ``AdapterNotInstalled`` with a precise message — not as a generic
    Pydantic ``ValueError`` that lists allowed values (which would leak
    the bundled-adapter list into config-error UX).
    """

    def test_default_drivers_match_bundled_set(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Strip any user .env so we measure class defaults
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")  # forces .env=None
        s = build_settings_without_env_file()

        assert s.db_driver == "postgres"
        assert s.vector_driver == "qdrant"
        assert s.secret_driver == "vault"
        assert s.embed_driver == "ollama"
        assert s.obs_driver == "langfuse_otel"

    def test_driver_fields_typed_as_strings(self) -> None:
        """Drivers must be ``str`` (not ``Literal``) so unknown values
        reach the factory's ``AdapterNotInstalled`` rather than getting
        rejected at config-validation time."""

        fields = Settings.model_fields
        for name in (
            "db_driver",
            "vector_driver",
            "secret_driver",
            "embed_driver",
            "obs_driver",
        ):
            assert fields[name].annotation is str, (
                f"{name} should be plain str; was {fields[name].annotation!r}"
            )

    def test_per_driver_paths_load_from_env(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        monkeypatch.setenv("COGNIC_DATABASE_URL", "postgresql+asyncpg://u:p@h/db")
        monkeypatch.setenv("COGNIC_QDRANT_URL", "http://qdrant:6333")
        monkeypatch.setenv("COGNIC_QDRANT_COLLECTION", "demo_col")
        monkeypatch.setenv("COGNIC_VAULT_ADDR", "http://vault:8200")
        monkeypatch.setenv("COGNIC_VAULT_TOKEN", "dev-token")
        monkeypatch.setenv("COGNIC_VAULT_NAMESPACE", "ns/a")
        monkeypatch.setenv("COGNIC_EMBEDDING_MODEL", "test-embed:1b")
        monkeypatch.setenv("COGNIC_EMBEDDING_BASE_URL", "http://ollama:11434")
        monkeypatch.setenv("COGNIC_EMBEDDING_DIMENSIONS", "512")
        monkeypatch.setenv("COGNIC_LANGFUSE_HOST", "http://lf:3000")
        monkeypatch.setenv("COGNIC_LANGFUSE_PUBLIC_KEY", "pk-test")
        monkeypatch.setenv("COGNIC_LANGFUSE_SECRET_KEY", "sk-test")

        s = build_settings_without_env_file()

        assert s.database_url == "postgresql+asyncpg://u:p@h/db"
        assert s.qdrant_url == "http://qdrant:6333"
        assert s.qdrant_collection == "demo_col"
        assert s.vault_addr == "http://vault:8200"
        assert s.vault_token == "dev-token"
        assert s.vault_namespace == "ns/a"
        assert s.embedding_model == "test-embed:1b"
        assert s.embedding_base_url == "http://ollama:11434"
        assert s.embedding_dimensions == 512
        assert s.langfuse_host == "http://lf:3000"
        assert s.langfuse_public_key == "pk-test"
        assert s.langfuse_secret_key == "sk-test"

    def test_unknown_driver_value_accepted_at_config_layer(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """``mssql`` is a planned plugin pack (per ADR-009 alternative
        adapters). Config must not refuse it. The factory, not config,
        surfaces the miss as ``AdapterNotInstalled``."""

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        monkeypatch.setenv("COGNIC_DB_DRIVER", "mssql")

        s = build_settings_without_env_file()
        assert s.db_driver == "mssql"

    def test_default_collection_and_dimensions(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Sensible defaults are declared on the field; only the
        operator-specific URLs / tokens / model names are required."""

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        s = build_settings_without_env_file()

        assert s.qdrant_collection == "cognic_default"
        assert s.embedding_model == "qwen3-embedding:8b"
        assert s.embedding_dimensions == 1024
        assert s.database_url is None
        assert s.qdrant_url is None
        assert s.vault_addr is None
        assert s.vault_token is None
        assert s.vault_namespace is None
        assert s.embedding_base_url is None
        assert s.langfuse_host is None
        assert s.langfuse_public_key is None
        assert s.langfuse_secret_key is None

    def test_negative_embedding_dimensions_refused(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """``embedding_dimensions`` must be ≥ 1 — a 0 or negative
        dimensionality cannot represent a real embedding."""

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        monkeypatch.setenv("COGNIC_EMBEDDING_DIMENSIONS", "0")

        with pytest.raises(ValueError):
            build_settings_without_env_file()


# ---------------------------------------------------------------------------
# Sprint 1D — enterprise adapter settings (Oracle / Dynatrace / OpenAI-compat)
# ---------------------------------------------------------------------------


class TestEnterpriseAdapterSettings:
    """Sprint 1D enterprise adapter settings — Dynatrace + OpenAI-compat
    auth surface. Oracle uses the existing ``database_url`` field with
    the ``oracle+oracledb://...`` SQLAlchemy URL shape (no Oracle-specific
    config field needed in 1D — see BUILD_PLAN amendment)."""

    def test_dynatrace_defaults_are_none(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        s = build_settings_without_env_file()

        assert s.dynatrace_tenant_url is None
        assert s.dynatrace_api_token is None
        assert s.dynatrace_api_token_vault_path is None

    def test_dynatrace_settings_load_from_env(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        monkeypatch.setenv("COGNIC_DYNATRACE_TENANT_URL", "https://abc12345.live.dynatrace.com")
        monkeypatch.setenv("COGNIC_DYNATRACE_API_TOKEN", "dt0c01.test-token")
        monkeypatch.setenv("COGNIC_DYNATRACE_API_TOKEN_VAULT_PATH", "secret/dynatrace/cognic")

        s = build_settings_without_env_file()
        assert s.dynatrace_tenant_url == "https://abc12345.live.dynatrace.com"
        assert s.dynatrace_api_token == "dt0c01.test-token"
        # Reserved field for Sprint 10 runtime Vault resolution; 1D stores
        # but does not consume.
        assert s.dynatrace_api_token_vault_path == "secret/dynatrace/cognic"

    def test_embed_provider_label_default(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Default is ``openai_compat`` so misconfigured deployments emit
        a label that's clearly the no-op placeholder rather than
        misattributing to a specific backend."""

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        s = build_settings_without_env_file()

        assert s.embed_provider_label == "openai_compat"

    @pytest.mark.parametrize(
        "label",
        ["vllm", "sglang", "openai", "azure_oai", "bedrock", "cohere", "openai_compat"],
    )
    def test_embed_provider_label_accepts_known_values(
        self,
        label: str,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        monkeypatch.setenv("COGNIC_EMBED_PROVIDER_LABEL", label)

        s = build_settings_without_env_file()
        assert s.embed_provider_label == label

    def test_embed_provider_label_unknown_value_accepted(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Mirroring the str-typed driver-field rationale: accept unknown
        labels at the config layer so future providers don't require a
        config-schema bump."""

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        monkeypatch.setenv("COGNIC_EMBED_PROVIDER_LABEL", "future_provider")

        s = build_settings_without_env_file()
        assert s.embed_provider_label == "future_provider"

    def test_openai_compat_auth_defaults(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Defaults: no API key (vLLM/SGLang no-auth path); header name
        defaults to Authorization (the OpenAI Bearer convention)."""

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        s = build_settings_without_env_file()

        assert s.embedding_api_key is None
        assert s.embedding_api_key_header == "Authorization"
        assert s.embedding_api_key_vault_path is None
        assert s.embedding_extra_headers == {}

    def test_openai_compat_auth_loads_from_env(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        monkeypatch.setenv("COGNIC_EMBEDDING_API_KEY", "sk-test-openai-key")
        monkeypatch.setenv("COGNIC_EMBEDDING_API_KEY_HEADER", "Authorization")
        monkeypatch.setenv("COGNIC_EMBEDDING_API_KEY_VAULT_PATH", "secret/openai/embedding")
        monkeypatch.setenv(
            "COGNIC_EMBEDDING_EXTRA_HEADERS",
            '{"api-version": "2024-02-15-preview"}',
        )

        s = build_settings_without_env_file()
        assert s.embedding_api_key == "sk-test-openai-key"
        assert s.embedding_api_key_header == "Authorization"
        assert s.embedding_api_key_vault_path == "secret/openai/embedding"
        assert s.embedding_extra_headers == {"api-version": "2024-02-15-preview"}

    def test_openai_compat_auth_azure_shape(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Azure-OpenAI proxies use ``api-key: <key>`` instead of
        ``Authorization: Bearer <key>``. The header-name override covers
        that shape without needing an Azure-specific adapter."""

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        monkeypatch.setenv("COGNIC_EMBEDDING_API_KEY", "azure-key-value")
        monkeypatch.setenv("COGNIC_EMBEDDING_API_KEY_HEADER", "api-key")

        s = build_settings_without_env_file()
        assert s.embedding_api_key == "azure-key-value"
        assert s.embedding_api_key_header == "api-key"
