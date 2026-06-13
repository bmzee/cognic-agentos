"""Settings loader contract — including prod-profile .env suppression."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import ValidationError
from pydantic_settings import SettingsError

from cognic_agentos.core import config as config_module
from cognic_agentos.core.config import (
    Settings,
    build_settings_without_env_file,
    get_settings,
)

# Wave-1 (T1) deploy-safety guards reject the dev ``embedding_model`` (G5) and
# the personal-registry ``ghcr.io/bmzee`` sandbox images (G7) in strict
# profiles. Tests below that build a ``prod`` Settings to exercise an UNRELATED
# field supply these deploy-safe values inline so construction succeeds. Kept as
# explicit constants (NOT routed through ``tests.support.prod_settings``, which
# also sets tier aliases) so each construction stays visible and the
# config-default / guard assertions in this file are never masked.
_PROD_EMBED_MODEL = "prod-embedding-model"
_PROD_RUNTIME_IMAGE = "ghcr.io/cognic-test/sandbox-runtime-python@sha256:" + "0" * 64
_PROD_PROXY_IMAGE = "ghcr.io/cognic-test/sandbox-egress-proxy@sha256:" + "0" * 64


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
    # Wave-1 strict-profile guards (G5/G7) require these in prod; supplied via env
    # (which IS read in prod) — consistent with this test's "env wins, .env
    # ignored" model. The .env values below are what must be ignored.
    monkeypatch.setenv("COGNIC_EMBEDDING_MODEL", _PROD_EMBED_MODEL)
    monkeypatch.setenv("COGNIC_SANDBOX_CANONICAL_RUNTIME_PYTHON_IMAGE", _PROD_RUNTIME_IMAGE)
    monkeypatch.setenv("COGNIC_SANDBOX_CANONICAL_EGRESS_PROXY_IMAGE", _PROD_PROXY_IMAGE)
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
        monkeypatch.setenv("COGNIC_EMBEDDING_MODEL", _PROD_EMBED_MODEL)
        monkeypatch.setenv("COGNIC_SANDBOX_CANONICAL_RUNTIME_PYTHON_IMAGE", _PROD_RUNTIME_IMAGE)
        monkeypatch.setenv("COGNIC_SANDBOX_CANONICAL_EGRESS_PROXY_IMAGE", _PROD_PROXY_IMAGE)
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
        # Dev profile: this exercises env-loading of driver paths + secrets
        # (incl. a plaintext COGNIC_LANGFUSE_SECRET_KEY), which Wave-1 G1 forbids
        # in strict profiles. The env-loading mechanism is profile-agnostic.
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "dev")
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
        monkeypatch.setenv("COGNIC_EMBEDDING_MODEL", _PROD_EMBED_MODEL)
        monkeypatch.setenv("COGNIC_SANDBOX_CANONICAL_RUNTIME_PYTHON_IMAGE", _PROD_RUNTIME_IMAGE)
        monkeypatch.setenv("COGNIC_SANDBOX_CANONICAL_EGRESS_PROXY_IMAGE", _PROD_PROXY_IMAGE)

        s = build_settings_without_env_file()
        assert s.db_driver == "mssql"

    def test_default_collection_and_dimensions(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Sensible defaults are declared on the field; only the
        operator-specific URLs / tokens / model names are required."""

        monkeypatch.chdir(tmp_path)
        # Dev profile: this asserts the dev-default ``embedding_model``
        # (``qwen3-embedding:8b``), which Wave-1 G5 forbids in strict profiles.
        # Field defaults are profile-agnostic; dev is the correct profile to
        # pin them. (``build_settings_without_env_file`` strips ``.env`` in any
        # profile, so the prod override here was only ever incidental.)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "dev")
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
        monkeypatch.setenv("COGNIC_EMBEDDING_MODEL", _PROD_EMBED_MODEL)
        monkeypatch.setenv("COGNIC_SANDBOX_CANONICAL_RUNTIME_PYTHON_IMAGE", _PROD_RUNTIME_IMAGE)
        monkeypatch.setenv("COGNIC_SANDBOX_CANONICAL_EGRESS_PROXY_IMAGE", _PROD_PROXY_IMAGE)
        s = build_settings_without_env_file()

        assert s.dynatrace_tenant_url is None
        assert s.dynatrace_api_token is None
        assert s.dynatrace_api_token_vault_path is None

    def test_dynatrace_settings_load_from_env(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        # Dev profile: this sets a plaintext COGNIC_DYNATRACE_API_TOKEN (G1) AND
        # the deprecated COGNIC_DYNATRACE_API_TOKEN_VAULT_PATH (G2), both forbidden
        # in strict profiles. The env-loading mechanism under test is
        # profile-agnostic.
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "dev")
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
        monkeypatch.setenv("COGNIC_EMBEDDING_MODEL", _PROD_EMBED_MODEL)
        monkeypatch.setenv("COGNIC_SANDBOX_CANONICAL_RUNTIME_PYTHON_IMAGE", _PROD_RUNTIME_IMAGE)
        monkeypatch.setenv("COGNIC_SANDBOX_CANONICAL_EGRESS_PROXY_IMAGE", _PROD_PROXY_IMAGE)
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
        monkeypatch.setenv("COGNIC_EMBEDDING_MODEL", _PROD_EMBED_MODEL)
        monkeypatch.setenv("COGNIC_SANDBOX_CANONICAL_RUNTIME_PYTHON_IMAGE", _PROD_RUNTIME_IMAGE)
        monkeypatch.setenv("COGNIC_SANDBOX_CANONICAL_EGRESS_PROXY_IMAGE", _PROD_PROXY_IMAGE)

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
        monkeypatch.setenv("COGNIC_EMBEDDING_MODEL", _PROD_EMBED_MODEL)
        monkeypatch.setenv("COGNIC_SANDBOX_CANONICAL_RUNTIME_PYTHON_IMAGE", _PROD_RUNTIME_IMAGE)
        monkeypatch.setenv("COGNIC_SANDBOX_CANONICAL_EGRESS_PROXY_IMAGE", _PROD_PROXY_IMAGE)

        s = build_settings_without_env_file()
        assert s.embed_provider_label == "future_provider"

    def test_openai_compat_auth_defaults(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Defaults: no API key (vLLM/SGLang no-auth path); header name
        defaults to Authorization (the OpenAI Bearer convention)."""

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
        monkeypatch.setenv("COGNIC_EMBEDDING_MODEL", _PROD_EMBED_MODEL)
        monkeypatch.setenv("COGNIC_SANDBOX_CANONICAL_RUNTIME_PYTHON_IMAGE", _PROD_RUNTIME_IMAGE)
        monkeypatch.setenv("COGNIC_SANDBOX_CANONICAL_EGRESS_PROXY_IMAGE", _PROD_PROXY_IMAGE)
        s = build_settings_without_env_file()

        assert s.embedding_api_key is None
        assert s.embedding_api_key_header == "Authorization"
        assert s.embedding_api_key_vault_path is None
        assert s.embedding_extra_headers == {}

    def test_openai_compat_auth_loads_from_env(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        # Dev profile: sets a plaintext COGNIC_EMBEDDING_API_KEY (G1-forbidden in
        # strict profiles). Env-loading of the auth surface is profile-agnostic.
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "dev")
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
        # Dev profile: sets a plaintext COGNIC_EMBEDDING_API_KEY (G1-forbidden in
        # strict profiles). The Azure header-shape behaviour is profile-agnostic.
        monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "dev")
        monkeypatch.setenv("COGNIC_EMBEDDING_API_KEY", "azure-key-value")
        monkeypatch.setenv("COGNIC_EMBEDDING_API_KEY_HEADER", "api-key")

        s = build_settings_without_env_file()
        assert s.embedding_api_key == "azure-key-value"
        assert s.embedding_api_key_header == "api-key"


# --- LLM gateway (Sprint 3 T1, per ADR-007) ---------------------------------


class TestLLMGatewaySettings:
    """Sprint 3 T1 — LLM gateway settings.

    Mirrors the plan's locked decisions: self-hosted-first defaults,
    CSV/JSON-array parsing on ``allowed_providers`` (mirrors the
    Sprint-1B ``cors_allowed_origins`` shape), policy_mode rejects
    unknown literals.
    """

    def test_defaults_are_self_hosted_first(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in (
            "COGNIC_TIER1_ALIAS",
            "COGNIC_TIER2_ALIAS",
            "COGNIC_LITELLM_BASE_URL",
            "COGNIC_LITELLM_MASTER_KEY",
            "COGNIC_ALLOW_EXTERNAL_LLM",
            "COGNIC_POLICY_MODE",
            "COGNIC_ALLOWED_PROVIDERS",
            "COGNIC_LLM_TIMEOUT_S",
            "COGNIC_LLM_CONCURRENCY_PER_PROFILE",
            "COGNIC_LLM_CONCURRENCY_MODE",
            "COGNIC_PROVIDER_HONESTY_LEDGER_WINDOW_MINUTES",
            "COGNIC_LLM_GUARDRAIL_SCOPE",
        ):
            monkeypatch.delenv(var, raising=False)
        s = build_settings_without_env_file()
        assert s.tier1_alias == "cognic-tier1-dev"
        assert s.tier2_alias == "cognic-tier2-dev"
        assert s.litellm_base_url is None
        assert s.litellm_master_key is None
        assert s.allow_external_llm is False
        assert s.policy_mode == "self_hosted"
        assert s.allowed_providers == []
        assert s.llm_timeout_s == 30.0
        assert s.llm_concurrency_per_profile == 4
        assert s.llm_concurrency_mode == "queued"
        assert s.provider_honesty_ledger_window_minutes == 60
        # T1 follow-up: default ``all`` means configured guardrails run
        # on local + cloud calls. Banks intentionally relax per perimeter.
        assert s.llm_guardrail_scope == "all"

    @pytest.mark.parametrize(
        "scope",
        ["all", "external_only", "self_hosted_only", "off"],
    )
    def test_guardrail_scope_accepts_all_four_modes(
        self, scope: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """T1 follow-up: per-route guardrail scope. ``all`` is the secure
        default; ``external_only`` lets banks skip local-model guardrails
        (perimeter-risk justification); ``self_hosted_only`` is the
        inverse (e.g. operator who guards on-prem traffic but trusts
        cloud-tenant isolation); ``off`` disables configured pipelines
        on every call. The runtime branch lives at the gateway boundary
        (T6); settings layer just exposes the knob."""
        monkeypatch.setenv("COGNIC_LLM_GUARDRAIL_SCOPE", scope)
        s = build_settings_without_env_file()
        assert s.llm_guardrail_scope == scope

    def test_guardrail_scope_rejects_unknown_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Unknown literal must fail at startup, not silently fall back
        to a default — operator misconfiguration surfaces loudly."""
        monkeypatch.setenv("COGNIC_LLM_GUARDRAIL_SCOPE", "external")
        with pytest.raises(ValueError):
            build_settings_without_env_file()

    def test_allowed_providers_parses_csv(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COGNIC_ALLOWED_PROVIDERS", "openai,azure")
        s = build_settings_without_env_file()
        assert s.allowed_providers == ["openai", "azure"]

    def test_allowed_providers_parses_json_array(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COGNIC_ALLOWED_PROVIDERS", '["openai", "anthropic"]')
        s = build_settings_without_env_file()
        assert s.allowed_providers == ["openai", "anthropic"]

    def test_allowed_providers_normalises_to_lowercase(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("COGNIC_ALLOWED_PROVIDERS", "OpenAI, AZURE")
        s = build_settings_without_env_file()
        assert s.allowed_providers == ["openai", "azure"]

    def test_allowed_providers_empty_string_yields_empty_list(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("COGNIC_ALLOWED_PROVIDERS", "")
        s = build_settings_without_env_file()
        assert s.allowed_providers == []

    def test_policy_mode_rejects_unknown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COGNIC_POLICY_MODE", "no_such_mode")
        with pytest.raises(ValueError):
            build_settings_without_env_file()

    def test_llm_concurrency_mode_rejects_unknown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COGNIC_LLM_CONCURRENCY_MODE", "spinwait")
        with pytest.raises(ValueError):
            build_settings_without_env_file()

    def test_llm_timeout_rejects_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COGNIC_LLM_TIMEOUT_S", "0")
        with pytest.raises(ValueError):
            build_settings_without_env_file()

    def test_llm_concurrency_per_profile_rejects_zero(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("COGNIC_LLM_CONCURRENCY_PER_PROFILE", "0")
        with pytest.raises(ValueError):
            build_settings_without_env_file()

    def test_provider_honesty_window_rejects_above_24h(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("COGNIC_PROVIDER_HONESTY_LEDGER_WINDOW_MINUTES", "1441")
        with pytest.raises(ValueError):
            build_settings_without_env_file()

    def test_explicit_cloud_settings_load(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COGNIC_TIER1_ALIAS", "cognic-tier1-cloud-openai")
        monkeypatch.setenv("COGNIC_LITELLM_BASE_URL", "http://litellm:4000")
        monkeypatch.setenv("COGNIC_LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setenv("COGNIC_ALLOW_EXTERNAL_LLM", "true")
        monkeypatch.setenv("COGNIC_POLICY_MODE", "cloud_openai")
        monkeypatch.setenv("COGNIC_ALLOWED_PROVIDERS", "openai")
        s = build_settings_without_env_file()
        assert s.tier1_alias == "cognic-tier1-cloud-openai"
        assert s.litellm_base_url == "http://litellm:4000"
        assert s.litellm_master_key == "sk-test"
        assert s.allow_external_llm is True
        assert s.policy_mode == "cloud_openai"
        assert s.allowed_providers == ["openai"]


# ---------------------------------------------------------------------------
# Sprint 4 — Plugin registry + trust gate + policy-engine seed settings
# (per ADRs 002 / 015 / 016).
# ---------------------------------------------------------------------------


class TestSprint4PluginPolicySettings:
    """Settings tests for the Sprint 4 plugin/trust-gate/policy seed surface.

    Per the Sprint 4 plan-of-record (a84ec85) §1: the file-backed allow-list
    + cosign + OPA + LocalObjectStoreAdapter root + path-traversal prefixes
    are all introduced as additive Settings fields. Defaults match the
    documented secure-by-default posture (cosign required; load-from-disk
    Rego seed; profile-aware object-store root).
    """

    def test_sprint_4_defaults_match_secure_posture(self) -> None:
        s = Settings(  # type: ignore[call-arg]
            _env_file=None,
            runtime_profile="prod",
            embedding_model=_PROD_EMBED_MODEL,
            sandbox_canonical_runtime_python_image=_PROD_RUNTIME_IMAGE,
            sandbox_canonical_egress_proxy_image=_PROD_PROXY_IMAGE,
        )
        # Cosign required by default — fail-closed posture per AGENTS.md
        # critical-controls discipline (trust gate).
        assert s.require_cosign is True
        # cosign_path default is None → resolver runs shutil.which at use-time.
        assert s.cosign_path is None
        assert s.cosign_verify_timeout_s == 30.0
        # File-backed allow-list defaults; Vault swap → Sprint 10.
        assert s.plugin_allowlist_path == Path("policies/_default/plugin_allowlist.json")
        # Rego seed bundle (per ADR-015 Sprint-4 phase).
        assert s.supply_chain_policy_bundle == Path("policies/_default/supply_chain.rego")
        # OPA defaults match cosign shape — None → shutil.which at use-time.
        assert s.opa_path is None
        assert s.opa_eval_timeout_s == 5.0
        # Path-traversal prefixes (boundary-asserted at trust-gate).
        assert s.signature_root_path == Path("attestations")
        assert s.trust_root_prefix == Path("trust-roots")

    def test_cosign_timeout_must_be_positive(self) -> None:
        """Strict fail-loud per Sprint-4 plan §2 invariant 6 — timeout=0
        would mean no upper bound; negative is nonsensical."""
        with pytest.raises(ValueError, match="greater than 0"):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                runtime_profile="prod",
                cosign_verify_timeout_s=0,
            )
        with pytest.raises(ValueError, match="greater than 0"):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                runtime_profile="prod",
                cosign_verify_timeout_s=-1,
            )

    def test_opa_timeout_must_be_positive(self) -> None:
        """Same shape as cosign-timeout. Per Sprint-4 plan §5 invariant 5."""
        with pytest.raises(ValueError, match="greater than 0"):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                runtime_profile="prod",
                opa_eval_timeout_s=0,
            )
        with pytest.raises(ValueError, match="greater than 0"):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                runtime_profile="prod",
                opa_eval_timeout_s=-0.5,
            )

    def test_local_object_store_root_prod_default(self) -> None:
        """Prod profile uses the /var/lib path. Pinned regardless of
        $TMPDIR — the post-init validator picks per profile, not per env."""
        s = Settings(  # type: ignore[call-arg]
            _env_file=None,
            runtime_profile="prod",
            embedding_model=_PROD_EMBED_MODEL,
            sandbox_canonical_runtime_python_image=_PROD_RUNTIME_IMAGE,
            sandbox_canonical_egress_proxy_image=_PROD_PROXY_IMAGE,
        )
        assert s.local_object_store_root == Path("/var/lib/cognic-agentos/object-store")

    def test_local_object_store_root_dev_derives_from_tmpdir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Dev profile derives root from $TMPDIR. Pinned so test environments
        don't accidentally write Sigstore bundles into a shared production
        path."""
        monkeypatch.setenv("TMPDIR", str(tmp_path))
        s = Settings(_env_file=None, runtime_profile="dev")  # type: ignore[call-arg]
        # The default is <tmpdir>/cognic-agentos-object-store; assert that
        # our tmp_path is the parent (or grandparent depending on env shape).
        assert s.local_object_store_root is not None
        assert tmp_path in s.local_object_store_root.parents or (
            s.local_object_store_root == tmp_path / "cognic-agentos-object-store"
        )

    def test_cognic_require_cosign_can_be_disabled_explicitly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Operator can disable cosign requirement (e.g. local dev without
        cosign installed). Comment in .env.example notes this is a critical-
        controls violation in production — but the Settings field accepts
        the override to avoid blocking local iteration."""
        monkeypatch.setenv("COGNIC_REQUIRE_COSIGN", "false")
        s = Settings(_env_file=None, runtime_profile="dev")  # type: ignore[call-arg]
        assert s.require_cosign is False


class TestMcpSettings:
    """Settings tests for the Sprint 5 MCP host surface.

    Per the Sprint 5 plan-of-record (1e43792) §T1: the MCP-host settings
    are introduced as additive Settings fields. Defaults match the
    documented secure-by-default posture (STDIO disabled in all profiles
    in Sprint 5 — the sandbox primitive lands Sprint 8; OAuth/MCP timeouts
    pinned at the same fail-closed shape as cosign/OPA).
    """

    def test_mcp_stdio_enabled_defaults_false(self) -> None:
        """Sprint-5 Decision Lock: STDIO is hard-disabled by default in
        ALL profiles. Sprint 8 may flip dev to True after sandbox lands;
        prod stays False until operator opt-in PLUS sandbox available
        PLUS four-gate manifest validates."""
        settings = build_settings_without_env_file()
        assert settings.mcp_stdio_enabled is False

    def test_mcp_stdio_command_allowlist_path_template(self) -> None:
        """Per ADR-002 §"MCP STDIO threat model" gate 2: the per-tenant
        static command allow-list is a Vault path. The default template
        carries `{tenant}` so each tenant's allow-list lives under its own
        secret path."""
        settings = build_settings_without_env_file()
        assert "{tenant}" in settings.mcp_stdio_command_allowlist_path
        assert "stdio-command-allowlist" in settings.mcp_stdio_command_allowlist_path

    def test_mcp_as_allowlist_path_template(self) -> None:
        """Per ADR-002 §"MCP Authorization" step 3: the per-tenant
        OAuth authorization-server allow-list lives in Vault. Template
        shape mirrors the STDIO command-allowlist path."""
        settings = build_settings_without_env_file()
        assert "{tenant}" in settings.mcp_as_allowlist_path
        assert "mcp-as-allowlist" in settings.mcp_as_allowlist_path

    def test_mcp_oauth_token_cache_ttl_defaults_one_hour(self) -> None:
        """Token cache TTL — refreshed before this expiry; refresh emits
        audit.mcp_token_refresh + decision_history row per T11."""
        settings = build_settings_without_env_file()
        assert settings.mcp_oauth_token_cache_ttl_s == 3600

    def test_mcp_oauth_request_timeout_defaults_thirty_seconds(self) -> None:
        """Strict timeout on every PRM discovery + token request HTTP
        call. Same fail-closed shape as cosign_verify_timeout_s."""
        settings = build_settings_without_env_file()
        assert settings.mcp_oauth_request_timeout_s == 30

    def test_mcp_call_tool_timeout_defaults_one_minute(self) -> None:
        """Strict timeout on every MCP call_tool invocation. Tools that
        exceed this raise mcp_call_tool_timeout, audit-logged with pack
        identity + tool name + duration."""
        settings = build_settings_without_env_file()
        assert settings.mcp_call_tool_timeout_s == 60

    def test_mcp_sampling_policy_bundle_defaults_to_default_rego(self) -> None:
        """Default-deny sampling Rego bundle path. Consumed by
        protocol/mcp_capabilities.py to evaluate the four-condition
        sampling default-deny per ADR-002 + MCP-CONFORMANCE.md."""
        settings = build_settings_without_env_file()
        assert settings.mcp_sampling_policy_bundle == Path("policies/_default/sampling.rego")

    def test_mcp_oauth_request_timeout_must_be_positive(self) -> None:
        """Strict fail-loud — same shape as cosign_verify_timeout_s."""
        with pytest.raises(ValueError, match="greater than 0"):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                runtime_profile="prod",
                mcp_oauth_request_timeout_s=0,
            )
        with pytest.raises(ValueError, match="greater than 0"):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                runtime_profile="prod",
                mcp_oauth_request_timeout_s=-1,
            )

    def test_mcp_call_tool_timeout_must_be_positive(self) -> None:
        """Strict fail-loud — same shape as cosign_verify_timeout_s."""
        with pytest.raises(ValueError, match="greater than 0"):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                runtime_profile="prod",
                mcp_call_tool_timeout_s=0,
            )

    def test_mcp_oauth_token_cache_ttl_must_be_positive(self) -> None:
        """Cache TTL of 0 means "always refresh" which would defeat the
        cache; negative is nonsensical."""
        with pytest.raises(ValueError, match="greater than 0"):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                runtime_profile="prod",
                mcp_oauth_token_cache_ttl_s=0,
            )

    def test_mcp_stdio_enabled_can_be_overridden_in_dev(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Operators can opt into STDIO in dev profile via env var.
        Sprint 8 will flip the default for dev; prod stays False until
        sandbox available + four-gate manifest validates (config-load
        check in T8)."""
        monkeypatch.setenv("COGNIC_MCP_STDIO_ENABLED", "true")
        s = Settings(_env_file=None, runtime_profile="dev")  # type: ignore[call-arg]
        assert s.mcp_stdio_enabled is True

    def test_mcp_oauth_credentials_path_template(self) -> None:
        """Per-tenant per-AS OAuth client credentials Vault path. Sprint
        5 R6 closure of the "no real OAuth client credentials" P1
        finding — admission MUST resolve a Vault secret containing
        ``client_id`` + ``client_secret`` + ``auth_method`` before any
        token request reaches the AS."""
        settings = build_settings_without_env_file()
        assert "{tenant}" in settings.mcp_oauth_credentials_path
        assert "{as_host}" in settings.mcp_oauth_credentials_path
        assert "mcp-oauth" in settings.mcp_oauth_credentials_path

    def test_mcp_oauth_credentials_path_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Operators override the default Vault path via env var; the
        resolved path is a string template (with both {tenant} and
        {as_host} placeholders preserved verbatim for runtime
        ``.format()``)."""
        monkeypatch.setenv(
            "COGNIC_MCP_OAUTH_CREDENTIALS_PATH",
            "secret/data/{tenant}/oauth/{as_host}/creds",
        )
        s = Settings(  # type: ignore[call-arg]
            _env_file=None,
            runtime_profile="prod",
            embedding_model=_PROD_EMBED_MODEL,
            sandbox_canonical_runtime_python_image=_PROD_RUNTIME_IMAGE,
            sandbox_canonical_egress_proxy_image=_PROD_PROXY_IMAGE,
        )
        assert s.mcp_oauth_credentials_path == "secret/data/{tenant}/oauth/{as_host}/creds"


# ---------------------------------------------------------------------------
# Sprint 6 — A2A endpoint + UI event-stream stub settings (T1)
# ---------------------------------------------------------------------------


class TestSprint6A2ASettings:
    """Sprint-6 T1 settings contract per the plan-of-record at
    ``docs/superpowers/plans/2026-05-04-sprint-6-a2a-endpoint.md``.

    Seven new settings cover the A2A endpoint surface (token cache,
    artifact retention, pinned spec version, schema-drift CI gate,
    JWS size cap, in/outbound HTTP timeouts). Each carries a
    fail-closed default + a positive-value validator where
    applicable; ``a2a_pinned_spec_version`` matches a strict
    ``^[0-9]+\\.[0-9]+$`` pattern so version bumps are deliberate.
    """

    def test_a2a_token_cache_ttl_s_default(self) -> None:
        """Default 3600s matches Sprint-5 ``mcp_oauth_token_cache_ttl_s``
        per R1 P3 reviewer correction (was 300 in the original draft)."""
        s = build_settings_without_env_file()
        assert s.a2a_token_cache_ttl_s == 3600

    def test_a2a_artifact_retention_seconds_default(self) -> None:
        s = build_settings_without_env_file()
        assert s.a2a_artifact_retention_seconds == 7 * 24 * 3600

    def test_a2a_artifact_inline_threshold_bytes_default(self) -> None:
        """Sprint-6 T11 R0 doctrine #4: deployment-tunable inline-vs-
        store threshold (was a hardcoded 64 KiB constant in the plan
        skeleton; promoted to Settings per AGENTS.md production-grade
        rule)."""
        s = build_settings_without_env_file()
        assert s.a2a_artifact_inline_threshold_bytes == 64 * 1024

    def test_a2a_pinned_spec_version_default(self) -> None:
        s = build_settings_without_env_file()
        assert s.a2a_pinned_spec_version == "1.0"

    def test_a2a_schema_drift_check_enabled_default(self) -> None:
        """Drift check OFF by default; CI sets COGNIC_RUN_A2A_UPSTREAM=1
        to opt in. The check itself is in
        tests/unit/protocol/test_a2a_schema_drift.py (T6)."""
        s = build_settings_without_env_file()
        assert s.a2a_schema_drift_check_enabled is False

    def test_a2a_card_jws_max_size_bytes_default(self) -> None:
        """64 KiB cap matches the AgentCard size budget the trust
        gate validates against; larger files are an attack vector
        (DoS via large-blob signature verification + memory pressure)."""
        s = build_settings_without_env_file()
        assert s.a2a_card_jws_max_size_bytes == 64 * 1024

    def test_a2a_outbound_request_timeout_s_default(self) -> None:
        """30s matches Sprint-5 ``mcp_oauth_request_timeout_s`` for
        operational consistency."""
        s = build_settings_without_env_file()
        assert s.a2a_outbound_request_timeout_s == 30

    def test_a2a_inbound_request_timeout_s_default(self) -> None:
        """Inbound timeout is the deadline for ``A2AEndpoint.handle()``
        to produce a response on a non-streaming task."""
        s = build_settings_without_env_file()
        assert s.a2a_inbound_request_timeout_s == 60

    def test_a2a_outbound_timeout_must_be_positive(self) -> None:
        """Fail-closed: 0s would silently accept hung connections."""
        with pytest.raises(ValidationError):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                a2a_outbound_request_timeout_s=0,
            )

    def test_a2a_inbound_timeout_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                a2a_inbound_request_timeout_s=0,
            )

    def test_a2a_card_jws_max_size_bytes_must_be_positive(self) -> None:
        """Fail-closed: 0-byte cap would refuse every card."""
        with pytest.raises(ValidationError):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                a2a_card_jws_max_size_bytes=0,
            )

    def test_a2a_token_cache_ttl_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                a2a_token_cache_ttl_s=0,
            )

    def test_a2a_artifact_retention_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                a2a_artifact_retention_seconds=0,
            )

    def test_a2a_artifact_inline_threshold_must_be_positive(self) -> None:
        """Fail-closed: 0-byte threshold would force EVERY artifact
        through ObjectStore (forcing the inline path off entirely),
        which is the wrong default for tiny payloads."""
        with pytest.raises(ValidationError):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                a2a_artifact_inline_threshold_bytes=0,
            )

    def test_a2a_pinned_spec_version_pattern_rejects_non_numeric(self) -> None:
        """Strict ``^[0-9]+\\.[0-9]+$`` pattern means version bumps are
        always deliberate (the schema-drift CI gate at T6 is the
        only legitimate trigger)."""
        with pytest.raises(ValidationError):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                a2a_pinned_spec_version="1.0.beta",
            )

    def test_a2a_pinned_spec_version_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Operators bump the pinned version via env var; the strict
        pattern still validates."""
        monkeypatch.setenv("COGNIC_A2A_PINNED_SPEC_VERSION", "1.1")
        s = Settings(  # type: ignore[call-arg]
            _env_file=None,
            runtime_profile="prod",
            embedding_model=_PROD_EMBED_MODEL,
            sandbox_canonical_runtime_python_image=_PROD_RUNTIME_IMAGE,
            sandbox_canonical_egress_proxy_image=_PROD_PROXY_IMAGE,
        )
        assert s.a2a_pinned_spec_version == "1.1"

    def test_a2a_schema_drift_check_enabled_env_override(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The fully-qualified ``COGNIC_A2A_SCHEMA_DRIFT_CHECK_ENABLED``
        env var flips the setting via the standard pydantic-settings
        env-prefix binding."""
        monkeypatch.setenv("COGNIC_A2A_SCHEMA_DRIFT_CHECK_ENABLED", "true")
        s = Settings(  # type: ignore[call-arg]
            _env_file=None,
            runtime_profile="prod",
            embedding_model=_PROD_EMBED_MODEL,
            sandbox_canonical_runtime_python_image=_PROD_RUNTIME_IMAGE,
            sandbox_canonical_egress_proxy_image=_PROD_PROXY_IMAGE,
        )
        assert s.a2a_schema_drift_check_enabled is True

    def test_a2a_schema_drift_check_enabled_via_run_a2a_upstream_alias(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """**R1 P2 regression** — the dedicated CI lane (per Doctrine
        Decision C + the plan's §T6 a2a-spec-drift workflow snippet)
        sets ``COGNIC_RUN_A2A_UPSTREAM=1``. Without the
        ``AliasChoices`` binding on the field, that env var would NOT
        flip ``a2a_schema_drift_check_enabled`` — the CI lane would
        silently skip the upstream check despite setting the documented
        env var. This test pins the alias so future maintainers can't
        regress it.
        """
        monkeypatch.setenv("COGNIC_RUN_A2A_UPSTREAM", "1")
        # Explicitly clear the fully-qualified var so the test only
        # exercises the alias path.
        monkeypatch.delenv("COGNIC_A2A_SCHEMA_DRIFT_CHECK_ENABLED", raising=False)
        s = Settings(  # type: ignore[call-arg]
            _env_file=None,
            runtime_profile="prod",
            embedding_model=_PROD_EMBED_MODEL,
            sandbox_canonical_runtime_python_image=_PROD_RUNTIME_IMAGE,
            sandbox_canonical_egress_proxy_image=_PROD_PROXY_IMAGE,
        )
        assert s.a2a_schema_drift_check_enabled is True

    def test_a2a_schema_drift_run_a2a_upstream_false_value(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The alias also honours falsy values per pydantic's bool
        coercion (``"0"`` / ``"false"`` / ``""``). Operators turning
        the env var off MUST get the default-False back, not a sticky
        True."""
        monkeypatch.setenv("COGNIC_RUN_A2A_UPSTREAM", "0")
        monkeypatch.delenv("COGNIC_A2A_SCHEMA_DRIFT_CHECK_ENABLED", raising=False)
        s = Settings(  # type: ignore[call-arg]
            _env_file=None,
            runtime_profile="prod",
            embedding_model=_PROD_EMBED_MODEL,
            sandbox_canonical_runtime_python_image=_PROD_RUNTIME_IMAGE,
            sandbox_canonical_egress_proxy_image=_PROD_PROXY_IMAGE,
        )
        assert s.a2a_schema_drift_check_enabled is False

    def test_a2a_schema_drift_check_enabled_constructor_override(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """**R2 P2 regression** — adding ``validation_alias`` removes
        the default name-based population, so without including the
        field name itself in ``AliasChoices`` a direct constructor
        override (``Settings(a2a_schema_drift_check_enabled=True)``)
        would be silently dropped by ``extra='ignore'``. That sharp
        edge would re-introduce the drift-gate skip in tests/factories
        + any T6 runtime enable path. This test pins the
        constructor-override path so future maintainers can't regress
        it.
        """
        # Clear any env vars so we exercise the constructor path purely.
        monkeypatch.delenv("COGNIC_A2A_SCHEMA_DRIFT_CHECK_ENABLED", raising=False)
        monkeypatch.delenv("COGNIC_RUN_A2A_UPSTREAM", raising=False)
        s = Settings(  # type: ignore[call-arg]
            _env_file=None,
            a2a_schema_drift_check_enabled=True,
        )
        assert s.a2a_schema_drift_check_enabled is True

        # And the False side: explicit constructor False MUST stick
        # even if a falsy env value is later set (which it isn't here,
        # but pin the orthogonality so a future precedence bug surfaces).
        s_false = Settings(  # type: ignore[call-arg]
            _env_file=None,
            a2a_schema_drift_check_enabled=False,
        )
        assert s_false.a2a_schema_drift_check_enabled is False


# ---------------------------------------------------------------------------
# Sprint 6 — closed-enum vocabulary scaffolding sanity (T1)
# ---------------------------------------------------------------------------


class TestSprint6ClosedEnumVocabulary:
    """T1 declares the Sprint-6 closed-enum literals in
    ``protocol/__init__.py``. Subsequent tasks (T5 authz, T6 schema,
    T7 cards, T8 version, T9 endpoint, T11 errors) import them.

    The drift detectors that pin literal-set arithmetic land at T11
    (in ``test_a2a_errors.py``) + T6 (in ``test_a2a_schema.py``) +
    Sprint-5's existing ``test_refusal_reason_completeness.py``
    extended at T1 for the 6 new registry-side reasons. T1 just
    asserts the vocab declarations are importable + carry the
    expected member counts.
    """

    def test_a2a_authz_reason_has_8_values(self) -> None:
        """8 values per file-structure §A2AAuthzReason (T5 will
        extend the validator to fire each)."""
        from typing import get_args

        from cognic_agentos.protocol import A2AAuthzReason

        assert len(get_args(A2AAuthzReason)) == 8

    def test_a2a_version_outcome_has_6_values(self) -> None:
        """6 values per ADR-003 §"Version negotiation" (T8 fires
        each)."""
        from typing import get_args

        from cognic_agentos.protocol import A2AVersionOutcome

        assert len(get_args(A2AVersionOutcome)) == 6

    def test_a2a_error_code_has_14_spec_codes(self) -> None:
        """14 spec-defined wire codes per A2A 1.0 §"Error codes":
        5 JSON-RPC envelope errors + 9 A2A-specific. R2 P2 #1
        reviewer correction split spec wire codes from AgentOS-
        policy reasons; this counts the wire side only."""
        from typing import get_args

        from cognic_agentos.protocol import A2AErrorCode

        assert len(get_args(A2AErrorCode)) == 14

    def test_a2a_policy_refusal_reason_has_11_values(self) -> None:
        """11 AgentOS-specific refusal reasons surfaced via
        ``data.policy_reason`` detail field on top of a spec-conformant
        ``error.code``. R2 P2 #1 split."""
        from typing import get_args

        from cognic_agentos.protocol import A2APolicyRefusalReason

        assert len(get_args(A2APolicyRefusalReason)) == 11

    def test_agent_card_validation_reason_has_11_values(self) -> None:
        """11 values: 1 upstream-schema gate + 7 AgentOS-profile gates +
        3 JWS-verification outcomes. T1 R1 P2 reviewer correction added
        the 3 JWS values (without them T7's validator would have to
        misclassify JWS failures as schema/profile failures or use
        untyped strings, breaking the closed-enum mapping doctrine).
        T14 R0 added the 7th profile gate
        ``agent_card_profile_wave2_auth_required`` — cards declaring
        ``mtlsSecurityScheme`` are refused under Wave-1 bearer-token
        transport policy per A2A-CONFORMANCE.md §"Wave breakdown"
        (Wave-1 = per-tenant pinned bearer token; Wave-2 = mTLS;
        Wave-3 = verifiable credentials)."""
        from typing import get_args

        from cognic_agentos.protocol import AgentCardValidationReason

        assert len(get_args(AgentCardValidationReason)) == 11

    def test_agent_card_validation_reason_includes_jws_outcomes(self) -> None:
        """**R1 P2 regression** — the three JWS-verification outcomes
        (blob-unreadable, signature-invalid, signer-not-allowlisted)
        MUST be in the literal so T7's two-pass validator + T7's
        `plugin_registry` integration can map JWS failures onto the
        correct registry RefusalReasons (`a2a_agent_card_jws_blob_unreadable`,
        `a2a_agent_card_signature_invalid`,
        `a2a_agent_card_signer_not_allowlisted`)."""
        from typing import get_args

        from cognic_agentos.protocol import AgentCardValidationReason

        values = set(get_args(AgentCardValidationReason))
        assert "agent_card_jws_blob_unreadable" in values
        assert "agent_card_signature_invalid" in values
        assert "agent_card_signer_not_allowlisted" in values

    def test_a2a_authz_reason_uses_a2a_prefix(self) -> None:
        """All A2AAuthzReason values carry the ``a2a_`` prefix
        (mirrors Sprint-5 ``mcp_*`` convention)."""
        from typing import get_args

        from cognic_agentos.protocol import A2AAuthzReason

        for value in get_args(A2AAuthzReason):
            assert value.startswith("a2a_"), f"A2AAuthzReason {value!r} missing ``a2a_`` prefix"

    def test_a2a_policy_refusal_reason_does_not_use_a2a_prefix(self) -> None:
        """A2APolicyRefusalReason values are unprefixed because the
        type name carries the namespace; mirrors Sprint-5 AuthzReason
        layout. R3 P3 reviewer correction pinned this distinction."""
        from typing import get_args

        from cognic_agentos.protocol import A2APolicyRefusalReason

        for value in get_args(A2APolicyRefusalReason):
            assert not value.startswith("a2a_"), (
                f"A2APolicyRefusalReason {value!r} should NOT carry "
                f"the a2a_ prefix (the type name carries the namespace)"
            )


class TestSprint7ASettings:
    """Sprint-7A T1 settings contract per the plan-of-record at
    ``docs/superpowers/plans/2026-05-06-sprint-7a-agentos-sdk-cli.md``.

    Seven new CLI settings cover the SDK + CLI surface (cosign /
    syft / grype / license-auditor binary paths + signing-key path
    + signing-trust-root path + dev-mode-skip-cosign override). The
    R9 P2 #1 prod-profile guard rejects any `signing_key_path`
    whose resolved absolute path lies under `examples/` or
    `tests/fixtures/` at startup so test-only signing keys cannot
    accidentally be wired into production deployments.
    """

    def test_cosign_path_default_none(self) -> None:
        from cognic_agentos.core.config import build_settings_without_env_file

        s = build_settings_without_env_file()
        assert s.cosign_path is None

    def test_syft_path_default_none(self) -> None:
        from cognic_agentos.core.config import build_settings_without_env_file

        s = build_settings_without_env_file()
        assert s.syft_path is None

    def test_grype_path_default_none(self) -> None:
        from cognic_agentos.core.config import build_settings_without_env_file

        s = build_settings_without_env_file()
        assert s.grype_path is None

    def test_license_auditor_path_default_none(self) -> None:
        from cognic_agentos.core.config import build_settings_without_env_file

        s = build_settings_without_env_file()
        assert s.license_auditor_path is None

    def test_signing_key_path_default_none(self) -> None:
        from cognic_agentos.core.config import build_settings_without_env_file

        s = build_settings_without_env_file()
        assert s.signing_key_path is None

    def test_signing_trust_root_path_default_none(self) -> None:
        from cognic_agentos.core.config import build_settings_without_env_file

        s = build_settings_without_env_file()
        assert s.signing_trust_root_path is None

    def test_dev_mode_skip_cosign_default_false(self) -> None:
        from cognic_agentos.core.config import build_settings_without_env_file

        s = build_settings_without_env_file()
        assert s.dev_mode_skip_cosign is False

    def test_signing_key_path_under_examples_in_prod_rejected(self) -> None:
        """R9 P2 #1 + R10 P2 #2 — prod profile rejects test-fixture-tree
        signing-key paths at startup so synthetic keys cannot leak
        into production deployments."""
        from pydantic import ValidationError

        from cognic_agentos.core.config import (
            Settings,
        )

        with pytest.raises(ValidationError) as excinfo:
            Settings(
                runtime_profile="prod",
                signing_key_path="/abs/path/to/examples/cognic-agent-example-minimal/attestations/test-signing/test_signing_key.private.pem",
            )
        assert "signing_key_path_under_test_fixture_tree_in_prod" in str(excinfo.value)

    def test_signing_key_path_under_tests_fixtures_in_prod_rejected(self) -> None:
        from pydantic import ValidationError

        from cognic_agentos.core.config import Settings

        with pytest.raises(ValidationError) as excinfo:
            Settings(
                runtime_profile="prod",
                signing_key_path="/abs/path/to/tests/fixtures/cli_sign_target_pack/attestations/test-signing/test_signing_key.private.pem",
            )
        assert "signing_key_path_under_test_fixture_tree_in_prod" in str(excinfo.value)

    def test_signing_key_path_under_examples_in_dev_allowed(self) -> None:
        """The R9 guard is prod-profile-only by design — unit-lane
        testing under dev/test profile MUST be able to use the
        test-fixture keys, otherwise T14 + T15 lifecycle tests
        cannot run."""
        from cognic_agentos.core.config import Settings

        # Dev profile + examples-tree path → allowed (no exception).
        s = Settings(
            runtime_profile="dev",
            signing_key_path="/abs/path/to/examples/cognic-agent-example-minimal/attestations/test-signing/test_signing_key.private.pem",
        )
        assert s.signing_key_path is not None
        assert "examples" in s.signing_key_path

    def test_signing_key_path_in_prod_real_path_allowed(self) -> None:
        """Prod profile + real signing-key path (NOT under
        examples/ or tests/fixtures/) → allowed. Pin both
        prod-profile-allowed paths AND prod-profile-rejected paths
        so the guard is enforced at the path-shape boundary, not
        by accident."""
        from cognic_agentos.core.config import Settings

        s = Settings(
            runtime_profile="prod",
            signing_key_path="/etc/cognic/signing-keys/prod.pem",
            embedding_model=_PROD_EMBED_MODEL,
            sandbox_canonical_runtime_python_image=_PROD_RUNTIME_IMAGE,
            sandbox_canonical_egress_proxy_image=_PROD_PROXY_IMAGE,
        )
        assert s.signing_key_path == "/etc/cognic/signing-keys/prod.pem"

    def test_signing_key_path_relative_examples_in_prod_rejected(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """R11 P2 #1 — the earlier draft matched raw substrings
        (``/examples/``), which silently accepted RELATIVE paths
        like ``examples/cognic-agent-example-minimal/...`` because
        the relative form starts with ``examples/`` (no leading
        slash). Fix resolves to absolute against cwd, so the
        relative form is now caught."""
        from pydantic import ValidationError

        from cognic_agentos.core.config import Settings

        # Resolve happens against cwd; use a tmp_path with the
        # examples/ structure so the resolve produces a path
        # containing ``/examples/``.
        (tmp_path / "examples" / "agent-pack" / "attestations").mkdir(parents=True)
        monkeypatch.chdir(tmp_path)

        with pytest.raises(ValidationError) as excinfo:
            Settings(
                runtime_profile="prod",
                signing_key_path="examples/agent-pack/attestations/test_signing_key.private.pem",
            )
        assert "signing_key_path_under_test_fixture_tree_in_prod" in str(excinfo.value)

    def test_signing_key_path_relative_tests_fixtures_in_prod_rejected(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """R11 P2 #1 — same bypass concern for relative paths under
        tests/fixtures/."""
        from pydantic import ValidationError

        from cognic_agentos.core.config import Settings

        (tmp_path / "tests" / "fixtures" / "cli_sign_target_pack").mkdir(parents=True)
        monkeypatch.chdir(tmp_path)

        with pytest.raises(ValidationError) as excinfo:
            Settings(
                runtime_profile="prod",
                signing_key_path="tests/fixtures/cli_sign_target_pack/test_signing_key.private.pem",
            )
        assert "signing_key_path_under_test_fixture_tree_in_prod" in str(excinfo.value)

    def test_signing_key_path_vault_uri_in_prod_allowed(self) -> None:
        """R11 P2 #1 — ``vault://`` URIs are NOT filesystem paths
        and cannot be under the test-fixture trees. Real prod
        deployments commonly use vault:// URIs; the guard MUST
        skip them rather than attempting Path.resolve() on a URI
        (which would produce a nonsense local path)."""
        from cognic_agentos.core.config import Settings

        s = Settings(
            runtime_profile="prod",
            signing_key_path="vault://secret/cognic/signing-keys/prod",
            embedding_model=_PROD_EMBED_MODEL,
            sandbox_canonical_runtime_python_image=_PROD_RUNTIME_IMAGE,
            sandbox_canonical_egress_proxy_image=_PROD_PROXY_IMAGE,
        )
        assert s.signing_key_path == "vault://secret/cognic/signing-keys/prod"

    def test_signing_key_path_https_uri_in_prod_allowed(self) -> None:
        """R11 P2 #1 — generalisation: any URI-shaped value (``://``
        present) skips the guard. Defends against future signing
        backends introducing other URI schemes (kms://, hsm://, etc.)
        without forcing them to round-trip through this guard."""
        from cognic_agentos.core.config import Settings

        s = Settings(
            runtime_profile="prod",
            signing_key_path="kms://aws/key/abc123",
            embedding_model=_PROD_EMBED_MODEL,
            sandbox_canonical_runtime_python_image=_PROD_RUNTIME_IMAGE,
            sandbox_canonical_egress_proxy_image=_PROD_PROXY_IMAGE,
        )
        assert s.signing_key_path == "kms://aws/key/abc123"

    def test_prod_uri_signing_key_with_dev_skip_cosign_still_rejected(self) -> None:
        """R12 P2 #1 — the earlier draft's ``return self`` in the
        URI branch short-circuited the dev_mode_skip_cosign guard.
        ``Settings(runtime_profile="prod", signing_key_path="vault://...",
        dev_mode_skip_cosign=True)`` was accepted, which violated
        Doctrine F (dev_mode_skip_cosign MUST be False in prod
        regardless of signing-key shape). Fix routes URI values
        past the fixture-tree check but THROUGH the dev-mode guard;
        this regression pins the corrected behaviour."""
        from pydantic import ValidationError

        from cognic_agentos.core.config import Settings

        with pytest.raises(ValidationError) as excinfo:
            Settings(
                runtime_profile="prod",
                signing_key_path="vault://secret/cognic/signing-keys/prod",
                dev_mode_skip_cosign=True,
            )
        # The dev-mode guard fires (NOT the fixture-tree guard);
        # pin the message text so a future refactor that re-introduces
        # the URI short-circuit trips this test.
        assert "dev_mode_skip_cosign=True is forbidden in prod" in str(excinfo.value)


class TestSprint7AClosedEnumVocabulary:
    """Sprint-7A T1 closed-enum vocabulary per the plan-of-record.

    Three closed-enum literals declared in `cli/__init__.py`:
      - `ValidatorReason` — the union of all per-concern validator
        refusal/warning literals (~25 values at T1 seed; grows during
        T7-T14 per R6 P3 #5).
      - `_WARNING_REASONS` — closed frozenset of warning-severity
        ValidatorReason values; everything else is refusal by
        definition (R3 P2 #2 + R6 P2 #1 doctrine).
      - `severity_for(reason)` helper — single source-of-truth for
        finding severity.

    Plus `DataClass` / `Purpose` / `RetentionPolicy` literals in
    `cli/_governance_vocab.py` (R1 P2 #4) — build-time owner of the
    data-governance vocabulary.
    """

    def test_validator_reason_imports_cleanly(self) -> None:
        from cognic_agentos.cli import ValidatorReason  # noqa: F401

    def test_validator_reason_is_a_literal(self) -> None:
        from typing import get_args

        from cognic_agentos.cli import ValidatorReason

        # Literal[...] returns a non-empty tuple from get_args.
        assert len(get_args(ValidatorReason)) > 0

    def test_validator_reason_has_at_least_seed_count(self) -> None:
        """T1 seed has ~25 values; pin minimum. Final shape grows
        during T7-T14 (per the plan's growth-window note)."""
        from typing import get_args

        from cognic_agentos.cli import ValidatorReason

        assert len(get_args(ValidatorReason)) >= 25

    def test_warning_reasons_subset_of_validator_reason(self) -> None:
        """R3 P2 #2 + R6 P2 #1: every member of `_WARNING_REASONS`
        MUST be a member of `ValidatorReason` (the closed warning
        set is a strict subset of the literal)."""
        from typing import get_args

        from cognic_agentos.cli import _WARNING_REASONS, ValidatorReason

        all_reasons = set(get_args(ValidatorReason))
        assert all_reasons >= _WARNING_REASONS, (
            f"_WARNING_REASONS contains values not in ValidatorReason: "
            f"{_WARNING_REASONS - all_reasons}"
        )

    def test_warning_reasons_contains_oasf_capability_set_missing(self) -> None:
        """T7 identity validator's only Wave-1 warning reason."""
        from cognic_agentos.cli import _WARNING_REASONS

        assert "identity_oasf_capability_set_missing" in _WARNING_REASONS

    def test_severity_for_returns_warning_for_warning_reason(self) -> None:
        from cognic_agentos.cli import severity_for

        assert severity_for("identity_oasf_capability_set_missing") == "warning"

    def test_severity_for_returns_refusal_for_non_warning_reason(self) -> None:
        from cognic_agentos.cli import severity_for

        # Pick a representative refusal reason from the seed.
        assert severity_for("manifest_not_found") == "refusal"

    def test_validator_finding_dataclass_shape(self) -> None:
        """ValidatorFinding(severity, reason, message, payload) with
        affects_exit_code property per R1 P2 #3 + R3 P2 #2."""
        from cognic_agentos.cli import ValidatorFinding

        f = ValidatorFinding(
            severity="refusal",
            reason="manifest_not_found",
            message="manifest file does not exist",
            payload={"path": "/x/y/z"},
        )
        assert f.severity == "refusal"
        assert f.reason == "manifest_not_found"
        assert f.message == "manifest file does not exist"
        assert f.payload == {"path": "/x/y/z"}
        assert f.affects_exit_code is True

    def test_validator_finding_warning_does_not_affect_exit_code(self) -> None:
        from cognic_agentos.cli import ValidatorFinding

        f = ValidatorFinding(
            severity="warning",
            reason="identity_oasf_capability_set_missing",
            message="Wave-1 warning; not a refusal",
        )
        assert f.affects_exit_code is False

    def test_validator_finding_is_attribute_frozen(self) -> None:
        """R11 P3 #2 — narrowed claim: ``frozen=True`` blocks
        attribute reassignment on the finding instance, but
        immutability is **shallow only** (payload is a mutable
        dict). Test only asserts what's actually true."""
        import dataclasses

        from cognic_agentos.cli import ValidatorFinding

        f = ValidatorFinding(severity="refusal", reason="manifest_not_found", message="x")
        with pytest.raises(dataclasses.FrozenInstanceError):
            f.severity = "warning"  # type: ignore[misc]

    def test_validator_finding_is_not_hashable(self) -> None:
        """R11 P3 #2 — pin the actual hashability contract: findings
        are NOT hashable because ``payload`` is a dict. If a future
        refactor changes ``payload``'s type to something hashable,
        this test trips and forces the doctrine doc-update."""
        from cognic_agentos.cli import ValidatorFinding

        f = ValidatorFinding(severity="refusal", reason="manifest_not_found", message="x")
        with pytest.raises(TypeError, match="unhashable"):
            hash(f)

    def test_validator_finding_payload_is_shallowly_mutable(self) -> None:
        """R11 P3 #2 — pin the actual immutability contract:
        ``payload`` is a plain dict and can be mutated by callers.
        The orchestrator treats findings as logically read-only by
        convention, not by enforcement."""
        from cognic_agentos.cli import ValidatorFinding

        f = ValidatorFinding(severity="refusal", reason="manifest_not_found", message="x")
        # Mutating payload succeeds — confirming the shallow-only
        # immutability boundary.
        f.payload["new_key"] = "added_after_construction"
        assert f.payload["new_key"] == "added_after_construction"

    def test_warning_reasons_drift_detector_exhaustive_split(self) -> None:
        """R10 P2 #2 + R3 P2 #2 — assert the exhaustive split:
        set(ValidatorReason) - _WARNING_REASONS == _EXPECTED_REFUSAL_REASONS
        where _EXPECTED_REFUSAL_REASONS is an inline test-side
        frozenset. Adding a literal value without explicitly
        placing it in either set trips this drift detector.

        T1 seed: 1 warning + ~24 refusals = ~25 total. The
        `_EXPECTED_REFUSAL_REASONS` set below pins the seed shape;
        every growth point during T7-T14 MUST update this set in
        the same commit that grows the literal.
        """
        from typing import get_args

        from cognic_agentos.cli import _WARNING_REASONS, ValidatorReason

        _EXPECTED_REFUSAL_REASONS_T1_SEED: frozenset[str] = frozenset(
            {
                # Manifest shape (T6 orchestrator)
                "manifest_not_found",
                "manifest_unparseable_toml",
                "manifest_missing_pack_id",
                "manifest_missing_required_block",
                # Identity (T7) — refusals
                "identity_agent_id_missing",
                "identity_display_name_missing",
                "identity_provider_organization_missing",
                "identity_provider_url_missing",
                "identity_agent_card_url_missing",
                "identity_agent_card_jws_path_missing",
                "identity_agent_card_jws_path_unresolvable",
                # A2A (T8)
                "a2a_wave2_feature_in_wave1_manifest",
                # MCP (T9)
                "mcp_wave2_feature_in_wave1_manifest",
                "mcp_caching_restricted_data_class",
                "mcp_elicitation_form_restricted_data_class",
                # Data governance (T10)
                "data_governance_contract_missing",
                "data_governance_contract_inconsistent_with_risk_tier",
                "data_governance_contract_inconsistent_with_mcp_caching",
                # Risk tier (T11)
                "risk_tier_inconsistent_with_data_classes",
                # Supply chain (T12 + Sprint 7B.3 T2 R-reviewer-round
                # P2 #1 — supply-chain blob_path validator extension).
                "supply_chain_attestation_path_missing",
                "supply_chain_attestation_path_unresolvable",
                "supply_chain_blob_path_unresolvable",
                # Sign (T14 — full Wave-1 bundle generator per Doctrine F;
                # Sprint 7B.3 T2 carry-forward adds two further sign
                # refusal reasons for the bundle-root contract per plan
                # R6 P2 #4 + R-reviewer-round P2 #1).
                "sign_cosign_not_installed",
                "sign_syft_not_installed",
                "sign_grype_not_installed",
                "sign_license_auditor_not_installed",
                "sign_signing_key_unavailable",
                "sign_subprocess_failed",
                "sign_agent_card_jws_signing_failed",
                "sign_provenance_template_render_failed",
                "sign_intoto_layout_template_render_failed",
                "sign_wheel_outside_bundle_root",
                "sign_manifest_blob_path_write_failed",
                # Verify (T14 — offline trust gate per ADR-016 Sprint-7A;
                # R15 pivot adds verify_entry_point_load_failed for the
                # isolated-subprocess EntryPoint.load() probe).
                "verify_cosign_signature_invalid",
                "verify_sbom_digest_mismatch",
                "verify_provenance_invalid",
                "verify_intoto_layout_invalid",
                "verify_attestation_path_unresolvable",
                "verify_agent_card_jws_invalid",
                "verify_trust_root_path_unresolvable",
                "verify_entry_point_load_failed",
                # Hooks (Sprint-7A2 T6 — cli/validators/hooks.py;
                # 9 closed-enum reasons; sub-cases via
                # payload.failure_mode). T1 vocabulary scaffold per
                # the plan-of-record at
                # docs/superpowers/plans/2026-05-09-sprint-7a2-hook-packs-runtime.md.
                "hook_block_shape_invalid",
                "hook_id_invalid",
                "hook_phase_invalid",
                "hook_ordering_class_invalid",
                "hook_timeout_invalid",
                "hook_fail_policy_invalid",
                "hook_pack_kind_constraint_violated",
                "hook_entry_point_mismatch",
                "hook_unresolved_reference",
                # Credentials (Sprint 10.6 T14 — cli/validators/credentials.py
                # per ADR-004 §25 + ADR-017). 17 [credentials.<name>] block
                # refusals covering logical-name grammar + vault_path shape
                # + expected_fields shape + ttl_s + purpose_category +
                # purpose_description + per-block + pack-level + unknown-
                # field rejection, plus 3 runtime block cross-validation
                # refusals (expected_workload_gid required-for-credential-
                # pack + invalid-range + without-credentials) owned by the
                # same validator since they gate on credential block
                # presence. T13 vocabulary scaffold per the plan-of-record
                # at docs/superpowers/plans/2026-05-26-sprint-10.6-
                # workload-credential-projection.md §83-122. Sprint 13.5c4
                # REMOVED credentials_risk_tier_not_permitted_pre_13_5
                # (ADR-014 arc close — high-tier enforcement lives at the
                # runtime approval seams; build-time de-blocking only).
                "credentials_logical_name_invalid_grammar",
                "credentials_logical_name_duplicate",
                "credentials_vault_path_empty",
                "credentials_vault_path_invalid_chars",
                "credentials_vault_path_invalid_shape",
                "credentials_vault_path_exceeds_length",
                "credentials_vault_path_duplicate_across_blocks",
                "credentials_expected_fields_empty",
                "credentials_expected_fields_count_exceeds_maximum",
                "credentials_expected_fields_contains_duplicates",
                "credentials_expected_fields_field_name_invalid_grammar",
                "credentials_expected_fields_reserved_underscore_prefix",
                "credentials_ttl_s_invalid",
                "credentials_purpose_category_invalid_value",
                "credentials_purpose_description_invalid_shape",
                "credentials_count_exceeds_maximum",
                "credentials_unknown_field",
                "runtime_expected_workload_gid_required_for_credential_pack",
                "runtime_expected_workload_gid_invalid_range",
                "runtime_expected_workload_gid_without_credentials",
                # Learning surface (Sprint 11.5c T1 — vocab seed;
                # validator body lands at T2 per ADR-019 §52).
                "learning_surface_violation",
            }
        )

        actual_refusals = set(get_args(ValidatorReason)) - _WARNING_REASONS
        assert actual_refusals == _EXPECTED_REFUSAL_REASONS_T1_SEED, (
            f"ValidatorReason refusal-set drift: "
            f"extra={actual_refusals - _EXPECTED_REFUSAL_REASONS_T1_SEED}, "
            f"missing={_EXPECTED_REFUSAL_REASONS_T1_SEED - actual_refusals}"
        )

    def test_governance_vocab_data_class_imports_cleanly(self) -> None:
        from cognic_agentos.cli._governance_vocab import DataClass  # noqa: F401

    def test_governance_vocab_data_class_is_non_empty_literal(self) -> None:
        from typing import get_args

        from cognic_agentos.cli._governance_vocab import DataClass

        assert len(get_args(DataClass)) > 0

    def test_governance_vocab_purpose_imports_cleanly(self) -> None:
        from typing import get_args

        from cognic_agentos.cli._governance_vocab import Purpose

        assert len(get_args(Purpose)) > 0

    def test_governance_vocab_retention_policy_imports_cleanly(self) -> None:
        from typing import get_args

        from cognic_agentos.cli._governance_vocab import RetentionPolicy

        assert len(get_args(RetentionPolicy)) > 0


class TestSprint7A2HookVocabulary:
    """Sprint-7A2 T1 — hook closed-enum vocabulary drift detectors.

    These tests pin the Wave-1 hook taxonomy added by Sprint-7A2's
    plan-of-record Doctrine Locks A + C + E:

      - HookPhase: 2 values (dlp_pre / dlp_post).
      - HookOrderingClass: 8 values (4 input-side, 4 output-side).
      - HookFailPolicy: 2 values (fail_closed / fail_open).
      - HOOK_ORDERING_RANK + HOOK_ORDERING_CLASS_PHASE: exhaustive
        coverage of every HookOrderingClass value.

    Future phases (memory pre/post per ADR-019; escalation pre per
    ADR-014; egress pre per ADR-017's egress allow-list) land in
    follow-up sprints; growth here MUST be paired with the validator
    + dispatcher updates in the same commit.
    """

    def test_hook_phase_has_wave1_two_values(self) -> None:
        from typing import get_args

        from cognic_agentos.cli._governance_vocab import HookPhase

        assert set(get_args(HookPhase)) == {"dlp_pre", "dlp_post"}

    def test_hook_ordering_class_has_eight_values(self) -> None:
        from typing import get_args

        from cognic_agentos.cli._governance_vocab import HookOrderingClass

        expected = {
            "input_validation",
            "input_authorization",
            "input_redaction",
            "input_normalization",
            "output_validation",
            "output_egress_check",
            "output_redaction",
            "output_masking",
        }
        assert set(get_args(HookOrderingClass)) == expected

    def test_hook_fail_policy_has_two_values(self) -> None:
        from typing import get_args

        from cognic_agentos.cli._governance_vocab import HookFailPolicy

        assert set(get_args(HookFailPolicy)) == {"fail_closed", "fail_open"}

    def test_hook_ordering_rank_covers_every_class(self) -> None:
        """Every HookOrderingClass value MUST appear as a key in
        HOOK_ORDERING_RANK; the dispatcher (Sprint-7A2 T8) reads
        rank for deterministic ordering and KeyError on a missing
        class would be a runtime crash."""
        from typing import get_args

        from cognic_agentos.cli._governance_vocab import (
            HOOK_ORDERING_RANK,
            HookOrderingClass,
        )

        assert set(HOOK_ORDERING_RANK.keys()) == set(get_args(HookOrderingClass))

    def test_hook_ordering_rank_within_phase_is_unique(self) -> None:
        """Within each phase, the input_*/output_* classes must have
        distinct ranks so the dispatcher's ordering is total (no
        ties-by-rank that fall back unpredictably to hook_id alpha)."""
        from cognic_agentos.cli._governance_vocab import (
            HOOK_ORDERING_CLASS_PHASE,
            HOOK_ORDERING_RANK,
        )

        per_phase: dict[str, list[int]] = {"dlp_pre": [], "dlp_post": []}
        for cls, rank in HOOK_ORDERING_RANK.items():
            per_phase[HOOK_ORDERING_CLASS_PHASE[cls]].append(rank)
        for phase, ranks in per_phase.items():
            assert len(ranks) == len(set(ranks)), f"phase={phase} has duplicate ranks: {ranks}"

    def test_hook_ordering_class_phase_covers_every_class(self) -> None:
        """Every HookOrderingClass value MUST appear as a key in
        HOOK_ORDERING_CLASS_PHASE; the validator (Sprint-7A2 T6)
        reads this map to refuse class+phase mismatches and KeyError
        on a missing class would be a refusal-path bug."""
        from typing import get_args

        from cognic_agentos.cli._governance_vocab import (
            HOOK_ORDERING_CLASS_PHASE,
            HookOrderingClass,
        )

        assert set(HOOK_ORDERING_CLASS_PHASE.keys()) == set(get_args(HookOrderingClass))

    def test_hook_ordering_class_phase_input_classes_pair_to_dlp_pre(self) -> None:
        from cognic_agentos.cli._governance_vocab import HOOK_ORDERING_CLASS_PHASE

        for cls, phase in HOOK_ORDERING_CLASS_PHASE.items():
            if cls.startswith("input_"):
                assert phase == "dlp_pre", f"input class {cls} must pair to dlp_pre"

    def test_hook_ordering_class_phase_output_classes_pair_to_dlp_post(self) -> None:
        from cognic_agentos.cli._governance_vocab import HOOK_ORDERING_CLASS_PHASE

        for cls, phase in HOOK_ORDERING_CLASS_PHASE.items():
            if cls.startswith("output_"):
                assert phase == "dlp_post", f"output class {cls} must pair to dlp_post"

    def test_settings_hook_max_timeout_s_default(self) -> None:
        """Settings.hook_max_timeout_s defaults to 30.0 seconds + must
        be > 0; the validator (Sprint-7A2 T6) reads this as the
        per-hook timeout ceiling; the runtime dispatcher
        (Sprint-7A2 T8) enforces the same ceiling at dispatch time."""
        settings = build_settings_without_env_file()
        assert settings.hook_max_timeout_s == 30.0
        assert isinstance(settings.hook_max_timeout_s, float)

    def test_hook_validator_reasons_owned_by_validators_hooks_py(self) -> None:
        """8 of 9 hook_* ValidatorReason entries route to
        ``validators/hooks.py`` ownership; the 9th
        (``hook_pack_kind_constraint_violated``) routes to
        ``validate.py`` because the orchestrator-level forbidden-
        block check (Sprint-7A2 T4: refuse [a2a] / [mcp] for
        kind="hook") emits it BEFORE per-concern dispatch.

        Pinned so a future T6 author cannot accidentally split hook
        reasons across multiple validator files OR drift the
        T4-owned reason back into validators/hooks.py — each closed-
        enum reason lands in exactly one file per the ownership-map
        invariant."""
        from cognic_agentos.cli import _VALIDATOR_REASON_OWNERSHIP, ValidatorReason

        hook_reasons_owned_by_hooks_py: set[ValidatorReason] = {
            "hook_block_shape_invalid",
            "hook_id_invalid",
            "hook_phase_invalid",
            "hook_ordering_class_invalid",
            "hook_timeout_invalid",
            "hook_fail_policy_invalid",
            "hook_entry_point_mismatch",
            "hook_unresolved_reference",
        }
        for reason in hook_reasons_owned_by_hooks_py:
            assert _VALIDATOR_REASON_OWNERSHIP[reason] == "validators/hooks.py", (
                f"hook reason {reason!r} must be owned by validators/hooks.py; "
                f"got {_VALIDATOR_REASON_OWNERSHIP[reason]!r}"
            )
        # The 9th hook reason — the orchestrator-emitted one — is
        # owned by validate.py per Sprint-7A2 T4. Moving it back to
        # validators/hooks.py would break the 1:1 ownership invariant
        # because validate.py would then emit a reason it doesn't own.
        assert _VALIDATOR_REASON_OWNERSHIP["hook_pack_kind_constraint_violated"] == "validate.py"


class TestSprint7B1PackKindVocabulary:
    """Sprint 7B.1 T2 — :data:`PackKind` multi-surface drift detector
    (NARROW form).

    Pins :data:`cognic_agentos.packs.lifecycle.PackKind` alignment with the
    build-time pack-kind surfaces:

    - ``cli.init._SUPPORTED_KINDS`` (Sprint-7A scaffold validator)
    - ``cli.sign._VALID_PACK_KINDS`` (Sprint-7A2 signing-time kind validator)

    The harness surfaces (``cli.test_harness._HARNESS_SUPPORTED_KINDS`` +
    ``cli.test_harness._KIND_TO_ENTRY_POINT_GROUP``) were Wave-1-narrow at
    T2 (``frozenset({"tool"})`` + 3-kind dict) and were widened at
    Sprint-7B.1 T6a to the full four-kind vocabulary. The harness-side
    three-way drift assertion (supported-kinds frozenset == entry-point
    group keys == ``get_args(PackKind)``) lives at
    ``tests/unit/cli/test_harness_vocabulary.py`` per the plan-of-record's
    Doctrine Lock A.

    Adding a 5th pack kind in a future sprint REQUIRES updating every
    surface listed above + the harness surfaces or this test fails — by
    design."""

    def test_pack_kind_aligns_with_init_supported_kinds(self) -> None:
        from typing import get_args

        from cognic_agentos.cli.init import _SUPPORTED_KINDS
        from cognic_agentos.packs.lifecycle import PackKind

        assert set(get_args(PackKind)) == _SUPPORTED_KINDS

    def test_pack_kind_aligns_with_sign_valid_pack_kinds(self) -> None:
        from typing import get_args

        from cognic_agentos.cli.sign import _VALID_PACK_KINDS
        from cognic_agentos.packs.lifecycle import PackKind

        assert set(get_args(PackKind)) == _VALID_PACK_KINDS

    def test_pack_state_is_canonical_11_tuple_per_adr_012(self) -> None:
        """ADR-012 §"Lifecycle states" lines 25-32 — pin the 11-tuple at
        the cross-sprint config layer so the migration CHECK constraint
        (T4) and storage Pydantic Literal (T3) cannot drift apart from the
        state-machine source-of-truth."""
        from typing import get_args

        from cognic_agentos.packs.lifecycle import PackState

        assert set(get_args(PackState)) == {
            "draft",
            "submitted",
            "under_review",
            "approved",
            "rejected",
            "withdrawn",
            "allow_listed",
            "installed",
            "disabled",
            "revoked",
            "uninstalled",
        }


class TestSprint85CheckpointSettings:
    """Settings tests for the Sprint 8.5 sandbox-checkpoint surface.

    Per spec §6 — three additive global Settings fields with explicit
    Field bounds. ``sandbox/reaper.py`` + ``sandbox/checkpoint_store.py``
    read these via the structural ``_CheckpointSettings`` Protocol; the
    real ``Settings`` only conforms once these three fields exist.
    """

    def test_checkpoint_settings_defaults(self) -> None:
        """Defaults match spec §6: 24h retention floor / 10-per-session
        cap / 5-minute reaper sweep cadence."""
        s = Settings(  # type: ignore[call-arg]
            _env_file=None,
            runtime_profile="prod",
            embedding_model=_PROD_EMBED_MODEL,
            sandbox_canonical_runtime_python_image=_PROD_RUNTIME_IMAGE,
            sandbox_canonical_egress_proxy_image=_PROD_PROXY_IMAGE,
        )
        assert s.sandbox_checkpoint_retention_s == 86_400
        assert s.sandbox_max_checkpoints_per_session == 10
        assert s.sandbox_reaper_interval_s == 300

    def test_checkpoint_retention_bounds(self) -> None:
        """Retention floor band: 60s .. 1 year. Below/above is refused."""
        with pytest.raises(ValidationError, match="greater than or equal to 60"):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                runtime_profile="prod",
                sandbox_checkpoint_retention_s=59,
            )
        with pytest.raises(ValidationError, match="less than or equal to 31536000"):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                runtime_profile="prod",
                sandbox_checkpoint_retention_s=31_536_001,
            )

    def test_max_checkpoints_per_session_bounds(self) -> None:
        """Per-session cap band: 1 .. 1000. A cap of 0 would make every
        checkpoint() refuse; above 1000 is an unbounded-storage risk."""
        with pytest.raises(ValidationError, match="greater than or equal to 1"):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                runtime_profile="prod",
                sandbox_max_checkpoints_per_session=0,
            )
        with pytest.raises(ValidationError, match="less than or equal to 1000"):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                runtime_profile="prod",
                sandbox_max_checkpoints_per_session=1001,
            )

    def test_reaper_interval_bounds(self) -> None:
        """Reaper sweep cadence band: 10s .. 1 hour."""
        with pytest.raises(ValidationError, match="greater than or equal to 10"):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                runtime_profile="prod",
                sandbox_reaper_interval_s=9,
            )
        with pytest.raises(ValidationError, match="less than or equal to 3600"):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                runtime_profile="prod",
                sandbox_reaper_interval_s=3601,
            )

    def test_checkpoint_settings_load_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Bank overlays tighten the retention floor + caps via env var
        per spec §6 / ADR-015."""
        monkeypatch.setenv("COGNIC_SANDBOX_CHECKPOINT_RETENTION_S", "3600")
        monkeypatch.setenv("COGNIC_SANDBOX_MAX_CHECKPOINTS_PER_SESSION", "5")
        monkeypatch.setenv("COGNIC_SANDBOX_REAPER_INTERVAL_S", "30")
        s = Settings(  # type: ignore[call-arg]
            _env_file=None,
            runtime_profile="prod",
            embedding_model=_PROD_EMBED_MODEL,
            sandbox_canonical_runtime_python_image=_PROD_RUNTIME_IMAGE,
            sandbox_canonical_egress_proxy_image=_PROD_PROXY_IMAGE,
        )
        assert s.sandbox_checkpoint_retention_s == 3600
        assert s.sandbox_max_checkpoints_per_session == 5
        assert s.sandbox_reaper_interval_s == 30

    def test_max_checkpoints_description_carries_p3r5_wording(self) -> None:
        """The §4.3-amended conditional-eviction wording (P3.r5) must
        survive in the field description — operators diagnosing a
        retention-locked persist() depend on the
        CheckpointMaxPerSessionRetentionLocked exception name being
        discoverable from the Settings field itself."""
        field = Settings.model_fields["sandbox_max_checkpoints_per_session"]
        assert field.description is not None
        assert "CheckpointMaxPerSessionRetentionLocked" in field.description

    def test_sandbox_reaper_enabled_defaults_false(self) -> None:
        """#489 — the production checkpoint reaper is OFF by default.
        AgentOS production runs multiple Kubernetes replicas and the
        Sprint 8.5 reaper is single-instance by design; an operator must
        explicitly enable it on exactly one instance."""
        s = Settings(  # type: ignore[call-arg]
            _env_file=None,
            runtime_profile="prod",
            embedding_model=_PROD_EMBED_MODEL,
            sandbox_canonical_runtime_python_image=_PROD_RUNTIME_IMAGE,
            sandbox_canonical_egress_proxy_image=_PROD_PROXY_IMAGE,
        )
        assert s.sandbox_reaper_enabled is False


def test_evidence_pack_signing_key_path_defaults_none() -> None:
    """#sprint-9 — evidence-pack signing identity is operator-provided;
    unset by default (export fails loud when unset)."""
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.evidence_pack_signing_key_path is None


# ──────────────────────────────────────────────────────────────────────
# Sprint 9.5b C1 — Settings.llm_model_id_map (ADR-013)
# ──────────────────────────────────────────────────────────────────────


class TestC1LLMModelIdMap:
    """Sprint 9.5b C1 — ``Settings.llm_model_id_map`` alias→model_id
    config seam per ADR-013. **User-locked review bar (PR #35 R2
    plan-patch D7 — verbatim from user message):**

    1. ``llm_model_id_map: dict[str, str]`` defaults to ``{}``.
    2. Env input works through ``COGNIC_LLM_MODEL_ID_MAP``.
    3. Invalid JSON / non-string keys or values fail at settings-load
       time.
    4. Existing gateway/config behavior stays unchanged when the map
       is empty (asserted implicitly — the gate-ladder pytest sweep
       across the existing gateway test suite is the proof; default
       ``{}`` is the no-op baseline).
    5. No gateway behavior yet in C1; C2 consumes it.

    Each bar item maps to ≥1 test below per the
    [[feedback_strict_review_off_gate]] discipline.
    """

    def test_llm_model_id_map_defaults_to_empty_dict(self) -> None:
        """Bar #1 — default is the empty dict; opt-in by env-var only."""
        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.llm_model_id_map == {}

    def test_llm_model_id_map_accepts_json_env_form(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Bar #2 — JSON-encoded env-var path. The setting accepts the
        canonical alias→model_id mapping shape used by Sprint 9.5b
        C2's gateway lookup."""
        monkeypatch.setenv(
            "COGNIC_LLM_MODEL_ID_MAP",
            '{"cognic-tier1-dev": "cognic-tier1-acme-v1"}',
        )
        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.llm_model_id_map == {"cognic-tier1-dev": "cognic-tier1-acme-v1"}

    def test_llm_model_id_map_accepts_multi_entry_env_form(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Bar #2 — multi-entry JSON (the realistic prod shape with
        multiple tier-aliases mapped to multiple registered models)."""
        monkeypatch.setenv(
            "COGNIC_LLM_MODEL_ID_MAP",
            '{"cognic-tier1-dev": "cognic-tier1-acme-v1", '
            '"cognic-tier2-dev": "cognic-tier2-acme-v1"}',
        )
        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.llm_model_id_map == {
            "cognic-tier1-dev": "cognic-tier1-acme-v1",
            "cognic-tier2-dev": "cognic-tier2-acme-v1",
        }

    def test_llm_model_id_map_rejects_invalid_json_at_load_time(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Bar #3 — invalid JSON syntax fails at settings-load time
        (NOT at gateway-call time). The fail-loud invariant is
        critical: operators must see the misconfiguration at startup,
        not surface it as a runtime mystery hours later.

        The exception class is implementation-specific: invalid JSON
        syntax is rejected by pydantic-settings at the source-read
        layer (``SettingsError``, BEFORE the Pydantic validator
        runs); a JSON-decodable-but-shape-invalid input (e.g. an
        array, or a dict with non-string values) is rejected by the
        ``dict[str, str]`` validator (``ValidationError``). Both
        satisfy the "fails at settings-load time" contract; pinning
        both classes catches a future pydantic-settings refactor
        that moves the boundary."""
        monkeypatch.setenv("COGNIC_LLM_MODEL_ID_MAP", "not-json{")
        with pytest.raises((ValidationError, SettingsError)):
            Settings(_env_file=None)  # type: ignore[call-arg]

    def test_llm_model_id_map_rejects_json_non_dict_shape(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Bar #3 — valid JSON that is not a dict (e.g. an array)
        rejected at load time. ``dict[str, str]`` annotation is the
        gate."""
        monkeypatch.setenv("COGNIC_LLM_MODEL_ID_MAP", '["a", "b"]')
        with pytest.raises(ValidationError):
            Settings(_env_file=None)  # type: ignore[call-arg]

    def test_llm_model_id_map_rejects_non_string_values(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Bar #3 — JSON dict with a non-string value (e.g. int 123)
        rejected at load time per the ``dict[str, str]`` annotation."""
        monkeypatch.setenv("COGNIC_LLM_MODEL_ID_MAP", '{"cognic-tier1-dev": 123}')
        with pytest.raises(ValidationError):
            Settings(_env_file=None)  # type: ignore[call-arg]

    def test_llm_model_id_map_rejects_null_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Bar #3 — JSON ``null`` value rejected. The annotation is
        ``dict[str, str]``, NOT ``dict[str, str | None]`` — an alias
        either maps to a model_id or is absent from the map; null is
        not a meaningful state."""
        monkeypatch.setenv("COGNIC_LLM_MODEL_ID_MAP", '{"cognic-tier1-dev": null}')
        with pytest.raises(ValidationError):
            Settings(_env_file=None)  # type: ignore[call-arg]

    def test_llm_model_id_map_rejects_non_string_keys_at_construction(self) -> None:
        """Bar #3 — non-string KEYS fail at settings-load time
        (user-found PR #35 R2 C1 coverage pin). JSON env input cannot
        express non-string object keys (the JSON spec mandates string
        keys at the syntax layer), so this case is unreachable via
        ``COGNIC_LLM_MODEL_ID_MAP=...`` and must be pinned via direct
        construction. Pydantic v2's ``dict[str, str]`` validator
        rejects the int key at construction; the test pins the
        contract so a future relaxation of the annotation surface
        (e.g. ``dict[Any, Any]``) would be caught here, NOT discovered
        as a runtime mystery when an operator passes a misshapen
        config dict programmatically."""
        with pytest.raises(ValidationError):
            Settings(  # type: ignore[call-arg]
                _env_file=None,
                llm_model_id_map={1: "cognic-tier1-acme-v1"},  # type: ignore[dict-item]
            )

    # NOTE: ``test_c1_does_not_touch_llm_gateway_module`` was REMOVED
    # at Sprint 9.5b C2 per the user-locked review-bar item #5 ("the
    # transitional C1 'gateway does not mention llm_model_id_map'
    # test is deleted in the same commit and replaced with a positive
    # C2 pin"). The positive replacement lives at
    # ``tests/unit/llm/test_gateway_model_id.py`` —
    # ``test_construction_sites_use_settings_llm_model_id_map_get``
    # asserts the lookup expression appears at EXACTLY 2 sites
    # (the strict + best-effort ledger-write helpers). The deletion
    # is the documented action when the deferral expires; see the C2
    # commit body for the bisection-clean rationale.


# ──────────────────────────────────────────────────────────────────────
# Sprint 10 T2 — Settings.vault_http_timeout_s + vault_http_max_retries
# ──────────────────────────────────────────────────────────────────────


class TestT2VaultHTTPSettings:
    """Sprint 10 T2 — two new Settings fields drive the shared
    ``VaultTransport`` per spec §3.5 + §8.2: ``vault_http_timeout_s``
    (per-request hvac timeout in seconds; bounded ``0 < x ≤ 60``)
    and ``vault_http_max_retries`` (bounded exponential-backoff
    count; bounded ``0 ≤ x ≤ 10``).

    Mirrors the Sprint 9.5b C1 pattern: bounded settings + invalid-
    value-fails-loud at construction time so misconfigured operators
    see the error at startup, not at first Vault round-trip.
    """

    def test_vault_http_timeout_s_default(self) -> None:
        """T2 #11 — ``vault_http_timeout_s`` defaults to ``10.0``
        seconds; Sprint-1C VaultAdapter convention preserved."""
        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.vault_http_timeout_s == 10.0

    def test_vault_http_max_retries_default(self) -> None:
        """T2 #12 — ``vault_http_max_retries`` defaults to ``3``
        (bounded exponential-backoff for transient hvac failures)."""
        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.vault_http_max_retries == 3

    def test_vault_http_timeout_s_must_be_positive(self) -> None:
        """T2 #13 — ``vault_http_timeout_s > 0``; fail-loud on a
        zero or negative value (would hang forever or never
        complete; misconfigured operator must see the error at
        startup)."""
        with pytest.raises(ValidationError):
            Settings(_env_file=None, vault_http_timeout_s=0.0)  # type: ignore[call-arg]

    def test_vault_http_timeout_s_must_be_bounded(self) -> None:
        """T2 #14 — ``vault_http_timeout_s ≤ 60.0``; defensive upper
        bound matches the 60s ceiling on most HTTP-client timeouts.
        Operators wanting a longer timeout must use a different
        primitive (e.g. background poll loop), not extend
        per-request timeout indefinitely."""
        with pytest.raises(ValidationError):
            Settings(_env_file=None, vault_http_timeout_s=120.0)  # type: ignore[call-arg]

    def test_vault_http_max_retries_must_be_non_negative(self) -> None:
        """T2 #15 — ``vault_http_max_retries ≥ 0`` (0 = no retries
        is a legitimate setting; negative is misconfig)."""
        with pytest.raises(ValidationError):
            Settings(_env_file=None, vault_http_max_retries=-1)  # type: ignore[call-arg]

    def test_vault_http_max_retries_must_be_bounded(self) -> None:
        """T2 #16 — ``vault_http_max_retries ≤ 10``; defensive upper
        bound on retry count (10 retries x bounded backoff = bounded
        total wall-clock; higher values would let a misconfigured
        operator hang the gateway for minutes per call)."""
        with pytest.raises(ValidationError):
            Settings(_env_file=None, vault_http_max_retries=100)  # type: ignore[call-arg]


class TestT8SandboxKernelDefaultMaxCredentialTtl:
    """Sprint 10 T8 — ``Settings.sandbox_kernel_default_max_credential_ttl_s``
    drives the per-tenant max credential TTL cap per spec §5.1 + §5.2.

    The Setting is threaded into the Rego input dict's
    ``kernel_default.max_credential_ttl_s`` field at
    ``sandbox/admission.py`` Step 9 and consumed by
    ``policies/_default/sandbox.rego`` rule 6 (positive
    ``_credential_ttl_within_tenant_max`` helper joined to the
    ``allow if`` conjunction). Bank overlays may raise via the Rego
    ``tenant.overlay.max_credential_ttl_s`` path (per-tenant overlay
    plumbing is a future-sprint hook); LOOSENING the kernel default
    requires a coordinated kernel + ADR amendment per the stop-rule
    policy bundle precedent at AGENTS.md L150.
    """

    def test_default_is_900_seconds(self) -> None:
        """T8 #1 — kernel default = 900s (15 minutes) per the
        conservative-Wave-1-default doctrine in spec §5.2."""
        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.sandbox_kernel_default_max_credential_ttl_s == 900

    def test_lower_bound_60_seconds(self) -> None:
        """T8 #2 — ``sandbox_kernel_default_max_credential_ttl_s ≥ 60``
        (1-minute floor: shorter TTLs cause an unacceptable Vault-mint
        round-trip rate; misconfig must fail at startup, not at first
        admission)."""
        # 60s is the floor — accepted.
        s = Settings(_env_file=None, sandbox_kernel_default_max_credential_ttl_s=60)  # type: ignore[call-arg]
        assert s.sandbox_kernel_default_max_credential_ttl_s == 60
        # 59s is below the floor — refused.
        with pytest.raises(ValidationError):
            Settings(_env_file=None, sandbox_kernel_default_max_credential_ttl_s=59)  # type: ignore[call-arg]

    def test_upper_bound_86400_seconds(self) -> None:
        """T8 #3 — ``sandbox_kernel_default_max_credential_ttl_s ≤ 86400``
        (24-hour ceiling: longer kernel-default TTLs widen the
        compromise window unacceptably; bank overlays raise via
        Rego ``tenant.overlay.max_credential_ttl_s`` per spec §5.2,
        not by raising the kernel-default ceiling)."""
        # 86400s is the ceiling — accepted.
        s = Settings(_env_file=None, sandbox_kernel_default_max_credential_ttl_s=86400)  # type: ignore[call-arg]
        assert s.sandbox_kernel_default_max_credential_ttl_s == 86400
        # 86401s is above the ceiling — refused.
        with pytest.raises(ValidationError):
            Settings(_env_file=None, sandbox_kernel_default_max_credential_ttl_s=86401)  # type: ignore[call-arg]


class TestSprint105SchedulerSettings:
    """Sprint 10.5a T6 — ADR-022 scheduler primitive Settings (spec §4.1
    + §4.5). Tests pin BOUNDED INVARIANTS (each cap must be positive
    integer; the queue TTL must be at least 1 second) rather than
    specific defaults — defaults are operator-tunable per the plan-of-
    record but the invariants are wire-protocol-public for the
    SchedulerEngine + reap_expired wiring at T11.

    Mirrors the ConcurrencyCaps + BoundedQueue bounded-invariant tests
    at ``tests/unit/core/scheduler/test_queue.py`` so the Settings
    layer + the in-memory primitives reject the same illegal-shape
    inputs.
    """

    def test_all_ten_scheduler_settings_have_positive_defaults(self) -> None:
        """All 10 fields must satisfy the bounded invariant — defaults
        can change per operator tuning; the positive bound cannot. Sprint 13.7
        (ADR-022) added the 3 composition-root settings (policy bundle + the two
        class SLAs)."""
        from cognic_agentos.core.config import Settings

        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.scheduler_queue_depth_interactive >= 1
        assert s.scheduler_queue_depth_background >= 1
        assert s.scheduler_per_tenant_interactive >= 1
        assert s.scheduler_per_tenant_background >= 1
        assert s.scheduler_per_pack >= 1
        assert s.scheduler_per_actor >= 1
        assert s.scheduler_queue_ttl_s >= 1
        # Sprint 13.7 (ADR-022) — composition-root settings.
        assert s.scheduler_class_sla_interactive_s > 0
        assert s.scheduler_class_sla_background_s > 0
        assert str(s.scheduler_policy_bundle).endswith("scheduler.rego")

    def test_queue_depth_interactive_rejects_zero(self) -> None:
        from cognic_agentos.core.config import Settings

        with pytest.raises(ValidationError):
            Settings(_env_file=None, scheduler_queue_depth_interactive=0)  # type: ignore[call-arg]

    def test_queue_depth_background_rejects_zero(self) -> None:
        from cognic_agentos.core.config import Settings

        with pytest.raises(ValidationError):
            Settings(_env_file=None, scheduler_queue_depth_background=0)  # type: ignore[call-arg]

    def test_per_tenant_interactive_rejects_zero(self) -> None:
        from cognic_agentos.core.config import Settings

        with pytest.raises(ValidationError):
            Settings(_env_file=None, scheduler_per_tenant_interactive=0)  # type: ignore[call-arg]

    def test_per_tenant_background_rejects_zero(self) -> None:
        from cognic_agentos.core.config import Settings

        with pytest.raises(ValidationError):
            Settings(_env_file=None, scheduler_per_tenant_background=0)  # type: ignore[call-arg]

    def test_per_pack_rejects_zero(self) -> None:
        from cognic_agentos.core.config import Settings

        with pytest.raises(ValidationError):
            Settings(_env_file=None, scheduler_per_pack=0)  # type: ignore[call-arg]

    def test_per_actor_rejects_zero(self) -> None:
        from cognic_agentos.core.config import Settings

        with pytest.raises(ValidationError):
            Settings(_env_file=None, scheduler_per_actor=0)  # type: ignore[call-arg]

    def test_queue_ttl_s_rejects_zero(self) -> None:
        from cognic_agentos.core.config import Settings

        with pytest.raises(ValidationError):
            Settings(_env_file=None, scheduler_queue_ttl_s=0)  # type: ignore[call-arg]

    def test_queue_ttl_s_rejects_negative(self) -> None:
        from cognic_agentos.core.config import Settings

        with pytest.raises(ValidationError):
            Settings(_env_file=None, scheduler_queue_ttl_s=-1)  # type: ignore[call-arg]

    def test_per_actor_accepts_minimum_one(self) -> None:
        """Bounded-invariant pin: each cap must accept its minimum
        valid value (1). Defaults are higher but the FLOOR is 1."""
        from cognic_agentos.core.config import Settings

        s = Settings(_env_file=None, scheduler_per_actor=1)  # type: ignore[call-arg]
        assert s.scheduler_per_actor == 1

    def test_operator_overrides_accepted(self) -> None:
        """Operator overrides must flow through Pydantic — confirms
        the fields are not accidentally read-only or property-shadowed."""
        from cognic_agentos.core.config import Settings

        s = Settings(  # type: ignore[call-arg]
            _env_file=None,
            scheduler_queue_depth_interactive=64,
            scheduler_per_tenant_background=128,
            scheduler_queue_ttl_s=600,
        )
        assert s.scheduler_queue_depth_interactive == 64
        assert s.scheduler_per_tenant_background == 128
        assert s.scheduler_queue_ttl_s == 600


class TestCanonicalImageSettings:
    """T30 / T10 — canonical sandbox image refs + canonical trust-root path.

    Real digest-pinned defaults (the AgentOS-signed canonical images produced by
    the T9 runbook; Option B — no placeholder defaults), env-overridable via the
    ``COGNIC_SANDBOX_CANONICAL_*`` prefix, with a digest-shape validator that
    refuses tag-only / malformed refs (canonical images MUST be immutable).
    """

    _RP_REF = (
        "ghcr.io/bmzee/cognic-agentos/sandbox-runtime-python@sha256:"
        "b9ed3440ebf8535ba779f574b3c12a45095720ce78c292d8cc5cd338990e8eac"
    )
    _EP_REF = (
        "ghcr.io/bmzee/cognic-agentos/sandbox-egress-proxy@sha256:"
        "eb4ea75b427d0bc42039c68039eec51d6b0d0789400ba5bfdbf470ebec9139aa"
    )

    @staticmethod
    def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
        for var in (
            "COGNIC_SANDBOX_CANONICAL_RUNTIME_PYTHON_IMAGE",
            "COGNIC_SANDBOX_CANONICAL_EGRESS_PROXY_IMAGE",
            "COGNIC_SANDBOX_CANONICAL_IMAGE_TRUST_ROOT_PATH",
        ):
            monkeypatch.delenv(var, raising=False)

    def test_real_digest_pinned_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._clear_env(monkeypatch)
        s = build_settings_without_env_file()
        assert s.sandbox_canonical_runtime_python_image == self._RP_REF
        assert s.sandbox_canonical_egress_proxy_image == self._EP_REF
        assert "@sha256:" in s.sandbox_canonical_runtime_python_image
        assert "@sha256:" in s.sandbox_canonical_egress_proxy_image
        # Trust-root path defaults to None — the operator points it at the
        # canonical cosign public key via env; no dev/operator path is baked
        # into the kernel default (mirrors signing_trust_root_path).
        assert s.sandbox_canonical_image_trust_root_path is None

    def test_env_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rp = "registry.example.com/cognic/sandbox-runtime-python@sha256:" + "a" * 64
        ep = "registry.example.com/cognic/sandbox-egress-proxy@sha256:" + "b" * 64
        monkeypatch.setenv("COGNIC_SANDBOX_CANONICAL_RUNTIME_PYTHON_IMAGE", rp)
        monkeypatch.setenv("COGNIC_SANDBOX_CANONICAL_EGRESS_PROXY_IMAGE", ep)
        monkeypatch.setenv(
            "COGNIC_SANDBOX_CANONICAL_IMAGE_TRUST_ROOT_PATH", "/etc/cognic/canonical-cosign.pub"
        )
        s = Settings()
        assert s.sandbox_canonical_runtime_python_image == rp
        assert s.sandbox_canonical_egress_proxy_image == ep
        assert s.sandbox_canonical_image_trust_root_path == Path("/etc/cognic/canonical-cosign.pub")

    def test_rejects_tag_only_ref_no_digest(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._clear_env(monkeypatch)
        with pytest.raises(ValidationError, match="digest-pinned"):
            Settings(sandbox_canonical_runtime_python_image="ghcr.io/x/sandbox-runtime-python:v1")

    def test_rejects_malformed_digest(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._clear_env(monkeypatch)
        # @sha256: present but the digest is not 64 lowercase-hex chars.
        with pytest.raises(ValidationError, match="digest-pinned"):
            Settings(sandbox_canonical_egress_proxy_image="ghcr.io/x/proxy@sha256:deadbeef")

    def test_rejects_missing_ref_before_digest(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # P2: a valid digest tail with an EMPTY ref prefix must be refused —
        # "@sha256:<64-hex>" is not a usable image reference, despite the digest
        # being well-formed.
        self._clear_env(monkeypatch)
        with pytest.raises(ValidationError, match="non-empty"):
            Settings(sandbox_canonical_runtime_python_image="@sha256:" + "a" * 64)

    def test_rejects_whitespace_in_ref(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The ref prefix must be whitespace-free (a real OCI ref never contains
        # whitespace); a space-bearing prefix is refused.
        self._clear_env(monkeypatch)
        with pytest.raises(ValidationError, match="whitespace-free"):
            Settings(sandbox_canonical_egress_proxy_image="ghcr.io/x y@sha256:" + "a" * 64)

    def test_accepts_valid_digest_pinned_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._clear_env(monkeypatch)
        ref = "registry.example.com/img@sha256:" + "c" * 64
        s = Settings(sandbox_canonical_runtime_python_image=ref)
        assert s.sandbox_canonical_runtime_python_image == ref
