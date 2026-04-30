"""Runtime configuration loader.

Layer classification: **platform primitive**.

Per the Phase-1 production-grade principles in ``docs/BUILD_PLAN.md``:
operational values (host, port, profile, timeouts, log levels, ...) are loaded
from environment variables here. No environment-specific value lives in source
elsewhere. Constants — route names, protocol identifiers, package metadata,
defaults declared on this class — are not "hardcoding" and are allowed.

Sprint 1A ships only server + profile fields. Sprint 1B/1C add observability,
adapter, and gateway groups under additional ``Settings`` subclasses or fields.
"""

from __future__ import annotations

import os
import platform
import sys
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from cognic_agentos import __version__

RuntimeProfile = Literal["dev", "stage", "prod"]

# Sentinel used by ``get_settings()`` to suppress the ``.env`` lookup in the
# ``prod`` profile. Pydantic-Settings treats ``_env_file=None`` at construction
# time as "ignore the class-level ``env_file`` setting".
_PROD_PROFILE_ENV_VAR = "COGNIC_RUNTIME_PROFILE"


class Settings(BaseSettings):
    """Top-level settings container.

    Loaded from environment variables with the ``COGNIC_`` prefix. In ``dev``
    and ``stage`` profiles a local ``.env`` file is also read (env vars always
    win over ``.env``). In ``prod`` profile ``.env`` is **not** read at all —
    operators must pass every value via the container runtime. The profile is
    detected from the environment in ``get_settings()`` *before* this class is
    instantiated, and the suppression is applied via ``_env_file=None``.
    """

    model_config = SettingsConfigDict(
        env_prefix="COGNIC_",
        env_file=".env",  # overridden to None in prod by get_settings()
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Server -------------------------------------------------------
    host: str = Field(default="127.0.0.1", description="Bind host for the HTTP server.")
    port: int = Field(default=8000, ge=1, le=65535, description="Bind port for the HTTP server.")
    api_prefix: str = Field(
        default="/api/v1",
        description="Prefix mounted in front of every portal route.",
    )

    # --- Profile + log level -----------------------------------------
    runtime_profile: RuntimeProfile = Field(
        default="dev",
        description="Operational profile. `prod` flips multiple security defaults closed.",
    )
    log_level: str = Field(
        default="INFO",
        description="Default logging level for the structured-logging stack.",
    )
    log_format: Literal["json", "text"] = Field(
        default="json",
        description=(
            "`json` is the production default — structured logs flow into the audit "
            "+ SIEM pipeline. `text` is a developer convenience only."
        ),
    )

    # --- Observability (Sprint 1B) -----------------------------------
    otel_exporter_endpoint: str | None = Field(
        default=None,
        description=(
            "OTLP gRPC endpoint for trace export (e.g. otel-collector:4317). "
            "When unset, the OTel tracer falls back to a console exporter in dev "
            "and a no-op exporter in prod (so traces are silently dropped rather "
            "than printed to stdout)."
        ),
    )
    otel_exporter_insecure: bool = Field(
        default=False,
        description=(
            "When True, OTLP traffic skips TLS — only safe for local-collector "
            "dev work. Bank-grade default is False (TLS required). Operators "
            "must explicitly opt in to insecure transport via env var."
        ),
    )
    otel_exporter_ca_cert_path: Path | None = Field(
        default=None,
        description=(
            "Path to a PEM-encoded CA certificate bundle to verify the OTLP "
            "collector's TLS certificate. Typically a Vault-mounted secret in "
            "prod. When set, mTLS is implied if client cert/key are also set."
        ),
    )
    otel_exporter_client_cert_path: Path | None = Field(
        default=None,
        description=(
            "Path to a PEM-encoded client certificate for mTLS to the OTLP "
            "collector. Set together with otel_exporter_client_key_path."
        ),
    )
    otel_exporter_client_key_path: Path | None = Field(
        default=None,
        description=(
            "Path to a PEM-encoded client private key for mTLS to the OTLP "
            "collector. Set together with otel_exporter_client_cert_path."
        ),
    )
    prometheus_metrics_path: str = Field(
        default="/metrics",
        description="Path the Prometheus instrumentator exposes the scrape endpoint at "
        "(joined under api_prefix).",
    )
    # ``NoDecode`` tells pydantic-settings NOT to JSON-decode the env value
    # into a list before field validators run. Without it, the
    # ``EnvSettingsSource`` parses the raw string as JSON at source-read
    # time and an empty/comma-separated value raises ``SettingsError``
    # before any validator can normalise it. With ``NoDecode`` the raw
    # string lands in the ``mode="before"`` validator below, which
    # accepts comma-separated, JSON-array, and empty-string forms.
    cors_allowed_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description=(
            "Allow-list of origins permitted by the CORS middleware. The literal "
            "string `*` is forbidden (per Phase-1 'CORS allow-list-only' principle). "
            "Env-var input may be either a comma-separated string "
            "(`https://a.example,https://b.example`) or a JSON array "
            '(`["https://a.example","https://b.example"]`); empty string = empty list.'
        ),
    )

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def _split_cors_origins(cls, value: object) -> list[str]:
        """Normalize env-var input to a list of trimmed, non-empty origins.

        Pydantic-Settings 2.x parses ``list[str]`` env values as JSON by
        default, which means a comma-separated env value (the most
        operator-friendly form) raises ``SettingsError`` at startup. This
        before-validator accepts:

        - ``None`` / empty string → ``[]``
        - JSON array string → parse as JSON
        - Comma-separated string → split + strip
        - Already-a-list (programmatic construction in tests) → identity

        Whatever shape arrives, the post-normalisation list goes through
        the wildcard-refusal validator below.
        """

        if value is None:
            return []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            if stripped.startswith("["):
                # JSON array — let pydantic-settings' default parser handle
                # it by returning the string unchanged. (Falls through to
                # the standard list-of-str coercion.)
                import json as _json

                parsed = _json.loads(stripped)
                if not isinstance(parsed, list):
                    raise ValueError("cors_allowed_origins JSON value must be a list of strings")
                return [str(item).strip() for item in parsed if str(item).strip()]
            return [origin.strip() for origin in stripped.split(",") if origin.strip()]
        raise ValueError(
            f"cors_allowed_origins must be list, JSON array, or comma-separated "
            f"string; got {type(value).__name__}"
        )

    @field_validator("cors_allowed_origins")
    @classmethod
    def _refuse_cors_wildcard(cls, value: list[str]) -> list[str]:
        if any(origin.strip() == "*" for origin in value):
            raise ValueError(
                "CORS allow-list rejects `*` per Phase-1 'CORS allow-list-only' "
                "principle in BUILD_PLAN.md. Declare each origin explicitly."
            )
        return value

    def model_post_init(self, __context: object) -> None:
        # mTLS pair check — client cert AND key must be set together; one
        # without the other is a misconfiguration that would silently fall
        # back to plain TLS.
        cert = self.otel_exporter_client_cert_path
        key = self.otel_exporter_client_key_path
        if (cert is None) != (key is None):
            raise ValueError(
                "otel_exporter_client_cert_path and "
                "otel_exporter_client_key_path must be set together (mTLS pair)."
            )

    # --- Adapters (Sprint 1C, per ADR-009) ---------------------------
    # Drivers are plain ``str`` so unknown values flow to the factory's
    # ``AdapterNotInstalled`` error path. The bundled set lives in
    # ``cognic_agentos.db.adapters.registry``; alternative drivers install
    # as plugin packs (per ADR-002) and self-register on import.

    db_driver: str = Field(
        default="postgres",
        description=(
            "Relational adapter driver. Bundled: postgres, oracle (Sprint 1D). "
            "Plugin packs: mssql, mysql."
        ),
    )
    database_url: str | None = Field(
        default=None,
        description="SQLAlchemy URL (e.g. postgresql+asyncpg://user:pass@host:5432/db).",
    )

    vector_driver: str = Field(
        default="qdrant",
        description=(
            "Vector adapter driver. Bundled: qdrant. "
            "Plugin packs: chroma, weaviate, pgvector, milvus."
        ),
    )
    qdrant_url: str | None = Field(
        default=None,
        description="Qdrant HTTP endpoint (e.g. http://qdrant:6333).",
    )
    qdrant_collection: str = Field(
        default="cognic_default",
        description="Default Qdrant collection name for upsert/search.",
    )

    secret_driver: str = Field(
        default="vault",
        description=("Secrets adapter driver. Bundled: vault. Plugin packs: aws, azure, cyberark."),
    )
    vault_addr: str | None = Field(
        default=None,
        description="Vault address (e.g. http://vault:8200).",
    )
    vault_token: str | None = Field(
        default=None,
        description=(
            "Vault token. Dev-only when set in source; prod uses Kubernetes auth "
            "or AppRole and never leaves Vault."
        ),
    )
    vault_namespace: str | None = Field(
        default=None,
        description="Vault Enterprise namespace (None = default namespace).",
    )

    embed_driver: str = Field(
        default="ollama",
        description=(
            "Embedding adapter driver. Bundled (dev): ollama. "
            "Bundled (prod, Sprint 1D): openai_compat."
        ),
    )
    embedding_model: str = Field(
        default="qwen3-embedding:8b",
        description=("Embedding model identifier (Ollama model tag or OpenAI-compat model name)."),
    )
    embedding_base_url: str | None = Field(
        default=None,
        description="Embedding service HTTP endpoint (e.g. http://ollama:11434).",
    )
    embedding_dimensions: int = Field(
        default=1024,
        ge=1,
        description="Vector dimensions emitted by the embedding model. Operators set per model.",
    )

    obs_driver: str = Field(
        default="langfuse_otel",
        description=(
            "Observability adapter driver. Bundled: langfuse_otel. "
            "Bundled (Sprint 1D): dynatrace. Plugin packs: splunk, datadog, newrelic."
        ),
    )
    langfuse_host: str | None = Field(
        default=None,
        description="Langfuse host (e.g. http://langfuse:3000).",
    )
    langfuse_public_key: str | None = Field(
        default=None,
        description="Langfuse public API key.",
    )
    langfuse_secret_key: str | None = Field(
        default=None,
        description=("Langfuse secret API key. Dev-only when set in source; prod uses Vault."),
    )

    # --- Sprint 1D enterprise-adapter settings -----------------------
    # Dynatrace observability: tenant URL + API token + reserved
    # vault-path field. Sprint 1D takes the API token via direct env
    # (or operator-side secret-mount); native runtime Vault resolution
    # of `dynatrace_api_token_vault_path` lands in Sprint 10 alongside
    # Vault credential leasing.
    dynatrace_tenant_url: str | None = Field(
        default=None,
        description="Dynatrace tenant URL (e.g. https://abc12345.live.dynatrace.com).",
    )
    dynatrace_api_token: str | None = Field(
        default=None,
        description=(
            "Dynatrace API token (header form: Api-Token <value>). "
            "Dev-only when set in source; prod sources via Vault (Sprint 10). "
            "Required scopes: metrics.read (health probe) + metrics.ingest (emit_metric)."
        ),
    )
    dynatrace_api_token_vault_path: str | None = Field(
        default=None,
        description=(
            "Reserved Vault path for the Dynatrace API token. "
            "Sprint 1D does NOT consume this — adapter takes the resolved "
            "token directly via ``dynatrace_api_token``. Sprint 10 wires "
            "runtime Vault resolution from this path."
        ),
    )

    # OpenAI-compat embedding: provider_label declares which backend the
    # configured base_url actually points at. Storage-only in Sprint 1D;
    # per-embed audit emission lands with Sprint 2 ``core/audit``.
    embed_provider_label: str = Field(
        default="openai_compat",
        description=(
            "Audit label for OpenAI-compat embedding backend. "
            "Known values: vllm, sglang, openai, azure_oai, bedrock, cohere, openai_compat. "
            "Unknown values accepted at config layer (str-typed) — the adapter forwards "
            "the label verbatim to audit emissions."
        ),
    )

    # OpenAI-compat embedding auth surface. Default = no auth (vLLM /
    # SGLang local). Set ``embedding_api_key`` for cloud providers; the
    # ``embedding_api_key_header`` toggles between ``Authorization`` (with
    # implicit ``Bearer `` prefix — OpenAI/Cohere) and a custom header
    # name (e.g. ``api-key`` for Azure-OpenAI proxies). ``extra_headers``
    # carries provider-specific quirks like Azure's ``api-version``.
    embedding_api_key: str | None = Field(
        default=None,
        description=(
            "OpenAI-compat embedding API key. None = no-auth (vLLM/SGLang local). "
            "Dev-only when set in source; prod sources via Vault (Sprint 10)."
        ),
    )
    embedding_api_key_header: str = Field(
        default="Authorization",
        description=(
            "Header name to send the embedding API key under. Defaults to "
            "``Authorization`` (adapter prefixes value with ``Bearer ``). "
            "Set to ``api-key`` for Azure OpenAI proxies (raw value, no prefix)."
        ),
    )
    embedding_api_key_vault_path: str | None = Field(
        default=None,
        description=(
            "Reserved Vault path for the embedding API key. "
            "Sprint 1D does NOT consume this — adapter takes the resolved "
            "key directly via ``embedding_api_key``. Sprint 10 wires "
            "runtime Vault resolution from this path."
        ),
    )
    embedding_extra_headers: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Optional extra headers to send on every /v1/embeddings + "
            "/v1/models request. Common uses: Azure ``api-version``, "
            "custom proxy auth tokens, observability correlation IDs. "
            "Env-var form is JSON-encoded (e.g. "
            '\'{"api-version": "2024-02-15-preview"}\').'
        ),
    )

    # --- LLM gateway (Sprint 3, per ADR-007) -------------------------
    # Drive the Sprint 3 cloud-policy enforcer + provider-honesty
    # ledger feed. self-hosted-first defaults: ``allow_external_llm``
    # closed; ``allowed_providers`` empty; ``policy_mode`` self-hosted.
    # The ``Tier alias / LiteLLM alias / ResolvedUpstream`` three-layer
    # model is enforced at the gateway boundary, not here — this layer
    # ships only the operator-facing knobs.
    tier1_alias: str = Field(
        default="cognic-tier1-dev",
        description="LiteLLM alias resolved when caller asks for tier=tier1.",
    )
    tier2_alias: str = Field(
        default="cognic-tier2-dev",
        description="LiteLLM alias resolved when caller asks for tier=tier2.",
    )
    litellm_base_url: str | None = Field(
        default=None,
        description="LiteLLM router base URL (e.g. http://litellm:4000).",
    )
    litellm_master_key: str | None = Field(
        default=None,
        description=(
            "LiteLLM master key. Dev-only when set in source; prod sources via Vault (Sprint 10)."
        ),
    )
    allow_external_llm: bool = Field(
        default=False,
        description=("Master cloud-policy gate per ADR-007. Default closed = self-hosted-first."),
    )
    policy_mode: Literal["self_hosted", "cloud_openai", "cloud_anthropic", "cloud_mixed"] = Field(
        default="self_hosted",
        description=(
            "Operator-declared deployment mode. Cross-checked against "
            "allow_external_llm at the gateway."
        ),
    )
    # ``NoDecode`` for the same reason as ``cors_allowed_origins`` —
    # pydantic-settings would otherwise JSON-parse the env var at source-
    # read time and reject the operator-friendly comma-separated form.
    allowed_providers: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description=(
            "Allow-list of external provider prefixes "
            "(``openai``, ``azure``, ``anthropic``, ``bedrock``, ``cohere``). "
            "Empty = self-hosted-only. Env-var input may be either a "
            "comma-separated string or a JSON array; values are lowercased."
        ),
    )
    llm_timeout_s: float = Field(
        default=30.0,
        gt=0.0,
        description="Per-call httpx timeout to LiteLLM, in seconds.",
    )
    llm_concurrency_per_profile: int = Field(
        default=4,
        ge=1,
        description="Max in-flight gateway calls per profile (tier1/tier2).",
    )
    llm_concurrency_mode: Literal["queued", "fail_fast"] = Field(
        default="queued",
        description=(
            "``queued`` blocks on a free slot. ``fail_fast`` raises "
            "``LLMConcurrencyExceeded`` immediately when saturated."
        ),
    )
    provider_honesty_ledger_window_minutes: int = Field(
        default=60,
        ge=1,
        le=1440,
        description=(
            "Window ``/api/v1/system/effective-routing`` reads from the "
            "``gateway_call_ledger`` (per ADR-007). Capped at 24h."
        ),
    )

    @field_validator("allowed_providers", mode="before")
    @classmethod
    def _split_allowed_providers(cls, value: object) -> list[str]:
        """Mirror the Sprint-1B ``cors_allowed_origins`` shape.

        Accepts ``None`` / ``[]`` / JSON array string / comma-separated
        string. Output is lowercased + trimmed; empty entries dropped.
        Rejects every other shape with a typed ``ValueError`` so misconfig
        surfaces at startup, not at the policy boundary.
        """

        if value is None:
            return []
        if isinstance(value, list):
            return [str(p).strip().lower() for p in value if str(p).strip()]
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            if stripped.startswith("["):
                import json as _json

                parsed = _json.loads(stripped)
                if not isinstance(parsed, list):
                    raise ValueError("allowed_providers JSON value must be a list of strings")
                return [str(p).strip().lower() for p in parsed if str(p).strip()]
            return [p.strip().lower() for p in stripped.split(",") if p.strip()]
        raise ValueError(
            f"allowed_providers must be list, JSON array, or CSV; got {type(value).__name__}"
        )

    # --- Build metadata ----------------------------------------------
    # Wired by the Dockerfile / CI at image-build time; defaults make
    # local-dev introspection useful without requiring an explicit env.
    build_sha: str = Field(default="dev", description="Git SHA of the build.")
    build_time: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"),
        description="ISO-8601 build timestamp.",
    )

    @property
    def package_version(self) -> str:
        return __version__

    @property
    def python_version(self) -> str:
        return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    @property
    def platform_string(self) -> str:
        return f"{platform.system()}-{platform.machine()}"


def build_settings_without_env_file() -> Settings:
    """Construct ``Settings`` while suppressing ``.env`` loading.

    Pydantic-Settings accepts ``_env_file=None`` at construction time as the
    documented escape hatch to override the class-level ``env_file`` setting,
    but its public type signature uses ``**values: Any`` and does not expose
    ``_env_file`` as a typed parameter. The single narrow ``type: ignore``
    here is the only place that knowledge bleeds into the codebase; every
    caller (``get_settings`` and the dedicated test) routes through this
    helper so neither has to repeat the ignore.
    """

    return Settings(_env_file=None)  # type: ignore[call-arg]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings instance.

    Cached so that every code path observes a single Settings object;
    tests reset the cache via ``get_settings.cache_clear()``. In ``prod``
    profile the ``.env`` file is suppressed (per the ``Settings``
    docstring) so an accidental file in CWD cannot influence runtime.
    """

    if os.environ.get(_PROD_PROFILE_ENV_VAR, "dev").lower() == "prod":
        return build_settings_without_env_file()
    return Settings()
