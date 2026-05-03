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

import importlib.util
import logging
import os
import platform
import sys
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from cognic_agentos import __version__

RuntimeProfile = Literal["dev", "stage", "prod"]

# Sentinel used by ``get_settings()`` to suppress the ``.env`` lookup in the
# ``prod`` profile. Pydantic-Settings treats ``_env_file=None`` at construction
# time as "ignore the class-level ``env_file`` setting".
_PROD_PROFILE_ENV_VAR = "COGNIC_RUNTIME_PROFILE"

_LOG = logging.getLogger("cognic_agentos.core.config")


class SandboxNotAvailableError(RuntimeError):
    """Raised at config-load when ``mcp_stdio_enabled`` is set in
    production but the sandbox runtime is not importable.

    Per ADR-002 §"Sandbox dependency hard-block" + ADR-004
    §"Sandbox primitive": STDIO MCP transport is fail-closed in
    production until BOTH (a) the sandbox primitive lands (Sprint 8)
    AND (b) the operator explicitly opts in. This error fires the
    moment ``Settings`` is constructed in a misconfigured shape, so
    operators see the misconfiguration at startup rather than on
    first MCP invocation. Same hierarchy class as
    :class:`cognic_agentos.protocol.MCPNotAvailableError` —
    catching ``RuntimeError`` at the operator-tooling boundary
    catches both.
    """


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

        # Sprint-5 T8: STDIO MCP transport sandbox-availability check.
        # Per ADR-002 §"Sandbox dependency hard-block" + ADR-004:
        # ``mcp_stdio_enabled`` in prod requires the sandbox runtime
        # primitive (Sprint 8). Enforced at config-load so the failure
        # surfaces at startup, not on first MCP invocation.
        _check_sandbox_availability(
            runtime_profile=self.runtime_profile,
            stdio_enabled=self.mcp_stdio_enabled,
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
    llm_guardrail_scope: Literal["all", "external_only", "self_hosted_only", "off"] = Field(
        default="all",
        description=(
            "Per-route scope for configured gateway guardrail pipelines. "
            "``all`` (secure default) runs guardrails on local + cloud "
            "calls. ``external_only`` runs them only for cloud/external "
            "upstreams. ``self_hosted_only`` runs them only for local/"
            "on-prem upstreams. ``off`` skips configured pipelines on "
            "every call. This knob controls whether configured pipelines "
            "execute; banks can still inject ``None`` for input or output "
            "pipeline at gateway construction to disable a direction "
            "globally — the two axes compose. Per ADR-007 self-hosted-"
            "first posture: AgentOS ships conservative (``all``); banks "
            "intentionally relax based on their perimeter risk."
        ),
    )

    # --- Sprint 4 — Plugin registry + trust gate + policy seed ---------
    # Per ADRs 002 (MCP plugin protocol — cosign trust gate +
    # per-tenant allow-list), 015 (policy-as-code — Rego evaluator
    # seed; load-from-disk only in Sprint 4, hot-reload in Sprint 13.5),
    # and 016 (supply-chain attestations — Wave-1 mandatory floor +
    # grace-period split).
    #
    # Field-naming note: the Sprint-4 plan-of-record (a84ec85) wrote
    # field names with a redundant ``cognic_`` prefix; that doubles up
    # against the ``env_prefix="COGNIC_"`` already declared on
    # SettingsConfigDict and would force operators to set
    # ``COGNIC_COGNIC_REQUIRE_COSIGN`` etc. Field names here drop the
    # in-Python prefix to mirror the existing Sprint-3 convention
    # (``tier1_alias`` → ``COGNIC_TIER1_ALIAS``); env-var names in
    # ``.env.example`` stay single-prefixed.
    plugin_allowlist_path: Path = Field(
        default=Path("policies/_default/plugin_allowlist.json"),
        description=(
            "Per-tenant plugin allow-list path. JSON: "
            "{tenant_id: [pack_name, ...]}. File-backed in Sprint 4; "
            "Vault swap → Sprint 10 (no API surface change at the swap)."
        ),
    )
    require_cosign: bool = Field(
        default=True,
        description=(
            "Master fail-closed flag for the plugin trust gate. Default "
            "true: pack registration refuses if cosign cannot verify the "
            "signature. Setting false in production is a critical-controls "
            "violation (per AGENTS.md). The override exists only so local "
            "dev without cosign installed can iterate."
        ),
    )
    cosign_path: str | None = Field(
        default=None,
        description=(
            "Override path to the cosign binary. None → ``shutil.which("
            "'cosign')`` at first use. Production: pinned in default-"
            "adapters Dockerfile target with SHA256 (per Sprint-4 plan §2)."
        ),
    )
    cosign_verify_timeout_s: float = Field(
        default=30.0,
        gt=0.0,
        description=(
            "Per-call cosign-verify timeout in seconds. Strict: SIGKILL "
            "on timeout; the timeout itself emits a chained "
            "``trust_gate.cosign_timeout`` audit event. Must be > 0."
        ),
    )
    supply_chain_policy_bundle: Path = Field(
        default=Path("policies/_default/supply_chain.rego"),
        description=(
            "Rego bundle path consulted by the Sprint-4 policy engine "
            "seed for supply-chain admission decisions (full-grade "
            "always allowed; partial-grade tolerance per tenant policy). "
            "Bundle reload requires AgentOS restart in Sprint 4; Sprint "
            "13.5 adds hot-reload."
        ),
    )
    opa_path: str | None = Field(
        default=None,
        description=(
            "Override path to the OPA Go binary. None → ``shutil.which("
            "'opa')`` at engine construction. Production: pinned in "
            "default-adapters Dockerfile target."
        ),
    )
    opa_eval_timeout_s: float = Field(
        default=5.0,
        gt=0.0,
        description=(
            "Per-evaluate OPA timeout in seconds. Strict: SIGKILL on "
            "timeout; fail-closed on parse failure / non-zero exit. "
            "Must be > 0."
        ),
    )
    object_store_driver: Literal["local_fs"] = Field(
        default="local_fs",
        description=(
            "ObjectStoreAdapter driver. Sprint 4 ships ``local_fs`` (production "
            "filesystem; first real impl per AGENTS.md production-grade rule). "
            "Sprint 8 adds ``s3``; the Literal here will widen to "
            'Literal["local_fs", "s3"] at that sprint.'
        ),
    )
    local_object_store_root: Path | None = Field(
        default=None,
        description=(
            "Root directory for the LocalObjectStoreAdapter "
            "(production filesystem ObjectStoreAdapter; first real "
            "implementation per AGENTS.md production-grade rule). When "
            "unset (the default), the post-init validator picks: prod "
            "profile → /var/lib/cognic-agentos/object-store; dev/staging "
            "→ $TMPDIR-derived. Operator override via env var or init "
            "kwarg always wins. Sprint 8 adds an S3 driver alongside; "
            "both drivers conform to ObjectStoreAdapter."
        ),
    )
    signature_root_path: Path = Field(
        default=Path("attestations"),
        description=(
            "Root prefix under which all pack signature paths must "
            "canonicalise. Path-traversal attempts are refused at the "
            "trust-gate boundary (per Sprint-4 plan §2 invariant 3)."
        ),
    )
    trust_root_prefix: Path = Field(
        default=Path("trust-roots"),
        description=(
            "Root prefix under which all per-tenant cosign trust-root "
            "paths must canonicalise. Path-traversal attempts are "
            "refused at the trust-gate boundary."
        ),
    )

    # --- Sprint 5 — MCP host (Streamable HTTP first; STDIO restricted) -
    # Per ADRs 002 (MCP plugin protocol — OAuth/PRM authorization +
    # STDIO four-gate threat model + sandbox dependency hard-block),
    # 014 (transitional high-risk-tier refusal until Sprint 13.5
    # approval engine), and 015 (sampling default-deny Rego seed).
    #
    # Sprint-5 Decision Lock (Option C): STDIO ships threat model +
    # manifest/config validation + fail-closed refusal at registration.
    # STDIO does NOT ship process launch — that's Sprint 8 with the
    # sandbox primitive. Every STDIO-related setting here is
    # validation/refusal-side; no field controls process-spawning
    # behaviour.
    mcp_stdio_enabled: bool = Field(
        default=False,
        description=(
            "STDIO MCP transport opt-in. Default False in ALL profiles "
            "in Sprint 5 (the sandbox primitive lands Sprint 8). When "
            "Sprint 8 lands, dev profile may flip to True; prod stays "
            "hard-disabled until operator explicitly opts in PLUS "
            "sandbox available PLUS four-gate manifest validates. "
            "Setting True with runtime_profile=prod and no sandbox "
            "importable triggers a fail-fast SandboxNotAvailableError "
            "at startup (T8)."
        ),
    )
    mcp_stdio_command_allowlist_path: str = Field(
        default="secret/cognic/{tenant}/stdio-command-allowlist",
        description=(
            "Vault path template for the per-tenant STDIO command "
            "allow-list. Sprint 5 reads this at registration time to "
            "refuse STDIO packs whose declared command is not on the "
            "list. Per ADR-002 §MCP STDIO threat model gate 2."
        ),
    )
    mcp_as_allowlist_path: str = Field(
        default="secret/cognic/{tenant}/mcp-as-allowlist",
        description=(
            "Vault path template for the per-tenant OAuth authorization-"
            "server allow-list. Sprint 5 refuses MCP servers whose PRM "
            "advertises a non-allowlisted AS. Per ADR-002 §MCP "
            "Authorization step 3."
        ),
    )
    mcp_oauth_token_cache_ttl_s: int = Field(
        default=3600,
        gt=0,
        description=(
            "TTL for the OAuth token cache (seconds). Tokens cached per "
            "(server, scope, resource) tuple; refreshed before this "
            "expiry; refresh emits audit.mcp_token_refresh on the "
            "audit_event chain plus a decision_history row per T11."
        ),
    )
    mcp_oauth_request_timeout_s: int = Field(
        default=30,
        gt=0,
        description=(
            "Strict timeout on every PRM discovery + token request + "
            "token refresh outbound HTTP call (seconds). Same fail-"
            "closed posture as cosign_verify_timeout_s."
        ),
    )
    mcp_call_tool_timeout_s: int = Field(
        default=60,
        gt=0,
        description=(
            "Strict timeout on every MCP call_tool invocation against "
            "an HTTP MCP server (seconds). Tools that exceed this raise "
            "mcp_call_tool_timeout, audit-logged with pack identity + "
            "tool name + duration."
        ),
    )
    mcp_sampling_policy_bundle: Path = Field(
        default=Path("policies/_default/sampling.rego"),
        description=(
            "Rego bundle path consumed by protocol/mcp_capabilities.py "
            "to evaluate the four-condition sampling default-deny per "
            "ADR-002 + MCP-CONFORMANCE.md. Operators override per-"
            "tenant by pointing this at a Vault-mounted bundle. Default "
            "ships with policies/_default/sampling.rego (default-deny; "
            "allow only when pack manifest, tenant policy, cloud-policy "
            "tier consistency, and allow_external_llm consistency all "
            "hold)."
        ),
    )
    mcp_oauth_credentials_path: str = Field(
        default="secret/cognic/{tenant}/mcp-oauth/{as_host}",
        description=(
            "Vault path template for per-tenant per-AS OAuth client "
            "credentials. Resolved at token-acquisition time as "
            "``mcp_oauth_credentials_path.format(tenant=tenant_id, "
            "as_host=urlparse(as_issuer).netloc.replace(':', '_'))``. "
            "**Sanitisation note** (R9 P3): the AS issuer netloc has "
            "``:`` replaced by ``_`` before interpolation so the value "
            "is safe to use as a Vault path segment. Operators "
            "populating Vault for an issuer with an explicit port (e.g. "
            "``https://as.example:8443``) MUST therefore write the "
            "secret to ``secret/cognic/<tenant>/mcp-oauth/as.example_8443`` "
            "(underscore), NOT ``as.example:8443``. Issuers without an "
            "explicit port are unaffected. Vault secret shape: "
            "``{client_id, client_secret, auth_method}`` where "
            "auth_method is one of ``client_secret_post`` / "
            "``client_secret_basic``. Sprint 5 ships these two; Wave 2 "
            "adds private_key_jwt + mTLS client-binding. The MCP authz "
            "client never logs the secret — it goes into the request "
            "and is dropped after."
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

    @model_validator(mode="after")
    def _resolve_local_object_store_root(self) -> Settings:
        """Resolve ``local_object_store_root`` per ``runtime_profile`` if unset.

        Prod profile → ``/var/lib/cognic-agentos/object-store``. Dev /
        staging → ``$TMPDIR``-derived path (so test runs and shared
        developer workstations don't accidentally write Sigstore bundles
        into a production-shared /var/lib path).

        Operator override via env var (``COGNIC_LOCAL_OBJECT_STORE_ROOT``)
        or init kwarg always wins — that's the path through `data` /
        explicit-init, which leaves the field non-None at validator entry.
        """

        if self.local_object_store_root is None:
            if self.runtime_profile == "prod":
                self.local_object_store_root = Path("/var/lib/cognic-agentos/object-store")
            else:
                self.local_object_store_root = _default_object_store_root()
        return self

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


def _check_sandbox_availability(
    *,
    runtime_profile: RuntimeProfile,
    stdio_enabled: bool,
) -> None:
    """Sprint-5 T8 fail-fast — STDIO MCP transport requires the
    sandbox primitive (Sprint 8) before it can launch a process.

    Decision matrix:

    ============= ======================== =========================== ==========
    profile       mcp_stdio_enabled        sandbox.runtime importable  outcome
    ============= ======================== =========================== ==========
    *any*         False                    *irrelevant*                pass
    prod          True                     False                       **raise**
    prod          True                     True                        pass
    dev / stage   True                     False                       warn
    dev / stage   True                     True                        pass
    ============= ======================== =========================== ==========

    The fail-fast on ``prod`` is the load-bearing rule per ADR-002
    §"Sandbox dependency hard-block": production must NEVER boot in a
    shape that could allow a STDIO pack to launch a process without
    the sandbox primitive's enforcement boundary. ``dev`` / ``stage``
    only warn because pack registration is still refused at runtime
    via T6's ``mcp_stdio_disabled_in_sprint_5`` capability validator
    regardless of sandbox availability — the dev/stage environment
    can boot for everything else.

    Sprint 8 lifts the bare-find_spec check; once
    ``cognic_agentos.sandbox.runtime`` exists this function evolves
    to call its readiness probe instead of just checking importability.
    """
    if not stdio_enabled:
        return
    # ``find_spec`` raises ``ModuleNotFoundError`` when the parent
    # package itself is missing (Sprint 5 has no
    # ``cognic_agentos.sandbox`` package at all). Treat that as
    # equivalent to "spec is None" — both signal "sandbox runtime is
    # not importable".
    try:
        sandbox_spec = importlib.util.find_spec("cognic_agentos.sandbox.runtime")
    except ModuleNotFoundError:
        sandbox_spec = None
    if sandbox_spec is not None:
        return
    if runtime_profile == "prod":
        raise SandboxNotAvailableError(
            "STDIO MCP transport requires the sandbox primitive "
            "(Sprint 8) per ADR-002 §Sandbox dependency hard-block + "
            "ADR-004 §Sandbox primitive. Production profile cannot "
            "opt in to mcp_stdio_enabled until BOTH sandbox available "
            "AND four-gate manifest validates. To recover: set "
            "COGNIC_MCP_STDIO_ENABLED=false (the Sprint-5 default) or "
            "wait for Sprint 8."
        )
    _LOG.warning(
        "mcp_stdio_enabled=True with no sandbox runtime importable "
        "(runtime_profile=%s). Pack registration refuses STDIO at the "
        "T6 capability validator regardless; this warning surfaces the "
        "misconfiguration so the operator can flip the flag before "
        "Sprint 8 lands.",
        runtime_profile,
    )


def _default_object_store_root() -> Path:
    """Profile-aware default for ``cognic_local_object_store_root``.

    Per Sprint-4 plan §4: dev environments derive the LocalObjectStoreAdapter
    root from ``$TMPDIR`` (so test runs and shared developer workstations
    don't accidentally write Sigstore bundles into a production-shared
    /var/lib path); prod defaults to ``/var/lib/cognic-agentos/object-store``
    which is writable by the AgentOS service account in the default
    deployment shape.
    """

    if (tmp := os.environ.get("TMPDIR")) is not None:
        return Path(tmp) / "cognic-agentos-object-store"
    return Path("/var/lib/cognic-agentos/object-store")


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
