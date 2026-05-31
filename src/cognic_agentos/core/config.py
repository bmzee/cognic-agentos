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

from pydantic import AliasChoices, Field, field_validator, model_validator
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

    # --- Sub-agent primitive (Sprint 11, ADR-005) --------------------
    subagent_max_recursion_depth: int = Field(
        default=3,
        ge=1,
        description=(
            "Wave-1 global recursion-depth cap for sub-agent spawning "
            "(ADR-005 §Recursion-depth). A spawn whose child would sit at "
            "depth greater than this value is refused (SubAgentDepthExceeded) "
            "and escalated. Per-tenant / per-agent overrides are deferred to "
            "the policy/approval layer (Sprint 13.5)."
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
    vault_http_timeout_s: float = Field(
        default=10.0,
        gt=0.0,
        le=60.0,
        description=(
            "Sprint 10 (T2) — per-request timeout for the shared "
            "VaultTransport (seconds). Bounded ``0 < x ≤ 60`` per "
            "spec §3.5; misconfig fails loud at Settings construction."
        ),
    )
    vault_http_max_retries: int = Field(
        default=3,
        ge=0,
        le=10,
        description=(
            "Sprint 10 (T2) — bounded exponential-backoff retry count "
            "for transient hvac failures from the shared VaultTransport. "
            "Bounded ``0 ≤ x ≤ 10`` (0 = no retries; 10 = ~10s "
            "worst-case backoff per call); misconfig fails loud at "
            "Settings construction."
        ),
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
    llm_model_id_map: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Sprint 9.5b C1 (ADR-013) — maps a resolved LiteLLM alias "
            "to a stable ``model_id`` from the Model Registry. Sprint "
            "9.5b C2's gateway sets ``GatewayCallRow.model_id`` via "
            "``self._settings.llm_model_id_map.get(litellm_alias)`` at "
            "the two ledger-write construction sites; an unmapped alias "
            "writes ``model_id=None`` + the existing 'unmapped alias' "
            "log path — the gateway never invents a ``model_id``. A "
            "future sprint may replace this static map with registry-"
            "backed dynamic resolution. Env-var form is JSON-encoded "
            '(e.g. \'{"cognic-tier1-dev": "cognic-tier1-acme-v1"}\'); '
            "invalid JSON / non-string keys or values fail at "
            "settings-load time via the ``dict[str, str]`` annotation "
            "(fail-loud invariant: operators see misconfiguration at "
            "startup, never as a runtime mystery)."
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
            "adapters Dockerfile target with SHA256 (per Sprint-4 plan §2). "
            "Sprint-7A consumer: ``cli/sign.py`` (T14)."
        ),
    )
    # ----- Sprint-9.5 B4 Model Registry settings (per ADR-013) ---------
    model_artifact_root: str = Field(
        default="/var/lib/cognic/model-artifacts",
        description=(
            "Filesystem root under which model-artefact refs "
            "(``signed_artifact_ref`` / ``sigstore_bundle_ref``) resolve, "
            "scoped per-tenant: ``<root>/<tenant_id>/<relative_ref>``. The "
            "per-tenant cosign trust root resolves to "
            "``<root>/<tenant_id>/trust-root.pub``. Consumed by "
            "``portal/api/models/lifecycle_routes.py``'s "
            "``_resolve_under_tenant_root`` cosign path-containment helper "
            "(rejects absolute paths / URI schemes / ``..`` segments / "
            "symlinks escaping the tenant root / wrong-tenant crossings / "
            "missing or non-file targets). Wave-1 — object-store-backed "
            "fetch is a Wave-2 seam (ADR-009)."
        ),
    )
    # ----- Sprint-7A T1 settings (per the Sprint-7A plan-of-record) -----
    syft_path: str | None = Field(
        default=None,
        description=(
            "Override path to the syft binary used by ``agentos sign --bundle`` "
            "(T14) for SBOM generation per ADR-016. None → ``shutil.which("
            "'syft')`` at first use; missing binary fails-loud with closed-enum "
            "``sign_syft_not_installed``. Sprint-7A T1."
        ),
    )
    grype_path: str | None = Field(
        default=None,
        description=(
            "Override path to the grype binary used by ``agentos sign --bundle`` "
            "(T14) for vulnerability scanning per ADR-016. None → "
            "``shutil.which('grype')`` at first use; missing binary fails-loud "
            "with closed-enum ``sign_grype_not_installed``. Sprint-7A T1."
        ),
    )
    license_auditor_path: str | None = Field(
        default=None,
        description=(
            "Override path to the license-auditor binary (pip-licenses or "
            "cyclonedx-py) used by ``agentos sign --bundle`` (T14) per "
            "ADR-016. None → ``shutil.which`` at first use; missing binary "
            "fails-loud with closed-enum ``sign_license_auditor_not_installed``. "
            "Sprint-7A T1."
        ),
    )
    signing_key_path: str | None = Field(
        default=None,
        description=(
            "Path or ``vault://`` URI to the signing key used by "
            "``agentos sign --bundle`` (T14) and verified against the trust "
            "root by ``agentos verify`` (T14). None → SDK fails-loud with "
            "closed-enum ``sign_signing_key_unavailable``. R9 P2 #1: prod "
            "profile rejects any path under ``examples/`` or "
            "``tests/fixtures/`` at startup so test-only synthetic keys "
            "cannot leak into production deployments. Sprint-7A T1."
        ),
    )
    evidence_pack_signing_key_path: str | None = Field(
        default=None,
        description=(
            "#sprint-9 — operator-provided signing key for ISO 42001 "
            "evidence-pack manifests (ADR-006). DISTINCT from "
            "signing_key_path (pack-publisher identity for `agentos sign "
            "--bundle`): this is the AgentOS *instance* trust identity. "
            "Accepts `vault://secret/...` (production-preferred, resolved "
            "via SecretAdapter) or a filesystem PEM path (operator escape "
            "hatch). Unset => evidence-pack export fails loud; an unsigned "
            "examiner artifact is forbidden."
        ),
    )
    signing_trust_root_path: str | None = Field(
        default=None,
        description=(
            "Path to the public-key PEM (or ``vault://`` URI) used by "
            "``agentos verify`` (T14) as the trust-root target. R9 P2 #1: "
            "in unit-lane testing this points at a committed test-only "
            "public PEM under ``examples/`` or ``tests/fixtures/``; in "
            "production this points at the per-tenant Vault trust-root path. "
            "Sprint-7A T1."
        ),
    )
    dev_mode_skip_cosign: bool = Field(
        default=False,
        description=(
            "Dev-only override that lets ``agentos sign --bundle`` skip the "
            "cosign-blob step (the rest of the bundle still generates). "
            "Per Doctrine F: prints a security warning to stderr; ``prod`` "
            "profile rejects ``True`` at startup with a closed-enum "
            "settings-validation error. Sprint-7A T1."
        ),
    )
    # ----- end Sprint-7A T1 settings -----
    cosign_verify_timeout_s: float = Field(
        default=30.0,
        gt=0.0,
        description=(
            "Per-call cosign-verify timeout in seconds. Strict: SIGKILL "
            "on timeout; the timeout itself emits a chained "
            "``trust_gate.cosign_timeout`` audit event. Must be > 0."
        ),
    )
    load_probe_timeout_s: float = Field(
        default=30.0,
        gt=0.0,
        description=(
            "Per-call timeout (seconds) for the isolated-subprocess "
            "``EntryPoint.load()`` probe used by ``agentos verify`` "
            "after cosign verify-blob succeeds. SIGKILL + reap on "
            "timeout; result routes to closed-enum "
            "``verify_entry_point_load_failed`` "
            "with ``payload.failure_mode=load_probe_timeout``. "
            "Must be > 0. Sprint-7A T14.C R15 pivot."
        ),
    )
    hook_max_timeout_s: float = Field(
        default=30.0,
        gt=0.0,
        description=(
            "Wave-1 ceiling (seconds) on the per-hook timeout pack "
            "authors may declare in ``[hooks].declarations[].timeout_seconds``. "
            "The Sprint-7A2 build-time hook validator refuses any "
            "declaration above this ceiling; the runtime hook "
            "dispatcher enforces the same ceiling at dispatch time "
            "via ``min(manifest.timeout_seconds, "
            "Settings.hook_max_timeout_s)`` so a malicious manifest "
            "cannot extend an admission-side accepted hook past the "
            "operator's policy limit. Must be > 0. Sprint-7A2 T1 "
            "Doctrine Lock A."
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

    # ------------------------------------------------------------------
    # Sprint 6 — A2A endpoint + UI event-stream stub (per ADR-003 + ADR-020)
    # ------------------------------------------------------------------

    a2a_token_cache_ttl_s: int = Field(
        default=3600,
        gt=0,
        description=(
            "TTL for the per-tenant A2A pinned-token cache. Tokens are "
            "read from Vault on cache miss + refreshed before TTL "
            "elapses. Default 3600s matches Sprint-5 "
            "``mcp_oauth_token_cache_ttl_s`` (R1 P3 reviewer correction "
            "— earlier draft said 300s but Sprint-5's default is 3600s; "
            "parity restored). Per ADR-003 + A2A-CONFORMANCE.md, A2A "
            "Wave-1 uses per-tenant pinned tokens (mTLS lands Wave 2; "
            "VC lands Wave 3)."
        ),
    )

    a2a_artifact_retention_seconds: int = Field(
        default=7 * 24 * 3600,
        gt=0,
        description=(
            "Retention window for A2A artifact references stored via "
            "``ObjectStoreAdapter``. Default 7 days; tenants override "
            "per regulatory class. Per ADR-003 §"
            "'Artifacts' — large outputs (PDFs, evidence packs, JSON "
            ">64 KiB) are stored by reference rather than inlined into "
            "task responses, so this retention window is the floor "
            "before the artifact ref becomes unresolvable."
        ),
    )

    a2a_artifact_inline_threshold_bytes: int = Field(
        default=64 * 1024,
        gt=0,
        description=(
            "Inline-vs-store threshold for A2A artifact bytes. Payloads "
            "with ``len(bytes) <= threshold`` ride inline in the Task "
            "envelope; larger payloads are persisted via "
            "``ObjectStoreAdapter`` and returned as ``ArtifactRef``. "
            "64 KiB is the A2A 1.0 spec recommendation; banks with "
            "stricter inline-payload caps (e.g. for dual-boundary "
            "review) override downward. Per Sprint-6 T11 R0 doctrine "
            "#4 reviewer correction (production-grade rule per "
            "AGENTS.md): deployment-tunable thresholds belong in "
            "Settings, not as module-level constants."
        ),
    )

    a2a_pinned_spec_version: str = Field(
        default="1.0",
        pattern=r"^[0-9]+\.[0-9]+$",
        description=(
            "Pinned A2A spec version. The schema-drift CI gate "
            "(``test_a2a_schema_drift.py``) compares upstream protobuf "
            "+ JSON-schema bindings against this pin. Bumping requires "
            "an explicit reviewed change tied to the drift gate — "
            "never silent. Per ADR-003 §'Versioning' + "
            "A2A-CONFORMANCE.md §'Versioning'."
        ),
    )

    a2a_schema_drift_check_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            # R2 P2 reviewer correction: include the field name itself
            # in AliasChoices so direct constructor overrides
            # (Settings(a2a_schema_drift_check_enabled=True)) still
            # work. Without this, validation_alias would replace the
            # default name-based population and ``extra='ignore'``
            # would silently drop the kwarg — sharp edge for tests +
            # T6's runtime enable path.
            "a2a_schema_drift_check_enabled",
            "COGNIC_A2A_SCHEMA_DRIFT_CHECK_ENABLED",
            "COGNIC_RUN_A2A_UPSTREAM",
        ),
        description=(
            "Whether the schema-drift CI gate runs. False locally "
            "(saves the network round-trip on every test run); the "
            "dedicated CI lane sets ``COGNIC_RUN_A2A_UPSTREAM=1`` "
            "which flips this setting to True via the AliasChoices "
            "binding. The drift gate itself is at "
            "``tests/unit/protocol/test_a2a_schema_drift.py`` (T6). "
            "Per Sprint-6 Doctrine Decision C — env-gate mirrors the "
            "Sprint-4 ``cosign_real`` pattern. (R1 P2 reviewer "
            "correction — the original binding only honoured the "
            "fully-qualified ``COGNIC_A2A_SCHEMA_DRIFT_CHECK_ENABLED`` "
            "env var, which would have made the CI lane silently skip "
            "the upstream check despite setting "
            "``COGNIC_RUN_A2A_UPSTREAM=1`` per the plan's documented "
            "convention.)"
        ),
    )

    a2a_card_jws_max_size_bytes: int = Field(
        default=64 * 1024,
        gt=0,
        description=(
            "Maximum size of a detached AgentCard JWS file the trust "
            "gate accepts. JWS files >64 KiB are an attack vector "
            "(DoS via large-blob signature verification + memory "
            "pressure on the trust-gate path). Per Sprint-6 Doctrine "
            "Decision B — caller-controlled URL threat model + "
            "AgentCard JWS verification ride the same fail-closed "
            "posture."
        ),
    )

    a2a_outbound_request_timeout_s: int = Field(
        default=30,
        gt=0,
        description=(
            "Timeout for outbound A2A HTTP calls (Agent Card fetch + "
            "task dispatch). 30s matches Sprint-5 "
            "``mcp_oauth_request_timeout_s`` for operational "
            "consistency. Per Sprint-6 Doctrine Decision B — outbound "
            "dispatch URLs come from JWS-verified Agent Cards only; "
            "this timeout is the deadline for both the discovery fetch "
            "and the dispatch send."
        ),
    )

    a2a_inbound_request_timeout_s: int = Field(
        default=60,
        gt=0,
        description=(
            "Deadline for inbound non-streaming A2A ``handle()`` calls "
            "before the endpoint emits ``task.failed`` with "
            "``deadline_exceeded``. 60s budget for typical bank-grade "
            "tool-bound tasks; streaming tasks use the spec's "
            "task-progress envelopes instead and are not bound by "
            "this timeout. Per ADR-003 §'Tasks'."
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
    def _validate_signing_key_path_prod_profile_guard(self) -> Settings:
        """Sprint-7A R9 P2 #1 — prod-profile guard rejecting test-fixture-tree
        signing keys at startup.

        ``examples/`` and ``tests/fixtures/`` are the canonical homes for
        synthetic test-only signing keys (per the R9 P2 #1 doctrine in the
        Sprint-7A plan-of-record). Those keys are committed via narrow
        ``.gitignore`` exceptions so T14 + T15 lifecycle tests can run
        deterministically in the unit lane. Production deployments MUST
        NOT reuse them — a real prod signing key lives at an
        operator-controlled path (or a ``vault://`` URI) outside both
        trees.

        The guard is prod-profile-only by design: dev / test profiles
        MUST be able to wire the test-fixture keys, otherwise T14 + T15
        cannot exercise the sign + verify lifecycle.

        Raises ``ValueError`` (which Pydantic wraps as
        ``ValidationError``) with the closed-enum reason
        ``signing_key_path_under_test_fixture_tree_in_prod`` when the
        guard fires. R10 P2 #2 — both rejected and allowed path shapes
        are pinned by tests in TestSprint7ASettings.

        R11 P2 #1 reviewer correction: the earlier draft matched
        ``"/examples/"`` and ``"/tests/fixtures/"`` as raw substrings,
        which silently accepted any RELATIVE path that didn't start
        with a slash (e.g., a ``signing_key_path`` like
        ``examples/cognic-agent-example-minimal/...`` bypassed the
        guard because the relative form starts with ``examples/``,
        not ``/examples/``). Fix: skip URI-shaped values (e.g.,
        ``vault://...``) since those aren't filesystem paths, then
        resolve filesystem paths to absolute form via
        ``Path.resolve()`` before the segment match.
        ``Path.resolve()`` works on non-existent paths in Python
        3.12+ — it just normalises lexically against the cwd, which
        is what we need.
        """
        if (
            self.runtime_profile == "prod"
            and self.signing_key_path is not None
            and "://" not in self.signing_key_path
        ):
            # Filesystem path branch — URI-shaped values (vault://,
            # kms://, etc.) skip the fixture-tree check because they
            # aren't filesystem paths. R12 P2 #1 reviewer correction:
            # the earlier draft used ``return self`` here, which
            # short-circuited the rest of the validator including the
            # dev_mode_skip_cosign guard below. Now URI values fall
            # through to the dev-mode guard cleanly. Resolve relative
            # paths to absolute against the current working directory;
            # this covers both ``signing_key_path="/abs/path/to/examples/..."``
            # (already absolute) and ``signing_key_path="examples/..."``
            # (relative to cwd) — the segment match below sees the
            # same shape regardless of how the operator spelled the
            # input.
            from pathlib import Path as _Path

            resolved = str(_Path(self.signing_key_path).resolve())
            for segment in ("/examples/", "/tests/fixtures/"):
                if segment in resolved:
                    raise ValueError(
                        "signing_key_path_under_test_fixture_tree_in_prod: "
                        f"signing_key_path={self.signing_key_path!r} "
                        f"resolves to {resolved!r} which is under "
                        f"{segment.strip('/')} — that tree is reserved "
                        "for synthetic test-only keys (Sprint-7A R9 P2 "
                        "#1). Production signing keys MUST live outside "
                        "the examples/ and tests/fixtures/ trees."
                    )
        if self.runtime_profile == "prod" and self.dev_mode_skip_cosign:
            raise ValueError(
                "dev_mode_skip_cosign=True is forbidden in prod profile "
                "per Sprint-7A Doctrine Decision F. Set runtime_profile to "
                "'dev' or 'test', or remove the override."
            )
        return self

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

    # --- UI event-stream knobs (Sprint 7B.4 per ADR-020) -----------------
    # P1 #6 ownership note: these 5 fields are wired in Settings (NOT in
    # protocol/ui_events.py) so operators can override them via the standard
    # env-var path (COGNIC_UI_EVENT_STREAM_*). The UIEventBroker primitive
    # reads them at construction time + uses them to bound subscriber state.
    # Each field's `ge=...` floor refuses operator misconfigurations that
    # would silently break the broker (cap=0 would refuse every subscriber;
    # queue_maxsize<16 would overflow on the first event burst; timeouts<1s
    # would reap subscribers mid-yield). Drift in defaults is operator-
    # visible production-behavior drift; pinned by
    # tests/unit/core/test_config_ui_event_stream_fields.py.
    ui_event_stream_per_tenant_cap: int = Field(
        default=50,
        ge=1,
        description="Max concurrent SSE subscribers per tenant; the broker refuses "
        "register_subscriber with TenantConnectionCapExceeded when hit.",
    )
    ui_event_stream_queue_maxsize: int = Field(
        default=1000,
        ge=16,
        description="Per-subscriber asyncio.Queue maxsize; QueueFull increments "
        "subscriber.overflow_count and logs ui.subscriber.queue_overflow.",
    )
    ui_event_stream_idle_timeout_s: int = Field(
        default=90,
        ge=15,
        description="Seconds of no successful generator yield (heartbeat or event) "
        "before reap_idle closes the subscriber.",
    )
    ui_event_stream_heartbeat_interval_s: int = Field(
        default=15,
        ge=1,
        description="Broker/generator-owned heartbeat interval (yields "
        'ServerSentEvent(comment="keepalive")).',
    )
    ui_event_stream_send_timeout_s: int = Field(
        default=30,
        ge=1,
        description="sse-starlette EventSourceResponse send_timeout; bounds "
        "half-open client cleanup.",
    )

    # --- Sandbox (Sprint 8A per ADR-004) ---------------------------------
    # Per-tenant resource caps consumed by ``sandbox.admission.admit_policy``
    # at spec §6.1 step 5. A policy declaring caps that exceed the tenant
    # max refuses with the matching ``SandboxRefusalReason``:
    # ``sandbox_policy_exceeds_tenant_max_{cpu,memory,walltime}``. Defaults
    # are conservative Wave-1 starting points; bank deployments override
    # via the COGNIC_SANDBOX_PER_TENANT_MAX_* env vars per tenant overlay.
    # Tests pin these fields exist by hasattr + default-positive assertions
    # at ``tests/unit/sandbox/test_admission_pipeline.py::
    # TestSettingsSandboxPerTenantMaxFields``.
    sandbox_per_tenant_max_cpu: float = Field(
        default=4.0,
        gt=0,
        description=(
            "Per-tenant ceiling for SandboxPolicy.cpu_cores (Docker --cpus "
            "throttle). admit_policy refuses sandbox_policy_exceeds_tenant_"
            "max_cpu when policy.cpu_cores exceeds this value."
        ),
    )
    sandbox_per_tenant_max_memory: int = Field(
        default=1024,
        gt=0,
        description=(
            "Per-tenant ceiling for SandboxPolicy.memory_mb (Docker "
            "--memory cap, megabytes). admit_policy refuses "
            "sandbox_policy_exceeds_tenant_max_memory on exceed."
        ),
    )
    sandbox_per_tenant_max_walltime: float = Field(
        default=300.0,
        gt=0,
        description=(
            "Per-tenant ceiling for SandboxPolicy.walltime_s (AgentOS-side "
            "wall-clock timer, seconds). admit_policy refuses "
            "sandbox_policy_exceeds_tenant_max_walltime on exceed."
        ),
    )

    # Sprint 10 T8 — per-tenant max credential lease TTL cap per
    # ADR-004 §25/§68/§102 + spec §5.1/§5.2. The kernel default
    # (15 minutes) is threaded by sandbox/admission.py Step 9 into
    # the Rego input dict's `kernel_default.max_credential_ttl_s`
    # field and consumed by policies/_default/sandbox.rego rule 6
    # (positive `_credential_ttl_within_tenant_max` helper joined
    # to the `allow if` conjunction). Bank overlays raise via the
    # Rego `tenant.overlay.max_credential_ttl_s` path (per-tenant
    # overlay plumbing is a future-sprint hook); LOOSENING the
    # kernel default requires a coordinated kernel + ADR amendment
    # per the stop-rule policy bundle precedent at AGENTS.md L150.
    sandbox_kernel_default_max_credential_ttl_s: int = Field(
        default=900,
        ge=60,
        le=86400,
        description=(
            "Sprint 10 — kernel default per-tenant max credential lease "
            "TTL (seconds). Threaded into the Rego input dict's "
            "kernel_default.max_credential_ttl_s field at sandbox/"
            "admission.py Step 9; consumed by policies/_default/"
            "sandbox.rego rule 6 (per-tenant max credential TTL cap). "
            "Bank overlays may raise via Rego tenant.overlay."
            "max_credential_ttl_s (per-tenant overlay plumbing is a "
            "future-sprint hook). Wave-1 flat cap; per-secret-class "
            "caps are future work."
        ),
    )

    # Sprint 8B — backend selection seam per ADR-004 amendment §32 +
    # the 2026-05-17 preflight decision. AgentOS owns the default
    # selection seam; bank overlays MAY override via the
    # COGNIC_SANDBOX_BACKEND env var. Default preserves Sprint-8A
    # behaviour on existing deployments (DockerSibling for dev/CI);
    # Wave-1 K8s production deployments override to "kubernetes_pod".
    # Per-tenant routing deferred to Sprint 14 deployment kit.
    # Wired into ``sandbox.backend_factory.get_backend(settings)``;
    # pinned by ``tests/unit/sandbox/test_backend_factory.py``.
    sandbox_backend: Literal["docker_sibling", "kubernetes_pod"] = Field(
        default="docker_sibling",
        description=(
            "Sprint 8B — selects the SandboxBackend implementation. "
            "AgentOS owns the default selection seam per the 2026-05-17 "
            "preflight decision. Bank overlays MAY override via the "
            "COGNIC_SANDBOX_BACKEND env var per ADR-004 amendment §32. "
            "Default preserves Sprint 8A behavior on existing deployments."
        ),
    )

    # --- Sandbox canonical image catalog (T30 per ADR-004 + ADR-016) ---
    # The two AgentOS-signed canonical platform images every sandbox launches
    # from. Real digest-pinned defaults (the signed refs produced by the T9
    # build/sign/push runbook — Option B, no placeholder defaults);
    # env-overridable via the COGNIC_SANDBOX_CANONICAL_* prefix. Consumed by the
    # backend factory (T11) to build the production CanonicalImageCatalog.
    sandbox_canonical_runtime_python_image: str = Field(
        default=(
            "ghcr.io/bmzee/cognic-agentos/sandbox-runtime-python@sha256:"
            "b9ed3440ebf8535ba779f574b3c12a45095720ce78c292d8cc5cd338990e8eac"
        ),
        description=(
            "T30 — full digest-pinned OCI ref of the canonical sandbox-runtime-"
            "python workload image. Env override: "
            "COGNIC_SANDBOX_CANONICAL_RUNTIME_PYTHON_IMAGE. Bank deployments "
            "re-home to their own registry + re-sign under their canonical "
            "trust root. Must be digest-pinned (validator below)."
        ),
    )
    sandbox_canonical_egress_proxy_image: str = Field(
        default=(
            "ghcr.io/bmzee/cognic-agentos/sandbox-egress-proxy@sha256:"
            "eb4ea75b427d0bc42039c68039eec51d6b0d0789400ba5bfdbf470ebec9139aa"
        ),
        description=(
            "T30 — full digest-pinned OCI ref of the canonical sandbox-egress-"
            "proxy sidecar image. Env override: "
            "COGNIC_SANDBOX_CANONICAL_EGRESS_PROXY_IMAGE. Replaces the former "
            "placeholder _CANONICAL_EGRESS_PROXY_IMAGE constant (swapped in the "
            "backends at T12). Must be digest-pinned (validator below)."
        ),
    )
    sandbox_canonical_image_trust_root_path: Path | None = Field(
        default=None,
        description=(
            "T30 — filesystem path to the canonical AgentOS cosign PUBLIC key "
            "used to verify canonical-image signatures at sandbox admission "
            "(catalog.canonical_trust_root, Option 1 / spec §7.1.1). Default "
            "None mirrors signing_trust_root_path: no dev/operator path is "
            "baked into the kernel — the operator points this at the published "
            "canonical public key via "
            "COGNIC_SANDBOX_CANONICAL_IMAGE_TRUST_ROOT_PATH. When None, "
            "canonical images have no canonical trust root and cosign "
            "verification fail-closes for them (no silent trust)."
        ),
    )

    @field_validator(
        "sandbox_canonical_runtime_python_image",
        "sandbox_canonical_egress_proxy_image",
    )
    @classmethod
    def _require_digest_pinned_canonical_image(cls, value: str) -> str:
        # Canonical images MUST be immutable: a full ``<ref>@sha256:<64-hex>``
        # digest pin, never a mutable tag. The ref PREFIX must be present and
        # whitespace-free (a real OCI ref never contains whitespace) and the
        # digest must be exactly 64 lowercase-hex chars — so a canonical image
        # can never silently drift under a moving tag, and "@sha256:<hex>" with
        # no ref (or a whitespace-bearing ref) is refused.
        ref, sep, digest = value.partition("@sha256:")
        if (
            not ref
            or any(c.isspace() for c in ref)
            or not sep
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise ValueError(
                f"canonical image ref must be digest-pinned as "
                f"<ref>@sha256:<64-lowercase-hex> with a non-empty, "
                f"whitespace-free <ref>; got {value!r}"
            )
        return value

    # --- Sandbox checkpoint / resumable-session (Sprint 8.5 per ADR-004) ---
    # Consumed by ``sandbox/checkpoint_store.py`` + ``sandbox/reaper.py``
    # via the structural ``_CheckpointSettings`` Protocol — the real
    # ``Settings`` conforms once these three fields exist. Bank overlays
    # MAY tighten via the COGNIC_SANDBOX_CHECKPOINT_* env vars.
    sandbox_checkpoint_retention_s: int = Field(
        default=86_400,
        ge=60,
        le=31_536_000,
        description=(
            "Sprint 8.5 — kernel-level retention floor for sandbox "
            "checkpoints. Bank overlays MAY tighten via env var; per-tenant "
            "Rego policy extension deferred to a later sprint per ADR-015. "
            "Checkpoints are purged by the reaper after this window."
        ),
    )
    sandbox_max_checkpoints_per_session: int = Field(
        default=10,
        ge=1,
        le=1000,
        description=(
            "Sprint 8.5 — per-session checkpoint cap. When a session would "
            "exceed this cap on checkpoint(), the OLDEST checkpoint that is "
            "OUTSIDE its retention window is purged (emits "
            "sandbox.lifecycle.checkpoint_purged with "
            "purge_reason='max_per_session_cap'). If EVERY existing "
            "checkpoint is INSIDE its retention window (eviction would be "
            "blocked by retention per §4.3 amended), persist() raises "
            "CheckpointMaxPerSessionRetentionLocked WITHOUT writing the new "
            "checkpoint AND WITHOUT emitting any checkpoint_purged chain "
            "row — operator response is to lower retention OR raise this cap."
        ),
    )
    sandbox_reaper_interval_s: int = Field(
        default=300,
        ge=10,
        le=3600,
        description=(
            "Sprint 8.5 — background reaper sweep interval. Reaper walks "
            "all checkpoints + purges any past their retention_window_s. "
            "Shorter intervals catch expirations faster; longer intervals "
            "reduce I/O."
        ),
    )
    sandbox_reaper_enabled: bool = Field(
        default=False,
        description=(
            "#489 — gates the production checkpoint-retention reaper. "
            "Default OFF: AgentOS production runs multiple Kubernetes "
            "replicas, and the Sprint 8.5 reaper is single-instance by "
            "design (N replicas => N reapers => duplicate "
            "sandbox.lifecycle.checkpoint_purged audit rows; byte-level "
            "deletes stay idempotent). Operators set this true on EXACTLY "
            "ONE instance (or a dedicated single-replica reaper "
            "Deployment). Cross-instance leader election is deferred to "
            "Sprint 10.5. When false, create_prod_app starts no reaper and "
            "logs a disabled-posture line at startup."
        ),
    )

    # --- Sprint 10.5a T6 — scheduler primitive Settings (ADR-022) ----
    # Per spec §4.1 + §4.5: 7 bounded-invariant fields consumed by
    # SchedulerEngine at engine construction time + reap_expired() at
    # the operator reconciler-loop call site. Defaults are operator-
    # tunable; the gt=0 floor is wire-protocol-public for the
    # ConcurrencyCaps + BoundedQueue primitives that consume them.
    # Bounded-invariant tests at
    # ``tests/unit/test_config.py::TestSprint105SchedulerSettings``
    # mirror the same gt=0 floor pinned at
    # ``tests/unit/core/scheduler/test_queue.py::TestConcurrencyCapsBounded``.
    scheduler_queue_depth_interactive: int = Field(
        default=32,
        gt=0,
        description=(
            "Sprint 10.5a — per-(tenant, interactive) BoundedQueue max "
            "depth. SchedulerEngine raises refused_queue_full when an "
            "interactive submission cannot be admitted because all caps "
            "are saturated AND the queue is at this depth."
        ),
    )
    scheduler_queue_depth_background: int = Field(
        default=256,
        gt=0,
        description=(
            "Sprint 10.5a — per-(tenant, background) BoundedQueue max "
            "depth. Higher than interactive per spec §4.3: background "
            "workloads tolerate deeper queues; interactive submissions "
            "need lower retry-after latency."
        ),
    )
    scheduler_per_tenant_interactive: int = Field(
        default=32,
        gt=0,
        description=(
            "Sprint 10.5a — per-tenant concurrent-interactive-task cap "
            "(ConcurrencyCaps.per_tenant_interactive). Engine refuses "
            "queue admission when this is exceeded AND the queue is at "
            "max depth (refused_queue_full); otherwise enqueues."
        ),
    )
    scheduler_per_tenant_background: int = Field(
        default=64,
        gt=0,
        description=(
            "Sprint 10.5a — per-tenant concurrent-background-task cap "
            "(ConcurrencyCaps.per_tenant_background). Per spec §4.5, "
            "background tenant cap is a separate axis from interactive."
        ),
    )
    scheduler_per_pack: int = Field(
        default=8,
        gt=0,
        description=(
            "Sprint 10.5a — per-pack concurrent-task cap "
            "(ConcurrencyCaps.per_pack). Applies uniformly to "
            "interactive + background classes."
        ),
    )
    scheduler_per_actor: int = Field(
        default=4,
        gt=0,
        description=(
            "Sprint 10.5a — per-actor (subject) concurrent-task cap "
            "(ConcurrencyCaps.per_actor). Applies uniformly to "
            "interactive + background classes."
        ),
    )
    scheduler_queue_ttl_s: int = Field(
        default=3600,
        gt=0,
        description=(
            "Sprint 10.5a — queue TTL (seconds) consumed by "
            "SchedulerEngine.reap_expired() per spec §4.4. A queued "
            "task whose age exceeds this value is transitioned "
            "pending → expired, quota released, removed from queue, "
            "and emits scheduler.task_expired chain row. Single value "
            "applied to BOTH interactive + background classes in "
            "Wave-1; per-class TTL is a future extension if operator "
            "tuning warrants it."
        ),
    )
    memory_block_max_bytes: int = Field(
        default=4096,
        gt=0,
        description="Sprint 11.5 — max serialized bytes for a single memory block.",
    )
    memory_scratch_ttl_s: int = Field(
        default=3600,
        gt=0,
        description="Sprint 11.5 — Redis TTL for scratch-tier memory.",
    )
    memory_tombstone_window_s: int = Field(
        default=2_592_000,
        gt=0,
        description="Sprint 11.5 — tombstone window before reaper purge (default 30d).",
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
