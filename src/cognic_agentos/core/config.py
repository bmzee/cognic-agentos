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
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

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
            "OTLP gRPC endpoint for trace export (e.g. http://otel-collector:4317). "
            "When unset, the OTel tracer falls back to a console exporter in dev "
            "and a no-op exporter in prod (so traces are silently dropped rather "
            "than printed to stdout)."
        ),
    )
    prometheus_metrics_path: str = Field(
        default="/metrics",
        description="Path the Prometheus instrumentator exposes the scrape endpoint at "
        "(joined under api_prefix).",
    )
    cors_allowed_origins: list[str] = Field(
        default_factory=list,
        description=(
            "Allow-list of origins permitted by the CORS middleware. The literal "
            "string `*` is forbidden (per Phase-1 'CORS allow-list-only' principle)."
        ),
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
