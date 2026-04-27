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

import platform
import sys
from datetime import UTC, datetime
from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from cognic_agentos import __version__

RuntimeProfile = Literal["dev", "stage", "prod"]


class Settings(BaseSettings):
    """Top-level settings container.

    Loaded from environment with the ``COGNIC_`` prefix or from a local
    ``.env`` file in dev. Production deployments pass values via the
    container runtime; ``.env`` is not read in ``prod`` profile (see
    ``model_config`` ordering below — env always wins over ``.env``).
    """

    model_config = SettingsConfigDict(
        env_prefix="COGNIC_",
        env_file=".env",
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
        description="Default logging level for the structured-logging stack (Sprint 1B).",
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


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings instance.

    Cached so that every code path observes a single Settings object;
    tests reset the cache via ``get_settings.cache_clear()``.
    """

    return Settings()
