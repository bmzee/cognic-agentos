"""Adapter factory — builds the ``Adapters`` container from ``Settings``.

The factory is the only place ``Settings`` field names cross into the
adapter layer. Adapter constructors take a small typed config they can
read from settings via small per-driver helper functions kept here to
avoid scattering settings access across adapter modules.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from typing import Any

from cognic_agentos.core.config import Settings
from cognic_agentos.db.adapters import protocols as P
from cognic_agentos.db.adapters.registry import AdapterRegistry, bundled_registry


@dataclass(slots=True)
class Adapters:
    """Typed container exposed to the FastAPI lifespan + harness.

    ``object_store`` ships in Sprint 8 (alongside evidence-pack export).
    ``None`` in Sprint 1C — the slot exists so Sprint 8 does not require
    a structural migration. Memory governance (Sprint 11.5 / ADR-019) is
    handled outside this dataclass; that sprint introduces both the
    protocol AND the slot at the same time.
    """

    relational: P.RelationalAdapter
    vector: P.VectorAdapter
    secret: P.SecretAdapter
    embedding: P.EmbeddingAdapter
    observability: P.ObservabilityAdapter
    object_store: P.ObjectStoreAdapter | None = None
    _all: list[Any] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        self._all = [
            self.relational,
            self.vector,
            self.secret,
            self.embedding,
            self.observability,
        ]

    async def open_all(self) -> None:
        """Open every adapter that has a ``connect()``. Idempotent for
        adapters whose constructor already established the connection
        (e.g. dict-backed memory variants)."""

        for a in self._all:
            connect = getattr(a, "connect", None)
            if callable(connect):
                await connect()

    async def close_all(self) -> None:
        """Close in reverse-open order. Errors are swallowed per-adapter
        and surfaced via the next ``/readyz`` probe."""

        for a in reversed(self._all):
            close = getattr(a, "close", None)
            if callable(close):
                # Logging happens at the lifespan boundary; here we never
                # let one adapter's shutdown error prevent the others from
                # cleaning up. ``contextlib.suppress`` is the canonical
                # Python pattern for this (per ruff SIM105).
                with contextlib.suppress(Exception):
                    await close()


def build_adapters(
    settings: Settings,
    *,
    registry: AdapterRegistry | None = None,
) -> Adapters:
    """Read driver names from ``settings``, instantiate each adapter, return ``Adapters``.

    Raises :exc:`AdapterNotInstalled` when a configured driver isn't registered.
    """

    reg = registry or bundled_registry

    relational_cls = reg.resolve("relational", settings.db_driver)
    vector_cls = reg.resolve("vector", settings.vector_driver)
    secret_cls = reg.resolve("secret", settings.secret_driver)
    embedding_cls = reg.resolve("embedding", settings.embed_driver)
    observability_cls = reg.resolve("observability", settings.obs_driver)

    return Adapters(
        relational=relational_cls(*_relational_args(settings)),
        vector=vector_cls(*_vector_args(settings)),
        secret=secret_cls(*_secret_args(settings)),
        embedding=embedding_cls(*_embedding_args(settings)),
        observability=observability_cls(*_observability_args(settings)),
    )


# --- per-driver constructor argument helpers --------------------------------
# Each helper returns the positional args the bundled adapter expects.
# Keeping them here means adding a new driver doesn't touch the factory's
# core logic — the pattern is consistent: registered class + helper.


def _relational_args(s: Settings) -> tuple[Any, ...]:
    if s.db_driver == "memory":
        return ()
    if s.db_driver == "postgres":
        return (s.database_url,)
    if s.db_driver == "oracle":
        # Oracle uses the existing database_url field with the
        # oracle+oracledb://...?service_name=... SQLAlchemy URL shape.
        return (s.database_url,)
    return ()  # plugin packs may take additional args via their own helper


def _vector_args(s: Settings) -> tuple[Any, ...]:
    if s.vector_driver == "memory":
        return ()
    if s.vector_driver == "qdrant":
        return (s.qdrant_url, s.qdrant_collection)
    return ()


def _secret_args(s: Settings) -> tuple[Any, ...]:
    if s.secret_driver == "memory":
        return ()
    if s.secret_driver == "vault":
        return (s.vault_addr, s.vault_token, s.vault_namespace)
    return ()


def _embedding_args(s: Settings) -> tuple[Any, ...]:
    if s.embed_driver == "memory":
        return ()
    if s.embed_driver == "ollama":
        return (s.embedding_base_url, s.embedding_model, s.embedding_dimensions)
    if s.embed_driver == "openai_compat":
        return (
            s.embedding_base_url,
            s.embedding_model,
            s.embedding_dimensions,
            s.embed_provider_label,
            s.embedding_api_key,
            s.embedding_api_key_header,
            s.embedding_extra_headers,
        )
    return ()


def _observability_args(s: Settings) -> tuple[Any, ...]:
    if s.obs_driver == "memory":
        return ()
    if s.obs_driver == "langfuse_otel":
        return (s.langfuse_host, s.langfuse_public_key, s.langfuse_secret_key)
    if s.obs_driver == "dynatrace":
        return (s.dynatrace_tenant_url, s.dynatrace_api_token)
    return ()
