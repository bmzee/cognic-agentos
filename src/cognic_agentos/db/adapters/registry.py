"""Adapter registry — maps (kind, driver_name) → adapter class.

Bundled adapter modules call ``bundled_registry.register(...)`` at import
time so a plain ``import cognic_agentos.db.adapters.postgres_adapter`` (or
the ``load_bundled_adapters`` helper in ``__init__.py``) populates the
default driver set before the factory runs.

Plugin-pack adapters (per ADR-002) discover via Python entry points in
Sprint 4 and register into a per-process ``AdapterRegistry`` the host
constructs from ``bundled_registry`` plus discovered packs.
"""

from __future__ import annotations

from typing import Literal

from cognic_agentos.db.adapters import protocols as P

# Sprint 1C's known kinds. The registry itself does NOT enforce this set —
# Sprint 11.5 adds "memory" (per ADR-019) without modifying this module
# (the AdapterKind alias is convenience typing for Sprint 1C consumers).
AdapterKind = Literal[
    "relational", "vector", "secret", "embedding", "object_store", "observability", "cache"
]

# The PEP-544 protocol classes exposed alongside each kind — used by tests
# (and Sprint 4 plugin host) to verify registered classes structurally
# satisfy the declared shape. Keys are plain ``str`` so future kinds
# (e.g. "memory" in Sprint 11.5) can join without changing the type.
PROTOCOL_FOR_KIND: dict[str, type] = {
    "relational": P.RelationalAdapter,
    "vector": P.VectorAdapter,
    "secret": P.SecretAdapter,
    "embedding": P.EmbeddingAdapter,
    "object_store": P.ObjectStoreAdapter,
    "observability": P.ObservabilityAdapter,
    "cache": P.CacheAdapter,
}


class AdapterNotInstalled(Exception):
    """Raised when ``Settings`` declares a driver no registered class serves.

    The factory surfaces this at startup so misconfigurations fail fast —
    no silent fallback is permitted (per ADR-009).
    """

    def __init__(self, kind: str, driver: str) -> None:
        super().__init__(
            f"adapter not installed: kind={kind} driver={driver!r}. "
            "Bundled drivers register at import time; alternative drivers "
            "must be installed as plugin packs (see ADR-002, ADR-009)."
        )
        self.kind = kind
        self.driver = driver


class AdapterRegistry:
    """Mapping from ``(kind, driver_name)`` → adapter class.

    The class is responsible for instantiation; the factory owns the
    instantiation parameters (passed via ``Settings``).
    """

    def __init__(self) -> None:
        self._reg: dict[tuple[str, str], type] = {}

    def register(self, kind: str, driver: str, cls: type) -> None:
        self._reg[(kind, driver)] = cls

    def resolve(self, kind: str, driver: str) -> type:
        try:
            return self._reg[(kind, driver)]
        except KeyError as exc:
            raise AdapterNotInstalled(kind, driver) from exc

    def has(self, kind: str, driver: str) -> bool:
        return (kind, driver) in self._reg

    def kinds(self) -> set[str]:
        return {k for (k, _) in self._reg}


# Process-wide bundled registry. Bundled adapter modules mutate this on import.
bundled_registry = AdapterRegistry()
