"""Adapter package — protocols, bundled implementations, registry, factory.

The public API (Sprint 1C):

- :mod:`protocols` — six ADR-009 typed contracts (RelationalAdapter,
  VectorAdapter, SecretAdapter, EmbeddingAdapter, ObjectStoreAdapter,
  ObservabilityAdapter). ``MemoryAdapter`` ships with Sprint 11.5
  per ADR-019.
- :class:`Adapters`, :func:`build_adapters` — typed container + factory.
- :class:`AdapterRegistry`, :exc:`AdapterNotInstalled`,
  :data:`bundled_registry`.
- :func:`load_bundled_adapters` — explicit loader the lifespan invokes
  at startup. Imports each bundled adapter module so its registration
  side-effect runs. Allowlisted optional-dep misses (kernel image
  deliberately omits the ``adapters`` extras) are skipped silently;
  unexpected import errors re-raise so real bugs surface.
"""

from __future__ import annotations

import importlib
import logging

from cognic_agentos.db.adapters import protocols
from cognic_agentos.db.adapters.factory import Adapters, build_adapters
from cognic_agentos.db.adapters.registry import (
    AdapterNotInstalled,
    AdapterRegistry,
    bundled_registry,
)

logger = logging.getLogger(__name__)


# The five bundled-adapter modules Sprint 1C ships, mapped to the top-level
# packages whose absence is **legitimate** in the kernel image (which omits
# the ``adapters`` optional-dep group). Any other ImportError — typo inside
# the module, transitive dep that the adapter module itself imports
# unexpectedly, broken package post-install — re-raises so operators see
# real bugs immediately. Empty frozenset means "no kernel-image-acceptable
# misses; any ImportError from this module is a bug."
_BUNDLED_ADAPTER_OPTIONAL_DEPS: dict[str, frozenset[str]] = {
    "cognic_agentos.db.adapters.postgres_adapter": frozenset({"sqlalchemy", "asyncpg"}),
    "cognic_agentos.db.adapters.qdrant_adapter": frozenset({"qdrant_client"}),
    "cognic_agentos.db.adapters.vault_adapter": frozenset({"hvac"}),
    # Ollama adapter only depends on httpx (always present); no kernel-image misses.
    "cognic_agentos.db.adapters.ollama_embedding_adapter": frozenset(),
    "cognic_agentos.db.adapters.langfuse_otel_adapter": frozenset({"langfuse"}),
    # Sprint 1D enterprise adapters
    "cognic_agentos.db.adapters.oracle_adapter": frozenset({"sqlalchemy", "oracledb"}),
}


def load_bundled_adapters() -> dict[str, str]:
    """Import each bundled adapter module so its driver registers.

    On ``ImportError``, inspect ``.name`` (PEP 451) — if the missing
    top-level package is on the adapter's optional-deps allowlist, log
    + skip (kernel image legitimately lacks it). Otherwise re-raise so
    real bugs are not silently buried.

    Returns a diagnostic map ``{module_name: 'loaded' | 'skipped: <reason>'}``.
    Configured-but-missing drivers later surface via ``AdapterNotInstalled``
    from the factory.
    """

    results: dict[str, str] = {}
    for fqmn in _BUNDLED_ADAPTER_OPTIONAL_DEPS:
        try:
            importlib.import_module(fqmn)
            results[fqmn] = "loaded"
        except ImportError as exc:
            missing_module = (exc.name or "").split(".")[0]
            allowlist = _BUNDLED_ADAPTER_OPTIONAL_DEPS[fqmn]
            if missing_module and missing_module in allowlist:
                results[fqmn] = f"skipped: optional dep {missing_module!r} not installed"
                logger.info(
                    "bundled adapter %s skipped: optional dep %r absent (kernel image)",
                    fqmn,
                    missing_module,
                )
            else:
                # Real bug — typo inside our adapter, broken package,
                # missing internal symbol, or the module file itself absent.
                # Do not bury it.
                logger.error(
                    "bundled adapter %s failed to load with unexpected ImportError "
                    "(missing module=%r, allowlist=%s): %s",
                    fqmn,
                    missing_module,
                    sorted(allowlist),
                    exc,
                )
                raise
    return results


__all__ = [
    "AdapterNotInstalled",
    "AdapterRegistry",
    "Adapters",
    "build_adapters",
    "bundled_registry",
    "load_bundled_adapters",
    "protocols",
]
