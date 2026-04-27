"""Adapter protocols — typed contracts every bundled or plugin adapter implements.

Per ADR-009. PEP-544 ``Protocol`` is used so adapters do NOT need to
inherit from a base class; structural conformance is enough. Each protocol
is decorated with ``@runtime_checkable`` so the test suite (and the
factory) can verify a registered class actually satisfies its declared
shape at registration time.

Async/sync flavour rule: every IO-bound method is ``async``. Pure-getter
methods (e.g. ``EmbeddingAdapter.dimensions``) are synchronous.

``ObjectStoreAdapter`` is declared-only in Sprint 1C — Sprint 8 ships
the S3/MinIO impl alongside evidence-pack export. Declaring it here lets
the rest of the codebase reference the type immediately and avoids a
churn migration later.

Memory governance (``MemoryAdapter`` per ADR-019) is **not** declared in
this sprint — it ships with Sprint 11.5 alongside ``core/memory/``. The
registry's ``kind`` field is unconstrained, so Sprint 11.5 can add
``"memory"`` without modifying this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable

AdapterStatus = Literal["ok", "degraded", "unreachable"]


@dataclass(frozen=True, slots=True)
class AdapterHealth:
    """Standardised return shape for every ``health_check()``.

    ``status`` is the boolean signal /readyz collapses across adapters
    (``ok`` → 200; anything else → 503). ``driver`` lets the operator
    see exactly which bundled or plugin driver answered. ``detail`` is a
    free-form string for diagnostic noise (e.g. error class). ``latency_ms``
    is the elapsed health-probe wall-time so dashboards can chart adapter
    responsiveness.
    """

    status: AdapterStatus
    driver: str
    detail: str | None = None
    latency_ms: float | None = None

    def __post_init__(self) -> None:
        if self.status not in ("ok", "degraded", "unreachable"):
            raise ValueError(
                f"AdapterHealth.status must be ok|degraded|unreachable; got {self.status!r}"
            )


# --- Vector helpers ----------------------------------------------------


@dataclass(frozen=True, slots=True)
class VectorItem:
    """A single point to upsert into a vector collection."""

    id: str
    vector: list[float]
    payload: dict[str, Any]


@dataclass(frozen=True, slots=True)
class VectorHit:
    """A single search result."""

    id: str
    score: float
    payload: dict[str, Any]


# --- Secret helpers ----------------------------------------------------


@dataclass(frozen=True, slots=True)
class SecretLease:
    """Result of ``SecretAdapter.lease()``."""

    lease_id: str
    ttl_s: int
    value: dict[str, Any]


# --- Protocols ---------------------------------------------------------


@runtime_checkable
class RelationalAdapter(Protocol):
    """RDBMS adapter — Sprint 1C ships postgres; Sprint 1D adds oracle."""

    async def connect(self) -> None: ...
    def session(self) -> Any: ...
    async def run_migrations(self, dir: str) -> None: ...
    async def close(self) -> None: ...
    async def health_check(self) -> AdapterHealth: ...


@runtime_checkable
class VectorAdapter(Protocol):
    """Vector store — Sprint 1C ships qdrant."""

    async def ensure_collection(self, name: str, dim: int, metric: str = "cosine") -> None: ...
    async def upsert(self, items: list[VectorItem]) -> None: ...
    async def search(
        self,
        vector: list[float],
        k: int = 10,
        filter: dict[str, Any] | None = None,
    ) -> list[VectorHit]: ...
    async def delete(self, ids: list[str]) -> None: ...
    async def health_check(self) -> AdapterHealth: ...


@runtime_checkable
class SecretAdapter(Protocol):
    """Secrets manager — Sprint 1C ships vault."""

    async def read(self, path: str) -> dict[str, Any]: ...
    async def write(self, path: str, value: dict[str, Any]) -> None: ...
    async def lease(self, path: str, ttl_s: int) -> SecretLease: ...
    async def revoke(self, lease_id: str) -> None: ...
    async def health_check(self) -> AdapterHealth: ...


@runtime_checkable
class EmbeddingAdapter(Protocol):
    """Embedding provider — Sprint 1C ships ollama (dev); Sprint 1D adds openai_compat (prod)."""

    async def embed(self, texts: list[str]) -> list[list[float]]: ...
    @property
    def dimensions(self) -> int: ...
    async def health_check(self) -> AdapterHealth: ...


@runtime_checkable
class ObjectStoreAdapter(Protocol):
    """Object storage — DECLARED ONLY in Sprint 1C; Sprint 8 ships the S3/MinIO impl
    alongside evidence-pack export."""

    async def put(self, bucket: str, key: str, body: bytes) -> None: ...
    async def get(self, bucket: str, key: str) -> bytes: ...
    async def delete(self, bucket: str, key: str) -> None: ...
    async def presign(self, bucket: str, key: str, ttl_s: int) -> str: ...
    async def health_check(self) -> AdapterHealth: ...


@runtime_checkable
class ObservabilityAdapter(Protocol):
    """Observability sink — Sprint 1C ships langfuse_otel (OTel-bridged + Langfuse health probe)."""

    async def emit_trace(self, name: str, attributes: dict[str, Any]) -> None: ...
    async def emit_metric(self, name: str, value: float, attributes: dict[str, Any]) -> None: ...
    async def flush(self) -> None: ...
    async def health_check(self) -> AdapterHealth: ...
