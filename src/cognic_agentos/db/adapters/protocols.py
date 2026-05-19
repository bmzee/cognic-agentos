"""Adapter protocols — typed contracts every bundled or plugin adapter implements.

Per ADR-009. PEP-544 ``Protocol`` is used so adapters do NOT need to
inherit from a base class; structural conformance is enough. Each protocol
is decorated with ``@runtime_checkable`` so the test suite (and the
factory) can verify a registered class actually satisfies its declared
shape at registration time.

Async/sync flavour rule: every IO-bound method is ``async``. Pure-getter
methods (e.g. ``EmbeddingAdapter.dimensions``) are synchronous.

``ObjectStoreAdapter`` ships its first production driver in Sprint 4
(``local_fs``, filesystem-backed, on the main runtime path per AGENTS.md
production-grade rule). Sprint 8 adds the ``s3`` driver alongside —
both drivers conform to this Protocol; deployments select per-tenant via
``Settings.object_store_driver``.

Memory governance (``MemoryAdapter`` per ADR-019) is **not** declared in
this sprint — it ships with Sprint 11.5 alongside ``core/memory/``. The
registry's ``kind`` field is unconstrained, so Sprint 11.5 can add
``"memory"`` without modifying this module.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
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
    """Object storage — production drivers ship per backend.

    Drivers:
      * ``local_fs`` (Sprint 4): filesystem-backed; production code on
        the main runtime path per AGENTS.md production-grade rule.
        Single-host AgentOS, NFS / EFS / Azure Files / on-prem mounts.
      * ``s3`` (Sprint 8): S3-compat (boto3 / MinIO). Adds signed-URL
        semantics for cross-host attestation-bundle access.
      * Future: Azure Blob, GCS via plugin packs.

    All drivers conform to this Protocol; deployments select via
    ``Settings.object_store_driver``.
    """

    async def put(
        self,
        bucket: str,
        key: str,
        body: bytes,
        *,
        retention_seconds: int | None = None,
    ) -> None:
        """Persist ``body`` at ``bucket/key``.

        Atomic semantics: callers see either the previous content or
        the complete new content; partial / corrupt writes are never
        visible to ``get()``.

        ``retention_seconds`` (optional): when set, the driver enforces
        retention at the adapter boundary — ``delete()`` raises within
        the retention window. Sprint-4 ``local_fs`` driver records
        retention metadata in a sidecar file; Sprint-8 ``s3`` driver
        uses S3 Object Lock. Drivers that cannot enforce retention
        (e.g. memory-only adapters) MAY silently no-op the retention
        kwarg, but production drivers MUST honour it.
        """
        ...

    async def get(self, bucket: str, key: str) -> bytes: ...
    async def delete(self, bucket: str, key: str) -> None:
        """Remove the object at ``bucket/key``.

        Drivers that enforce retention raise ``RetentionWindowActiveError``
        (or driver-specific equivalent) when the retention window has
        not elapsed. Operators must wait for the window to expire
        rather than swallowing the error.
        """
        ...

    async def presign(self, bucket: str, key: str, ttl_s: int) -> str:
        """Return an external-HTTP-accessible signed URL for the key.

        Drivers backed by storage that does not natively support
        signed URLs (e.g. the Sprint-4 ``local_fs`` driver) MAY raise
        ``NotImplementedError`` rather than synthesise a degenerate
        URL that would silently mislead callers expecting cross-host
        retrieval. Callers needing presigned-URL semantics must
        select a driver that implements them (e.g. ``s3`` once
        Sprint 8 ships). R2-#1 reviewer-fix: this caveat is required
        because the local driver fails loud per AGENTS.md
        production-grade rule.
        """
        ...

    def list_prefix(
        self,
        bucket: str,
        prefix: str,
    ) -> AsyncIterator[str]:
        """Lazily yield keys under ``bucket/prefix`` in a **deterministic
        per-driver order** (NOT necessarily globally lexicographic — see
        the "Order contract" paragraphs below for the per-driver
        semantics).

        **Async-generator shape — NOT a coroutine.** Declared as plain
        ``def`` returning ``AsyncIterator[str]`` (NOT ``async def``).
        Implementations are async-generator functions (``async def`` +
        ``yield``); calling the method returns an ``AsyncIterator``
        DIRECTLY without await. PEP 525 + ``typing.AsyncIterator``
        convention.

        The wrong shape — ``async def f() -> AsyncIterator[str]`` — would
        type as "coroutine returning an AsyncIterator" and force callers
        to ``async for x in (await f())`` instead of the natural
        ``async for x in f()``. This Protocol declaration locks the
        right call shape across all driver implementations. Pinned by
        ``tests/unit/db/test_object_store_adapter_list_prefix.py::TestListPrefixProtocolShape``.

        Caller pattern (the only supported one):

            async for key in object_store.list_prefix("bucket", "prefix/"):
                ...

        Yields full keys (NOT relative-to-prefix) in a **deterministic
        per-driver order**. The Sprint-4 ``local_fs`` driver uses
        depth-first traversal with sorted-per-directory order; future
        ``s3`` drivers will use ``ListObjectsV2`` which yields globally
        lexicographic order. These differ for keys spanning directory
        boundaries — e.g., keys ``a/z`` and ``a.txt`` yield
        ``["a/z", "a.txt"]`` under ``local_fs`` (depth-first into ``a/``
        first) but ``["a.txt", "a/z"]`` under S3 (``.`` < ``/`` in
        ASCII). The Protocol guarantees DETERMINISM (stable within a
        driver across calls with the same state); callers requiring a
        specific cross-driver order (e.g., globally lexicographic) MUST
        re-sort the yielded keys. Sprint 8.5 ``CheckpointStore`` callers
        do not depend on order (``load_latest()`` picks by ``created_at``
        from metadata; ``purge_expired()`` is order-independent).

        Empty result is a normal empty iterator (NOT an exception).
        Implementations MUST be lazy — yielding one key per loop
        iteration rather than loading the full key list into memory — so
        reaper sweeps over multi-million-key tenants do not OOM.
        Globally-lexicographic order is NOT compatible with the
        single-pass lazy contract (would require buffering or a
        merge-sort across directories); the per-driver determinism
        contract is the deliberate trade-off.

        The Sprint-4 ``local_fs`` driver walks the prefix directory via
        ``os.scandir()`` recursively (async-generator function yielding
        one key at a time) with a dual symlink-escape defence per Sprint
        8.5 spec §3.5 + §9. Future ``s3`` drivers map to
        ``ListObjectsV2`` with continuation-token pagination.

        Sprint 8.5 added this method as an additive wire-contract change
        to the Sprint-4 critical-controls Protocol per ADR-009 §"Wave-1
        ObjectStoreAdapter consumers" — required by
        ``CheckpointStore.load_latest()`` + ``purge_expired()``.
        """
        ...

    async def health_check(self) -> AdapterHealth: ...


@runtime_checkable
class ObservabilityAdapter(Protocol):
    """Observability sink — Sprint 1C ships langfuse_otel (OTel-bridged + Langfuse health probe)."""

    async def emit_trace(self, name: str, attributes: dict[str, Any]) -> None: ...
    async def emit_metric(self, name: str, value: float, attributes: dict[str, Any]) -> None: ...
    async def flush(self) -> None: ...
    async def health_check(self) -> AdapterHealth: ...
