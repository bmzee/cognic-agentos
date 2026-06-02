"""Sprint 11.5b T8 — memory infra exceptions (core/ stop-rule per AGENTS.md).

``MemoryBackendUnavailable`` is an INFRASTRUCTURE exception — a backend-down /
driver-error condition, NOT a governance refusal. It is deliberately separate
from the storage module so that the routing layer (``_routing.py``) can catch it
WITHOUT runtime-importing ``core.memory.storage`` (which the Layer-C
architectural-arrow guard at
``tests/unit/architecture/test_memory_layer_c_no_direct_storage.py`` forbids
outside ``storage.py`` — a runtime storage import could construct an adapter and
bypass the ``MemoryGate``). ``storage.py`` re-exports this symbol for
backward-compatibility, so existing ``from ...storage import
MemoryBackendUnavailable`` call sites are unaffected.
"""

from __future__ import annotations


class MemoryBackendUnavailable(Exception):
    """Infra failure (backend unreachable / driver error).

    Deliberately a plain ``Exception`` — NOT a ``MemoryOperationRefused``
    subclass. An unreachable backend is not a governance refusal and must
    not be mistaken for the wire-public ``MemoryRefusalReason`` taxonomy.

    ``unreachable`` is ``True`` ONLY when the underlying cause indicates the
    backend is *unreachable* (``ConnectionError``, ``OSError``,
    ``TimeoutError``, or a ``redis.exceptions.RedisError``). A Redis read/write
    bug (e.g. a bad data shape) is a different failure mode — the
    ``RoutingMemoryAdapter`` falls back to Postgres scratch ONLY when
    ``unreachable=True``.
    """

    def __init__(self, detail: str, *, unreachable: bool = False) -> None:
        super().__init__(detail)
        self.unreachable = unreachable


__all__ = ("MemoryBackendUnavailable",)
