"""Sprint-7A2 — :mod:`cognic_agentos.packs.hooks` runtime hook subsystem.

Two modules per Doctrine Lock D in
``docs/superpowers/plans/2026-05-09-sprint-7a2-hook-packs-runtime.md``:

* :mod:`cognic_agentos.packs.hooks.registry` — ``HookRegistry``
  admission gate (T6). Single-writer at admission; indexed by
  ``(phase, hook_id)``; fail-closed on cross-pack duplicate IDs,
  unverified packs, stale digests, and timeout-above-ceiling.
* :mod:`cognic_agentos.packs.hooks.dispatcher` — ``HookDispatcher``
  deterministic phase dispatcher (T7). Reads an immutable snapshot
  from the registry; never mutates registry state. (Lands at T7;
  this package does not export it yet.)

The hook surface is a Wave-1 ADR-017 enforcement primitive: DLP
pre/post hooks gate the calling-pack invocation lifecycle. The
``Hook`` base class + ``HookContext`` / ``HookResult`` value objects
live in :mod:`cognic_agentos.sdk.hook` (public authoring API); the
runtime registry / dispatcher live here (OS-internal admission +
dispatch).
"""

from __future__ import annotations

from cognic_agentos.packs.hooks.registry import (
    HookDeclaration,
    HookEntry,
    HookRegistry,
    HookRegistryRefusal,
    HookRegistryRefusalReason,
    VerifiedHookPack,
)

__all__ = [
    "HookDeclaration",
    "HookEntry",
    "HookRegistry",
    "HookRegistryRefusal",
    "HookRegistryRefusalReason",
    "VerifiedHookPack",
]
