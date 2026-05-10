"""Sprint-7A2 — :mod:`cognic_agentos.packs.hooks` runtime hook subsystem.

Three modules per Doctrine Lock D in
``docs/superpowers/plans/2026-05-09-sprint-7a2-hook-packs-runtime.md``:

* :mod:`cognic_agentos.packs.hooks.registry` — ``HookRegistry``
  admission gate (T6). Single-writer at admission; indexed by
  ``(phase, hook_id)``; fail-closed on cross-pack duplicate IDs,
  unverified packs, stale digests, and timeout-above-ceiling.
* :mod:`cognic_agentos.packs.hooks.dispatcher` — ``HookDispatcher``
  deterministic phase dispatcher (T7). Reads an immutable snapshot
  from the registry; never mutates registry state. Five closed-enum
  failure modes per Doctrine Lock E
  (``hook_timeout`` / ``hook_exception`` / ``hook_malformed_result`` /
  ``hook_policy_refused`` / ``hook_payload_unscannable``). T8 added
  ``dispatch_for_pack`` for per-pack hook subset selection.
  Payload-contents-never-logged invariant pinned by
  ``tests/architecture/test_hook_payload_never_logged.py``.
* :mod:`cognic_agentos.packs.hooks.dlp_integration` — ``DLPGuard``
  runtime DLP scan adapter (T8). Per ADR-017 line 97: "pack manifest
  names which hooks must run; AgentOS resolves them via the plugin
  registry". Wraps the dispatcher's per-pack selector with the
  data-governance pre/post phase semantics + closed-enum 3-value
  ``DLPRefusalReason`` (``dlp_hook_id_unresolved`` /
  ``dlp_dispatcher_failed`` / ``dlp_dispatcher_refused``).

The hook surface is a Wave-1 ADR-017 enforcement primitive: DLP
pre/post hooks gate the calling-pack invocation lifecycle. The
``Hook`` base class + ``HookContext`` / ``HookResult`` value objects
live in :mod:`cognic_agentos.sdk.hook` (public authoring API); the
runtime registry / dispatcher / DLP adapter live here (OS-internal
admission + dispatch).
"""

from __future__ import annotations

from cognic_agentos.packs.hooks.dispatcher import (
    HookDispatcher,
    HookDispatchOutcome,
    HookDispatchResult,
    HookDispatchSelectionError,
    HookFailureMode,
)
from cognic_agentos.packs.hooks.dlp_integration import (
    DLPGuard,
    DLPGuardOutcome,
    DLPRefusalReason,
)
from cognic_agentos.packs.hooks.registry import (
    HookDeclaration,
    HookEntry,
    HookRegistry,
    HookRegistryRefusal,
    HookRegistryRefusalReason,
    VerifiedHookPack,
)

__all__ = [
    "DLPGuard",
    "DLPGuardOutcome",
    "DLPRefusalReason",
    "HookDeclaration",
    "HookDispatchOutcome",
    "HookDispatchResult",
    "HookDispatchSelectionError",
    "HookDispatcher",
    "HookEntry",
    "HookFailureMode",
    "HookRegistry",
    "HookRegistryRefusal",
    "HookRegistryRefusalReason",
    "VerifiedHookPack",
]
