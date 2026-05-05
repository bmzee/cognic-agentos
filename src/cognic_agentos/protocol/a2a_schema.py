"""protocol/a2a_schema.py — pinned A2A 1.0 wire-format types.

Critical-controls module per AGENTS.md (Sprint-6 amendment, "Protocol
— A2A endpoint" section). Wire-format drift = wire-protocol break;
the schema-drift CI gate (``test_a2a_schema_drift.py``) catches
upstream movement before it reaches us.

Re-exports the ``a2a-sdk`` SDK's protobuf-generated message types
under stable AgentOS names so downstream code keeps working when we
bump the SDK pin. The pinned digest below is captured from the
upstream A2A 1.0 spec source at SDK pin time (T2 + T6 capture); the
drift gate compares upstream's current digest against this constant
and fails the build on mismatch (per Sprint-6 Decision Lock #1 —
silent upgrades forbidden).

Pinned A2A spec version: ``1.0`` (April 2026 release, Linux-Foundation
governance). Bumping the pinned version is a deliberate reviewed
change.

**Admission-side per Sprint-5 R3 P1 + Sprint-6 same doctrine.** The
module imports cleanly without ``a2a-sdk`` installed; only attribute
access (e.g., ``a2a_schema.AgentCard``) materialises the SDK via
:func:`require_a2a`. Module-level constants
(:data:`_PINNED_PROTOBUF_DIGEST`, :data:`_UPSTREAM_PROTOBUF_URL`,
:data:`A2A_SPEC_VERSION`) remain accessible without the SDK so the
drift CI gate's metadata can be read in any image.

**Capture-time divergence from the plan-of-record (T6 R0 capture):**
the plan's draft listed both ``_PINNED_PROTOBUF_DIGEST`` AND
``_PINNED_JSON_SCHEMA_DIGEST`` (with parity check) on the assumption
the spec authors publish both artifacts at canonical URLs. Reality
at T6 capture time: the A2A spec source-of-truth is a single
``a2a.proto`` file at
``github.com/a2aproject/A2A/blob/v1.0.0/specification/a2a.proto``;
the ``specification/json/`` directory contains only a README pointing
back at the protobuf source. There is no separately-published JSON-
schema bundle to pin or check parity against. T6 ships the protobuf
digest only; the JSON-schema artifact + parity check land when (or
if) the spec authors publish a canonical JSON-schema bundle.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cognic_agentos.protocol import require_a2a

#: Pinned A2A spec version. Single source of truth for any code
#: that needs to assert spec compliance + the version emitted in
#: the ``A2A-Version`` outbound header (T8).
A2A_SPEC_VERSION: str = "1.0"

#: SHA-256 of the upstream A2A 1.0 protobuf source at the pinned
#: tag. Captured at T6 commit time from
#: ``raw.githubusercontent.com/a2aproject/A2A/v1.0.0/specification/a2a.proto``.
#: The drift CI gate (``test_a2a_schema_drift.py``) re-fetches this
#: URL and compares the resulting SHA-256 against this constant;
#: mismatch fails the build and a deliberate review + version-bump
#: pass is required (per Sprint-6 Decision Lock #1).
_PINNED_PROTOBUF_DIGEST: str = "4b74c0baa923ae0acb55474e548f1d6e5d3f83b80d757b65f8bf3e99a3c2257f"

#: Canonical upstream URL for the pinned protobuf source. Pinned to
#: the ``v1.0.0`` git tag (NOT ``main``) so spec-authors' work-in-
#: progress on main doesn't trip the gate; only a deliberate
#: spec-author decision to update v1.0.0 (or our own decision to
#: bump the pinned tag) trips it.
_UPSTREAM_PROTOBUF_URL: str = (
    "https://raw.githubusercontent.com/a2aproject/A2A/v1.0.0/specification/a2a.proto"
)

#: The 7 SDK type names this module re-exports. Sourced from
#: ``a2a.types`` (the protobuf-generated message classes; metaclass
#: ``MessageMeta`` from the google.protobuf library). Pinned exactly
#: so a future SDK rename trips the drift gate before it reaches us.
_REEXPORTED_TYPE_NAMES: frozenset[str] = frozenset(
    {
        "AgentCard",
        "Artifact",
        "CancelTaskRequest",
        "StreamResponse",
        "Task",
        "TaskArtifactUpdateEvent",
        "TaskStatusUpdateEvent",
    }
)

#: Public ``__all__`` surface — the 7 lazy SDK type names + the
#: spec-version public constant + the version accessor. The pinned-
#: digest + upstream-URL constants are module-private (underscore-
#: prefixed) by convention; downstream code reads them only via
#: explicit ``from a2a_schema import _PINNED_PROTOBUF_DIGEST`` for
#: drift-gate / debugging purposes — they are NOT part of the
#: public re-export surface and the drift CI gate is the only
#: production consumer.
__all__ = (
    "A2A_SPEC_VERSION",
    "AgentCard",
    "Artifact",
    "CancelTaskRequest",
    "StreamResponse",
    "Task",
    "TaskArtifactUpdateEvent",
    "TaskStatusUpdateEvent",
    "get_pinned_spec_version",
)

if TYPE_CHECKING:
    # Static-typing-only imports. At runtime, the names are resolved
    # via :func:`__getattr__` on first access — letting the module
    # import cleanly without ``a2a-sdk`` installed (admission-side
    # per Sprint-5 R3 P1 doctrine).
    from a2a.types import (
        AgentCard,
        Artifact,
        CancelTaskRequest,
        StreamResponse,
        Task,
        TaskArtifactUpdateEvent,
        TaskStatusUpdateEvent,
    )


def get_pinned_spec_version() -> str:
    """Return the pinned A2A spec version. Single source of truth
    for code that needs to assert spec compliance."""
    return A2A_SPEC_VERSION


def __getattr__(name: str) -> Any:
    """Lazy attribute access for the re-exported SDK types.

    Module-level ``__getattr__`` (PEP 562) fires on attribute access
    for names not already in the module dict. Pattern:

    - ``import cognic_agentos.protocol.a2a_schema`` — module imports
      cleanly without the SDK (no module-level ``from a2a import``).
    - ``from a2a_schema import AgentCard`` — Python imports the
      module, then looks up ``AgentCard`` in the module dict; if
      absent, calls ``__getattr__("AgentCard")`` which fires
      :func:`require_a2a` (raising :class:`A2ANotAvailableError` if
      the SDK is missing) and returns the SDK class.
    - First access caches the resolved name into ``globals()`` so
      subsequent accesses skip ``__getattr__``.

    Names not in :data:`_REEXPORTED_TYPE_NAMES` fall through to a
    standard ``AttributeError`` so typos surface immediately.
    """
    if name not in _REEXPORTED_TYPE_NAMES:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    require_a2a()
    # Lazy import — only fires when SDK is actually present.
    from a2a import types as _a2a_types

    resolved = getattr(_a2a_types, name)
    # Cache into module dict so subsequent accesses skip __getattr__.
    globals()[name] = resolved
    return resolved
