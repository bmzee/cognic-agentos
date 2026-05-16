"""Sprint-7B.4 T12 — /.well-known/cognic-ui-events.json publication
per ADR-020 §6 + RFC 8615.

Single GET endpoint registered AT ROOT (NOT under /api/v1/ui/) so
standard well-known scanners (RFC 8615) can discover the published
schema. Returns:

  - ``schema_version`` (currently ``"1.0"``)
  - ``families`` — sorted list of all 11 Wave-1 event families
  - ``wave_1_sse_streamed`` — sorted list of the 9 SSE-streamed
    families (Wave-1 audit-event-backed families ``tool_call.*`` and
    ``artifact.*`` are EXCLUDED — they ship via the Wave-2 audit-event
    SSE surface)
  - ``events`` — per-family JSON Schema, generated via
    ``pydantic.TypeAdapter(<family_union>).json_schema()``

Wire-protocol-public per ADR-020 + AGENTS.md "Wire-protocol contracts"
stop rule — any change to a Wave-1 Pydantic event model that affects
the serialized schema is a wire-protocol break that bank-overlay UI
clients depend on. The snapshot-pinned drift regression in
:file:`tests/unit/portal/api/ui/test_well_known_routes.py
::TestSchemaSnapshotPinned` enforces deliberate snapshot updates.

Cache: ``public, max-age=300, immutable``. The schema is keyed by
``schema_version``; clients invalidate by bumping the version.

NOTE: ``from __future__ import annotations`` is DELIBERATELY OMITTED
per the standing FastAPI invariant (route signatures need runtime-
resolved annotations for ``inspect.signature()``)."""

from typing import Any

import pydantic
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from cognic_agentos.protocol.ui_events import (
    _SSE_WAVE_1_STREAMED_FAMILIES,
    _WAVE_1_FAMILIES,
    _AgentRunEvent,
    _ApprovalEvent,
    _ArtifactEvent,
    _DecisionAuditEvent,
    _FrontendActionEvent,
    _InterruptEvent,
    _KillSwitchEvent,
    _MemoryEvent,
    _PolicyEvent,
    _SubagentEvent,
    _ToolCallEvent,
)

#: Current published schema version. Bump on ANY breaking change to
#: a Wave-1 Pydantic event model (field removal, rename, type
#: narrowing, discriminator change). Additive changes (new optional
#: field, new event family) do NOT require a bump — clients tolerate
#: extra fields via Pydantic ``extra="allow"`` defaults.
_SCHEMA_VERSION = "1.0"


#: Map from family name (matches ``_WAVE_1_FAMILIES`` members) to the
#: discriminated-union type that Pydantic's TypeAdapter can convert
#: to JSON Schema. Iteration order is intentionally NOT alphabetical
#: — the published ``families`` array sorts independently, but this
#: map preserves the canonical family enumeration so a future code
#: review can spot a missing family by reading top-to-bottom against
#: ``_WAVE_1_FAMILIES``.
_FAMILY_UNIONS: dict[str, Any] = {
    "agent_run": _AgentRunEvent,
    "tool_call": _ToolCallEvent,
    "subagent": _SubagentEvent,
    "approval": _ApprovalEvent,
    "artifact": _ArtifactEvent,
    "interrupt": _InterruptEvent,
    "frontend_action": _FrontendActionEvent,
    "memory": _MemoryEvent,
    "decision_audit": _DecisionAuditEvent,
    "policy": _PolicyEvent,
    "kill_switch": _KillSwitchEvent,
}


def register_well_known_routes(app: FastAPI) -> None:
    """Register the .well-known endpoint DIRECTLY at the app root.

    RFC 8615 mandates root registration — this function MUST NOT be
    called on a sub-router (it'd land under that router's prefix and
    break standard discovery)."""

    @app.get("/.well-known/cognic-ui-events.json", include_in_schema=False)
    async def cognic_ui_events_schema() -> JSONResponse:
        return JSONResponse(
            content=_build_schema(),
            headers={"Cache-Control": "public, max-age=300, immutable"},
        )


def _build_schema() -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "families": sorted(_WAVE_1_FAMILIES),
        "wave_1_sse_streamed": sorted(_SSE_WAVE_1_STREAMED_FAMILIES),
        "events": _build_events_schema(),
    }


def _build_events_schema() -> dict[str, dict[str, Any]]:
    """Produce JSON Schema for each Wave-1 family discriminated union.

    Returns ``{family_name: <json-schema-dict>}``. The
    :class:`pydantic.TypeAdapter` call drives Pydantic's own JSON
    Schema generator; the output is deterministic across runs (no
    timestamps / hashes) so the snapshot regression catches any drift
    in model shape."""
    return {
        family_name: pydantic.TypeAdapter(union_type).json_schema()
        for family_name, union_type in _FAMILY_UNIONS.items()
    }


__all__ = [
    "register_well_known_routes",
]
