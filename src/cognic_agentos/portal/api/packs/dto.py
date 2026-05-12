"""Sprint 7B.2 T3 — Pack-API Pydantic DTOs.

Logic-free Pydantic v2 wire-shape definitions consumed by every T4-T7
pack endpoint. T3 ships:

- :class:`PackBaseModel` — frozen + ``extra="forbid"`` base class that
  every endpoint-specific DTO in T4-T7 inherits. Mirrors the
  :class:`~cognic_agentos.portal.rbac.actor.Actor` model-config at
  ``portal/rbac/actor.py:68``.
- :class:`PackResponse` — read-only projection of a
  :class:`~cognic_agentos.packs.storage.PackRecord`. Used by every
  pack-list / pack-detail endpoint that surfaces a single record.

The two SHA-256 digests (``manifest_digest`` / ``signed_artefact_digest``)
are deliberately EXCLUDED from :class:`PackResponse` — they are
admin-only fields surfaced through the inspection-tier endpoints at
T7 only (per the plan-of-record's ``inspection_routes.py``). The
default view is intentionally narrow to keep cross-tenant attackers
from harvesting cryptographic-signature material via the standard read
surfaces.

Style note: plain ``= Literal[...]`` would be re-exported here rather
than introduced fresh, but :data:`PackKind` and :data:`PackState`
already live at ``packs/lifecycle.py:111``/``:116`` and DTOs use them
directly via import. Mirrors the Sprint-7B.1 convention.
"""

from __future__ import annotations

import datetime
import uuid

import pydantic

from cognic_agentos.packs.lifecycle import PackKind, PackState


class PackBaseModel(pydantic.BaseModel):
    """Frozen + ``extra="forbid"`` base for every Sprint 7B.2 pack DTO.

    ``frozen=True`` defends against handler-side mutation mid-request
    (confused-deputy bug class); ``extra="forbid"`` pins the wire-shape
    so a bank-overlay extension cannot smuggle unmodelled fields
    through. Every field added to a subclass is a deliberate
    wire-protocol decision.

    Subclassed by every endpoint-specific request/response DTO landing
    in T4-T7.
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")


class PackResponse(PackBaseModel):
    """Default public-surface view of a
    :class:`~cognic_agentos.packs.storage.PackRecord`.

    Field set mirrors :class:`PackRecord` at ``packs/storage.py:351-378``
    minus the two SHA-256 digests (``manifest_digest`` /
    ``signed_artefact_digest``). The narrower projection keeps
    cryptographic-signature material off the default read surface;
    inspection-tier endpoints (T7) extend with a dedicated DTO that
    includes the digests under the ``pack.audit.read`` scope.

    The :data:`PackKind` and :data:`PackState` fields carry the same
    closed-enum constraints as the Sprint-7B.1 source-of-truth Literals
    at ``packs/lifecycle.py:111``/``:116`` — out-of-vocab values refuse
    at Pydantic validation time.

    ``from_attributes=True`` (T3-R1 P3 closure): :class:`PackResponse`
    accepts both dict-shaped input AND attribute-bearing objects (i.e.
    real :class:`PackRecord` instances). Pydantic v2's
    ``from_attributes`` falls back to ``getattr(obj, field_name)`` per
    declared field — fields the DTO does not declare (the two digests)
    are simply not read, so the ``extra="forbid"`` invariant inherited
    from :class:`PackBaseModel` is preserved while T4-T7 route authors
    can pass a freshly-loaded :class:`PackRecord` directly to
    ``PackResponse.model_validate`` without an intermediate
    ``model_dump`` conversion. Override scoped to :class:`PackResponse`
    only — sibling DTOs that take wire-input (T4-T7 request bodies)
    keep the strict dict-only contract from :class:`PackBaseModel`.
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid", from_attributes=True)

    id: uuid.UUID
    kind: PackKind
    pack_id: str
    display_name: str
    state: PackState
    tenant_id: str | None
    created_by: str
    last_actor: str
    created_at: datetime.datetime
    updated_at: datetime.datetime
