"""Sprint 7B.2 T4 — author surface endpoints (CRITICAL CONTROLS).

Per the plan-of-record at
``docs/superpowers/plans/2026-05-11-sprint-7b2-portal-api-rbac-owasp.md``
Task 4 §"Endpoints (ADR-012 §55-59 + BUILD_PLAN §616)". This module ships
the 4 author-surface endpoints behind ``/api/v1/packs/drafts``:

======  ====================================  ========================  ==================
Method  Path                                  RBAC                      Lifecycle action
======  ====================================  ========================  ==================
POST    ``/api/v1/packs/drafts``              ``pack.submit``           ``save_draft``
PUT     ``/api/v1/packs/drafts/{id}``         ``pack.submit`` + tenant  ``update_draft``
POST    ``/api/v1/packs/drafts/{id}/submit``  ``pack.submit`` + tenant  ``submit`` txn
DELETE  ``/api/v1/packs/drafts/{id}``         ``pack.withdraw``+tenant  ``cancel_draft``
======  ====================================  ========================  ==================

Same-tenant author collaboration policy (Round 7 P2 #4 + Round 8 P2 #3):
any actor holding the relevant author scope (``pack.submit`` for
CREATE/UPDATE/SUBMIT, ``pack.withdraw`` for CANCEL) within the same
``tenant_id`` as the target pack can perform the operation. The original
``created_by`` (immutable) + ``last_actor`` (bumped on every mutation) +
the chain row's ``payload.actor_id`` together capture the audit lineage.

What's NOT in this module (deferred to other Sprint 7B.2 tasks):

- **Conformance auto-run on POST ``/submit``** — Sprint 7B.2 T9 wires
  the conformance runner into the submit handler, attaching the result
  as ``payload.conformance`` on the submit transition's chain row.
- **Locked manifest-digest precondition** — Sprint 7B.2 T9 closes the
  load-then-submit TOCTOU window by passing ``expected_manifest_digest``
  to :meth:`PackRecordStore.transition`.
- **5-gate approve composer** — Sprint 7B.3.

The endpoints respond to refusal paths uniformly: closed-enum reason
in the response body's ``detail.reason`` field (matches the
``RBACDenialReason`` / ``TenantIsolationFailure`` patterns already
established by :func:`RequireScope` + :func:`RequireTenantOwnership`).
"""

import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Final, Literal

import pydantic
from fastapi import APIRouter, Depends, HTTPException

from cognic_agentos.packs.lifecycle import LifecycleTransitionRefused, PackKind
from cognic_agentos.packs.storage import (
    PACK_DISPLAY_NAME_MAX_LEN,
    PACK_ID_MAX_LEN,
    PackNotFound,
    PackRecord,
    PackRecordRefused,
    PackRecordStore,
)
from cognic_agentos.portal.api.packs.dto import PackBaseModel, PackResponse
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.tenant_isolation import (
    RequireTenantOwnership,
    TenantIsolationFailure,
)

_LOG = logging.getLogger(__name__)


#: SHA-256 digest width in bytes. Both ``manifest_digest`` and
#: ``signed_artefact_digest`` are SHA-256 outputs per the ``packs`` table
#: schema (``chain_hash_column_type()`` width-32 column). Wire encoding
#: is canonical lowercase hex (64 lowercase hex chars → 32 bytes).
#:
#: T4 R2 P3 #4 — the contract is **lowercase hex ONLY**. Uppercase or
#: mixed-case hex strings refuse at the DTO layer even though
#: ``bytes.fromhex`` would accept them, so cross-implementation
#: consumers (e.g. the bank-overlay client SDK) observe a single
#: canonical form on the wire and identical SHA-256 digests serialize
#: to identical strings byte-for-byte.
_SHA256_DIGEST_BYTES = 32
_SHA256_DIGEST_HEX_CHARS = _SHA256_DIGEST_BYTES * 2  # 64
_SHA256_DIGEST_HEX_PATTERN = re.compile(r"[0-9a-f]{64}")


#: T4 R3 P2 #1 — bounded request_id prefixes for the two route-driven
#: lifecycle transitions. The ``decision_history.request_id`` column at
#: ``core/decision_history.py:196`` is ``String(64)``; the pre-fix submit
#: handler built ``f"submit-{record.id}-{datetime.now(UTC).isoformat()}"``
#: which is 7 + 36 + 1 + ≥26 = ≥70 chars (SQLite accepted silently;
#: Postgres + Oracle reject with column-overflow). Post-fix: prefix +
#: ``uuid4().hex`` = 12 + 32 = **44 chars** (well under 64, leaves headroom
#: for future prefix evolution).
_PACK_SUBMIT_REQUEST_ID_PREFIX: Final[str] = "pack-submit-"
_PACK_CANCEL_REQUEST_ID_PREFIX: Final[str] = "pack-cancel-"
_REQUEST_ID_MAX_LEN: Final[int] = 64


def _mint_request_id(prefix: str) -> str:
    """T4 R3 P2 #1 — bounded request_id minter.

    Returns ``<prefix><uuid4().hex>`` (32 hex chars). For the two
    in-tree prefixes (``"pack-submit-"`` / ``"pack-cancel-"``), the
    output is 44 chars — well under the 64-char column cap on
    ``decision_history.request_id``. Build-time invariant at module
    foot pins prefix length so a future prefix rename + uuid hex
    length cannot together exceed the cap silently.
    """
    return f"{prefix}{uuid.uuid4().hex}"


def _decode_sha256_hex(value: Any) -> bytes:
    """T4 R1 P2 #1 fix — canonical wire decoder for SHA-256 digest fields.

    Pydantic v2's lax ``bytes`` field type treats a JSON string as
    UTF-8-encoded bytes (1 ASCII char → 1 byte), so a 64-char hex string
    representing a SHA-256 digest would land as 64 UTF-8 bytes — a
    malformed value that ``save_draft`` would silently persist (no
    storage-layer shape guard) while ``update_draft`` would refuse with
    ``pack_record_update_field_invalid_shape`` (asymmetric: create
    persists junk; update refuses the same client shape).

    This validator + decoder closes the asymmetry: every request DTO
    digest field is a hex-encoded ``str`` on the wire; this function
    decodes to exactly 32 bytes OR raises ``ValueError`` (Pydantic's
    validation harness translates that to a 422 with a structured body
    enumerating the offending field — same wire-protocol behaviour as
    every other Pydantic validator). Pre-DB refusal — no malformed
    digest ever reaches the persistence layer.

    Accepts ``bytes`` input as a defence-in-depth alternative path
    (already 32 bytes → pass through). Refuses anything else.
    """

    if isinstance(value, bytes):
        if len(value) != _SHA256_DIGEST_BYTES:
            raise ValueError(
                f"SHA-256 digest must be exactly {_SHA256_DIGEST_BYTES} bytes; "
                f"got {len(value)} bytes"
            )
        return value
    if not isinstance(value, str):
        raise ValueError(
            f"SHA-256 digest must be a hex-encoded str or 32-byte bytes; got {type(value).__name__}"
        )
    if len(value) != _SHA256_DIGEST_HEX_CHARS:
        raise ValueError(
            f"SHA-256 digest hex string must be exactly {_SHA256_DIGEST_HEX_CHARS} chars; "
            f"got {len(value)}"
        )
    # T4 R2 P3 #4 — enforce lowercase hex BEFORE delegating to
    # ``bytes.fromhex``. The stdlib decoder accepts uppercase ("A"-"F")
    # and mixed-case input, but the wire-protocol contract is
    # canonical lowercase only. Refusing uppercase here keeps the wire
    # encoding deterministic across producers (bank-overlay SDKs,
    # CLI tooling, etc) so a single SHA-256 digest serialises to one
    # string byte-for-byte.
    if not _SHA256_DIGEST_HEX_PATTERN.fullmatch(value):
        raise ValueError(
            "invalid hex characters in SHA-256 digest: "
            "canonical wire encoding is lowercase hex [0-9a-f] only "
            "(uppercase + mixed-case refused)"
        )
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:  # pragma: no cover - defensive
        # The regex above already constrains input to lowercase hex
        # chars; bytes.fromhex of a 64-char [0-9a-f] string cannot
        # raise. This guard is belt-and-braces against a future
        # refactor that loosens the upstream regex.
        raise ValueError(f"invalid hex characters in SHA-256 digest: {exc}") from None
    if len(decoded) != _SHA256_DIGEST_BYTES:  # pragma: no cover - defensive
        # bytes.fromhex on an even-length hex string always returns
        # len/2 bytes; this guard is belt-and-braces against a future
        # Pydantic refactor that hands us pre-decoded data. The
        # earlier 64-char length guard already constrains decoded len
        # to exactly 32 — the only way to reach this branch is via
        # the explicit pass-through in the test suite + a future
        # refactor that loosens the upstream length check. Marked
        # ``no cover`` because there is no input value that exercises
        # it under the current control flow.
        raise ValueError(
            f"SHA-256 digest hex decoded to {len(decoded)} bytes; expected {_SHA256_DIGEST_BYTES}"
        )
    return decoded


#: Annotated SHA-256 digest type — wire shape is hex ``str``; validated
#: value lands as 32-byte ``bytes``. Used on every request DTO that
#: takes a digest field. Mirrors the Sprint-7B.1 storage-layer 32-byte
#: contract end-to-end.
Sha256DigestBytes = Annotated[bytes, pydantic.BeforeValidator(_decode_sha256_hex)]


#: T4 R5 P2 narrowing — :data:`AuthorRefusalReason` is the closed-enum
#: vocabulary for **409-status storage/lifecycle refusals surfaced from
#: author handlers**, NOT the full author-surface wire-protocol refusal
#: vocabulary. The complete refusal surface emitted by these endpoints
#: is a 3-way union:
#:
#:   * :data:`AuthorRefusalReason` — 409 storage/lifecycle refusals
#:     (this Literal, 6 values)
#:   * :data:`~cognic_agentos.portal.rbac.tenant_isolation.TenantIsolationFailure`
#:     — 404/500 tenant-isolation failures (``pack_not_found`` /
#:     ``tenant_id_mismatch`` / ``actor_tenant_id_missing`` /
#:     ``pack_store_not_configured``)
#:   * :data:`~cognic_agentos.portal.rbac.enforcement.RBACDenialReason`
#:     — 403/500 RBAC denials (``scope_not_held`` /
#:     ``actor_unauthenticated`` / ``actor_binder_not_configured``)
#:
#: The submit + cancel + update endpoints emit ``pack_not_found`` directly
#: (under :data:`_PACK_NOT_FOUND_REASON` below) when ``transition()`` /
#: ``update_draft()`` raise :class:`PackNotFound` from a race between
#: tenant-isolation preload and the storage operation; that string lives
#: in :data:`TenantIsolationFailure`, NOT here. The handler-side reuse
#: keeps the 404 wire-protocol contract symmetric with the tenant-
#: isolation gate's own 404 emit path.
#:
#: The build-time drift detector + the test-layer union-coverage check
#: pin the 3-way invariant. Pre-R5 the docstring claimed this Literal
#: WAS the full author-surface vocabulary — that claim left
#: ``pack_not_found`` outside the declared/drift-checked surface.
#:
#: Style note: plain ``= Literal[...]`` (no ``TypeAlias`` annotation) to
#: match the Sprint-7B.1 repo convention at ``packs/lifecycle.py:111``.
AuthorRefusalReason = Literal[
    # Sprint 7B.1 storage closed-enums surfaced as 409 wire-protocol bodies
    "pack_record_save_draft_initial_state_not_draft",
    "pack_record_update_non_draft_state",
    "pack_record_update_field_not_allowed",
    "pack_record_update_field_invalid_shape",
    # Sprint 7B.1 lifecycle closed-enums surfaced when transition() refuses
    "lifecycle_transition_invalid_state_pair",
    "lifecycle_transition_terminal_state",
]


#: T4 R5 P2 — centralised typed literal for the ``pack_not_found`` 404
#: emit path. Three handler sites (submit / cancel / update post-transition
#: reload + storage PackNotFound) emit this string in the 404 detail body;
#: centralising via a ``Final`` Literal alias gives the build-time drift
#: detector below a typed handle to verify membership in
#: :data:`TenantIsolationFailure`. If a future refactor renames
#: ``pack_not_found`` to e.g. ``pack_record_not_found`` in the tenant-
#: isolation enum but forgets to update the handler emit sites, the
#: drift detector fails import.
_PACK_NOT_FOUND_REASON: Final[Literal["pack_not_found"]] = "pack_not_found"


class CreateDraftRequest(PackBaseModel):
    """POST /api/v1/packs/drafts request body. The actor's
    ``tenant_id`` is bound from :class:`Actor` (NOT carried in the
    request body — same-tenant constraint enforced at write time so
    a cross-tenant caller cannot poison this field). The actor's
    ``subject`` populates ``created_by`` + ``last_actor`` likewise.

    Frozen + ``extra="forbid"`` inherited from :class:`PackBaseModel`
    so smuggled fields refuse at validation; no ``from_attributes``
    because this is wire-input only (dict-shaped JSON payload).

    T4 R1 P2 #1 fix — ``manifest_digest`` + ``signed_artefact_digest``
    use the :data:`Sha256DigestBytes` wire-canonical hex decoder
    (64-char lowercase hex on the wire → 32 bytes after validation).
    The raw ``bytes`` type previously accepted any UTF-8 string and
    persisted up to N malformed bytes (asymmetric vs update_draft
    which DOES shape-validate).
    """

    kind: PackKind
    pack_id: Annotated[str, pydantic.Field(min_length=1, max_length=PACK_ID_MAX_LEN)]
    display_name: Annotated[str, pydantic.Field(min_length=1, max_length=PACK_DISPLAY_NAME_MAX_LEN)]
    manifest_digest: Sha256DigestBytes
    signed_artefact_digest: Sha256DigestBytes
    # ``sbom_pointer`` is ``str | None``: None means "no SBOM declared"
    # (legitimate Wave-1 posture per the plan); when present it must be
    # a non-empty string. The ``packs.sbom_pointer`` column is ``Text``
    # without a width cap; we enforce non-empty only to match the
    # storage-layer ``_is_valid_update_value_shape`` contract.
    sbom_pointer: Annotated[str, pydantic.Field(min_length=1)] | None = None


class UpdateDraftRequest(PackBaseModel):
    """PUT /api/v1/packs/drafts/{id} request body. All fields are
    optional; only fields explicitly set in the request flow through
    to :meth:`PackRecordStore.update_draft`. Mirrors the storage-layer
    allow-list of 4 mutable fields.

    The DTO does NOT declare the immutable fields (``tenant_id`` /
    ``state`` / ``kind`` / ``pack_id`` / ``created_by``) — wire-level
    refusal: ``extra="forbid"`` causes any such smuggled field to
    refuse at Pydantic validation time (returns 422 from FastAPI's
    default validation handler, BEFORE the route runs).

    T4 R1 P2 #1 fix — digest fields use the :data:`Sha256DigestBytes`
    wire-canonical hex decoder. The Optional wrapper preserves the
    semantic that absent-in-body means no update; a present-but-malformed
    hex value refuses with 422 BEFORE the storage layer's
    ``_is_valid_update_value_shape`` rejection — wire-level defence-
    in-depth.

    T4 R2 P2 #1 fix — explicit JSON ``null`` on a digest field is
    refused at the DTO layer (422). Pre-fix an explicit ``null``
    bypassed the :data:`Sha256DigestBytes` ``BeforeValidator`` because
    the ``| None`` union allows None to skip validation; the field
    then landed in ``model_dump(exclude_unset=True)`` as ``{...: None}``
    and surfaced as a 409 from the storage-layer shape validator —
    asymmetric vs the 422 path that malformed hex takes. The
    :meth:`_refuse_explicit_null_digest_fields` model-validator
    closes the asymmetry: explicit null on a digest field carries
    the same 422 wire-protocol verdict as malformed hex. (To skip
    updating a digest field, omit the key from the request body
    entirely; presence-with-null is intentionally distinguished
    from absent.)
    """

    display_name: (
        Annotated[str, pydantic.Field(min_length=1, max_length=PACK_DISPLAY_NAME_MAX_LEN)] | None
    ) = None
    manifest_digest: Sha256DigestBytes | None = None
    signed_artefact_digest: Sha256DigestBytes | None = None
    sbom_pointer: Annotated[str, pydantic.Field(min_length=1)] | None = None

    @pydantic.model_validator(mode="after")
    def _refuse_explicit_null_digest_fields(self) -> "UpdateDraftRequest":
        """T4 R2 P2 #1 — wire-protocol-symmetry guard.

        Pydantic v2's BeforeValidator does not fire for None on a
        ``T | None`` field, so an explicit JSON ``null`` would bypass
        the :data:`Sha256DigestBytes` hex decoder. The
        ``manifest_digest`` and ``signed_artefact_digest`` columns are
        ``NOT NULL`` in the ``packs`` schema; an update that sets them
        to ``None`` would either crash at the DB layer or (more
        likely) refuse at the storage shape-validator with 409 —
        wire-protocol-asymmetric with the 422 path that malformed hex
        takes. Refuse explicit-null at the DTO so both shapes hit 422.

        Distinguishes absent (not in ``model_fields_set`` — passes
        through) from explicit-null (in ``model_fields_set`` AND value
        is None — refuses). Absent semantics ("don't update this
        field") are preserved.
        """
        for field in ("manifest_digest", "signed_artefact_digest"):
            if field in self.model_fields_set and getattr(self, field) is None:
                raise ValueError(
                    f"{field} may not be explicit null; "
                    "omit the field from the request body to skip updating it "
                    "(presence-with-null is distinct from absence)"
                )
        return self


def _author_refusal_payload(reason: AuthorRefusalReason) -> dict[str, str]:
    """Stable wire-shape for author-surface refusal bodies. Keys
    mirror the RBAC + tenant-isolation patterns
    (``RBACDenialReason`` carries ``reason`` in
    ``detail.reason``)."""
    return {"reason": reason}


def _record_to_response(record: PackRecord) -> PackResponse:
    """Project a storage-layer :class:`PackRecord` to the public
    :class:`PackResponse` DTO. ``from_attributes=True`` on
    :class:`PackResponse` (Sprint 7B.2 T3 R1 P3 closure) lets us pass
    the record directly without an intermediate ``model_dump``."""
    return PackResponse.model_validate(record)


def build_author_routes(*, store: PackRecordStore) -> APIRouter:
    """Build the author-surface sub-router.

    The ``store`` argument is captured in this factory so each endpoint
    closes over a single :class:`PackRecordStore` instance per app
    lifespan (mirrors the Sprint-3 ``build_system_router`` pattern at
    ``portal/api/system_routes.py:153``).

    The returned router does NOT carry a prefix — :func:`build_packs_router`
    mounts it under the parent ``/api/v1/packs`` prefix. Each endpoint's
    path is relative to ``/drafts`` and full path is therefore
    ``/api/v1/packs/drafts[…]``.
    """

    router = APIRouter()
    # Construct the dependency callables once per router build. FastAPI
    # caches sub-dependencies (e.g. ``_bind_actor``) by callable identity
    # within a single request, so binding once at router-build time keeps
    # the per-request resolution cheap.
    _require_pack_submit = RequireScope("pack.submit")
    _require_pack_withdraw = RequireScope("pack.withdraw")
    _require_tenant_ownership = RequireTenantOwnership(pack_id_param="pack_id")

    # -----------------------------------------------------------------
    # POST /drafts — create a new draft
    # -----------------------------------------------------------------

    @router.post(
        "/drafts",
        summary="Create a new draft pack",
        status_code=201,
    )
    async def create_draft(
        body: CreateDraftRequest,
        actor: Annotated[Actor, Depends(_require_pack_submit)],
    ) -> PackResponse:
        """Create a fresh draft pack. The actor's ``tenant_id`` is
        bound from :class:`Actor` (NOT taken from the body — cross-
        tenant write is impossible by construction). ``created_by``
        + ``last_actor`` are both set to the actor's ``subject``."""
        now = datetime.now(UTC)
        record = PackRecord(
            id=uuid.uuid4(),
            kind=body.kind,
            pack_id=body.pack_id,
            display_name=body.display_name,
            state="draft",
            manifest_digest=body.manifest_digest,
            signed_artefact_digest=body.signed_artefact_digest,
            sbom_pointer=body.sbom_pointer,
            tenant_id=actor.tenant_id,
            created_by=actor.subject,
            last_actor=actor.subject,
            created_at=now,
            updated_at=now,
        )
        try:
            await store.save_draft(record)
        except PackRecordRefused as exc:
            # The genesis-state guard is the only refusal path for
            # save_draft today; our DTO-side ``state="draft"`` literal
            # makes it unreachable through this endpoint. Defensive
            # mapping kept so future refusal modes don't crash with
            # a bare 500.
            _LOG.warning(
                "portal.packs.create_draft_refused",
                extra={
                    "reason": exc.reason,
                    "actor_subject": actor.subject,
                },
            )
            raise HTTPException(
                status_code=409,
                detail=_author_refusal_payload(exc.reason),
            ) from None
        return _record_to_response(record)

    # -----------------------------------------------------------------
    # PUT /drafts/{pack_id} — update an existing draft
    # -----------------------------------------------------------------

    @router.put(
        "/drafts/{pack_id}",
        summary="Update an existing draft pack",
    )
    async def update_draft_endpoint(
        body: UpdateDraftRequest,
        actor: Annotated[Actor, Depends(_require_pack_submit)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
    ) -> PackResponse:
        """Update an existing draft. Same-tenant author collaboration
        is allowed (the actor may differ from the original ``created_by``);
        cross-tenant access is refused by :func:`RequireTenantOwnership`
        with a 404 + ``tenant_id_mismatch`` BEFORE this handler runs.

        Only fields explicitly present in the request body flow into
        the storage-layer ``updates`` dict (``model_dump(exclude_unset=
        True)``) so a partial-update PUT does not stomp untouched
        fields with their default values."""
        # T4 R1 P2 #2 fix — the draft-state precondition must fire
        # BEFORE the empty-body no-op return. Previously an empty PUT
        # would short-circuit to a 200 echo of the preloaded record
        # for ANY state (submitted, withdrawn, etc), bypassing the
        # draft-only contract the endpoint path advertises. Now: any
        # PUT against a non-draft pack returns 409 with closed-enum
        # ``pack_record_update_non_draft_state`` regardless of body
        # contents.
        if record.state != "draft":
            _LOG.warning(
                "portal.packs.update_draft_refused",
                extra={
                    "reason": "pack_record_update_non_draft_state",
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                    "from_state": record.state,
                },
            )
            raise HTTPException(
                status_code=409,
                detail=_author_refusal_payload("pack_record_update_non_draft_state"),
            )

        # ``exclude_unset=True`` is critical: only fields the caller
        # explicitly supplied land in the storage-layer updates dict.
        # Pydantic v2's exclude_unset distinguishes "field was not in
        # the request body" from "field was set to None".
        updates = body.model_dump(exclude_unset=True)
        if not updates:
            # No-op update against a confirmed-draft pack — return the
            # current record without bumping last_actor (avoid empty-
            # mutation chain noise). The state guard above ensures
            # this path is only reachable for genuinely-draft packs.
            return _record_to_response(record)

        try:
            await store.update_draft(
                pack_id=record.id,
                updates=updates,
                actor_id=actor.subject,
            )
        except PackNotFound:
            # Race: tenant-isolation dependency loaded the pack, then
            # something deleted it before update_draft fired. Mirror
            # the tenant-isolation layer's 404 + closed-enum body.
            raise HTTPException(
                status_code=404,
                detail={"reason": _PACK_NOT_FOUND_REASON},
            ) from None
        except PackRecordRefused as exc:
            _LOG.warning(
                "portal.packs.update_draft_refused",
                extra={
                    "reason": exc.reason,
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                },
            )
            # All 3 update_draft refusal reasons surface as 409 Conflict.
            raise HTTPException(
                status_code=409,
                detail=_author_refusal_payload(exc.reason),
            ) from None

        # Re-load to surface the persisted state (with bumped
        # last_actor + updated_at) in the response.
        updated = await store.load(record.id)
        if updated is None:
            # Race: row deleted between update_draft success and re-load.
            raise HTTPException(
                status_code=404,
                detail={"reason": _PACK_NOT_FOUND_REASON},
            )
        return _record_to_response(updated)

    # -----------------------------------------------------------------
    # POST /drafts/{pack_id}/submit — transition draft → submitted
    # -----------------------------------------------------------------

    @router.post(
        "/drafts/{pack_id}/submit",
        summary="Submit a draft for review",
    )
    async def submit_draft(
        actor: Annotated[Actor, Depends(_require_pack_submit)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
    ) -> PackResponse:
        """Submit the draft for reviewer attention. Lifecycle:
        ``draft → submitted`` via :meth:`PackRecordStore.transition`
        with transition name ``"submit"``.

        Sprint 7B.2 T4 ships ONLY the bare transition. T9 will:
        (a) auto-run the OWASP conformance suite + attach the result
        as ``payload.conformance`` on the chain row; (b) close the
        load-then-submit TOCTOU window via a locked manifest-digest
        precondition fed by ``expected_manifest_digest``.

        T4 R1 P2 #3 fix — :class:`PackNotFound` is caught + translated
        to a structured 404. ``PackRecordStore.transition``'s
        precondition closure raises :class:`PackNotFound` when its
        ``SELECT ... FOR UPDATE`` finds no row, which can happen if a
        concurrent deleter races us between the tenant-isolation
        dependency's load + our transition call. Without this catch
        the exception would leak as a generic 500."""
        try:
            await store.transition(
                pack_id=record.id,
                transition="submit",
                actor_id=actor.subject,
                tenant_id=actor.tenant_id,
                evidence_pointer=None,
                request_id=_mint_request_id(_PACK_SUBMIT_REQUEST_ID_PREFIX),
            )
        except PackNotFound:
            # T4 R1 P2 #3 — race: row gone between tenant-isolation
            # preload + transition() precondition. Mirror the 404 +
            # closed-enum body the tenant-isolation layer surfaces.
            _LOG.warning(
                "portal.packs.submit_refused",
                extra={
                    "reason": _PACK_NOT_FOUND_REASON,
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                },
            )
            raise HTTPException(
                status_code=404,
                detail={"reason": _PACK_NOT_FOUND_REASON},
            ) from None
        except LifecycleTransitionRefused as exc:
            _LOG.warning(
                "portal.packs.submit_refused",
                extra={
                    "reason": exc.reason,
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                    "from_state": record.state,
                },
            )
            # 409 — state-machine refusal (the pack is in the wrong
            # state for this transition, or the pack is terminal).
            # Idempotency contract: re-submitting an already-submitted
            # pack lands here with ``lifecycle_transition_invalid_state_pair``
            # per the 7B.1 closed-enum.
            raise HTTPException(
                status_code=409,
                detail={"reason": exc.reason},
            ) from None

        updated = await store.load(record.id)
        if updated is None:
            raise HTTPException(
                status_code=404,
                detail={"reason": _PACK_NOT_FOUND_REASON},
            )
        return _record_to_response(updated)

    # -----------------------------------------------------------------
    # DELETE /drafts/{pack_id} — transition draft → withdrawn (cancel_draft)
    # -----------------------------------------------------------------

    @router.delete(
        "/drafts/{pack_id}",
        summary="Cancel a draft pack",
    )
    async def cancel_draft(
        actor: Annotated[Actor, Depends(_require_pack_withdraw)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
    ) -> PackResponse:
        """Cancel a draft pack via the Sprint 7B.2 T4
        ``cancel_draft`` lifecycle transition (``draft → withdrawn``).
        Distinct from the existing ``withdraw`` transition (which
        requires source state ``submitted`` / ``under_review``).

        Scope is ``pack.withdraw`` (NOT ``pack.submit``) per Round 8
        P2 #3: the author-role split treats cancel as a "decision to
        withdraw" act, distinct from the create/update/submit
        capability — same-tenant collaborators can edit without
        being able to discard, and vice versa.

        T4 R1 P2 #3 fix — :class:`PackNotFound` is caught + translated
        to a structured 404. Same race-window doctrine as
        :func:`submit_draft` above."""
        try:
            await store.transition(
                pack_id=record.id,
                transition="cancel_draft",
                actor_id=actor.subject,
                tenant_id=actor.tenant_id,
                evidence_pointer=None,
                request_id=_mint_request_id(_PACK_CANCEL_REQUEST_ID_PREFIX),
            )
        except PackNotFound:
            # T4 R1 P2 #3 — race: row gone between tenant-isolation
            # preload + transition() precondition.
            _LOG.warning(
                "portal.packs.cancel_draft_refused",
                extra={
                    "reason": _PACK_NOT_FOUND_REASON,
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                },
            )
            raise HTTPException(
                status_code=404,
                detail={"reason": _PACK_NOT_FOUND_REASON},
            ) from None
        except LifecycleTransitionRefused as exc:
            _LOG.warning(
                "portal.packs.cancel_draft_refused",
                extra={
                    "reason": exc.reason,
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                    "from_state": record.state,
                },
            )
            raise HTTPException(
                status_code=409,
                detail={"reason": exc.reason},
            ) from None

        updated = await store.load(record.id)
        if updated is None:
            raise HTTPException(
                status_code=404,
                detail={"reason": _PACK_NOT_FOUND_REASON},
            )
        return _record_to_response(updated)

    return router


__all__ = [
    "AuthorRefusalReason",
    "CreateDraftRequest",
    "UpdateDraftRequest",
    "build_author_routes",
]


# Build-time invariant: every AuthorRefusalReason value MUST correspond
# to a real storage-layer or lifecycle-layer closed-enum value. Drift
# detector — adding a value here without a corresponding fire-site
# would silently break the wire-protocol-public refusal contract.
#
# Pinned at module load time so any drift surfaces during import (the
# test surface adds a parametrized regression for operator-facing
# diagnostics).
def _validate_author_refusal_reason_drift() -> None:
    from typing import get_args

    from cognic_agentos.packs.lifecycle import (
        LifecycleRefusalReason as _LR,
    )
    from cognic_agentos.packs.storage import (
        PackRecordRefusalReason as _PR,
    )

    upstream = set(get_args(_LR)) | set(get_args(_PR))
    declared = set(get_args(AuthorRefusalReason))
    drift = declared - upstream
    if drift:  # pragma: no cover - import-time fail-loud guard
        # Only fires on intentional drift between AuthorRefusalReason
        # and its upstream closed-enums. The test-level cross-check
        # in ``TestSprint7B2AuthorRefusalReasonClosedEnum`` (named
        # ``test_every_author_refusal_reason_traces_to_upstream_closed_enum``)
        # is the positive regression; this branch is the negative-path
        # fail-loud at import time.
        raise RuntimeError(
            f"AuthorRefusalReason has values not in any upstream closed-enum: {drift!r}. "
            "This is a wire-protocol-drift bug — every author-surface refusal value "
            "MUST originate from either packs.storage.PackRecordRefusalReason or "
            "packs.lifecycle.LifecycleRefusalReason."
        )

    # T4 R5 P2 — verify the centralised _PACK_NOT_FOUND_REASON literal
    # is a member of TenantIsolationFailure. The handler emit sites
    # write this string into the 404 detail body; if a future rename
    # of the tenant-isolation enum's ``pack_not_found`` value lands
    # without updating the handler emit sites, this drift detector
    # fails import.
    isolation_vocab = set(get_args(TenantIsolationFailure))
    if _PACK_NOT_FOUND_REASON not in isolation_vocab:  # pragma: no cover - import-time fail-loud
        raise RuntimeError(
            f"_PACK_NOT_FOUND_REASON={_PACK_NOT_FOUND_REASON!r} is not a member of "
            f"TenantIsolationFailure {sorted(isolation_vocab)!r}. "
            "This is a wire-protocol-drift bug — author handlers' 404 "
            "responses MUST carry a closed-enum reason that the tenant-"
            "isolation layer also recognises (the 404 emit symmetry "
            "doctrine: a route-level PackNotFound race and the gate-"
            "level tenant-isolation 404 surface the same reason)."
        )


_validate_author_refusal_reason_drift()


# Build-time invariant: the request_id minter must produce output that
# always fits the ``decision_history.request_id`` column cap. uuid4().hex
# is exactly 32 chars; the cap is 64; the prefix budget is therefore
# 32 chars. Both in-tree prefixes are 12 chars — well under the budget.
# Any future prefix that pushes the total over the cap is a wire-
# protocol bug; this assert refuses module load to surface it at import.
for _prefix in (_PACK_SUBMIT_REQUEST_ID_PREFIX, _PACK_CANCEL_REQUEST_ID_PREFIX):
    assert len(_prefix) + 32 <= _REQUEST_ID_MAX_LEN, (
        f"request_id prefix {_prefix!r} ({len(_prefix)} chars) + uuid4().hex (32 chars) "
        f"= {len(_prefix) + 32} > {_REQUEST_ID_MAX_LEN}; "
        "would overflow decision_history.request_id column cap"
    )
del _prefix
