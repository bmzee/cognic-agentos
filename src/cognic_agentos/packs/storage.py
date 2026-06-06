"""Sprint 7B.1 T3 — bank pack record store (per ADR-012).

This module is **CRITICAL CONTROLS** per AGENTS.md "Authoring — Bank pack
lifecycle (Sprint 7B.1)". 95% line / 90% branch coverage required by the
gate at ``tools/check_critical_coverage.py`` (T7 promotion).

Responsibilities
----------------

- **Write side.** :meth:`PackRecordStore.save_draft` inserts a fresh
  ``draft``-state pack row (no chain event — draft creation is the
  state-machine genesis, not a transition).
  :meth:`PackRecordStore.transition` is the load-bearing primitive:
  every state advance flows through
  :meth:`cognic_agentos.core.decision_history.DecisionHistoryStore.append_with_precondition`
  (Sprint-2.5 T2 atomic primitive). The precondition closure
  ``SELECT ... FOR UPDATE``s the pack row, calls
  :func:`cognic_agentos.packs.lifecycle.validate_transition` under the
  chain-head lock, and either raises ``LifecycleTransitionRefused``
  (transaction rolls back) or atomically advances the
  ``packs.state`` cache + emits the ``pack.lifecycle.<to_state>``
  chain row (Doctrine Lock D in the plan-of-record).
- **Read side.** :meth:`PackRecordStore.load`,
  :meth:`PackRecordStore.list_by_status`, and
  :meth:`PackRecordStore.load_lifecycle_history` read denormalised
  ``packs.state`` (O(1)) or walk the
  ``decision_history.event_type LIKE 'pack.lifecycle.%'`` slice
  filtered to ``payload['pack_id'] == str(pack_id)`` — same JSON-key
  client-side filter pattern as
  :meth:`cognic_agentos.core.escalation.EscalationStore._read_current_state_within_txn`.

Doctrine
--------

- **No silent fallback.** Three orthogonal failure categories, each
  with a distinct exception class so callers can dispatch on the
  difference without parsing strings (T3 R1 P3 doctrine clarification —
  pre-R1 the doctrine listed only two categories because
  :class:`PackRecordRefused` did not yet exist):

  1. **API-contract refusal** — :class:`PackRecordRefused` carries the
     closed-enum :data:`PackRecordRefusalReason` (Sprint 7B.2 T4 bumped
     this from 1 to 4 values: the genesis-state guard
     ``pack_record_save_draft_initial_state_not_draft`` plus three
     ``update_draft`` API-contract refusals
     ``pack_record_update_non_draft_state`` /
     ``pack_record_update_field_not_allowed`` /
     ``pack_record_update_field_invalid_shape``). Raised by
     :meth:`PackRecordStore.save_draft` BEFORE any DB connection is
     acquired when the supplied record violates the API's preconditions
     (``state != "draft"`` would bypass the lifecycle audit chain),
     and by :meth:`PackRecordStore.update_draft` for the three
     update-side preconditions (non-draft-state target, allow-list
     violation, per-field value-shape violation).
  2. **State-machine transition refusal** —
     :class:`LifecycleTransitionRefused` carries the closed-enum
     :data:`cognic_agentos.packs.lifecycle.LifecycleRefusalReason`
     (14 reasons; the 14th —
     ``lifecycle_transition_manifest_digest_changed_during_submit`` —
     emits from the locked precondition's manifest-digest cross-check
     added at Sprint 7B.2 T9, NOT from :func:`validate_transition`).
     Raised by :meth:`PackRecordStore.transition` from either path:
     PREFLIGHT (``lifecycle_transition_name_unknown`` — runtime guard
     at function entry; no DB connection acquired) or IN-PRECONDITION
     (any other reason — from
     :func:`cognic_agentos.packs.lifecycle.validate_transition` running
     under the chain-head lock, OR from the storage-side digest cross-
     check that fires under the same lock; transaction rolls back
     atomically).
  3. **Lookup miss** — :class:`PackNotFound` carries the missing
     ``pack_id: uuid.UUID`` (NOT a closed enum — no enum is needed
     because the failure mode is single-valued; the structured field
     IS the diagnostic). Raised by :meth:`PackRecordStore.transition`'s
     precondition when the pack row's ``SELECT ... FOR UPDATE``
     returns no row. Distinct from refusals because no decision was
     made — the caller asked about a row that does not exist.
- **Chain is the source of truth** (Doctrine Lock D, mirroring
  ``governance_chain_heads`` denormalisation). ``packs.state`` is an
  atomically-maintained cache for O(1) reads; the canonical history
  lives in ``decision_history``.
- **Atomicity guarantee.** The chain INSERT + ``packs.state`` UPDATE
  + ``governance_chain_heads`` UPDATE all commit in a single
  ``engine.begin()`` transaction owned by ``append_with_precondition``.
  Failure at any step rolls back all three — fail-closed.
- **No RBAC enforcement** (Doctrine Lock G). ``actor_id`` is recorded
  in the chain payload + ``packs.last_actor`` but role gates are
  Sprint 7B.2 (alongside the 14 RBAC scopes per ADR-012).
- **No portal API surface** (Doctrine Lock F). HTTP DTOs + endpoints
  land in Sprint 7B.2.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Final, Literal

import pydantic
from sqlalchemy import (
    CheckConstraint,
    Column,
    Index,
    Select,
    String,
    Table,
    Text,
    insert,
    or_,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine
from sqlalchemy.types import TIMESTAMP, Uuid

from cognic_agentos.core.audit import _metadata
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    DecisionRecord,
    _decision_history,
)
from cognic_agentos.db.types import chain_hash_column_type
from cognic_agentos.packs.approval_types import ApprovalOverrideReason
from cognic_agentos.packs.lifecycle import (
    _VALID_TRANSITIONS,
    LifecycleTransitionRefused,
    PackKind,
    PackState,
    TransitionName,
    iso_controls_for,
    validate_transition,
)

#: Sprint 7B.2 T4 — module-level logger for structured-log emission paths.
#: Today only the ``update_draft`` value-shape refusal branch writes to it
#: (``packs.update_draft.invalid_shape``); other refusal paths still raise
#: typed exceptions that callers dispatch on. The contract per Sprint 7B.2
#: T4 plan §"Structured-log emission contract": diagnostic field names
#: surface via this logger rather than being extended onto the typed-
#: exception payload (so the 7B.1 ``PackRecordRefused.__init__`` signature
#: stays unchanged at ``(reason, *, state=None)``).
_LOG = logging.getLogger(__name__)

#: Each :data:`TransitionName` in the canonical 11-tuple has exactly one
#: legal ``to_state`` (verified at build time by
#: ``tests/unit/packs/test_storage.py::TestSprint7B1TransitionToTargetStateMap``
#: against ``_VALID_TRANSITIONS``). Storage derives ``to_state`` from
#: ``transition`` alone so the public ``transition()`` API does not have
#: to take a redundant ``to_state`` argument that the lifecycle table
#: already implies. Drift is caught by the build-time test — adding a
#: new transition without an entry here OR adding a ``_VALID_TRANSITIONS``
#: row whose pair set has a different ``to_state`` than mapped here
#: would fail the drift detector.
#:
#: Sprint 7B.2 T4 added ``cancel_draft → "withdrawn"`` per ADR-012 §59
#: (the developer-scratches-own-draft path). The lifecycle.py
#: ``_VALID_TRANSITIONS["cancel_draft"]`` table extension is the
#: authoritative source; this map mirrors it in lockstep per Sprint-7B.1
#: T3 R1 P2 #2 asymmetric-guard pattern (Round 3 P2 #3 ownership split:
#: lifecycle.py owns transition vocabulary; storage.py owns this local
#: target-state mirror because storage needs ``target_state`` resolved
#: BEFORE the precondition closure for the chain row's event-type tag).
_TRANSITION_TO_TARGET_STATE: Final[Mapping[TransitionName, PackState]] = {
    "submit": "submitted",
    "claim": "under_review",
    "approve": "approved",
    "reject": "rejected",
    "withdraw": "withdrawn",
    "allow_list": "allow_listed",
    "install": "installed",
    "disable": "disabled",
    "revoke": "revoked",
    "uninstall": "uninstalled",
    "cancel_draft": "withdrawn",
}

#: Sprint 7B.2 T4 R3 P2 #3 — shared column-width constants for the
#: ``packs`` table. Wire-protocol-public: the DTOs at
#: ``portal/api/packs/author_routes.py`` import these and apply them as
#: Pydantic ``Field(max_length=...)`` constraints so wire-input refusal
#: at 422 matches the DB column cap. Pre-fix the create DTO accepted
#: empty ``pack_id`` / empty ``display_name`` / empty ``sbom_pointer``;
#: ``save_draft()`` has no equivalent shape guard, so malformed values
#: could persist while ``update_draft`` refused analogous shapes —
#: asymmetric create vs update field semantics. Promoting these
#: constants to module level closes the asymmetry: every consumer
#: derives from the single source of truth.
PACK_ID_MAX_LEN: Final[int] = 256
PACK_DISPLAY_NAME_MAX_LEN: Final[int] = 256
PACK_KIND_MAX_LEN: Final[int] = 16
PACK_STATE_MAX_LEN: Final[int] = 32
PACK_TENANT_ID_MAX_LEN: Final[int] = 256
PACK_ACTOR_MAX_LEN: Final[int] = 256

#: Module-level Table object registered against the SAME ``_metadata`` as
#: ``audit_event`` + ``decision_history`` (imported from ``core/audit``).
#: A single ``_metadata.create_all()`` (in tests) or ``alembic upgrade
#: head`` (in production) creates ``packs`` alongside the chain tables.
#:
#: Column types use the shared dialect-portable seam at ``db/types`` —
#: ``chain_hash_column_type()`` for the 32-byte digest columns,
#: ``TIMESTAMP(timezone=True)`` for timestamps (NOT ``DateTime`` — same
#: Oracle-compile-output rationale documented at
#: ``20260430_0002_gateway_call_ledger.py:49+65-67``). T4's Alembic
#: migration mirrors this exact shape.
_packs = Table(
    "packs",
    _metadata,
    Column("id", Uuid(), primary_key=True),
    Column("kind", String(PACK_KIND_MAX_LEN), nullable=False),
    Column("pack_id", String(PACK_ID_MAX_LEN), nullable=False),
    Column("display_name", String(PACK_DISPLAY_NAME_MAX_LEN), nullable=False),
    Column("state", String(PACK_STATE_MAX_LEN), nullable=False),
    Column("manifest_digest", chain_hash_column_type(), nullable=False),
    Column("signed_artefact_digest", chain_hash_column_type(), nullable=False),
    Column("sbom_pointer", Text(), nullable=True),
    Column("tenant_id", String(PACK_TENANT_ID_MAX_LEN), nullable=True),
    Column("created_by", String(PACK_ACTOR_MAX_LEN), nullable=False),
    Column("last_actor", String(PACK_ACTOR_MAX_LEN), nullable=False),
    Column("created_at", TIMESTAMP(timezone=True), nullable=False),
    Column("updated_at", TIMESTAMP(timezone=True), nullable=False),
    CheckConstraint(
        "kind IN ('tool', 'skill', 'agent', 'hook')",
        name="ck_packs_kind",
    ),
    CheckConstraint(
        "state IN ('draft', 'submitted', 'under_review', 'approved', "
        "'rejected', 'withdrawn', 'allow_listed', 'installed', 'disabled', "
        "'revoked', 'uninstalled')",
        name="ck_packs_state",
    ),
    Index("ix_packs_kind_state", "kind", "state"),
    Index("ix_packs_tenant_state", "tenant_id", "state"),
)


# ``LifecycleTransitionRefused`` is defined in
# :mod:`cognic_agentos.packs.lifecycle` (the closed-enum
# :data:`LifecycleRefusalReason` it carries lives there) and re-exported
# here for backward-compatible import paths — pre-Sprint-7B.1-T5 callers
# imported via the storage module. The class is the same Python object
# in both locations
# (``packs.storage.LifecycleTransitionRefused is
# packs.lifecycle.LifecycleTransitionRefused``).
#
# Storage-module fire-sites (two):
#   (a) :meth:`PackRecordStore.transition` preflight guard at the
#       ``transition not in _TRANSITION_TO_TARGET_STATE`` check —
#       no DB connection acquired; closed-enum reason
#       ``"lifecycle_transition_name_unknown"``.
#   (b) The ``_precondition`` closure on a ``validate_transition``
#       non-None return — the ``engine.begin()`` transaction owned by
#       :meth:`DecisionHistoryStore.append_with_precondition` rolls
#       back atomically (no chain row, no state cache mutation);
#       closed-enum reason is any value of
#       :data:`LifecycleRefusalReason` other than
#       ``"lifecycle_transition_name_unknown"``.
#
# The pure-functional helper :func:`iso_controls_for` (which storage
# calls inside ``transition()`` per Sprint-7B.1-T5 R1 P2) also raises
# this exception on out-of-vocabulary inputs — but storage's preflight
# guard at (a) above intercepts every storage-side call site BEFORE
# the helper is reached, so the helper's own runtime guard at
# ``packs/lifecycle.py:416-417`` cannot fire from within this module.
# The helper's guard fires only when external callers (planned:
# Sprint 7B.2 portal handlers) invoke ``iso_controls_for`` directly —
# that fire-site lives in :mod:`cognic_agentos.packs.lifecycle`, NOT
# here. No in-tree caller invokes the helper directly today; storage
# is the only consumer of the helper, and it routes through the
# preflight guard at (a) above.


class PackNotFound(Exception):
    """Raised by :meth:`PackRecordStore.transition` when the requested
    ``pack_id`` has no row in ``packs``. Distinct from
    :class:`LifecycleTransitionRefused` so callers can dispatch on the
    difference between "the pack does not exist" and "the pack exists
    but the transition is refused"."""

    def __init__(self, pack_id: uuid.UUID) -> None:
        self.pack_id = pack_id
        super().__init__(f"pack not found: {pack_id}")


#: Closed-enum vocabulary for ``save_draft`` + ``update_draft`` API-contract
#: refusals. Sprint 7B.2 T4 bumped this from 1 to 4 values: the original
#: genesis-state guard plus three ``update_draft`` API-contract refusals.
#: The dual-contract surface (Sprint-7B.1 genesis-state guard + Sprint-7B.2
#: update_draft preconditions) covers every author-side write path; future
#: kind-specific or identity-specific preconditions land alongside without
#: breaking the closed-enum dispatch contract.
PackRecordRefusalReason = Literal[
    "pack_record_save_draft_initial_state_not_draft",
    "pack_record_update_non_draft_state",
    "pack_record_update_field_not_allowed",
    "pack_record_update_field_invalid_shape",
]


class PackRecordRefused(Exception):
    """Raised by :meth:`PackRecordStore.save_draft` (genesis-state guard)
    OR :meth:`PackRecordStore.update_draft` (3 update_draft API-contract
    refusals — non-draft-state, field-not-allowed, field-invalid-shape).

    The dual-contract surface was finalised at Sprint 7B.2 T4: the
    Sprint-7B.1 contract was genesis-state-only because ``save_draft``
    is the entry point to the state machine, so ``record.state`` MUST
    be ``"draft"``. Calling ``save_draft(state="installed")`` would
    persist a row with no ``decision_history`` predecessor, bypassing
    the lifecycle audit path entirely (T3 R1 P2 finding). Sprint 7B.2 T4
    added ``update_draft`` for in-place edits to draft-state packs;
    its three refusal modes land on the same exception class:

    - ``pack_record_update_non_draft_state`` — pack exists but is not
      in ``draft`` state (covers the race where a concurrent
      ``transition("submit")`` or ``transition("cancel_draft")`` advanced
      the pack out of ``draft`` between the route's preload and the
      atomic UPDATE).
    - ``pack_record_update_field_not_allowed`` — caller's ``updates``
      dict contains a key outside the 4-field allow-list (covers
      attempts to mutate any of the 5 immutable fields ``tenant_id``
      / ``state`` / ``kind`` / ``pack_id`` / ``created_by``).
    - ``pack_record_update_field_invalid_shape`` — allow-listed key
      carries a value that fails the per-field type/shape contract
      (Sprint 7B.2 T4 plan Round 6 P3 #4 — pure-Python validation;
      mirrors the ``cli/validators/`` early-refusal pattern).

    Distinct from :class:`LifecycleTransitionRefused` because neither
    branch is a state-machine refusal — the lifecycle table never had
    a chance to fire. Callers (Sprint 7B.2 portal author handlers) can
    dispatch on the exception class to distinguish "your draft request
    was malformed" from "the state machine refused your transition".

    The exception payload carries the closed-enum :data:`PackRecordRefusalReason`
    ONLY — no failing-field-name attribute (Sprint 7B.2 T4 Round 7 P2 #3
    decision to keep the 7B.1 ``__init__`` signature unchanged at
    ``(reason, *, state=None)``). Failing-field-name diagnostics surface
    via the structured-log record emitted by ``update_draft`` at the
    value-shape refusal branch (``packs.update_draft.invalid_shape``);
    SIEM correlation + examiner audit consume the log, not the
    exception payload.
    """

    def __init__(
        self,
        reason: PackRecordRefusalReason,
        *,
        state: PackState | None = None,
    ) -> None:
        self.reason = reason
        self.state = state
        if state is not None:
            super().__init__(f"{reason} (state={state!r})")
        else:
            super().__init__(reason)


class PackRecord(pydantic.BaseModel):
    """Frozen + ``extra="forbid"`` Pydantic v2 model for a pack record.

    Pack-kind / pack-state vocabulary correctness is enforced at
    construction (Doctrine Lock E layer 1) — out-of-vocabulary values
    are rejected before they reach the Postgres CHECK constraint or the
    chain-emission path. The model is wire-shape parallel to the
    ``packs`` table; column-for-field mapping is implicit (same
    canonical names).
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")

    id: uuid.UUID
    kind: PackKind
    pack_id: str
    display_name: str
    state: PackState
    manifest_digest: bytes
    signed_artefact_digest: bytes
    sbom_pointer: str | None
    tenant_id: str | None
    created_by: str
    last_actor: str
    created_at: datetime
    updated_at: datetime


#: Sprint 7B.3 T8 — the ``pack.approval_override`` chain-event contract.
#: ``decision_type`` matches ADR-012 §107 verbatim; the ISO control is
#: ``A.6.2.4`` (governance overrides). The control is pinned DIRECTLY as
#: a constant here — NOT derived via
#: :func:`cognic_agentos.packs.lifecycle.iso_controls_for` — because an
#: approval-gate override is NOT a lifecycle transition: there is no
#: :data:`TransitionName` to map, and ``append_override_event`` uses the
#: plain ``DecisionHistoryStore.append`` API (no precondition closure,
#: no ``packs.state`` cache mutation). ``A.6.2.4`` is a member of the
#: same ``packs.lifecycle._KNOWN_ISO_CONTROL_CODES`` set that
#: ``iso_controls_for`` draws from, so the override path's tag is
#: vocabulary-consistent with the lifecycle path's tags.
_OVERRIDE_EVENT_DECISION_TYPE: Final[str] = "pack.approval_override"
_OVERRIDE_EVENT_ISO_CONTROLS: Final[tuple[str, ...]] = ("A.6.2.4",)


#: Sprint 7B.3 T10 — the closed-enum 4-value evidence-panel vocabulary.
#: ``EvidencePanelName`` IS the wire-protocol contract for BOTH the
#: ``pack.evidence_read.<panel_name>`` chain-event ``decision_type``
#: namespace (4 possible values) AND the ``payload["panel_name"]`` key.
#: It lives HERE — co-located with
#: :meth:`PackRecordStore.append_evidence_read_event`, the method that
#: emits it — exactly as :data:`_OVERRIDE_EVENT_DECISION_TYPE` co-locates
#: with ``append_override_event`` (R17 P3 #1 location LOCK). The
#: ``packs/evidence/`` projector modules stay pure (manifest-in /
#: dict-out) and have no need of this vocabulary; ``evidence_routes.py``
#: imports it from here.
EvidencePanelName = Literal[
    "data_governance",
    "risk_tier",
    "supply_chain",
    "conformance_matrix",
]

#: Sprint 7B.3 T10 — the ``pack.evidence_read.<panel_name>`` chain-event
#: contract. The ISO control is ``A.5.31`` (audit logs / event logging);
#: pinned DIRECTLY as a constant here — NOT derived via
#: :func:`cognic_agentos.packs.lifecycle.iso_controls_for` — because an
#: evidence-panel read is NOT a lifecycle transition: there is no
#: :data:`TransitionName` to map, and ``append_evidence_read_event`` uses
#: the plain ``DecisionHistoryStore.append`` API (no precondition closure,
#: no ``packs.state`` cache mutation). Mirrors the
#: :data:`_OVERRIDE_EVENT_DECISION_TYPE` doctrine. ``A.5.31`` is a member
#: of the same ``packs.lifecycle._KNOWN_ISO_CONTROL_CODES`` set that
#: ``iso_controls_for`` draws from, so the evidence-read path's tag is
#: vocabulary-consistent with the lifecycle path's tags.
_EVIDENCE_READ_EVENT_DECISION_TYPE_PREFIX: Final[str] = "pack.evidence_read"
_EVIDENCE_READ_EVENT_ISO_CONTROLS: Final[tuple[str, ...]] = ("A.5.31",)


@dataclasses.dataclass(frozen=True)
class OverrideEventAppendResult:
    """Structured return value of :meth:`PackRecordStore.append_override_event`.

    Carries the two values ``DecisionHistoryStore.append`` returns —
    ``(record_id, chain_hash)`` — so the T9 route caller can correlate
    the override event with the subsequent approve transition: it threads
    ``str(result.record_id)`` into ``transition()``'s ``override_event_id``
    keyword-only kwarg (the kwarg that landed in T2 Slice C). Field order
    matches the underlying ``append`` tuple-return shape.

    NOT a :class:`~cognic_agentos.core.decision_history.DecisionRecord`
    (an earlier plan draft typed it that way — R2 P2 #3 fix): the live
    ``DecisionRecord`` model has no persisted ``id`` field; persistence
    identity is the ``(record_id, chain_hash)`` pair the store mints at
    append time.
    """

    record_id: uuid.UUID
    chain_hash: bytes


@dataclasses.dataclass(frozen=True)
class EvidenceReadEventAppendResult:
    """Structured return value of
    :meth:`PackRecordStore.append_evidence_read_event`.

    Carries the two values ``DecisionHistoryStore.append`` returns —
    ``(record_id, chain_hash)``. Mirrors :class:`OverrideEventAppendResult`
    exactly (Sprint 7B.3 T10; plan §553): a panel-read audit event, like
    an override event, is appended via the plain ``append`` API, so the
    persistence identity is the ``(record_id, chain_hash)`` pair the store
    mints at append time — NOT a
    :class:`~cognic_agentos.core.decision_history.DecisionRecord` (the
    live model has no persisted ``id`` field).
    """

    record_id: uuid.UUID
    chain_hash: bytes


class PackRecordStore:
    """Async pack-record store. Constructor takes an
    :class:`AsyncEngine` and lazily wraps it in a
    :class:`DecisionHistoryStore` (mirrors
    ``core/escalation.py:463-465``).

    Transitions go through the Sprint-2.5 T2 atomic primitive
    :meth:`DecisionHistoryStore.append_with_precondition`; the
    precondition closure does the row-locked state read + validation +
    state-cache UPDATE under the chain-head lock. The chain INSERT +
    state UPDATE + chain-head UPDATE all commit atomically.
    """

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._history = DecisionHistoryStore(engine)

    async def save_draft(self, record: PackRecord) -> uuid.UUID:
        """Insert a fresh ``draft``-state pack row. Returns the row id.

        No chain event is emitted — draft creation is the state-machine
        genesis, not a transition. The first chain event fires on the
        first ``transition()`` (typically ``submit``).

        Refuses (fail-loud, fail-closed) any record whose ``state`` is
        not ``"draft"``. This is the API contract guard that prevents
        callers from bypassing the lifecycle audit path: ``PackRecord``
        is wire-shape for rows in every lifecycle state (so ``load()``
        can return them), but ``save_draft`` is specifically the
        entry point to the state machine. Without this guard,
        ``save_draft(record_with_state='installed')`` would persist
        a row with no ``decision_history`` predecessor — bypassing the
        chain emission and producing an audit-unrooted pack record.
        Raises :class:`PackRecordRefused` with closed-enum reason
        ``pack_record_save_draft_initial_state_not_draft``; no pack
        row is inserted (the guard runs BEFORE the INSERT).
        """

        if record.state != "draft":
            raise PackRecordRefused(
                "pack_record_save_draft_initial_state_not_draft",
                state=record.state,
            )

        async with self._engine.begin() as conn:
            await conn.execute(
                insert(_packs).values(
                    id=record.id,
                    kind=record.kind,
                    pack_id=record.pack_id,
                    display_name=record.display_name,
                    state=record.state,
                    manifest_digest=record.manifest_digest,
                    signed_artefact_digest=record.signed_artefact_digest,
                    sbom_pointer=record.sbom_pointer,
                    tenant_id=record.tenant_id,
                    created_by=record.created_by,
                    last_actor=record.last_actor,
                    created_at=record.created_at,
                    updated_at=record.updated_at,
                )
            )
        return record.id

    async def update_draft(
        self,
        *,
        pack_id: uuid.UUID,
        updates: dict[str, Any],
        actor_id: str,
    ) -> None:
        """Sprint 7B.2 T4 — in-place edit of a ``draft``-state pack.

        Updates a fixed allow-list of 4 non-state fields
        (``display_name`` / ``manifest_digest`` / ``signed_artefact_digest``
        / ``sbom_pointer``) on a pack iff its current ``state == 'draft'``.
        ``last_actor`` + ``updated_at`` are ALWAYS overwritten by this
        call regardless of which allow-listed fields the caller supplied
        (so the audit-trail invariant ``last_actor`` = current modifier
        holds). The original ``created_by`` is NEVER mutated (it sits in
        the 5-field immutable set ``tenant_id`` / ``state`` / ``kind`` /
        ``pack_id`` / ``created_by`` — attempts to include any of these
        in ``updates`` are refused with
        ``pack_record_update_field_not_allowed``).

        No chain event is emitted — mirrors :meth:`save_draft`'s
        genesis-state pattern. The pack is still in the pre-submit
        editing window where the audit chain has not yet started; the
        first chain event fires on the first ``transition()`` (typically
        ``submit`` or ``cancel_draft``).

        Refusal precedence (Sprint 7B.2 T4 plan §"Atomicity specification")
        — fires top-down, fail-loud at the first mismatch:

        1. **Field-allowlist refusal** (pure-Python, before any DB call):
           if any key in ``updates`` is outside the 4-field allow-list,
           raise :class:`PackRecordRefused` with reason
           ``pack_record_update_field_not_allowed``. Mirrors the
           early-refusal pattern in Sprint-7B.1 T3 storage's preflight
           transition-name guard.
        2. **Per-field value-shape refusal** (pure-Python, Round 6 P3 #4):
           for each allow-listed key, verify the value matches the
           per-field shape contract (``str`` non-empty ≤256 for
           ``display_name``; ``bytes`` len==32 for both digests;
           ``str`` non-empty or ``None`` for ``sbom_pointer``). First
           mismatch raises :class:`PackRecordRefused` with reason
           ``pack_record_update_field_invalid_shape``. The failing
           field name surfaces via structured-log emission
           (``packs.update_draft.invalid_shape``) for SIEM correlation;
           NOT carried in the exception payload (Round 7 P2 #3 decision
           to keep ``PackRecordRefused.__init__`` signature unchanged).
        3. **Atomic UPDATE with state precondition**: single SQL
           ``UPDATE packs SET <allowlisted-fields>, last_actor, updated_at
           WHERE id = :pack_id AND state = 'draft'``. The state predicate
           is part of the WHERE clause (NOT a separate
           ``SELECT ... FOR UPDATE`` precondition closure — no chain row
           is emitted, so ``append_with_precondition`` is not the right
           primitive; the atomic UPDATE alone provides the consistency
           guarantee).
        4. **Rowcount-based refusal disambiguation**: rowcount==1 →
           success path; rowcount==0 → follow-up
           ``SELECT id, state FROM packs WHERE id = :pack_id`` to
           distinguish :class:`PackNotFound` from
           :class:`PackRecordRefused` with reason
           ``pack_record_update_non_draft_state`` (the latter covers
           the race where a concurrent ``transition("submit")`` or
           ``transition("cancel_draft")`` advanced the pack out of
           ``draft`` between the route's preload and the atomic UPDATE).

        Tenant-isolation enforcement is route-level (caller goes through
        :func:`portal.rbac.tenant_isolation.RequireTenantOwnership` at
        the FastAPI dependency layer); storage enforces ONLY the
        state-machine + field-allowlist + value-shape invariants. The
        kwarg signature deliberately does NOT take a ``tenant_id``
        argument so a caller cannot smuggle a cross-tenant mutation
        past this layer (per Sprint 7B.2 T4 plan Round 5 P2 #3
        resolution, mirroring 7B.1 ``save_draft()`` which also does
        not accept ``tenant_id`` as a separate kwarg).

        Parameters
        ----------
        pack_id
            Target pack's primary-key UUID. The route layer resolves this
            from the URL path via ``RequireTenantOwnership(pack_id_param=...)``
            BEFORE calling here.
        updates
            Field-name → new-value mapping. Must contain only keys from
            the 4-field allow-list above; values must match the per-field
            shape contract.
        actor_id
            Authenticated principal's ``subject`` (from
            :class:`Actor.subject`). Written to ``last_actor`` and used
            in the structured-log emission's ``extra`` payload.

        Raises
        ------
        PackRecordRefused
            With closed-enum reason
            ``pack_record_update_field_not_allowed`` (Step 1) /
            ``pack_record_update_field_invalid_shape`` (Step 2) /
            ``pack_record_update_non_draft_state`` (Step 4). All three
            refuse fail-loud, fail-closed: no row mutation, no chain
            row.
        PackNotFound
            Step 4 follow-up SELECT returned no row — pack does not
            exist at this ``pack_id``. Distinct from
            ``pack_record_update_non_draft_state`` because no decision
            was made — the caller asked about a row that does not
            exist.
        """

        # Step 1 — field-allowlist refusal (pure-Python; no DB call).
        # The 4-field allow-list is the ONLY mutable surface; everything
        # outside it (including the 5 immutable fields tenant_id / state
        # / kind / pack_id / created_by) refuses with the same closed-enum
        # reason so the caller dispatches uniformly. Mirrors the Sprint-
        # 7B.1 T3 storage preflight transition-name guard pattern.
        _ALLOWED_FIELDS: frozenset[str] = frozenset(
            {
                "display_name",
                "manifest_digest",
                "signed_artefact_digest",
                "sbom_pointer",
            }
        )
        for key in updates:
            if key not in _ALLOWED_FIELDS:
                raise PackRecordRefused("pack_record_update_field_not_allowed")

        # Step 2 — per-field value-shape refusal (pure-Python; no DB call).
        # First mismatch raises with the closed-enum reason ONLY; the
        # failing field name surfaces via structured-log emission BEFORE
        # the raise so SIEM correlation has the diagnostic without
        # extending the typed-exception payload (Sprint 7B.2 T4 plan
        # Round 7 P2 #3 + Round 8 reviewer answer #1 contract).
        for key, value in updates.items():
            if not _is_valid_update_value_shape(key, value):
                _LOG.warning(
                    "packs.update_draft.invalid_shape",
                    extra={"pack_id": str(pack_id), "field": key},
                )
                raise PackRecordRefused("pack_record_update_field_invalid_shape")

        # Step 3 — atomic UPDATE with state predicate as part of the
        # WHERE clause. The ``state = 'draft'`` predicate IS the
        # consistency guarantee — a concurrent transition() that
        # advances the pack out of draft causes our UPDATE to affect
        # zero rows, surfacing as a clean refusal in Step 4. No
        # SELECT ... FOR UPDATE precondition closure because no chain
        # row is emitted; the atomic UPDATE is the only authoritative
        # state check.
        async with self._engine.begin() as conn:
            update_values: dict[str, Any] = dict(updates)
            update_values["last_actor"] = actor_id
            update_values["updated_at"] = datetime.now(UTC)
            result = await conn.execute(
                update(_packs)
                .where(_packs.c.id == pack_id)
                .where(_packs.c.state == "draft")
                .values(**update_values)
            )
            if result.rowcount == 1:
                return

            # Step 4 — rowcount==0 disambiguation. Follow-up SELECT runs
            # inside the same transaction (no FOR UPDATE — disambiguation
            # is purely informational; the refusal is already determined
            # by the UPDATE's rowcount==0; the SELECT only chooses
            # between PackNotFound vs pack_record_update_non_draft_state).
            row = (await conn.execute(select(_packs.c.state).where(_packs.c.id == pack_id))).first()
            if row is None:
                raise PackNotFound(pack_id)
            raise PackRecordRefused(
                "pack_record_update_non_draft_state",
                state=row.state,
            )

    async def transition(
        self,
        *,
        pack_id: uuid.UUID,
        transition: TransitionName,
        actor_id: str,
        tenant_id: str | None,
        evidence_pointer: str | None,
        request_id: str,
        actor_type: str | None = None,
        payload_conformance: dict[str, Any] | None = None,
        expected_manifest_digest: bytes | None = None,
        evidence_attachments: dict[str, Any] | None = None,
        reviewer_acknowledgement: dict[str, Any] | None = None,
        payload_manifest: dict[str, Any] | None = None,
        override_event_id: str | None = None,
        signed_artefact_root: str | None = None,
    ) -> tuple[uuid.UUID, bytes]:
        """Atomically advance a pack through a named lifecycle
        transition. Returns ``(record_id, chain_hash)`` from the chain
        insert.

        ISO 42001 control tags are derived canonically (Sprint 7B.1 T5
        + R1 P2 reviewer fix) — callers do NOT supply ``iso_controls``.
        The transition name alone determines the tags via
        :func:`cognic_agentos.packs.lifecycle.iso_controls_for`,
        single source of truth per ADR-006 §"Evidence emission" and
        ADR-012's "all state transitions emit hash-chained audit events
        tagged with applicable ISO 42001 controls" contract. Caller-
        supplied tags would let a misconfigured or malicious caller emit
        an audit-untagged or wrongly-tagged chain row, breaking
        examiner-side evidence-pack export.

        **Sprint 7B.2 T6 slice-2 (R24 P2 Path B + B2 user-authorized
        CC-ADJ):** the optional keyword-only ``actor_type`` parameter
        is persisted as a top-level ``payload["actor_type"]`` key when
        non-None. The watchpoint (d) plan-of-record contract: the
        allow-list audit row records ``actor.actor_type == "human"``
        in the chain payload for examiner traceability without
        requiring log-correlation across surfaces. Persistence is
        conditional (key omitted entirely when ``actor_type is None``)
        so existing call sites + every pre-T6 chain row stay
        byte-shape compatible — backward-compat guardrail per the
        user-authorized patch contract. Storage performs no
        vocabulary validation; it accepts any string and writes it
        verbatim. The :data:`~cognic_agentos.portal.rbac.actor.ActorType`
        ``"human" | "service"`` closed-enum lives at the rbac
        boundary; storage stays a thin string passthrough so the
        layering (packs/storage MUST NOT depend on portal/rbac) holds.
        Slices 3-4 of T6 thread the same kwarg for install / disable /
        revoke / uninstall transitions so every operator audit row
        carries the actor's type for parity with allow-list.

        Atomic semantics (Doctrine Lock D): chain-head ``SELECT FOR
        UPDATE`` → pack-row ``SELECT FOR UPDATE`` → ``validate_transition``
        → state-cache UPDATE → chain row INSERT → chain-head UPDATE,
        all inside a single ``engine.begin()`` transaction owned by
        :meth:`DecisionHistoryStore.append_with_precondition`. Failure
        at any step rolls back all three — fail-closed.

        Raises (PREFLIGHT — NO DB connection acquired):
          :class:`LifecycleTransitionRefused` with reason
            ``"lifecycle_transition_name_unknown"`` — the supplied
            ``transition`` is not a member of
            :data:`cognic_agentos.packs.lifecycle.TransitionName`.
            The runtime guard fires at function entry (mirrors the
            ``packs/lifecycle.py`` step-3 guard from T2 R1 P2 + the
            T3 R1 P2 #2 reviewer fix). No transaction is started, so
            there is nothing to roll back.

        Raises (IN-PRECONDITION — transaction rolls back atomically):
          Three distinct sources, all firing under the chain-head + pack-
          row FOR UPDATE locks established by the precondition closure;
          all three trigger atomic rollback of the chain row INSERT +
          ``packs.state`` cache UPDATE + chain-head UPDATE via the
          enclosing ``engine.begin()`` transaction.

          (1) :class:`PackNotFound` — ``pack_id`` has no row in ``packs``
            after the precondition's ``SELECT ... FOR UPDATE`` returns
            empty.
          (2) :class:`LifecycleTransitionRefused` with reason
            ``"lifecycle_transition_manifest_digest_changed_during_submit"``
            — the storage-side digest cross-check added at Sprint 7B.2
            T9. Fires from inside ``_precondition`` AFTER the SELECT
            returns AND BEFORE :func:`validate_transition`, when the
            caller passed a non-None ``expected_manifest_digest`` kwarg
            AND the row-locked ``packs.manifest_digest`` column does
            NOT match (race-condition fix per plan §1179-1181 closing
            the TOCTOU window between the submit route's preloaded
            :class:`PackRecord` and the in-precondition state-machine
            check). Storage-only-emit — :func:`validate_transition` has
            no access to the persisted digest column and therefore
            cannot produce this reason.
          (3) :class:`LifecycleTransitionRefused` with any OTHER
            reason — the pure-functional state-machine refusal from
            :func:`cognic_agentos.packs.lifecycle.validate_transition`
            running under the chain-head FOR UPDATE lock AFTER the
            digest cross-check passes. Examples:
            ``"lifecycle_transition_invalid_state_pair"``,
            ``"lifecycle_transition_terminal_state"``,
            ``"lifecycle_transition_approve_without_review_claim"``.

        The contract — no chain row inserted, no ``packs.state`` cache
        mutation — holds for BOTH preflight and in-precondition refusal
        paths; only the rollback mechanism differs. Preflight: nothing
        to roll back because the function returns before
        ``append_with_precondition`` is called. In-precondition: the
        ``engine.begin()`` transaction owned by
        ``DecisionHistoryStore.append_with_precondition`` rolls back
        atomically (mirror of Sprint-2.5 T2's rollback contract).
        """

        # Runtime guard: ``TransitionName`` is a Literal but Python
        # does not enforce Literal at runtime, so a caller passing
        # ``transition="archive"`` would raise ``KeyError`` from the
        # ``_TRANSITION_TO_TARGET_STATE[transition]`` indexed access
        # below — leaking an unstructured exception past the
        # closed-enum boundary that downstream consumers (Sprint 7B.2
        # portal handlers planned) would catch on
        # ``LifecycleTransitionRefused``. Mirrors the asymmetric-runtime-
        # guard fix at ``packs/lifecycle.py`` step 3 (T2 R1 P2): both
        # layers MUST refuse out-of-vocabulary transition names with
        # the same ``lifecycle_transition_name_unknown`` closed-enum
        # reason. T3 R1 P2 finding.
        if transition not in _TRANSITION_TO_TARGET_STATE:
            raise LifecycleTransitionRefused("lifecycle_transition_name_unknown")

        target_state = _TRANSITION_TO_TARGET_STATE[transition]
        # Canonical ISO 42001 control derivation (T5 R1 P2 — single
        # source of truth at ``packs.lifecycle``; callers cannot supply
        # nor override). The preflight ``transition not in
        # _TRANSITION_TO_TARGET_STATE`` guard above means the helper's
        # own runtime guard at ``packs/lifecycle.py:416-417`` cannot
        # fire from this call site — both guards check the same closed
        # set (the storage map and the lifecycle map both key off
        # ``TransitionName``; verified by the build-time drift detector
        # ``TestSprint7B1IsoControlsMapShape::test_map_keys_match_transition_name_literal``
        # at ``tests/unit/packs/test_lifecycle_audit.py``). The helper
        # call is nonetheless retained (rather than indexing
        # ``_TRANSITION_TO_ISO_CONTROLS`` directly) so storage stays
        # routed through the public lifecycle seam — single source of
        # truth for the mapping, not two callers indexing the same
        # private dict.
        canonical_iso_controls = iso_controls_for(transition)

        async def _precondition(
            conn: AsyncConnection,
            prev_sequence: int,
            prev_hash: bytes,
        ) -> tuple[PackState, PackKind]:
            # SELECT FOR UPDATE on the pack row. Locks the row even
            # though the chain-head lock already serialises chain
            # appends — documents future-writer safety per Doctrine
            # Lock D step 1. Sprint 7B.2 T9: ``manifest_digest`` is
            # added to the projection so the locked precondition can
            # cross-check against the caller's
            # ``expected_manifest_digest`` kwarg under the same row
            # lock (race-condition fix per plan §1179-1181 — closes
            # the TOCTOU window between the route's preloaded pack
            # record and the in-precondition state-machine check).
            row = (
                await conn.execute(
                    select(_packs.c.state, _packs.c.kind, _packs.c.manifest_digest)
                    .where(_packs.c.id == pack_id)
                    .with_for_update()
                )
            ).first()
            if row is None:
                raise PackNotFound(pack_id)

            from_state: PackState = row.state
            kind: PackKind = row.kind

            # Sprint 7B.2 T9 — locked manifest-digest cross-check.
            # When ``expected_manifest_digest is None`` (default;
            # every non-submit caller) skip the check entirely so
            # backward-compat with every pre-T9 chain row holds. When
            # non-None, the digest read from the row-locked SELECT
            # MUST match exactly; mismatch raises the closed-enum
            # refusal from inside the closure so
            # ``DecisionHistoryStore.append_with_precondition`` 's
            # ``engine.begin()`` transaction rolls back atomically
            # (no chain row inserted, no ``packs.state`` cache
            # mutation — Doctrine Lock D preserved).
            if (
                expected_manifest_digest is not None
                and bytes(row.manifest_digest) != expected_manifest_digest
            ):
                raise LifecycleTransitionRefused(
                    "lifecycle_transition_manifest_digest_changed_during_submit"
                )

            reason = validate_transition(
                from_state=from_state,
                to_state=target_state,
                kind=kind,
                transition=transition,
            )
            if reason is not None:
                raise LifecycleTransitionRefused(reason)

            # State-cache UPDATE under the lock. ``packs`` is not a
            # chain table per ``core/decision_history.py:461-462`` —
            # preconditions MAY write non-chain tables under the same
            # transaction. last_actor + updated_at moved here so
            # the chain row's payload reflects the persisted state.
            await conn.execute(
                update(_packs)
                .where(_packs.c.id == pack_id)
                .values(
                    state=target_state,
                    last_actor=actor_id,
                    updated_at=datetime.now(UTC),
                )
            )
            return from_state, kind

        def _build_record(captured: tuple[PackState, PackKind]) -> DecisionRecord:
            from_state, kind = captured
            # Sprint 7B.2 T6 slice-2 (R24 P2 Path B + B2): conditional
            # ``actor_type`` payload key. Only inserted when the kwarg
            # was passed non-None — preserves byte-shape compat with
            # every pre-slice-2 chain row + every call site that
            # doesn't need the actor-type evidence surface (the T5
            # review handlers + the T4 author handlers all stay
            # untouched at their existing payload shape).
            payload: dict[str, Any] = {
                "pack_id": str(pack_id),
                "kind": kind,
                "from_state": from_state,
                "to_state": target_state,
                "transition_name": transition,
                "evidence_pointer": evidence_pointer,
                "iso_controls": list(canonical_iso_controls),
            }
            if actor_type is not None:
                payload["actor_type"] = actor_type
            # Sprint 7B.2 T9 — conditional ``conformance`` +
            # ``evidence_attachments`` payload keys. The omitted-kwarg
            # branch leaves the payload byte-shape compatible with every
            # pre-T9 chain row (and every non-submit / non-reject
            # caller); this is the user-watchpoint (ii) invariant —
            # omitted kwargs MUST NOT add empty keys.
            if payload_conformance is not None:
                payload["conformance"] = payload_conformance
            if evidence_attachments is not None:
                payload["evidence_attachments"] = evidence_attachments
            # Sprint 7B.3 T2 Slice C — 4 new optional payload keys.
            # All gated by the same is-not-None pattern as actor_type /
            # conformance / evidence_attachments above; omitted kwargs
            # do NOT add empty keys (user-watchpoint (ii) invariant per
            # T9 + R1 P2 #1 + R6 P2 #4). Storage stays a thin
            # passthrough; the route handlers own which kwarg fires
            # on which transition (T5 review reject path threads
            # evidence_attachments; T9 review approve threads
            # reviewer_acknowledgement + override_event_id; T2/T9 author
            # submit threads payload_manifest + signed_artefact_root).
            if reviewer_acknowledgement is not None:
                payload["reviewer_acknowledgement"] = reviewer_acknowledgement
            if payload_manifest is not None:
                payload["manifest"] = payload_manifest
            if override_event_id is not None:
                payload["override_event_id"] = override_event_id
            if signed_artefact_root is not None:
                payload["signed_artefact_root"] = signed_artefact_root
            return DecisionRecord(
                decision_type=f"pack.lifecycle.{target_state}",
                request_id=request_id,
                actor_id=actor_id,
                tenant_id=tenant_id,
                payload=payload,
                iso_controls=canonical_iso_controls,
            )

        return await self._history.append_with_precondition(
            record_builder=_build_record,
            precondition=_precondition,
        )

    async def append_override_event(
        self,
        *,
        pack_id: uuid.UUID,
        override_actor_subject: str,
        override_reason: ApprovalOverrideReason,
        gate_composition_snapshot: dict[str, Any],
        request_id: str,
    ) -> OverrideEventAppendResult:
        """Emit a ``pack.approval_override`` chain event recording a
        privileged reviewer's ADR-012 §107 force-approve authorisation.

        Sprint 7B.3 T8. Unlike :meth:`transition` this uses the plain
        ``DecisionHistoryStore.append`` API (``core/decision_history.py``)
        — NOT ``append_with_precondition``. An approval-gate override is
        NOT a lifecycle state-machine transition: there is no
        ``validate_transition`` precondition to run and no ``packs.state``
        cache to mutate. The chain-head ``SELECT FOR UPDATE`` inside
        ``append`` provides canonical ordering only.

        **Override-then-approve atomicity doctrine (R3 P2 #4 — dangling-
        override audit design).** The ``pack.approval_override`` event is
        emitted FIRST and records the reviewer's authorisation decision
        as an immutable audit fact. The subsequent approve transition
        (the T9 caller's separate ``transition("approve", ...,
        override_event_id=str(result.record_id))`` call) is an
        INDEPENDENT chain event whose success or failure does not
        retroactively affect this one. If the approve transition later
        refuses (state / race / tenant check), the chain CORRECTLY shows
        the override event with ``outcome="authorized"`` and NO
        ``pack.lifecycle.approved`` event — examiners read this as
        "reviewer authorised override at T1; approve did not complete by
        T2". The dangling-override pattern is INTENTIONAL: the override
        authorisation itself is the fact being recorded. Atomic-across-
        two-writes is not cleanly available without touching
        ``core/decision_history.py`` (an AGENTS.md stop-rule module);
        the plan deliberately chose the non-atomic two-event semantics.

        Args:
          pack_id: the pack the override authorises a force-approve for;
            persisted as ``payload["pack_id"] = str(pack_id)`` (mirroring
            ``transition()``'s ``_build_record`` contract). ``append_override_event``
            does NOT read or mutate the ``packs`` row (an override is not
            a state transition) — but the chain row MUST be pack-linkable:
            under the dangling-override audit design the surviving override
            row is the only record of the authorisation, and per-pack
            history readers filter on ``payload["pack_id"]``.
          override_actor_subject: the privileged reviewer's subject;
            persisted as ``payload["actor_subject"]``.
          override_reason: the categorised :data:`ApprovalOverrideReason`
            from the request body; persisted verbatim as
            ``payload["override_reason"]`` (closed-enum value — no synonym
            substitution).
          gate_composition_snapshot: the canonical-safe ``dict`` the T9
            caller builds via
            :func:`cognic_agentos.packs.approval_gates.composition_snapshot`
            — the full gate composition AT override time so examiners can
            reconstruct WHICH gates were red / blocking. Storage stays a
            thin dict passthrough: it performs NO vocabulary or shape
            validation (same doctrine as ``transition()``'s
            ``payload_conformance`` kwarg). A non-canonical-safe dict
            (tuples, sets, custom types) fails loud on the
            ``core.canonical.canonical_bytes`` gate inside ``append``.
          request_id: the caller-minted request id for the chain row's
            ``request_id`` column (the T9 route handler mints it; mirrors
            every other chain-writing seam — ``transition()`` takes the
            same kwarg).

        Returns:
          :class:`OverrideEventAppendResult` carrying the
          ``(record_id, chain_hash)`` pair from the underlying ``append``.

        Chain row shape:
          - ``decision_type`` = ``pack.approval_override``
          - ``iso_controls`` = ``("A.6.2.4",)`` (governance overrides)
          - ``payload`` = the explicit 5-key shape
            ``{pack_id, actor_subject, override_reason,
            gate_composition_snapshot, outcome}`` with
            ``outcome == "authorized"`` — a NEW closed-enum single-value
            Literal at 7B.3 (forward-compatible: a future sprint may
            extend it with ``completed`` / ``approve_refused_post_override``
            / ``superseded`` via a second event correlation). ``pack_id``
            is ``str(pack_id)`` (R14 reviewer P2 — the override row MUST
            be pack-linkable). The ``DecisionRecord.actor_id`` field is
            left ``None`` — the actor is carried in
            ``payload["actor_subject"]``, so the canonical-form actor-id
            merge does not add a 6th key.
        """
        payload: dict[str, Any] = {
            "pack_id": str(pack_id),
            "actor_subject": override_actor_subject,
            "override_reason": override_reason,
            "gate_composition_snapshot": gate_composition_snapshot,
            "outcome": "authorized",
        }
        record = DecisionRecord(
            decision_type=_OVERRIDE_EVENT_DECISION_TYPE,
            request_id=request_id,
            payload=payload,
            iso_controls=_OVERRIDE_EVENT_ISO_CONTROLS,
        )
        record_id, chain_hash = await self._history.append(record)
        return OverrideEventAppendResult(record_id=record_id, chain_hash=chain_hash)

    async def append_evidence_read_event(
        self,
        *,
        pack_id: uuid.UUID,
        actor_subject: str,
        panel_name: EvidencePanelName,
        tenant_id: str,
        request_id: str,
    ) -> EvidenceReadEventAppendResult:
        """Emit a ``pack.evidence_read.<panel_name>`` chain event recording
        a reviewer's access to one of the four evidence panels.

        Sprint 7B.3 T10 (plan §533-566). Like :meth:`append_override_event`
        this uses the plain ``DecisionHistoryStore.append`` API — NOT
        ``append_with_precondition``. An evidence-panel read is NOT a
        lifecycle state-machine transition: there is no
        ``validate_transition`` precondition to run and no ``packs.state``
        cache to mutate. The chain-head ``SELECT FOR UPDATE`` inside
        ``append`` provides canonical ordering only.

        The route handler calls this AFTER the panel projector returns
        successfully, so a 200 panel response correlates 1:1 with exactly
        one chain row; 4xx/5xx panel responses emit zero audit events
        (the read did not happen).

        Args:
          pack_id: the pack whose evidence panel was read; persisted as
            ``payload["pack_id"] = str(pack_id)`` so the audit row is
            pack-linkable (per-pack history readers filter on
            ``payload["pack_id"]``). ``append_evidence_read_event`` does
            NOT read or mutate the ``packs`` row — a panel read is not a
            state transition.
          actor_subject: the reviewer's subject; persisted as
            ``payload["actor_subject"]``.
          panel_name: the closed-enum :data:`EvidencePanelName` value —
            one of the four evidence panels; drives BOTH the chain-event
            ``decision_type`` namespace (``pack.evidence_read.<panel_name>``)
            AND the ``payload["panel_name"]`` key. Persisted verbatim (no
            synonym substitution).
          tenant_id: the reviewer's tenant; threaded to the
            :class:`~cognic_agentos.core.decision_history.DecisionRecord`
            ``tenant_id`` FIELD (DB column ``decision_history.tenant_id``)
            — NOT the payload dict (R17 P2 #2). Evidence-panel reads are
            tenant-scoped examiner-traceable events; the tenant boundary
            belongs on the chain row's first-class column.
            ``append_evidence_read_event`` is the first pack chain-writing
            seam to populate that column.
          request_id: the caller-minted request id for the chain row's
            ``request_id`` column (the route handler mints it via the
            ``evidence_routes.py`` ``_mint_request_id`` helper; mirrors
            every other chain-writing seam — ``transition()`` +
            ``append_override_event`` take the same kwarg).

        Returns:
          :class:`EvidenceReadEventAppendResult` carrying the
          ``(record_id, chain_hash)`` pair from the underlying ``append``.

        Chain row shape:
          - ``decision_type`` = ``f"pack.evidence_read.{panel_name}"``
            (4 possible values from :data:`EvidencePanelName`)
          - ``iso_controls`` = ``("A.5.31",)`` (audit logs)
          - ``tenant_id`` = the ``tenant_id`` arg (first-class column,
            NOT the payload — R17 P2 #2)
          - ``payload`` = the explicit 4-key shape ``{actor_subject,
            pack_id, panel_name, requested_at}`` — NO manifest content,
            NO sensitive data-class values, NO ``tenant_id`` key.
            ``requested_at`` is an ISO 8601 UTC timestamp stamped at emit
            time. The ``DecisionRecord.actor_id`` field is left ``None``
            — the actor is carried in ``payload["actor_subject"]``, so
            the canonical-form actor-id merge does not add a 5th key.
        """
        payload: dict[str, Any] = {
            "actor_subject": actor_subject,
            "pack_id": str(pack_id),
            "panel_name": panel_name,
            "requested_at": datetime.now(UTC).isoformat(),
        }
        record = DecisionRecord(
            decision_type=f"{_EVIDENCE_READ_EVENT_DECISION_TYPE_PREFIX}.{panel_name}",
            request_id=request_id,
            payload=payload,
            tenant_id=tenant_id,
            iso_controls=_EVIDENCE_READ_EVENT_ISO_CONTROLS,
        )
        record_id, chain_hash = await self._history.append(record)
        return EvidenceReadEventAppendResult(record_id=record_id, chain_hash=chain_hash)

    async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
        """Return the pack record for ``pack_id`` or ``None`` if none
        exists. O(1) read against the ``packs.state`` cache; the
        canonical history walks via :meth:`load_lifecycle_history`.
        """

        async with self._engine.connect() as conn:
            row = (await conn.execute(select(_packs).where(_packs.c.id == pack_id))).first()
        if row is None:
            return None
        return _row_to_record(dict(row._mapping))

    async def list_by_status(
        self,
        state: PackState,
        limit: int = 50,
        cursor: uuid.UUID | None = None,
        *,
        tenant_id: str | None = None,
    ) -> list[PackRecord]:
        """Paginated state-filter read. Returns records whose
        denormalised ``packs.state`` cache matches.

        ``cursor`` is the last id returned by the previous page; pass
        ``None`` (default) for the first page. Ordering is by
        ``packs.id`` so the cursor pagination is dialect-portable
        across PG / Oracle / SQLite without depending on
        ``ORDER BY ... NULLS LAST`` quirks.

        Sprint 7B.2 T5 (plan Round 11 P2 #1 + Round 14 P2 #1 backward-
        compatible signature): optional keyword-only ``tenant_id``
        filter. When non-None, adds ``tenant_id == :tenant_id`` to the
        WHERE clause server-side, leveraging the ``ix_packs_tenant_state``
        composite index per migration L129. The reviewer-queue endpoint
        at ``GET /api/v1/packs/review-queue`` calls this with
        ``tenant_id=actor.tenant_id`` so cross-tenant rows are filtered
        server-side (no in-handler filtering, no pagination skew).

        The ``tenant_id`` parameter lives BEHIND the ``*`` separator so
        it is keyword-only-with-default — pre-T5 call sites passing
        only ``state`` (or ``state``, ``limit``, ``cursor``) keep
        identical semantics.
        """

        stmt = select(_packs).where(_packs.c.state == state).order_by(_packs.c.id)
        if cursor is not None:
            stmt = stmt.where(_packs.c.id > cursor)
        if tenant_id is not None:
            stmt = stmt.where(_packs.c.tenant_id == tenant_id)
        stmt = stmt.limit(limit)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(stmt)).all()
        return [_row_to_record(dict(r._mapping)) for r in rows]

    async def list_for_tenant(
        self,
        tenant_id: str,
        *,
        limit: int = 50,
        cursor: uuid.UUID | None = None,
        state: PackState | None = None,
    ) -> list[PackRecord]:
        """Paginated tenant-scoped read for the inspection surface.

        Sprint 7B.2 T7 (plan Round 19 P2 #4 + Round 22 P2 #2): the new
        inspection endpoint ``GET /api/v1/packs`` lacks a ``{pack_id}``
        path-param so :class:`RequireTenantOwnership` cannot enforce
        row-level filtering — server-side WHERE clause filtering is
        REQUIRED and is the authoritative tenant boundary. Mirrors the
        T5 reviewer-queue solution via :meth:`list_by_status`'s
        ``tenant_id`` kwarg, but with two doctrinal differences:

        - ``tenant_id`` is REQUIRED (positional-or-keyword, BEFORE
          the ``*`` separator) — the inspection endpoint cannot list
          packs without a tenant scope; making it optional would
          re-open the cross-tenant leak class.
        - ``state`` is OPTIONAL keyword-only (AFTER the ``*``) —
          inspection lists across all lifecycle states by default;
          callers narrow via the ``state`` kwarg when needed.

        ``cursor`` is the last id returned by the previous page; pass
        ``None`` (default) for the first page. Ordering is by
        ``packs.id`` so cursor pagination is dialect-portable across
        PG / Oracle / SQLite (same convention as :meth:`list_by_status`).

        The WHERE clause covers ``(tenant_id, state)`` so the existing
        ``ix_packs_tenant_state`` composite index per migration L129
        services both the always-present ``tenant_id == :tenant_id``
        predicate and the optional ``state == :state`` predicate. The
        SQL is built via the module-private
        :func:`_build_list_for_tenant_stmt` helper — same builder the
        Slice-1 SQL-shape regression imports + asserts on; eliminates
        the vacuous-proof bug class where a test-local duplicate
        ``select`` could pass while the production query drifts
        (plan Round 22 P2 #2).
        """

        stmt = _build_list_for_tenant_stmt(tenant_id, limit=limit, cursor=cursor, state=state)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(stmt)).all()
        return [_row_to_record(dict(r._mapping)) for r in rows]

    async def load_lifecycle_history(self, pack_id: uuid.UUID) -> list[DecisionRecord]:
        """Walk the ``decision_history.event_type LIKE 'pack.lifecycle.%'``
        slice filtered to ``payload['pack_id'] == str(pack_id)``,
        sorted by ``sequence`` ascending. Mirrors
        :meth:`cognic_agentos.core.escalation.EscalationStore._read_current_state_within_txn`
        JSON-key extraction (client-side filter on payload key —
        dialect-portable across PG native JSON / SQLite native JSON /
        Oracle CLOB-with-app-side-serialisation).
        """

        target_id = str(pack_id)
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(
                        _decision_history.c.event_type,
                        _decision_history.c.request_id,
                        _decision_history.c.tenant_id,
                        _decision_history.c.trace_id,
                        _decision_history.c.span_id,
                        _decision_history.c.langfuse_trace_id,
                        _decision_history.c.provider_label,
                        _decision_history.c.iso_controls,
                        _decision_history.c.payload,
                        _decision_history.c.sequence,
                    )
                    .where(_decision_history.c.event_type.like("pack.lifecycle.%"))
                    .order_by(_decision_history.c.sequence)
                )
            ).all()

        history: list[DecisionRecord] = []
        for row in rows:
            payload: dict[str, Any] = row.payload or {}
            if payload.get("pack_id") != target_id:
                continue
            iso_controls_raw = row.iso_controls or []
            history.append(
                DecisionRecord(
                    decision_type=row.event_type,
                    request_id=row.request_id,
                    payload=payload,
                    actor_id=None,
                    tenant_id=row.tenant_id,
                    trace_id=row.trace_id,
                    span_id=row.span_id,
                    langfuse_trace_id=row.langfuse_trace_id,
                    provider_label=row.provider_label,
                    iso_controls=tuple(iso_controls_raw),
                )
            )
        return history

    async def load_pack_audit_events(self, pack_id: uuid.UUID) -> list[DecisionRecord]:
        """Walk the examiner-facing audit slice for a pack — BOTH the
        ``decision_history.event_type LIKE 'pack.lifecycle.%'`` slice AND
        the ``pack.approval_override`` force-approve authorisation event —
        filtered to ``payload['pack_id'] == str(pack_id)``, sorted by
        ``sequence`` ascending.

        Review §4.4 (C-narrow). This is the read seam behind
        ``GET /{pack_id}/audit``: ADR-012 §107 designates the
        ``pack.approval_override`` row the examiner's force-approve
        authorisation fact, and it had ZERO read surface before this.

        Deliberately a NEAR-COPY of :meth:`load_lifecycle_history` rather
        than a shared-helper refactor: ``load_lifecycle_history`` is a
        critical-controls method feeding the detail view + the four
        evidence projectors, and AGENTS.md forbids casual refactors of
        critical-controls code. Keeping it byte-identical guarantees those
        consumers (and their lifecycle-only contract tests) stay
        untouched. The ONLY difference is the ``WHERE`` union below.

        ``pack.evidence_read.*`` rows are DELIBERATELY excluded (deferred
        per the §4.4 C-narrow decision); they ARE audit events
        (ISO A.5.31) but surfacing them is out of scope for the
        override-visibility fix. A future sprint may widen the union.
        """

        target_id = str(pack_id)
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(
                        _decision_history.c.event_type,
                        _decision_history.c.request_id,
                        _decision_history.c.tenant_id,
                        _decision_history.c.trace_id,
                        _decision_history.c.span_id,
                        _decision_history.c.langfuse_trace_id,
                        _decision_history.c.provider_label,
                        _decision_history.c.iso_controls,
                        _decision_history.c.payload,
                        _decision_history.c.sequence,
                    )
                    .where(
                        or_(
                            _decision_history.c.event_type.like("pack.lifecycle.%"),
                            _decision_history.c.event_type == _OVERRIDE_EVENT_DECISION_TYPE,
                        )
                    )
                    .order_by(_decision_history.c.sequence)
                )
            ).all()

        history: list[DecisionRecord] = []
        for row in rows:
            payload: dict[str, Any] = row.payload or {}
            if payload.get("pack_id") != target_id:
                continue
            iso_controls_raw = row.iso_controls or []
            history.append(
                DecisionRecord(
                    decision_type=row.event_type,
                    request_id=row.request_id,
                    payload=payload,
                    actor_id=None,
                    tenant_id=row.tenant_id,
                    trace_id=row.trace_id,
                    span_id=row.span_id,
                    langfuse_trace_id=row.langfuse_trace_id,
                    provider_label=row.provider_label,
                    iso_controls=tuple(iso_controls_raw),
                )
            )
        return history

    async def load_latest_submit_created_at(self, pack_id: uuid.UUID) -> datetime | None:
        """Return the ``created_at`` timestamp of the most recent
        ``pack.lifecycle.submitted`` chain row for the given pack, or
        ``None`` when no submit row exists.

        Sprint 7B.3 T5 seam — feeds the 7-year sigstore-bundle
        retention computation in :func:`project_supply_chain_panel` per
        ADR-016 §70-72. The route handler at
        :mod:`cognic_agentos.portal.api.packs.evidence_routes` calls
        this method alongside :meth:`load_lifecycle_history` and passes
        the result to the projector as the ``submit_created_at``
        kwarg.

        Why a NEW method rather than extending
        :class:`~cognic_agentos.core.decision_history.DecisionRecord`
        with a ``created_at`` field: the canonical
        :class:`DecisionRecord` is the wire-format for evidence-pack
        export per ADR-006 + AGENTS.md "Stop rules"; extending it
        would be a CC change to the canonical dataclass. AGENTS.md
        L138 (Sprint 7B.2 T7 doctrine) already documents the precedent
        for deferring CC-ADJ canonical-dataclass extensions in favour
        of minimal-surface storage methods. The persisted
        ``created_at`` column at
        :data:`_decision_history.c.created_at` is already there per
        Sprint 2 (``TIMESTAMP(timezone=True)``); this method projects
        it without surfacing it through the canonical wire shape.

        Implementation mirrors :meth:`load_lifecycle_history`'s
        dialect-portable client-side filter on the ``payload['pack_id']``
        key (PG / SQLite / Oracle CLOB-with-app-side-serialisation).
        Ordering by ``sequence DESC`` returns the most recent submit
        first; we read only the head and return its timestamp.

        Returns:
            ``datetime`` — timezone-aware (preserves the column's
              tzinfo); always the MOST RECENT submit's timestamp when
              multiple exist (re-submit-after-cancel_draft flow per
              ADR-012 §59 + Sprint 7B.2 T4).
            ``None`` — when no submit chain row exists for the given
              pack-id (draft state, unknown pack-id, or pre-submit
              read).
        """

        target_id = str(pack_id)
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(
                        _decision_history.c.created_at,
                        _decision_history.c.payload,
                    )
                    .where(_decision_history.c.event_type == "pack.lifecycle.submitted")
                    .order_by(_decision_history.c.sequence.desc())
                )
            ).all()

        for row in rows:
            payload: dict[str, Any] = row.payload or {}
            if payload.get("pack_id") != target_id:
                continue
            created_at: datetime = row.created_at
            # Defensive tzinfo restoration for backends that drop the
            # column's timezone on read (SQLite + aiosqlite). The write
            # path at ``core/decision_history.py:528`` uses
            # ``datetime.now(UTC)`` so every persisted timestamp IS
            # UTC; Postgres preserves the tzinfo, SQLite drops it. The
            # method's contract promises a timezone-aware datetime, so
            # we restore it when the column read produced a naive
            # value — no-op on Postgres (the conditional skips).
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=UTC)
            return created_at
        return None


def _is_valid_update_value_shape(field_name: str, value: Any) -> bool:
    """Sprint 7B.2 T4 — per-field value-shape validator for
    :meth:`PackRecordStore.update_draft`.

    Returns ``True`` iff ``value`` matches the per-field type/shape
    contract documented at :meth:`PackRecordStore.update_draft` Step 2.
    Per-field contracts derived from :class:`PackRecord` field types
    at :class:`PackRecord` definition above:

    - ``display_name`` — ``str``, non-empty, length ≤ 256 chars
      (DB column is ``String(256)``; longer values would either fail
      a CHECK constraint or silently truncate depending on dialect)
    - ``manifest_digest`` — ``bytes``, exactly 32 bytes (SHA-256
      output width per :data:`chain_hash_column_type`)
    - ``signed_artefact_digest`` — ``bytes``, exactly 32 bytes (same
      as manifest_digest)
    - ``sbom_pointer`` — ``str`` non-empty OR ``None`` (DB column is
      ``Text(nullable=True)``; an empty string is semantically distinct
      from None and treated as malformed input here)

    Helper returns ``False`` on the FIRST validation rule that fails;
    the caller's loop is per-key, so the first mismatching key
    surfaces in the structured-log emission. ``field_name`` outside
    the 4-field allow-list returns ``False`` defensively (Step 1
    should have already refused; this is belt-and-braces).
    """

    if field_name == "display_name":
        return isinstance(value, str) and 0 < len(value) <= PACK_DISPLAY_NAME_MAX_LEN
    if field_name in ("manifest_digest", "signed_artefact_digest"):
        return isinstance(value, bytes) and len(value) == 32
    if field_name == "sbom_pointer":
        if value is None:
            return True
        return isinstance(value, str) and len(value) > 0
    return False


def _build_list_for_tenant_stmt(
    tenant_id: str,
    *,
    limit: int,
    cursor: uuid.UUID | None,
    state: PackState | None = None,
) -> Select[Any]:
    """Build the SELECT statement for :meth:`PackRecordStore.list_for_tenant`.

    Sprint 7B.2 T7 (plan Round 22 P2 #2) — module-private builder
    pattern. The public :meth:`PackRecordStore.list_for_tenant` invokes
    this helper as its ONLY query-construction path; the Slice-1
    SQL-shape regression at
    ``tests/unit/packs/test_storage_list_for_tenant.py::
    test_list_for_tenant_compiles_with_indexed_where_clause`` imports
    this SAME builder and asserts on its compiled output. Single
    source of truth for the WHERE-clause shape; production + test
    reference the same module-private symbol.

    WHERE shape (authoritative):

    - ``packs.tenant_id == :tenant_id`` — ALWAYS present; this is the
      server-side authoritative tenant boundary (no in-handler
      filtering can leak cross-tenant rows).
    - ``packs.state == :state`` — only when ``state`` is non-None.
    - ``packs.id > :cursor`` — only when ``cursor`` is non-None
      (cursor pagination excludes the cursor record itself).

    Ordering is by ``packs.id`` for dialect-portable cursor pagination
    across PG / Oracle / SQLite. Both filter columns ``(tenant_id,
    state)`` are covered by the ``ix_packs_tenant_state`` composite
    index per migration L129 — the always-present tenant filter
    matches the leading column, the optional state filter matches the
    trailing column.

    Underscore prefix marks this as module-private but it is
    module-public for the test import, mirroring the existing
    :func:`_row_to_record` helper convention. Plan Round 22 P2 #2 +
    P3 #3 propagation refresh — eliminates the
    "test-writes-its-own-select-and-assertion-passes-while-production-
    drifts" vacuous-proof bug class.
    """

    stmt = select(_packs).where(_packs.c.tenant_id == tenant_id).order_by(_packs.c.id)
    if state is not None:
        stmt = stmt.where(_packs.c.state == state)
    if cursor is not None:
        stmt = stmt.where(_packs.c.id > cursor)
    stmt = stmt.limit(limit)
    return stmt


def _row_to_record(mapping: Mapping[str, Any]) -> PackRecord:
    """Project a ``packs`` row mapping back into a :class:`PackRecord`.
    Single source of truth for column → field name parity.
    """

    return PackRecord(
        id=mapping["id"],
        kind=mapping["kind"],
        pack_id=mapping["pack_id"],
        display_name=mapping["display_name"],
        state=mapping["state"],
        manifest_digest=bytes(mapping["manifest_digest"]),
        signed_artefact_digest=bytes(mapping["signed_artefact_digest"]),
        sbom_pointer=mapping["sbom_pointer"],
        tenant_id=mapping["tenant_id"],
        created_by=mapping["created_by"],
        last_actor=mapping["last_actor"],
        created_at=mapping["created_at"],
        updated_at=mapping["updated_at"],
    )


# Build-time invariant: the cached _TRANSITION_TO_TARGET_STATE map and
# the lifecycle module's _VALID_TRANSITIONS table MUST agree on the
# (transition_name → to_state) projection. Asserted here so import-time
# alone surfaces drift; the build-time test in test_storage.py provides
# the operator-facing diagnostic.
assert set(_TRANSITION_TO_TARGET_STATE.keys()) == set(_VALID_TRANSITIONS.keys()), (
    "_TRANSITION_TO_TARGET_STATE keys diverge from _VALID_TRANSITIONS keys"
)
for _t, _target in _TRANSITION_TO_TARGET_STATE.items():
    _to_states = {to for _, to in _VALID_TRANSITIONS[_t]}
    assert _to_states == {_target}, (
        f"_TRANSITION_TO_TARGET_STATE[{_t!r}]={_target!r} diverges from "
        f"_VALID_TRANSITIONS[{_t!r}] to_state set {_to_states!r}"
    )
del _t, _target, _to_states


__all__: tuple[str, ...] = (
    "PACK_ACTOR_MAX_LEN",
    "PACK_DISPLAY_NAME_MAX_LEN",
    "PACK_ID_MAX_LEN",
    "PACK_KIND_MAX_LEN",
    "PACK_STATE_MAX_LEN",
    "PACK_TENANT_ID_MAX_LEN",
    "LifecycleTransitionRefused",
    "PackNotFound",
    "PackRecord",
    "PackRecordRefusalReason",
    "PackRecordRefused",
    "PackRecordStore",
)
