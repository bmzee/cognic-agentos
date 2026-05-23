"""Postgres/Oracle-backed Model Registry record store — Sprint 9.5 per
ADR-013. The model-registry mirror of ``packs/storage.py``.

CRITICAL CONTROL. Consumer of
``DecisionHistoryStore.append_with_precondition`` — appends
``model.lifecycle.*`` chain rows. Does NOT modify the chain substrate.

Two distinct write paths (design spec §4.1):
  * ``register()``  — genesis: INSERT the ``models`` row + append
    ``model.lifecycle.proposed`` in one transaction.
  * ``transition()`` — promote / retire: SELECT ... FOR UPDATE the row,
    validate, UPDATE the state cache, append
    ``model.lifecycle.<state>``.  (Implemented in Task A4.)
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Final, get_args

import pydantic
from sqlalchemy import (
    TIMESTAMP,
    CheckConstraint,
    Column,
    Float,
    Index,
    String,
    Table,
    Uuid,
    insert,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from cognic_agentos.core.audit import _metadata
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    DecisionRecord,
    _decision_history,
)
from cognic_agentos.models.registry import (
    MODEL_LIFECYCLE_ISO_CONTROLS,
    ModelKind,
    ModelLifecycleRefused,
    ModelLifecycleState,
    ModelTransition,
    validate_transition,
)

MODEL_ID_MAX_LEN: Final[int] = 128
MODEL_TENANT_ID_MAX_LEN: Final[int] = 128
MODEL_ACTOR_MAX_LEN: Final[int] = 256

#: Genesis-included transition -> target state. ``register`` is genesis
#: and is NOT here; the 5 non-genesis transitions mirror
#: ``models/registry._VALID_TRANSITIONS`` keys. Consumed by
#: ``transition()`` in Task A4; defined here so the build-time invariant
#: assert can fire at module load.
_TRANSITION_TO_TARGET_STATE: Final[Mapping[ModelTransition, ModelLifecycleState]] = {
    "promote_eval_passed": "eval_passed",
    "promote_tenant_approved": "tenant_approved",
    "promote_serving": "serving",
    "promote_deprecated": "deprecated",
    "retire": "retired",
}

# Build-time invariant — _TRANSITION_TO_TARGET_STATE keys exactly match
# the ModelTransition closed-enum vocabulary (mirrors packs/storage.py).
assert set(_TRANSITION_TO_TARGET_STATE.keys()) == set(get_args(ModelTransition)), (
    "_TRANSITION_TO_TARGET_STATE keys diverge from get_args(ModelTransition)"
)

#: SQLAlchemy Core Table for the model registry, registered against the
#: shared ``core.audit._metadata`` — ``_metadata.create_all`` (tests) and
#: ``alembic upgrade head`` (migration 0004) both build it. The migration
#: at ``20260522_0004_model_registry.py`` MUST mirror this Table exactly;
#: drift is pinned by ``tests/unit/db/test_migration_20260522_0004.py``.
#:
#: Per planning-time design decision #4: ``id`` is a surrogate UUID PK
#: (DB/join identity, mirrors ``packs/``); ``model_id`` is the wire
#: identity + the unique natural key (the portal path-param). The two
#: are intentionally distinct.
_models = Table(
    "models",
    _metadata,
    Column("id", Uuid(), primary_key=True),
    Column("model_id", String(MODEL_ID_MAX_LEN), nullable=False, unique=True),
    Column("tenant_id", String(MODEL_TENANT_ID_MAX_LEN), nullable=False),
    Column("base_model", String(256), nullable=True),
    Column("version", String(64), nullable=False),
    Column("kind", String(32), nullable=False),
    Column("recipe_hash", String(64), nullable=True),
    Column("training_data_fingerprint", String(64), nullable=True),
    Column("eval_results_ref", String(512), nullable=True),
    Column("adversarial_pass_rate", Float(), nullable=True),
    Column("signature_digest", String(64), nullable=True),
    Column("signed_artifact_ref", String(512), nullable=True),
    Column("sigstore_bundle_ref", String(512), nullable=True),
    Column("serving_endpoint", String(512), nullable=True),
    Column("lifecycle_state", String(32), nullable=False),
    Column("last_actor", String(MODEL_ACTOR_MAX_LEN), nullable=False),
    Column("created_at", TIMESTAMP(timezone=True), nullable=False),
    Column("updated_at", TIMESTAMP(timezone=True), nullable=False),
    CheckConstraint(
        "kind IN ('foundation', 'fine_tune', 'adapter', 'embedding')",
        name="ck_models_kind",
    ),
    CheckConstraint(
        "lifecycle_state IN ('proposed', 'eval_passed', 'tenant_approved', "
        "'serving', 'deprecated', 'retired')",
        name="ck_models_lifecycle_state",
    ),
    Index("ix_models_tenant_state", "tenant_id", "lifecycle_state"),
)


class ModelRecord(pydantic.BaseModel):
    """Frozen + ``extra="forbid"`` projection of one ``models`` row."""

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")

    id: uuid.UUID
    model_id: str
    tenant_id: str
    base_model: str | None
    version: str
    kind: ModelKind
    recipe_hash: str | None
    training_data_fingerprint: str | None
    eval_results_ref: str | None
    adversarial_pass_rate: float | None
    signature_digest: str | None
    signed_artifact_ref: str | None
    sigstore_bundle_ref: str | None
    serving_endpoint: str | None
    lifecycle_state: ModelLifecycleState
    last_actor: str
    created_at: datetime
    updated_at: datetime


class ModelNotFound(Exception):
    """Raised when a ``models`` row lookup by surrogate ``id`` yields
    no row. Distinct from :class:`ModelLifecycleRefused` so callers can
    dispatch 404 (not-found) vs 409 (refused).
    """

    def __init__(self, row_id: uuid.UUID) -> None:
        self.row_id = row_id
        super().__init__(f"model not found: {row_id}")


def _record_to_row(record: ModelRecord) -> dict[str, Any]:
    """Project a :class:`ModelRecord` into a ``_models`` INSERT values
    dict.
    """
    return {
        "id": record.id,
        "model_id": record.model_id,
        "tenant_id": record.tenant_id,
        "base_model": record.base_model,
        "version": record.version,
        "kind": record.kind,
        "recipe_hash": record.recipe_hash,
        "training_data_fingerprint": record.training_data_fingerprint,
        "eval_results_ref": record.eval_results_ref,
        "adversarial_pass_rate": record.adversarial_pass_rate,
        "signature_digest": record.signature_digest,
        "signed_artifact_ref": record.signed_artifact_ref,
        "sigstore_bundle_ref": record.sigstore_bundle_ref,
        "serving_endpoint": record.serving_endpoint,
        "lifecycle_state": record.lifecycle_state,
        "last_actor": record.last_actor,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    }


def _row_to_record(mapping: Mapping[str, Any]) -> ModelRecord:
    """Project a ``models`` row mapping back into a :class:`ModelRecord`."""
    return ModelRecord(
        id=mapping["id"],
        model_id=mapping["model_id"],
        tenant_id=mapping["tenant_id"],
        base_model=mapping["base_model"],
        version=mapping["version"],
        kind=mapping["kind"],
        recipe_hash=mapping["recipe_hash"],
        training_data_fingerprint=mapping["training_data_fingerprint"],
        eval_results_ref=mapping["eval_results_ref"],
        adversarial_pass_rate=mapping["adversarial_pass_rate"],
        signature_digest=mapping["signature_digest"],
        signed_artifact_ref=mapping["signed_artifact_ref"],
        sigstore_bundle_ref=mapping["sigstore_bundle_ref"],
        serving_endpoint=mapping["serving_endpoint"],
        lifecycle_state=mapping["lifecycle_state"],
        last_actor=mapping["last_actor"],
        created_at=mapping["created_at"],
        updated_at=mapping["updated_at"],
    )


def _lifecycle_payload(
    record: ModelRecord,
    *,
    from_state: ModelLifecycleState | None,
    to_state: ModelLifecycleState,
    actor_type: str,
) -> dict[str, Any]:
    """Build the ``model.lifecycle.*`` chain-row payload — the
    **immutable evidence snapshot** of the (post-update) model record
    at the time of the transition.

    Per spec §4.1: the payload carries ``model_id`` (event subject),
    ``from_state``, ``to_state``, ``kind``, ``last_actor``,
    ``actor_type``, **and the transition-relevant evidence**
    (``signature_digest`` on the ``eval_passed`` row,
    ``eval_results_ref`` + ``adversarial_pass_rate`` on the
    ``tenant_approved`` row, ``serving_endpoint`` on the ``serving``
    row when populated at register time).

    Per spec §4.2 each ISO control tag is backed by a specific field
    surfaced on this payload — the hash-chained row, NOT the mutable
    ``models`` table column, IS the authoritative evidence per
    ADR-006:

    * ``A.6.2.6`` (roles & responsibilities) — ``last_actor`` +
      ``actor_type`` + the ``from_state``/``to_state`` transition
      itself.
    * ``A.7.4``  (impact assessment) — ``eval_results_ref``.
    * ``A.8.2``  (data quality) — ``training_data_fingerprint``.
    * ``A.8.5``  (system development) — ``recipe_hash`` +
      ``base_model``.
    * ``A.10.2`` (stakeholder transparency) — ``version`` (lineage) +
      ``serving_endpoint`` (when set) + the lifecycle event itself.

    All nullable model-state fields persist as their ACTUAL value —
    ``None`` at lifecycle stages where the value has not yet been
    populated IS the evidence (the chain row records the
    known/unknown state at that transition; an examiner reading
    ``eval_results_ref is None`` on a ``proposed`` row knows
    eval has not yet run).

    ``iso_controls`` is a LIST inside the payload (the Sprint-2
    canonical-form rejects tuples in chain payloads); the
    registry-level :data:`MODEL_LIFECYCLE_ISO_CONTROLS` tuple stays
    the source-of-truth tag set, and the
    :class:`DecisionRecord.iso_controls` field separately receives
    the tuple.
    """
    return {
        # Event subject + identity facts (immutable across the lifecycle).
        "model_id": record.model_id,
        "kind": record.kind,
        "version": record.version,
        "base_model": record.base_model,
        # Training/data identity (A.8.2 + A.8.5 evidence).
        "recipe_hash": record.recipe_hash,
        "training_data_fingerprint": record.training_data_fingerprint,
        # Cosign artefact identity (populated at register time;
        # promote_eval_passed re-verifies under the lock).
        "signature_digest": record.signature_digest,
        "signed_artifact_ref": record.signed_artifact_ref,
        "sigstore_bundle_ref": record.sigstore_bundle_ref,
        # Eval / adversarial evidence (populated by the
        # promote_tenant_approved transition; post-update record so
        # the row reflects the SET values, not the pre-update None).
        "eval_results_ref": record.eval_results_ref,
        "adversarial_pass_rate": record.adversarial_pass_rate,
        # Serving endpoint (A.10.2 transparency — set at register
        # when known; None at earlier stages is honest evidence).
        "serving_endpoint": record.serving_endpoint,
        # Actor identity + transition facts.
        "last_actor": record.last_actor,
        "actor_type": actor_type,
        "from_state": from_state,
        "to_state": to_state,
        # ISO 42001 control-tag set (canonical-form rejects tuples).
        "iso_controls": list(MODEL_LIFECYCLE_ISO_CONTROLS),
    }


class ModelRecordStore:
    """Async model-registry store. ``register`` is the genesis path;
    ``transition`` (Task A4) advances the lifecycle.
    """

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._history = DecisionHistoryStore(engine)

    async def register(
        self,
        record: ModelRecord,
        *,
        request_id: str,
        actor_id: str,
        actor_type: str,
    ) -> tuple[uuid.UUID, bytes]:
        """Genesis: INSERT a ``proposed``-state row + append the
        ``model.lifecycle.proposed`` chain row, atomically.

        Three operations commit or roll back together — the duplicate
        check + the row INSERT + the chain-row append — under the
        chain-head ``FOR UPDATE`` lock held by
        ``DecisionHistoryStore.append_with_precondition``. A duplicate
        ``model_id`` raises
        ``ModelLifecycleRefused("model_register_duplicate_id")`` from
        inside the precondition closure, which causes the engine's
        transactional rollback to fire — no chain row, no orphan
        ``models`` row.

        Initial-state gate (closed-enum
        ``model_register_initial_state_not_proposed``, A3 R1 P1
        reviewer fix): the caller MUST submit ``record.lifecycle_state
        == "proposed"``. Without this gate a direct store caller
        could register a row already in ``serving``/``retired``/etc
        while ``register()`` emitted a ``model.lifecycle.proposed``
        chain row — bypassing the eval / trust / tenant-approval
        transition gates and corrupting the chain/state-cache
        invariant. Refused BEFORE the transaction opens — no chain
        row is ever attempted, nothing to roll back.
        """
        if record.lifecycle_state != "proposed":
            raise ModelLifecycleRefused("model_register_initial_state_not_proposed")

        async def _precondition(
            conn: AsyncConnection, prev_sequence: int, prev_hash: bytes
        ) -> ModelRecord:
            existing = (
                await conn.execute(
                    select(_models.c.id).where(_models.c.model_id == record.model_id)
                )
            ).first()
            if existing is not None:
                raise ModelLifecycleRefused("model_register_duplicate_id")
            await conn.execute(insert(_models).values(**_record_to_row(record)))
            return record

        def _build_record(captured: ModelRecord) -> DecisionRecord:
            return DecisionRecord(
                decision_type="model.lifecycle.proposed",
                request_id=request_id,
                actor_id=actor_id,
                tenant_id=captured.tenant_id,
                payload=_lifecycle_payload(
                    captured,
                    from_state=None,
                    to_state="proposed",
                    actor_type=actor_type,
                ),
                iso_controls=MODEL_LIFECYCLE_ISO_CONTROLS,
            )

        return await self._history.append_with_precondition(
            record_builder=_build_record, precondition=_precondition
        )

    async def load(self, row_id: uuid.UUID) -> ModelRecord | None:
        """Read-only load by the SURROGATE ``id`` (DB/join identity).
        Returns ``None`` if absent. Task A5 adds ``load_by_model_id``
        for lookup by the natural wire identity.
        """
        async with self._engine.connect() as conn:
            row = (await conn.execute(select(_models).where(_models.c.id == row_id))).first()
        return _row_to_record(dict(row._mapping)) if row is not None else None

    async def transition(
        self,
        *,
        row_id: uuid.UUID,
        transition: ModelTransition,
        actor_id: str,
        actor_type: str,
        request_id: str,
        signature_verified: bool | None = None,
        eval_results_ref: str | None = None,
        adversarial_pass_rate: float | None = None,
        expected_signed_artifact_ref: str | None = None,
        expected_sigstore_bundle_ref: str | None = None,
        expected_signature_digest: str | None = None,
    ) -> tuple[uuid.UUID, bytes]:
        """Advance the lifecycle. Keyword-only; positional misuse is
        a state-machine bug class.

        Path-specific gates (design spec §2.3 + §4.1; plan amendment
        R1 P1 TOCTOU):

        - ``promote_eval_passed``: ``signature_verified`` is the
          cosign verdict computed by the caller OUTSIDE this
          transaction (route handler runs the subprocess pre-lock).
          Required ``True``; otherwise refused
          ``model_promote_signature_verification_failed`` BEFORE the
          transaction opens — no chain row attempted. Inside the
          locked precondition the TOCTOU guard re-checks that the
          row's ``signed_artifact_ref`` / ``sigstore_bundle_ref`` /
          ``signature_digest`` are byte-identical to the caller's
          ``expected_*`` kwargs (what cosign verified pre-lock);
          mismatch refuses
          ``model_promote_signature_refs_changed_during_promote``.
        - ``promote_tenant_approved``: ``eval_results_ref`` +
          ``adversarial_pass_rate`` are validated under the lock for
          presence (missing) and shape (blank / out-of-range);
          missing -> ``model_promote_eval_evidence_missing``;
          malformed -> ``model_promote_eval_evidence_malformed``.
          On the successful path BOTH fields are persisted on the
          row alongside the state-cache update — they are the only
          fields outside ``lifecycle_state`` / ``last_actor`` /
          ``updated_at`` that ``transition()`` ever writes.
        - All transitions: ``validate_transition`` runs under the
          row-locked view; refusal raises ``ModelLifecycleRefused``
          and rolls back (no chain row, no state mutation).

        Returns ``(chain_record_id, new_chain_hash)`` from
        ``DecisionHistoryStore.append_with_precondition``.

        Raises:
            ModelNotFound: when ``row_id`` has no row in ``models``.
            ModelLifecycleRefused: state-machine refusals + the
                shape/TOCTOU/signature-verification refusals above.
        """
        # P2 preflight transition-name guard — out-of-vocab transition
        # gets the closed-enum refusal, not a raw KeyError. Type hints
        # do NOT protect runtime callers; mirrors packs/storage.py's
        # preflight guard at packs/storage.py:742-743.
        if transition not in _TRANSITION_TO_TARGET_STATE:
            raise ModelLifecycleRefused("model_transition_name_unknown")

        target_state = _TRANSITION_TO_TARGET_STATE[transition]

        # A6 payload-evidence fix — closure-captured PRE-UPDATE
        # lifecycle_state, threaded from ``_precondition`` (which sees
        # the row under SELECT...FOR UPDATE) into ``_build_record``
        # (which builds the chain payload). MUST be captured here
        # because ``_precondition`` returns the POST-UPDATE record so
        # the chain payload's evidence fields reflect the just-written
        # state for eval_results_ref / adversarial_pass_rate; that
        # overlay sets ``record.lifecycle_state`` to ``target_state``,
        # which would silently corrupt ``from_state`` if we read it
        # off the returned record.
        from_state_capture: ModelLifecycleState | None = None

        # Pre-transaction gates for promote_eval_passed (the subprocess
        # ran in the route handler; only the bool verdict + the
        # caller-bound expected_* refs reach storage). No chain row
        # attempted; nothing to roll back.
        if transition == "promote_eval_passed":
            # Cosign verification verdict — must be exactly True.
            if signature_verified is not True:
                raise ModelLifecycleRefused("model_promote_signature_verification_failed")
            # P1 (A4 R1): TOCTOU is meaningless if the caller doesn't
            # bind the cosign verdict to specific artefact refs/digest.
            # ALL THREE expected_* values are mandatory for
            # promote_eval_passed — the locked precondition's re-check
            # is what guarantees the verdict still applies to the row
            # we're about to promote.
            if (
                expected_signed_artifact_ref is None
                or expected_sigstore_bundle_ref is None
                or expected_signature_digest is None
            ):
                raise ModelLifecycleRefused("model_promote_signature_expected_refs_missing")

        async def _precondition(
            conn: AsyncConnection, prev_sequence: int, prev_hash: bytes
        ) -> ModelRecord:
            nonlocal from_state_capture
            row = (
                await conn.execute(select(_models).where(_models.c.id == row_id).with_for_update())
            ).first()
            if row is None:
                raise ModelNotFound(row_id)
            current = _row_to_record(dict(row._mapping))
            # Capture the PRE-UPDATE lifecycle_state — this is the
            # chain row's ``from_state``. Captured BEFORE validate /
            # UPDATE / overlay so the overlay's ``lifecycle_state =
            # target_state`` does not stomp it (A6 evidence-snapshot
            # invariant: chain row carries genuine pre→post transition
            # facts).
            from_state_capture = current.lifecycle_state

            # TOCTOU guard for promote_eval_passed — cosign verified
            # the refs/digest OUTSIDE this transaction; the caller
            # threads what it verified as expected_* kwargs and we
            # re-check byte-identical under the lock. Mirrors
            # packs/storage.py's expected_manifest_digest race fix.
            # For non-promote_eval_passed paths the kwargs stay None
            # and the check is skipped.
            if expected_signed_artifact_ref is not None and (
                current.signed_artifact_ref != expected_signed_artifact_ref
                or current.sigstore_bundle_ref != expected_sigstore_bundle_ref
                or current.signature_digest != expected_signature_digest
            ):
                raise ModelLifecycleRefused("model_promote_signature_refs_changed_during_promote")

            # In-memory precondition: tenant_approved eval-evidence
            # shape. Both fields required + ref non-blank + rate in
            # [0, 1]. Refusal rolls back inside the transaction (no
            # state update, no chain row).
            if transition == "promote_tenant_approved":
                if eval_results_ref is None or adversarial_pass_rate is None:
                    raise ModelLifecycleRefused("model_promote_eval_evidence_missing")
                if not eval_results_ref.strip() or not (0.0 <= adversarial_pass_rate <= 1.0):
                    raise ModelLifecycleRefused("model_promote_eval_evidence_malformed")

            # State-machine validator under the row-locked from_state.
            reason = validate_transition(
                from_state=current.lifecycle_state,
                to_state=target_state,
                transition=transition,
            )
            if reason is not None:
                raise ModelLifecycleRefused(reason)

            # State-cache UPDATE. Only lifecycle_state + last_actor +
            # updated_at on every transition; eval_results_ref +
            # adversarial_pass_rate ONLY on tenant_approved (the
            # evidence that justified the approval is what gets
            # persisted).
            values: dict[str, Any] = {
                "lifecycle_state": target_state,
                "last_actor": actor_id,
                "updated_at": datetime.now(UTC),
            }
            if transition == "promote_tenant_approved":
                values["eval_results_ref"] = eval_results_ref
                values["adversarial_pass_rate"] = adversarial_pass_rate
            await conn.execute(update(_models).where(_models.c.id == row_id).values(**values))
            # Post-update record (A6 evidence-snapshot fix): apply the
            # ``values`` overlay onto ``current`` so the chain payload
            # built by ``_build_record`` reflects the POST-UPDATE state
            # for the fields just written. Returning the PRE-UPDATE
            # record (the pre-fix shape) would make a
            # ``tenant_approved`` chain row's
            # ``payload["eval_results_ref"]`` show the register-time
            # ``None`` instead of the freshly-set evidence ref —
            # silently breaking the ADR-006 evidence-integrity
            # invariant. ``ModelRecord`` is frozen + ``extra="forbid"``;
            # ``model_copy(update=...)`` rebinds the listed fields
            # without revalidation (the values dict's keys are 1:1
            # ModelRecord field names by construction).
            return current.model_copy(update=values)

        def _build_record(captured: ModelRecord) -> DecisionRecord:
            return DecisionRecord(
                decision_type=f"model.lifecycle.{target_state}",
                request_id=request_id,
                actor_id=actor_id,
                tenant_id=captured.tenant_id,
                payload=_lifecycle_payload(
                    captured,
                    # PRE-UPDATE state captured in _precondition — NOT
                    # captured.lifecycle_state (the overlay set that to
                    # target_state).
                    from_state=from_state_capture,
                    to_state=target_state,
                    actor_type=actor_type,
                ),
                iso_controls=MODEL_LIFECYCLE_ISO_CONTROLS,
            )

        return await self._history.append_with_precondition(
            record_builder=_build_record, precondition=_precondition
        )

    async def load_by_model_id(self, model_id: str) -> ModelRecord | None:
        """Read-only load by the natural ``model_id`` string identity
        (the wire path-param). Mirrors :meth:`load` but keys on the
        unique ``model_id`` column instead of the surrogate ``id`` PK.
        Consumed by ``RequireModelTenantOwnership`` at the portal
        admission seam (B2) — ``None`` maps to 404 there.
        """
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(select(_models).where(_models.c.model_id == model_id))
            ).first()
        return _row_to_record(dict(row._mapping)) if row is not None else None

    async def list_for_tenant(
        self,
        tenant_id: str,
        *,
        limit: int = 50,
        cursor: uuid.UUID | None = None,
        state: ModelLifecycleState | None = None,
    ) -> list[ModelRecord]:
        """Tenant-scoped paginated list. The ``WHERE tenant_id ==
        :tenant_id`` clause IS the tenant boundary — cross-tenant
        rows MUST NOT appear in another tenant's list (the inspection-
        list endpoint has no actor-side filter; the SQL filter is
        authoritative).

        Deterministic ordering by the surrogate ``id`` PK ASC + cursor
        on ``WHERE id > cursor`` — mirrors
        ``packs/storage.py:_build_list_for_tenant_stmt``. The
        ``state`` keyword filters to a single :data:`ModelLifecycleState`;
        omitted → all states.
        """
        stmt = select(_models).where(_models.c.tenant_id == tenant_id).order_by(_models.c.id)
        if state is not None:
            stmt = stmt.where(_models.c.lifecycle_state == state)
        if cursor is not None:
            stmt = stmt.where(_models.c.id > cursor)
        stmt = stmt.limit(limit)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(stmt)).all()
        return [_row_to_record(dict(r._mapping)) for r in rows]

    async def load_lifecycle_history(self, model_id: str) -> list[DecisionRecord]:
        """Walk the ``decision_history`` chain for every event whose
        ``event_type LIKE 'model.lifecycle.%'`` AND whose
        ``payload['model_id']`` matches ``model_id`` EXACTLY (string
        equality — NOT a LIKE/substring match). Sorted by
        ``sequence`` ASC (oldest first); includes genesis + every
        subsequent transition.

        Mirrors ``packs/storage.py:load_lifecycle_history`` — the
        JSON-key client-side filter pattern (dialect-portable across
        Postgres / Oracle / SQLite). Returns reconstructed
        :class:`DecisionRecord` instances with ``actor_id=None``
        (the actor identity is carried inside ``payload['actor_id']``
        per the canonical-form merge at append time;
        ``DecisionRecord.actor_id`` is a caller-side input, not a
        chain-row column).
        """
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(
                        _decision_history.c.event_type,
                        _decision_history.c.request_id,
                        _decision_history.c.tenant_id,
                        _decision_history.c.payload,
                        _decision_history.c.iso_controls,
                        _decision_history.c.sequence,
                    )
                    .where(_decision_history.c.event_type.like("model.lifecycle.%"))
                    .order_by(_decision_history.c.sequence)
                )
            ).all()
        history: list[DecisionRecord] = []
        for row in rows:
            payload: dict[str, Any] = row.payload or {}
            # EXACT string-equality filter on payload['model_id'] —
            # never LIKE/substring; the chain payload always carries
            # model_id as a top-level string (per _lifecycle_payload).
            if payload.get("model_id") != model_id:
                continue
            iso_controls_raw = row.iso_controls or []
            history.append(
                DecisionRecord(
                    decision_type=row.event_type,
                    request_id=row.request_id,
                    payload=payload,
                    actor_id=None,
                    tenant_id=row.tenant_id,
                    iso_controls=tuple(iso_controls_raw),
                )
            )
        return history


__all__ = [
    "MODEL_ACTOR_MAX_LEN",
    "MODEL_ID_MAX_LEN",
    "MODEL_TENANT_ID_MAX_LEN",
    "ModelNotFound",
    "ModelRecord",
    "ModelRecordStore",
    "_models",
]
