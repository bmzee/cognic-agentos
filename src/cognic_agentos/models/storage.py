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
from datetime import datetime
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
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from cognic_agentos.core.audit import _metadata
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.models.registry import (
    MODEL_LIFECYCLE_ISO_CONTROLS,
    ModelKind,
    ModelLifecycleRefused,
    ModelLifecycleState,
    ModelTransition,
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
    """Build the ``model.lifecycle.*`` chain-row payload. ``iso_controls``
    is a LIST inside the payload (the Sprint-2 canonical-form rejects
    tuples in chain payloads); the registry-level
    :data:`MODEL_LIFECYCLE_ISO_CONTROLS` tuple stays the source-of-truth
    tag set, and the :class:`DecisionRecord.iso_controls` field
    separately receives the tuple.
    """
    return {
        "model_id": record.model_id,
        "kind": record.kind,
        "from_state": from_state,
        "to_state": to_state,
        "actor_type": actor_type,
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


__all__ = [
    "MODEL_ACTOR_MAX_LEN",
    "MODEL_ID_MAX_LEN",
    "MODEL_TENANT_ID_MAX_LEN",
    "ModelNotFound",
    "ModelRecord",
    "ModelRecordStore",
    "_models",
]
