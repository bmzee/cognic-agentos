"""DecisionHistoryStore — append-only hash-chained decision-history table.

**Critical-controls module.** Per AGENTS.md amendment in PR #5: every
edit gets per-task halt-before-commit review. ``core/decision_history``
records governance-relevant decisions (per ADR-006 §"Initial control
coverage" — decision_history.append with optional ``impact: high``
satisfies ISO 42001 control A.7.4 "AI system impact assessment").

**Implementation note (Sprint 2 Task 7, Option 2):** this module is a
parallel implementation of ``core/audit`` against the
``decision_history`` chain. Both stores walk the same flow: SELECT FOR
UPDATE the chain-head row, build the canonical envelope including the
full record-identity fields, INSERT the evidence row, compare-and-set
the chain head — atomically. A future refactor may factor out a
private ``_HashChainedAppendStore`` base class shared between
AuditStore and DecisionHistoryStore. Tests on both modules pin the
guarantees so the refactor has a regression baseline.

Schema-side coupling: the ``decision_history`` Table registers against
the SAME ``_metadata`` as ``audit_event`` (imported from
``core.audit``). This way a single ``_metadata.create_all()`` (in
tests) or ``alembic upgrade head`` (in deployments) creates both
tables in one migration.

**Naming:** ``DecisionRecord`` rather than ``DecisionEvent`` so the
type matches the BUILD_PLAN deliverable shape
``DecisionHistoryStore.append(record)``. The ``decision_type`` field
maps to the migration's ``event_type`` column (column shape stays
parallel with ``audit_event`` for chain-verifier reuse).
"""

from __future__ import annotations

import dataclasses
import json as _json
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Column,
    SmallInteger,
    String,
    Table,
    insert,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine
from sqlalchemy.types import TIMESTAMP, Uuid

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import canonical_bytes, hash_record
from cognic_agentos.db.types import GovernanceJSON, chain_hash_column_type

#: Locked at 1 for Sprint 2; bump requires AGENTS.md per-edit review of
#: ``core/canonical`` + a migration that sets the new default.
_SCHEMA_VERSION: int = 1

#: Sentinel for actor_id collision detection. Distinguishes "key
#: missing from payload" from "key present with value None" — the
#: ``dict.get(..., None)`` shorthand collapses both, which would let
#: ``DecisionRecord(actor_id='x', payload={'actor_id': None})``
#: silently overwrite the caller's explicit ``None`` instead of
#: raising on the inconsistency.
_MISSING: object = object()


def _validate_and_normalize_record(record: DecisionRecord) -> DecisionRecord:
    """Validate + snapshot a DecisionRecord. Pure, synchronous,
    idempotent — feeding the output of one call into another call
    returns a functionally identical record (canonical bytes are
    canonical-stable; actor_id has already been merged so the merge
    branch is a no-op).

    Returns a NEW frozen ``DecisionRecord`` whose:

      - ``payload`` is a deep-copied dict produced by
        ``canonical_bytes`` round-trip — JSON-native types, sorted
        keys, dialect-portable. Caller mutation of the original
        payload after this call cannot affect the returned record.
      - ``actor_id`` (the dataclass field) is set to ``None``. If the
        caller's dataclass had a non-None ``actor_id``, it has been
        merged into the snapshotted ``payload`` under the
        ``"actor_id"`` key.
      - All other fields are identical to the input.

    Raises:
        TypeError: if ``record.actor_id`` is non-``str``-non-``None``,
            OR if the raw ``record.payload['actor_id']`` is
            non-``str``-non-``None`` (caught BEFORE
            ``canonical_bytes`` auto-promotes UUID/Decimal/bytes/
            regular-Enum to strings — preserving the str|None
            invariant on actor provenance).
        ValueError: from ``canonical_bytes`` on canonical-form
            violations (NaN/Infinity, naive datetime, non-string
            dict keys, tuples, non-string Enum values, non-finite
            Decimals, datetimes whose tzinfo returns None from
            ``utcoffset()``).
        ValueError: on actor_id collision between the dataclass
            field and an existing ``payload['actor_id']`` whose
            value differs (silent overwrite would let typos or
            ambiguous caller-side construction land inconsistent
            actor provenance into the chain).

    **Why this is a separate helper, called from BOTH ``append`` AND
    ``append_with_precondition``:**

    The wrapper ``append()`` calls this function PRE-AWAIT — before
    any ``async with`` / ``await`` — so caller-side mutation of the
    record's payload between
    ``asyncio.create_task(store.append(record))`` and the first await
    cannot affect the hashed envelope. This preserves the Sprint 2
    R3 "snapshot before first await" hardening that the original T2
    refactor regressed.

    The new method ``append_with_precondition`` calls this function
    IN-LOCK on the output of ``record_builder``. For wrapper-supplied
    records the in-lock call is functionally idempotent (already
    normalized). For direct callers (escalation T3 et al.) that
    produce records inside the lock from in-lock-captured state, the
    in-lock call is the load-bearing validation + normalization step.
    """

    # Validate the dataclass actor_id type.
    if record.actor_id is not None and not isinstance(record.actor_id, str):
        raise TypeError(
            f"DecisionRecord.actor_id must be str | None, got "
            f"{type(record.actor_id).__name__}={record.actor_id!r}"
        )

    # Validate the RAW payload['actor_id'] BEFORE canonical
    # normalisation. canonical_bytes auto-promotes UUID/Decimal/
    # bytes/regular-Enum to strings; a check that ran post-
    # normalisation would silently accept those.
    raw_payload_actor = record.payload.get("actor_id", _MISSING)
    if (
        raw_payload_actor is not _MISSING
        and raw_payload_actor is not None
        and not isinstance(raw_payload_actor, str)
    ):
        raise TypeError(
            f"payload['actor_id'] must be str (or absent / None), got "
            f"{type(raw_payload_actor).__name__}={raw_payload_actor!r}"
        )

    # Snapshot + canonicalise the payload via the canonical-form
    # round-trip. Deep snapshot independent of caller mutation,
    # canonical-form validation at the boundary, projection to
    # JSON-native types so the persisted column matches the canonical
    # bytes that get hashed.
    payload_snapshot: dict[str, Any] = _json.loads(canonical_bytes(record.payload))

    # Merge actor_id into the snapshotted payload with the
    # strict-equality collision policy. _MISSING sentinel
    # distinguishes "key absent" from "key present with value None".
    existing_actor = payload_snapshot.get("actor_id", _MISSING)
    if record.actor_id is not None:
        if existing_actor is _MISSING:
            payload_snapshot["actor_id"] = record.actor_id
        elif existing_actor != record.actor_id:
            raise ValueError(
                f"DecisionRecord.actor_id={record.actor_id!r} conflicts "
                f"with payload['actor_id']={existing_actor!r}; the two "
                f"must agree or the dataclass field must be left as None"
            )
        # else: existing_actor == record.actor_id; no-op.

    # Return a new frozen record with the deep-copied normalised
    # payload + actor_id field cleared (already merged into payload).
    # Idempotent: feeding this output back through the function
    # produces a functionally identical record.
    return dataclasses.replace(record, payload=payload_snapshot, actor_id=None)


# Module-level Table — registered in the SHARED _metadata imported from
# core.audit. Identical column shape to _audit_event so the chain
# verifier (Task 8) can walk both with the same code path.
_decision_history = Table(
    "decision_history",
    _metadata,
    Column("record_id", Uuid(), primary_key=True),
    Column("sequence", BigInteger, nullable=False, unique=True),
    Column("schema_version", SmallInteger, nullable=False),
    Column("tenant_id", String(64), nullable=True),
    Column("prev_hash", chain_hash_column_type(), nullable=False),
    Column("hash", chain_hash_column_type(), nullable=False, unique=True),
    Column("created_at", TIMESTAMP(timezone=True), nullable=False),
    Column("event_type", String(64), nullable=False),
    Column("request_id", String(64), nullable=False),
    Column("trace_id", String(32), nullable=True),
    Column("span_id", String(16), nullable=True),
    Column("langfuse_trace_id", String(64), nullable=True),
    Column("provider_label", String(32), nullable=True),
    Column("iso_controls", GovernanceJSON(), nullable=True),
    Column("payload", GovernanceJSON(), nullable=False),
)


@dataclasses.dataclass(frozen=True, slots=True)
class DecisionRecord:
    """Caller-side representation of a governance-tracked decision.

    The dataclass itself is frozen + slotted: field bindings cannot be
    reassigned after the record is handed to ``DecisionHistoryStore.append``.
    However, ``payload`` is a mutable dict and the caller still holds
    its reference. Payload immutability against caller-side mutation is
    enforced by the **store**, which normalises the payload through the
    canonical serializer at method boundary (JSON round-trip via
    ``canonical_bytes`` → ``json.loads``).

    Field shape parallels ``AuditEvent`` so the chain-verifier code
    path is shared. The semantic distinctions are:
      - ``decision_type`` (e.g. ``"approved"``, ``"escalated"``,
        ``"denied"``) — corresponds to the migration's ``event_type``
        column.
      - ``actor_id`` — the agent / role that made the decision.
        ``DecisionHistoryStore.append`` merges this into the
        normalised ``payload`` under the key ``"actor_id"`` before
        hashing + insertion, so the actor provenance lives in the
        chain (and the persisted ``payload`` JSON column). If the
        caller's ``payload`` already carries an ``actor_id`` key,
        equality with the dataclass field is required — mismatches
        raise ``ValueError`` rather than silently overwriting one
        value with the other. Sprint 4 RBAC may promote ``actor_id``
        to a top-level evidence column once tenant-context wiring
        lands.

    ``iso_controls`` is a tuple at the boundary; the store converts to
    list before passing into ``canonical_bytes`` (which rejects tuples
    per Round-3 amendment of the Sprint-2 plan).
    """

    decision_type: str
    request_id: str
    payload: dict[str, Any]
    actor_id: str | None = None
    tenant_id: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    langfuse_trace_id: str | None = None
    provider_label: str | None = None
    iso_controls: tuple[str, ...] = ()


class DecisionHistoryStore:
    """Append-only hash-chained decision-history store.

    Mirrors AuditStore.append for the parallel chain. Same atomic
    transaction shape: SELECT FOR UPDATE → INSERT → compare-and-set
    UPDATE. Concurrent appenders block on the chain-head row lock
    (proven on Postgres + Oracle in Task 12; SQLite cannot prove
    locking but the SQL shape is exercised here).
    """

    _CHAIN_ID = "decision_history"

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def append(self, record: DecisionRecord) -> tuple[uuid.UUID, bytes]:
        """Public append API. Unchanged contract for existing callers.

        **Sprint 2 R3 "snapshot before first await" preserved:** the
        wrapper calls ``_validate_and_normalize_record(record)``
        SYNCHRONOUSLY, before any ``await`` / ``async with``. Caller-
        side mutation of ``record.payload`` between
        ``asyncio.create_task(store.append(record))`` and the first
        await point cannot affect the hashed envelope or persisted
        row — the snapshot has already deep-copied the payload via
        the canonical-form round-trip and merged ``actor_id`` into
        it.

        The pre-await snapshot also surfaces validation errors
        (TypeError on actor_id type; ValueError on canonical-form
        violations or actor_id collision) BEFORE entering the
        transaction, so callers see them as fail-fast errors rather
        than as transaction-rollback errors.

        After the snapshot, the wrapper delegates to
        ``append_with_precondition`` with an async no-op precondition
        + an identity ``record_builder`` that returns the snapshotted
        record. PEP 695 generic inference resolves ``T = None``
        without ``# type: ignore``. The in-lock call to
        ``_validate_and_normalize_record`` on the snapshotted record
        is functionally idempotent (canonical-stable canonical bytes
        + already-merged actor_id) and produces the same envelope.
        """

        # Pre-await snapshot. _validate_and_normalize_record returns
        # a NEW frozen DecisionRecord with a deep-copied payload that
        # is independent of the caller's original record. After this
        # line, caller mutation of the original record.payload has
        # no effect on the chain.
        snapshot = _validate_and_normalize_record(record)

        async def _no_precondition(
            conn: AsyncConnection,
            prev_sequence: int,
            prev_hash: bytes,
        ) -> None:
            return None

        return await self.append_with_precondition(
            record_builder=lambda _state: snapshot,
            precondition=_no_precondition,
        )

    async def append_with_precondition[T](
        self,
        *,
        record_builder: Callable[[T], DecisionRecord],
        precondition: Callable[[AsyncConnection, int, bytes], Awaitable[T]],
    ) -> tuple[uuid.UUID, bytes]:
        """Append a DecisionRecord atomically. The async precondition
        runs INSIDE the chain-head FOR UPDATE locked transaction (after
        the head is read, before any INSERT) and projects a value of
        type ``T``; that value flows into the synchronous
        ``record_builder``, which builds the DecisionRecord that is
        then hashed + inserted under the same lock.

        Order of operations under the lock (load-bearing — Sprint 2.5
        T2 plan contract):

          1. ``SELECT ... FOR UPDATE`` on ``governance_chain_heads`` →
             ``(prev_sequence, prev_hash)``.
          2. ``captured = await precondition(conn, prev_sequence,
             prev_hash)``. May raise → transaction rolls back.
          3. ``built_record = record_builder(captured)`` — sync, no
             I/O. May raise → rollback.
          4. ``normalised = _validate_and_normalize_record(built_record)``.
             Validates dataclass + raw payload actor_id types,
             snapshot+canonicalises the payload via canonical_bytes
             round-trip, merges actor_id with strict-equality
             collision policy. May raise TypeError /
             ``ValueError`` (canonical-form rejection or actor_id
             collision) → rollback. Idempotent on records the
             ``append`` wrapper has already pre-normalised before
             the first await.
          5. Build the canonical envelope from the normalised record;
             compute ``new_hash``.
          6. ``INSERT`` the evidence row.
          7. ``UPDATE`` chain_heads compare-and-set (rowcount must be
             1; otherwise raise ``RuntimeError`` → rollback).
          8. Commit.

        Concurrency / consistency:
          - Two concurrent calls serialise on the chain-head row lock.
            Whichever wins the lock first runs steps 2-7 to completion;
            the loser blocks on (1), then (when the winner commits)
            sees the new head state and runs its own (2). State-machine
            validators (e.g. escalation T3) raise from (2) when the
            new head has advanced past the expected from-state — the
            transaction rolls back, no row inserted.
          - Validation errors (step 4, step 7) all propagate via
            transaction rollback. No row inserted, chain head
            unchanged.

        Contract on the precondition:
          - MUST be async + awaitable.
          - MUST be SELECT-only against any chain table. INSERTing /
            UPDATEing chain rows from inside the precondition is
            undefined behaviour and breaks canonical-form invariants.
          - SHOULD be cheap. The lock is held until commit; long
            preconditions block concurrent appenders.
          - MAY raise any exception; the caller's try/except
            dispatches on the exception class.

        Contract on record_builder:
          - MUST be synchronous + side-effect-free.
          - MUST return a DecisionRecord whose payload is canonicalisable
            per ``core/canonical`` (same rules ``append`` already
            enforces).

        Generic ``T`` and the no-state case:
          ``T`` is inferred from the precondition's return type. The
          existing ``append()`` wrapper uses an async precondition
          returning ``None`` + an identity record_builder — PEP 695
          inference resolves ``T = None`` cleanly under mypy strict.
        """

        async with self._engine.begin() as conn:
            # Step 1: lock the chain-head row.
            head_stmt = (
                select(_chain_heads.c.latest_sequence, _chain_heads.c.latest_hash)
                .where(_chain_heads.c.chain_id == self._CHAIN_ID)
                .with_for_update()
            )
            head = (await conn.execute(head_stmt)).one()
            prev_sequence = int(head.latest_sequence)
            prev_hash = bytes(head.latest_hash)

            # Step 2: run the precondition under the lock. The
            # precondition can SELECT any table to validate state; if
            # it raises, the async-with block rolls back the
            # transaction (no row inserted, chain head unchanged).
            captured: T = await precondition(conn, prev_sequence, prev_hash)

            # Step 3: build the record from the captured value. Sync;
            # no I/O. If record_builder raises (caller bug or
            # post-validation rejection inside the builder), the
            # transaction rolls back.
            built_record = record_builder(captured)

            # Step 4: validate + snapshot + actor_id-merge the built
            # record via the shared helper. Idempotent on already-
            # normalised records — the ``append`` wrapper pre-
            # snapshots the caller's record before the first await
            # and passes a normalised record through the identity
            # builder; this in-lock call sees an already-clean payload
            # + actor_id-None dataclass, so the merge branch is a
            # no-op. Load-bearing for direct callers (escalation T3
            # et al.) that produce records inside the lock from
            # in-lock-captured state.
            #
            # Failures here roll back the transaction:
            #   - TypeError: actor_id type violation (dataclass or raw
            #     payload)
            #   - ValueError from canonical_bytes: NaN/Infinity, naive
            #     datetime, non-string dict keys, etc.
            #   - ValueError on actor_id collision between dataclass
            #     field + raw payload
            normalised = _validate_and_normalize_record(built_record)
            iso_controls_list: list[str] = list(normalised.iso_controls)

            # Step 5: build the canonical envelope + hash.
            new_sequence = prev_sequence + 1
            now = datetime.now(UTC)
            record_id = uuid.uuid4()

            envelope: dict[str, Any] = {
                "schema_version": _SCHEMA_VERSION,
                "chain_id": self._CHAIN_ID,
                "record_id": str(record_id),
                "sequence": new_sequence,
                "tenant_id": normalised.tenant_id,
                "created_at": now,
                # decision_type → event_type column shape parity.
                "event_type": normalised.decision_type,
                "request_id": normalised.request_id,
                "trace_id": normalised.trace_id,
                "span_id": normalised.span_id,
                "langfuse_trace_id": normalised.langfuse_trace_id,
                "provider_label": normalised.provider_label,
                "iso_controls": iso_controls_list,
                "payload": normalised.payload,
            }
            new_hash = hash_record(canonical_bytes(envelope), prev_hash)

            # Step 6: INSERT the evidence row.
            await conn.execute(
                insert(_decision_history).values(
                    record_id=record_id,
                    sequence=new_sequence,
                    schema_version=_SCHEMA_VERSION,
                    tenant_id=normalised.tenant_id,
                    prev_hash=prev_hash,
                    hash=new_hash,
                    created_at=now,
                    event_type=normalised.decision_type,
                    request_id=normalised.request_id,
                    trace_id=normalised.trace_id,
                    span_id=normalised.span_id,
                    langfuse_trace_id=normalised.langfuse_trace_id,
                    provider_label=normalised.provider_label,
                    iso_controls=iso_controls_list,
                    payload=normalised.payload,
                )
            )

            # Step 9: compare-and-set the chain head. rowcount != 1
            # means the chain head drifted between the SELECT FOR
            # UPDATE and the UPDATE — defence-in-depth against
            # dialect surprises + out-of-band writes + migration drift.
            update_result = await conn.execute(
                update(_chain_heads)
                .where(_chain_heads.c.chain_id == self._CHAIN_ID)
                .where(_chain_heads.c.latest_sequence == prev_sequence)
                .where(_chain_heads.c.latest_hash == prev_hash)
                .values(
                    latest_sequence=new_sequence,
                    latest_hash=new_hash,
                    updated_at=now,
                )
            )
            if update_result.rowcount != 1:
                raise RuntimeError(
                    f"chain head compare-and-set failed for chain_id="
                    f"{self._CHAIN_ID!r}: expected sequence={prev_sequence}, "
                    f"hash={prev_hash.hex()}; UPDATE affected "
                    f"{update_result.rowcount} rows. The chain head drifted "
                    f"between the SELECT FOR UPDATE and the UPDATE — "
                    f"either a dialect did not honour the lock, an "
                    f"out-of-band write mutated the row, or the migration "
                    f"shape diverged from db/types."
                )

            return record_id, new_hash


__all__: tuple[str, ...] = (
    "DecisionHistoryStore",
    "DecisionRecord",
    "_decision_history",
)
