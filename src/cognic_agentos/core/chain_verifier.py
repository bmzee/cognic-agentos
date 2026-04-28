"""ChainVerifier — walk audit_event + decision_history chains and
surface tamper via a typed TamperReport.

**Critical-controls module.** Per AGENTS.md amendment in PR #5: every
edit gets per-task halt-before-commit review. ``core/chain_verifier``
is the read-side counterpart to ``core/audit`` + ``core/decision_history``;
its job is to prove (or disprove) chain integrity by re-running the
canonical envelope construction over each persisted row and comparing
the recomputed hash to the stored one.

What ChainVerifier detects:

  - ``hash_mismatch``: a row's stored hash does not equal
    ``sha256(prev_hash || canonical_bytes(envelope))`` recomputed
    from the row's columns. Catches any mutation of payload, metadata,
    record_id, sequence, schema_version, tenant_id, created_at, etc.
    — anything that participates in the canonical envelope. Also
    catches NULL-tamper on nullable JSON columns: the verifier
    passes ``row.iso_controls`` and ``row.payload`` through verbatim,
    so a DBA who NULLs an originally-empty list / dict produces
    different canonical bytes from the original (which was always
    written as a list / dict per the append contract).
  - ``sequence_gap``: row.sequence is not exactly ``prev_seq + 1``.
    Catches DELETE / RENUMBER attacks and accidental data loss.
  - ``prev_hash_mismatch``: row.prev_hash does not equal the
    predecessor row's stored hash. Catches re-anchored chains and
    half-mutations where the linkage was rewritten but not the
    content (or vice versa).
  - ``head_mismatch`` (walk only): the ``governance_chain_heads`` row
    for this chain is missing, or its ``latest_sequence`` /
    ``latest_hash`` do not match the last evidence row. Catches
    tampering with the mutable head row that holds the FOR UPDATE
    lock — without this check, a DBA could corrupt the head and
    leave the evidence rows untouched, and ``walk()`` would still
    return clean even though future appends would compute against
    a corrupted chain.
  - ``record_not_found`` (verify_record only): the requested
    record_id was not present in the chain.

What ChainVerifier does NOT detect:

  - An insider DBA who rewrites the entire chain consistently
    (re-hashes every row + chain head). That threat is defended by
    ADR-006 §"Tamper-evident evidence chain" Merkle root + signed
    manifest at evidence-pack export time (Phase 3.3) — not in
    Sprint-2 scope.

Dialect-aware datetime normalisation: SQLite drops tzinfo on
``TIMESTAMP`` round-trip; Postgres + Oracle preserve it. The
verifier re-attaches UTC to any naive datetime read from the row,
since ``canonical_bytes`` correctly rejects naive datetimes (per
Round-3 amendment of Task 2 / ``core/canonical``). The original
write was always UTC-aware (``datetime.now(UTC)`` in
``AuditStore.append`` / ``DecisionHistoryStore.append``), so
re-attaching UTC reconstructs the exact tz-aware datetime that
participated in the hash.
"""

from __future__ import annotations

import dataclasses
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import Table, select
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.audit import _audit_event, _chain_heads
from cognic_agentos.core.canonical import ZERO_HASH, canonical_bytes, hash_record
from cognic_agentos.core.decision_history import _decision_history

# Chain registry — a verifier can only walk chains it knows the
# canonical envelope shape for. Both Sprint-2 chains have the same
# column shape; the canonical chain_id is the only difference.
_CHAIN_TABLES: dict[str, Table] = {
    "audit_event": _audit_event,
    "decision_history": _decision_history,
}


BreakKind = Literal[
    "hash_mismatch",
    "sequence_gap",
    "prev_hash_mismatch",
    "head_mismatch",
    "record_not_found",
]


@dataclasses.dataclass(frozen=True, slots=True)
class TamperReport:
    """Result of a chain walk or per-record verify.

    ``records_checked`` is the count of evidence rows the verifier
    inspected during this call (an integer count, not a sequence
    number). On clean walks this equals the chain length. On broken
    walks it equals the count of rows that participated in the
    detection — including the broken row itself. ``first_break_sequence``
    carries the offending row's chain sequence; the two numbers can
    differ when a sequence gap is present (e.g. on the chain
    1, 2, 4, 5 the verifier inspects 3 rows before raising on row 4,
    so ``records_checked=3`` and ``first_break_sequence=4``).

    ``first_break_sequence`` + ``break_kind`` + ``detail`` are
    populated only when ``is_clean is False``. ``detail`` is a
    human-readable diagnostic; never load-bearing for downstream
    consumers (operators read it; programmatic callers branch on
    ``break_kind``).

    For ``head_mismatch`` the ``first_break_sequence`` is set to the
    governance_chain_heads row's stored ``latest_sequence`` so the
    operator can correlate (``None`` when the head row is missing).
    """

    chain_id: str
    is_clean: bool
    records_checked: int
    first_break_sequence: int | None = None
    break_kind: BreakKind | None = None
    detail: str | None = None


def _normalise_datetime(value: datetime) -> datetime:
    """Re-attach UTC to naive datetimes.

    SQLite drops tzinfo on ``TIMESTAMP`` round-trip; Postgres + Oracle
    preserve it. The original write was always UTC-aware, so a naive
    value here is unambiguous: it represents UTC. On dialects that
    preserve tzinfo this is a no-op.
    """

    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _envelope_from_row(chain_id: str, row: Any) -> dict[str, Any]:
    """Reconstruct the canonical envelope that was hashed pre-insert.

    Mirrors the envelope construction in ``AuditStore.append`` and
    ``DecisionHistoryStore.append`` exactly. Any drift between this
    function and the append-side construction would yield false
    tamper reports across the entire chain.

    **No NULL-coercion masking.** ``iso_controls`` and ``payload``
    are passed through verbatim — including ``None`` values that
    shouldn't normally appear (the append contract always writes
    a list / dict, even empty). If a DBA NULLs an originally-empty
    ``iso_controls=[]``, the recomputed envelope here has
    ``iso_controls=None``, canonical_bytes serialises that as JSON
    ``null`` (different bytes from ``[]``), and the chain verifier
    surfaces ``hash_mismatch``. Coercing NULL → default would silently
    hide that tamper.
    """

    return {
        "schema_version": int(row.schema_version),
        "chain_id": chain_id,
        "record_id": str(row.record_id),
        "sequence": int(row.sequence),
        "tenant_id": row.tenant_id,
        "created_at": _normalise_datetime(row.created_at),
        "event_type": row.event_type,
        "request_id": row.request_id,
        "trace_id": row.trace_id,
        "span_id": row.span_id,
        "langfuse_trace_id": row.langfuse_trace_id,
        "provider_label": row.provider_label,
        "iso_controls": row.iso_controls,
        "payload": row.payload,
    }


class ChainVerifier:
    """Walks a Sprint-2 governance chain and surfaces tamper.

    Constructed against an engine + a chain_id literal. ``walk()``
    walks the entire chain; ``verify_record(record_id)`` walks until
    the target record (so the verifier doesn't pay full-chain cost for
    a single-row check, but still sees prior breaks).
    """

    def __init__(self, engine: AsyncEngine, chain_id: str) -> None:
        if chain_id not in _CHAIN_TABLES:
            raise ValueError(
                f"unsupported chain_id: {chain_id!r}; supported chains are {sorted(_CHAIN_TABLES)}"
            )
        self._engine = engine
        self._chain_id = chain_id
        self._table = _CHAIN_TABLES[chain_id]

    async def walk(self) -> TamperReport:
        """Walk the entire chain. Returns the first break encountered;
        clean if no breaks."""

        return await self._walk(target_record_id=None)

    async def verify_record(self, record_id: uuid.UUID) -> TamperReport:
        """Walk the chain up to and including ``record_id``. Returns:

        - ``is_clean=True`` if the chain is intact through the target
          record.
        - The break report if any earlier row is broken (target row
          is irrelevant once the chain is broken before it).
        - ``record_not_found`` if the chain ends without finding the
          requested record_id.
        """

        return await self._walk(target_record_id=record_id)

    async def _walk(self, *, target_record_id: uuid.UUID | None) -> TamperReport:
        # ``engine.begin()`` (transaction) instead of ``engine.connect()``
        # — on Postgres + Oracle, READ COMMITTED isolation lets the two
        # SELECTs (evidence rows + chain head) see different committed
        # states if a concurrent append commits between them. Wrapping
        # both reads in a single transaction + locking the chain head
        # row up front makes walk() snapshot-safe against concurrent
        # appenders.
        async with self._engine.begin() as conn:
            # walk() — lock the chain-head row BEFORE scanning evidence
            # rows. Appenders use the same FOR UPDATE lock in
            # AuditStore.append / DecisionHistoryStore.append; concurrent
            # appenders block on this lock until our transaction commits
            # (commits at __aexit__ of ``async with engine.begin()``,
            # which releases all SELECT-acquired locks). The evidence-
            # row scan that follows therefore sees a chain that is
            # consistent with the locked head.
            #
            # verify_record() — skip the lock entirely. Per-record
            # contract is "is the chain context for this record intact
            # at read time?", which doesn't require whole-chain head
            # consistency. Skipping the lock avoids unnecessary
            # contention against appenders for one-record probes.
            locked_head_row: Any | None = None
            if target_record_id is None:
                locked_head_row = (
                    await conn.execute(
                        select(
                            _chain_heads.c.latest_sequence,
                            _chain_heads.c.latest_hash,
                        )
                        .where(_chain_heads.c.chain_id == self._chain_id)
                        .with_for_update()
                    )
                ).first()

            rows = (
                await conn.execute(select(self._table).order_by(self._table.c.sequence.asc()))
            ).all()

            prev_hash = ZERO_HASH
            prev_seq = 0
            records_checked = 0  # true count of evidence rows inspected

            for row in rows:
                records_checked += 1
                seq = int(row.sequence)

                # Sequence-gap check.
                if seq != prev_seq + 1:
                    return TamperReport(
                        chain_id=self._chain_id,
                        is_clean=False,
                        records_checked=records_checked,
                        first_break_sequence=seq,
                        break_kind="sequence_gap",
                        detail=f"expected sequence {prev_seq + 1}, got {seq}",
                    )

                # prev_hash linkage check.
                stored_prev = bytes(row.prev_hash)
                if stored_prev != prev_hash:
                    return TamperReport(
                        chain_id=self._chain_id,
                        is_clean=False,
                        records_checked=records_checked,
                        first_break_sequence=seq,
                        break_kind="prev_hash_mismatch",
                        detail=(
                            f"row.prev_hash does not link to predecessor's hash at sequence {seq}"
                        ),
                    )

                # Recompute the canonical envelope and verify the hash.
                envelope = _envelope_from_row(self._chain_id, row)
                recomputed = hash_record(canonical_bytes(envelope), stored_prev)
                stored_hash = bytes(row.hash)
                if recomputed != stored_hash:
                    return TamperReport(
                        chain_id=self._chain_id,
                        is_clean=False,
                        records_checked=records_checked,
                        first_break_sequence=seq,
                        break_kind="hash_mismatch",
                        detail=(
                            f"recomputed hash does not match stored hash for "
                            f"record_id={row.record_id} at sequence {seq}"
                        ),
                    )

                # Per-record success path. If we're verifying a specific
                # record and this is it, return clean for the slice
                # walked. No head check on this path — verify_record's
                # contract is per-record chain-context integrity, not
                # whole-chain head consistency.
                if target_record_id is not None and str(row.record_id) == str(target_record_id):
                    return TamperReport(
                        chain_id=self._chain_id,
                        is_clean=True,
                        records_checked=records_checked,
                    )

                prev_hash = stored_hash
                prev_seq = seq

            # Loop exited normally — walked the entire chain.
            if target_record_id is not None:
                # verify_record walked the full chain without finding
                # the target. No head check — record_not_found is the
                # answer to a per-record query.
                return TamperReport(
                    chain_id=self._chain_id,
                    is_clean=False,
                    records_checked=records_checked,
                    break_kind="record_not_found",
                    detail=(f"record_id={target_record_id} not found in chain {self._chain_id!r}"),
                )

            # walk() — full traversal of evidence rows clean. NOW check
            # the chain head against the values we LOCKED at the top of
            # the transaction. The head row must exist for this chain_id
            # AND its (latest_sequence, latest_hash) must match the
            # last evidence row — or (0, ZERO_HASH) if the chain is
            # empty. Without this, a DBA could corrupt the head and
            # leave evidence untouched, producing a clean walk over
            # broken append-state.
            #
            # We compare against locked_head_row (acquired via
            # SELECT ... FOR UPDATE at the top of the transaction)
            # rather than re-SELECTing here. The locked values are
            # snapshot-coherent with the evidence scan: any concurrent
            # appender was blocked on the FOR UPDATE lock and could
            # not have committed an intermediate state visible only
            # to one of the two SELECTs.
            if locked_head_row is None:
                return TamperReport(
                    chain_id=self._chain_id,
                    is_clean=False,
                    records_checked=records_checked,
                    break_kind="head_mismatch",
                    detail=(
                        f"governance_chain_heads row missing for chain_id="
                        f"{self._chain_id!r}; the row is seeded by migration 0001 "
                        f"and required by AuditStore.append / "
                        f"DecisionHistoryStore.append"
                    ),
                )

            head_sequence = int(locked_head_row.latest_sequence)
            head_hash = bytes(locked_head_row.latest_hash)

            if head_sequence != prev_seq or head_hash != prev_hash:
                return TamperReport(
                    chain_id=self._chain_id,
                    is_clean=False,
                    records_checked=records_checked,
                    first_break_sequence=head_sequence,
                    break_kind="head_mismatch",
                    detail=(
                        f"chain head ({head_sequence}, {head_hash.hex()}) "
                        f"does not match last evidence state "
                        f"({prev_seq}, {prev_hash.hex()})"
                    ),
                )

        return TamperReport(
            chain_id=self._chain_id,
            is_clean=True,
            records_checked=records_checked,
        )


__all__: tuple[str, ...] = (
    "BreakKind",
    "ChainVerifier",
    "TamperReport",
)
