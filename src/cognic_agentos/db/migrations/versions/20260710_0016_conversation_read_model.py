"""conversation read-model enablement — ADR-028 M8.5-B (HP-1).

Three additive surfaces for the transcript + chain-join read APIs:

1. ``conversation_turns.turn_completed_request_id`` — the hop-1 correlation
   column. ``ConversationTurnExecutor`` mints a unique ``conv-turn-<hex>``
   request id per turn and ``ConversationStore.append_turn`` uses it for the
   ``conversation.turn_completed`` chain row; persisting the SAME id on the
   turn row (atomically, same transaction)
   makes hop 1 of the ADR-028 three-hop reconstruction join
   (``conversation_id -> agent_run_id -> agent.run.dispatch``) addressable
   through the EXISTING ``ix_decision_history_request_id`` index (migration
   0001) instead of an unindexable JSON-payload predicate (the payload column
   is CLOB-backed on Oracle — no portable index).
2. ``ix_decision_history_tenant_event_sequence`` — the bounded dispatch-window
   access path: dispatch rows carry RANDOM request ids, so hop 3 is fetched by
   ``tenant_id + event_type + sequence BETWEEN the run anchors`` and
   exact-filtered on ``payload.run_id`` in Python within that bounded window.
3. ``ix_conversations_tenant_creator_created`` — the list endpoint's
   recent-first keyset (``created_at DESC, conversation_id DESC``), tiebreaker
   column included.

BACKFILL (fails loud — never enforces non-null over unmatched rows): every
existing ``conversation_turns`` row must match EXACTLY ONE
``conversation.turn_completed`` chain row on the FULL tuple — tenant_id
(chain-row column vs the conversation's), conversation_id, turn_id, seq,
agent_run_id, and actor_id == the conversation's creator_subject. Distinct
failure classes (each aborts the migration): malformed payload, duplicate
turn claim, duplicate request id, orphan chain row, orphan turn, field
mismatch.

RERUNNABILITY: every DDL step is inspector-guarded (column existence AND
current nullability, the unique constraint, both indexes) and the backfill
targets ``IS NULL`` rows only — Oracle autocommits DDL, so a mid-migration
failure leaves an unstamped partial state that a plain re-run completes
cleanly. Nullability + uniqueness ride ``batch_alter_table`` (SQLite
rebuild-compatible).

DOWNGRADE removes a DERIVED LOOKUP COLUMN while preserving the source
evidence: the ``conversation.turn_completed`` chain rows remain append-only
and the correlation stays reconstructable from them.

Revision ID: 0016
Revises: 0015
"""

from __future__ import annotations

import json
import uuid
from typing import Any, NoReturn

import sqlalchemy as sa
from alembic import op

from cognic_agentos.db.types import GovernanceJSON

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | None = None
depends_on: str | None = None

_COLUMN = "turn_completed_request_id"
_UQ = "uq_conversation_turns_turn_completed_request_id"
_IX_DH = "ix_decision_history_tenant_event_sequence"
_IX_CONV = "ix_conversations_tenant_creator_created"

#: The payload keys hop-1 validation requires (the M8.5-A chain contract).
_REQUIRED_PAYLOAD_KEYS = ("conversation_id", "turn_id", "seq", "agent_run_id", "actor_id")

# Migration-local read stubs (typed so Uuid round-trips uniformly across
# sqlite CHAR / PG uuid / Oracle RAW).
_turns = sa.table(
    "conversation_turns",
    sa.column("turn_id", sa.Uuid()),
    sa.column("conversation_id", sa.Uuid()),
    sa.column("seq", sa.Integer()),
    sa.column("agent_run_id", sa.String(64)),
    sa.column(_COLUMN, sa.String(64)),
)
_conversations = sa.table(
    "conversations",
    sa.column("conversation_id", sa.Uuid()),
    sa.column("tenant_id", sa.String(128)),
    sa.column("creator_subject", sa.String(256)),
)
_dh = sa.table(
    "decision_history",
    sa.column("request_id", sa.String(64)),
    sa.column("tenant_id", sa.String(64)),
    sa.column("event_type", sa.String(64)),
    # GovernanceJSON, NOT generic sa.JSON: SQLAlchemy's Oracle dialect has no
    # generic JSON bind/result processors — the kernel's type decodes the
    # CLOB text itself (native JSON on PostgreSQL + SQLite).
    sa.column("payload", GovernanceJSON()),
)


class _BackfillError(RuntimeError):
    """A distinct-classed 0016 backfill failure. The migration aborts unstamped."""


def _fail(failure_class: str, detail: str) -> NoReturn:
    raise _BackfillError(f"0016 backfill: {failure_class} — {detail}")


def _fail_ddl(detail: str) -> NoReturn:
    raise RuntimeError(f"0016 ddl: existing object shape mismatch — {detail}")


def _parse_payload(request_id: str, raw: Any) -> dict[str, Any]:
    payload = raw
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except ValueError:
            _fail("malformed payload", f"request_id={request_id}: unparseable JSON")
    if not isinstance(payload, dict):
        _fail("malformed payload", f"request_id={request_id}: payload is not an object")
    missing = [k for k in _REQUIRED_PAYLOAD_KEYS if k not in payload]
    if missing:
        _fail("malformed payload", f"request_id={request_id}: missing keys {missing}")
    if not isinstance(payload["seq"], int) or isinstance(payload["seq"], bool):
        _fail("malformed payload", f"request_id={request_id}: seq is not an int")
    for key in ("conversation_id", "turn_id", "agent_run_id", "actor_id"):
        if not isinstance(payload[key], str):
            _fail("malformed payload", f"request_id={request_id}: {key} is not a string")
    try:
        uuid.UUID(payload["conversation_id"])
        uuid.UUID(payload["turn_id"])
    except ValueError:
        _fail("malformed payload", f"request_id={request_id}: non-UUID conversation_id/turn_id")
    return payload


def _backfill(bind: sa.Connection) -> None:
    # 1. Every turn, joined to its conversation (tenant + creator truth).
    turn_rows = bind.execute(
        sa.select(
            _turns.c.turn_id,
            _turns.c.conversation_id,
            _turns.c.seq,
            _turns.c.agent_run_id,
            _turns.c[_COLUMN],
            _conversations.c.tenant_id,
            _conversations.c.creator_subject,
        ).select_from(
            _turns.join(
                _conversations,
                _turns.c.conversation_id == _conversations.c.conversation_id,
            )
        )
    ).fetchall()
    turns_by_id: dict[uuid.UUID, Any] = {}
    for row in turn_rows:
        turns_by_id[row.turn_id] = row

    # 2. Every turn_completed chain row, full-tuple validated.
    chain_rows = bind.execute(
        sa.select(_dh.c.request_id, _dh.c.tenant_id, _dh.c.payload).where(
            _dh.c.event_type == "conversation.turn_completed"
        )
    ).fetchall()

    claimed_by_turn: dict[uuid.UUID, str] = {}
    seen_request_ids: dict[str, uuid.UUID] = {}
    for chain in chain_rows:
        payload = _parse_payload(chain.request_id, chain.payload)
        turn_id = uuid.UUID(payload["turn_id"])
        # UNCONDITIONAL: any second occurrence of either key violates the
        # exactly-one invariant — an IDENTICAL duplicate row is corruption
        # too, not a benign repeat (review finding, 2026-07-10).
        if turn_id in claimed_by_turn:
            _fail(
                "duplicate turn claim",
                f"turn_id={turn_id} claimed by request_ids "
                f"{claimed_by_turn[turn_id]} and {chain.request_id}",
            )
        if chain.request_id in seen_request_ids:
            _fail(
                "duplicate request_id",
                f"request_id={chain.request_id} claims turns "
                f"{seen_request_ids[chain.request_id]} and {turn_id}",
            )
        turn = turns_by_id.get(turn_id)
        if turn is None:
            _fail("orphan chain row", f"request_id={chain.request_id} names unknown turn {turn_id}")
        mismatches = []
        if uuid.UUID(payload["conversation_id"]) != turn.conversation_id:
            mismatches.append("conversation_id")
        if payload["seq"] != turn.seq:
            mismatches.append("seq")
        if payload["agent_run_id"] != turn.agent_run_id:
            mismatches.append("agent_run_id")
        if payload["actor_id"] != turn.creator_subject:
            mismatches.append("actor_id/creator_subject")
        if chain.tenant_id != turn.tenant_id:
            mismatches.append("tenant_id")
        if mismatches:
            _fail(
                "field mismatch",
                f"request_id={chain.request_id} turn_id={turn_id}: {mismatches}",
            )
        existing = getattr(turn, _COLUMN)
        if existing is not None and existing != chain.request_id:
            _fail(
                "field mismatch",
                f"turn_id={turn_id}: pre-filled column {existing!r} disagrees "
                f"with chain request_id {chain.request_id!r}",
            )
        claimed_by_turn[turn_id] = chain.request_id
        seen_request_ids[chain.request_id] = turn_id

    orphan_turns = [str(tid) for tid in turns_by_id if tid not in claimed_by_turn]
    if orphan_turns:
        _fail("orphan turn", f"turns with no turn_completed chain row: {orphan_turns}")

    # 3. Idempotent fill: only IS NULL rows are written.
    to_fill = [
        {"tid": tid, "rid": rid}
        for tid, rid in claimed_by_turn.items()
        if getattr(turns_by_id[tid], _COLUMN) is None
    ]
    for entry in to_fill:
        bind.execute(
            sa.update(_turns)
            .where(_turns.c.turn_id == entry["tid"])
            .where(_turns.c[_COLUMN].is_(None))
            .values(**{_COLUMN: entry["rid"]})
        )


def _validate_uq_shape(uqs: dict[str | None, Any]) -> None:
    """A pre-existing unique constraint named ``_UQ`` must cover EXACTLY the
    correlation column; anything else is a partial-state hazard. (Extracted
    so the wrong-columns case is directly testable — SQLite cannot express
    a post-hoc table-level UNIQUE for an end-to-end regression.)"""
    if _UQ in uqs and list(uqs[_UQ]["column_names"]) != [_COLUMN]:
        _fail_ddl(
            f"unique constraint {_UQ} covers {uqs[_UQ]['column_names']}, expected [{_COLUMN!r}]"
        )


def _validate_index_shape(insp: sa.Inspector, table: str, name: str, columns: list[str]) -> None:
    """A pre-existing index with the right NAME but the wrong shape is a
    partial-state hazard, not a no-op (review finding, 2026-07-10)."""
    index = next(i for i in insp.get_indexes(table) if i["name"] == name)
    if list(index["column_names"]) != columns:
        _fail_ddl(f"index {name} has columns {index['column_names']}, expected {columns}")
    if bool(index.get("unique")):
        _fail_ddl(f"index {name} is UNIQUE; expected a non-unique query index")


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    # Step 1 (guarded + shape-validated): the correlation column.
    cols = {c["name"]: c for c in insp.get_columns("conversation_turns")}
    if _COLUMN not in cols:
        op.add_column(
            "conversation_turns",
            sa.Column(_COLUMN, sa.String(64), nullable=True),
        )
    else:
        length = getattr(cols[_COLUMN]["type"], "length", None)
        if length != 64:
            _fail_ddl(f"column {_COLUMN} has length {length}, expected 64")

    # Step 2 (idempotent, fail-loud): the full-tuple backfill.
    _backfill(bind)

    # Step 3 (guarded + shape-validated): non-null + uniqueness via batch
    # (SQLite rebuild).
    insp = sa.inspect(bind)
    cols = {c["name"]: c for c in insp.get_columns("conversation_turns")}
    uqs = {u["name"]: u for u in insp.get_unique_constraints("conversation_turns")}
    _validate_uq_shape(uqs)
    need_notnull = bool(cols[_COLUMN]["nullable"])
    need_uq = _UQ not in uqs
    if need_notnull or need_uq:
        with op.batch_alter_table("conversation_turns") as batch:
            if need_notnull:
                batch.alter_column(_COLUMN, existing_type=sa.String(64), nullable=False)
            if need_uq:
                batch.create_unique_constraint(_UQ, [_COLUMN])

    # Step 4 (guarded + shape-validated): the two query indexes.
    insp = sa.inspect(bind)
    if _IX_DH not in {i["name"] for i in insp.get_indexes("decision_history")}:
        op.create_index(_IX_DH, "decision_history", ["tenant_id", "event_type", "sequence"])
    else:
        _validate_index_shape(
            insp, "decision_history", _IX_DH, ["tenant_id", "event_type", "sequence"]
        )
    if _IX_CONV not in {i["name"] for i in insp.get_indexes("conversations")}:
        op.create_index(
            _IX_CONV,
            "conversations",
            ["tenant_id", "creator_subject", "created_at", "conversation_id"],
        )
    else:
        _validate_index_shape(
            insp,
            "conversations",
            _IX_CONV,
            ["tenant_id", "creator_subject", "created_at", "conversation_id"],
        )


def downgrade() -> None:
    # Removes the DERIVED lookup column + the two query indexes while
    # preserving the source evidence: the conversation.turn_completed chain
    # rows are append-only and the correlation stays reconstructable.
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if _IX_CONV in {i["name"] for i in insp.get_indexes("conversations")}:
        op.drop_index(_IX_CONV, table_name="conversations")
    if _IX_DH in {i["name"] for i in insp.get_indexes("decision_history")}:
        op.drop_index(_IX_DH, table_name="decision_history")
    cols = {c["name"] for c in insp.get_columns("conversation_turns")}
    if _COLUMN in cols:
        uq_names = {u["name"] for u in insp.get_unique_constraints("conversation_turns")}
        with op.batch_alter_table("conversation_turns") as batch:
            if _UQ in uq_names:
                batch.drop_constraint(_UQ, type_="unique")
            batch.drop_column(_COLUMN)
