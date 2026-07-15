"""ADR-028 M8.5-B — pin migration 0016 (conversation read-model enablement)
via real alembic upgrade + inspect, with a SEEDED 0015 -> 0016 backfill.

Per the recorded doctrine, storage shape is proven against the
ALEMBIC-MIGRATED database, never ``metadata.create_all``. The backfill is
exercised on seeded pre-0016 data (turns + their ``conversation.turn_completed``
chain rows) — every distinct failure class aborts the migration BEFORE
non-null enforcement, and a plain re-run over an unstamped partial state
completes cleanly (the Oracle DDL-autocommit posture).
"""

from __future__ import annotations

import importlib
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command

from cognic_agentos.db.migrations.alembic_config import make_alembic_config
from cognic_agentos.db.types import GovernanceJSON

_COLUMN = "turn_completed_request_id"
_UQ = "uq_conversation_turns_turn_completed_request_id"
_IX_DH = "ix_decision_history_tenant_event_sequence"
_IX_CONV = "ix_conversations_tenant_creator_created"

_TENANT = "t-0016"
_CREATOR = "analyst.zed"


def _sqlite_url(tmp_path: Any, name: str) -> str:
    # The SYNC url for seeding/inspection; alembic's env.py requires the
    # async driver, so _upgrade/_downgrade swap the scheme.
    return f"sqlite:///{tmp_path / name}"


def _async_url(url: str) -> str:
    return url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)


def _upgrade(url: str, revision: str) -> None:
    command.upgrade(make_alembic_config(_async_url(url)), revision)


def _downgrade(url: str, revision: str) -> None:
    command.downgrade(make_alembic_config(_async_url(url)), revision)


# Typed seed stubs (NOT reflection: sqlite reflection strips sa.Uuid to
# CHAR, breaking uuid binds; typed stubs also store values in the SAME
# on-disk format the production Tables use).
_conversations_t = sa.table(
    "conversations",
    sa.column("conversation_id", sa.Uuid()),
    sa.column("tenant_id", sa.String(128)),
    sa.column("agent_id", sa.String(128)),
    sa.column("creator_subject", sa.String(256)),
    sa.column("state", sa.String(32)),
    sa.column("turn_count", sa.Integer()),
    sa.column("cumulative_tokens", sa.Integer()),
    sa.column("turn_in_progress", sa.Boolean()),
    sa.column("created_at", sa.TIMESTAMP(timezone=True)),
)
_turns_t = sa.table(
    "conversation_turns",
    sa.column("turn_id", sa.Uuid()),
    sa.column("conversation_id", sa.Uuid()),
    sa.column("seq", sa.Integer()),
    sa.column("user_message", sa.Text()),
    sa.column("answer", sa.Text()),
    sa.column("agent_run_id", sa.String(64)),
    sa.column("prompt_tokens", sa.Integer()),
    sa.column("completion_tokens", sa.Integer()),
    sa.column("created_at", sa.TIMESTAMP(timezone=True)),
    sa.column(_COLUMN, sa.String(64)),
)
_dh_t = sa.table(
    "decision_history",
    sa.column("record_id", sa.Uuid()),
    sa.column("sequence", sa.BigInteger()),
    sa.column("schema_version", sa.SmallInteger()),
    sa.column("tenant_id", sa.String(64)),
    sa.column("prev_hash", sa.LargeBinary(32)),
    sa.column("hash", sa.LargeBinary(32)),
    sa.column("created_at", sa.TIMESTAMP(timezone=True)),
    sa.column("event_type", sa.String(64)),
    sa.column("request_id", sa.String(64)),
    # GovernanceJSON — the SAME type the kernel writes through (parity with
    # the live PostgreSQL/Oracle lanes; generic sa.JSON lacks Oracle support).
    sa.column("payload", GovernanceJSON()),
)


def _seed_conversation(
    conn: sa.Connection,
    conversation_id: uuid.UUID,
    *,
    tenant_id: str = _TENANT,
    creator_subject: str = _CREATOR,
) -> None:
    conn.execute(
        sa.insert(_conversations_t).values(
            conversation_id=conversation_id,
            tenant_id=tenant_id,
            agent_id="bank-analyst",
            creator_subject=creator_subject,
            state="active",
            turn_count=1,
            cumulative_tokens=0,
            turn_in_progress=False,
            created_at=datetime.now(UTC),
        )
    )


def _seed_turn(
    conn: sa.Connection,
    *,
    turn_id: uuid.UUID,
    conversation_id: uuid.UUID,
    seq: int = 1,
    agent_run_id: str = "agent-run-0016",
) -> None:
    conn.execute(
        sa.insert(_turns_t).values(
            turn_id=turn_id,
            conversation_id=conversation_id,
            seq=seq,
            user_message="q",
            answer="a",
            agent_run_id=agent_run_id,
            prompt_tokens=1,
            completion_tokens=1,
            created_at=datetime.now(UTC),
        )
    )


_SEQ_COUNTER = iter(range(900_000, 999_999))


def _seed_chain_row(
    conn: sa.Connection,
    *,
    request_id: str,
    payload: Any,
    tenant_id: str = _TENANT,
    event_type: str = "conversation.turn_completed",
) -> None:
    seq = next(_SEQ_COUNTER)
    conn.execute(
        sa.insert(_dh_t).values(
            record_id=uuid.uuid4(),
            sequence=seq,
            schema_version=1,
            tenant_id=tenant_id,
            prev_hash=seq.to_bytes(32, "big"),
            hash=(seq + 100_000).to_bytes(32, "big"),
            created_at=datetime.now(UTC),
            event_type=event_type,
            request_id=request_id,
            payload=payload,  # dict/list/str pass through GovernanceJSON as-is
        )
    )


def _valid_payload(
    turn_id: uuid.UUID,
    conversation_id: uuid.UUID,
    *,
    seq: int = 1,
    agent_run_id: str = "agent-run-0016",
    actor_id: str = _CREATOR,
) -> dict[str, Any]:
    return {
        "conversation_id": str(conversation_id),
        "turn_id": str(turn_id),
        "seq": seq,
        "agent_run_id": agent_run_id,
        "actor_id": actor_id,
        "question_sha256": "0" * 64,
        "question_bytes": 1,
        "answer_sha256": "1" * 64,
        "answer_bytes": 1,
        "prompt_tokens": 1,
        "completion_tokens": 1,
    }


def _seeded_0015(tmp_path: Any, name: str) -> tuple[str, sa.Engine, uuid.UUID, uuid.UUID, str]:
    """Upgrade to 0015, seed one conversation + turn + matching chain row.

    Returns (url, engine, conversation_id, turn_id, request_id).
    """
    url = _sqlite_url(tmp_path, name)
    _upgrade(url, "0015")
    engine = sa.create_engine(url)
    conversation_id, turn_id = uuid.uuid4(), uuid.uuid4()
    request_id = f"conv-turn-{uuid.uuid4().hex}"
    with engine.begin() as conn:
        _seed_conversation(conn, conversation_id)
        _seed_turn(conn, turn_id=turn_id, conversation_id=conversation_id)
        _seed_chain_row(
            conn, request_id=request_id, payload=_valid_payload(turn_id, conversation_id)
        )
    return url, engine, conversation_id, turn_id, request_id


# ---------------------------------------------------------------------------
# Shape pins (fresh head)
# ---------------------------------------------------------------------------


def test_head_shape_column_constraint_and_indexes(tmp_path: Any) -> None:
    url = _sqlite_url(tmp_path, "shape.db")
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    insp = sa.inspect(engine)
    cols = {c["name"]: c for c in insp.get_columns("conversation_turns")}
    assert _COLUMN in cols
    assert cols[_COLUMN]["nullable"] is False
    assert _UQ in {u["name"] for u in insp.get_unique_constraints("conversation_turns")}
    assert _IX_DH in {i["name"] for i in insp.get_indexes("decision_history")}
    ix_conv = {i["name"]: i for i in insp.get_indexes("conversations")}
    assert _IX_CONV in ix_conv
    # The keyset tiebreaker column is IN the index (review finding 5).
    assert ix_conv[_IX_CONV]["column_names"] == [
        "tenant_id",
        "creator_subject",
        "created_at",
        "conversation_id",
    ]
    engine.dispose()


def test_dh_index_columns_match_the_window_query(tmp_path: Any) -> None:
    url = _sqlite_url(tmp_path, "dhix.db")
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    ix = {i["name"]: i for i in sa.inspect(engine).get_indexes("decision_history")}
    assert ix[_IX_DH]["column_names"] == ["tenant_id", "event_type", "sequence"]
    engine.dispose()


# ---------------------------------------------------------------------------
# Seeded backfill — happy path + idempotent reruns
# ---------------------------------------------------------------------------


def test_seeded_backfill_fills_and_enforces(tmp_path: Any) -> None:
    url, engine, _cid, turn_id, request_id = _seeded_0015(tmp_path, "bf.db")
    _upgrade(url, "head")
    with engine.connect() as conn:
        row = conn.execute(
            sa.select(_turns_t.c[_COLUMN]).where(_turns_t.c.turn_id == turn_id)
        ).one()
    assert row[0] == request_id
    insp = sa.inspect(engine)
    assert {c["name"]: c for c in insp.get_columns("conversation_turns")}[_COLUMN][
        "nullable"
    ] is False
    engine.dispose()


def test_unstamped_partial_state_rerun_completes(tmp_path: Any) -> None:
    """The Oracle posture: DDL autocommits, so a failure after add_column
    leaves an unstamped partial state. Simulate it (column added + backfill
    done, nothing stamped past 0015) and prove a plain upgrade completes."""
    url, engine, _cid, _turn_id, request_id = _seeded_0015(tmp_path, "partial.db")
    with engine.begin() as conn:
        conn.execute(sa.text(f"ALTER TABLE conversation_turns ADD COLUMN {_COLUMN} VARCHAR(64)"))
        conn.execute(
            sa.text(f"UPDATE conversation_turns SET {_COLUMN} = :rid"),
            {"rid": request_id},
        )
    _upgrade(url, "head")  # must guard every step and finish cleanly
    insp = sa.inspect(engine)
    cols = {c["name"]: c for c in insp.get_columns("conversation_turns")}
    assert cols[_COLUMN]["nullable"] is False
    assert _UQ in {u["name"] for u in insp.get_unique_constraints("conversation_turns")}
    engine.dispose()


def test_downgrade_removes_derived_column_and_indexes_only(tmp_path: Any) -> None:
    """Downgrade removes the DERIVED lookup column while preserving the
    source evidence — the chain row survives and stays reconstructable."""
    url, engine, _cid, _turn_id, request_id = _seeded_0015(tmp_path, "down.db")
    _upgrade(url, "head")
    _downgrade(url, "0015")
    insp = sa.inspect(engine)
    assert _COLUMN not in {c["name"] for c in insp.get_columns("conversation_turns")}
    assert _IX_DH not in {i["name"] for i in insp.get_indexes("decision_history")}
    assert _IX_CONV not in {i["name"] for i in insp.get_indexes("conversations")}
    with engine.connect() as conn:
        kept = conn.execute(
            sa.select(sa.func.count()).select_from(_dh_t).where(_dh_t.c.request_id == request_id)
        ).scalar_one()
    assert kept == 1  # the source evidence is preserved
    # And the round trip re-upgrades cleanly (re-runnable backfill).
    _upgrade(url, "head")
    engine.dispose()


# ---------------------------------------------------------------------------
# Backfill failure classes — each aborts BEFORE non-null enforcement
# ---------------------------------------------------------------------------


def _expect_backfill_failure(url: str, engine: sa.Engine, failure_class: str) -> None:
    with pytest.raises(Exception, match=f"0016 backfill: {failure_class}"):
        _upgrade(url, "head")
    # Fail-loud means NOT stamped and non-null NOT enforced.
    cols = {c["name"]: c for c in sa.inspect(engine).get_columns("conversation_turns")}
    assert _COLUMN not in cols or cols[_COLUMN]["nullable"] is True


def test_backfill_fails_on_orphan_turn(tmp_path: Any) -> None:
    url = _sqlite_url(tmp_path, "orphan_turn.db")
    _upgrade(url, "0015")
    engine = sa.create_engine(url)
    cid, tid = uuid.uuid4(), uuid.uuid4()
    with engine.begin() as conn:
        _seed_conversation(conn, cid)
        _seed_turn(conn, turn_id=tid, conversation_id=cid)
        # no chain row at all
    _expect_backfill_failure(url, engine, "orphan turn")
    engine.dispose()


def test_backfill_fails_on_orphan_chain_row(tmp_path: Any) -> None:
    url, engine, cid, _tid, _rid = _seeded_0015(tmp_path, "orphan_chain.db")
    with engine.begin() as conn:
        _seed_chain_row(
            conn,
            request_id=f"conv-turn-{uuid.uuid4().hex}",
            payload=_valid_payload(uuid.uuid4(), cid),  # unknown turn_id
        )
    _expect_backfill_failure(url, engine, "orphan chain row")
    engine.dispose()


def test_backfill_fails_on_duplicate_turn_claim(tmp_path: Any) -> None:
    url, engine, cid, tid, _rid = _seeded_0015(tmp_path, "dup_claim.db")
    with engine.begin() as conn:
        _seed_chain_row(
            conn,
            request_id=f"conv-turn-{uuid.uuid4().hex}",
            payload=_valid_payload(tid, cid),  # second claim on the same turn
        )
    _expect_backfill_failure(url, engine, "duplicate turn claim")
    engine.dispose()


def test_backfill_fails_on_duplicate_request_id(tmp_path: Any) -> None:
    url, engine, cid, _tid, rid = _seeded_0015(tmp_path, "dup_rid.db")
    tid2 = uuid.uuid4()
    with engine.begin() as conn:
        _seed_turn(conn, turn_id=tid2, conversation_id=cid, seq=2)
        _seed_chain_row(
            conn,
            request_id=rid,  # SAME request id claiming a different turn
            payload=_valid_payload(tid2, cid, seq=2),
        )
    _expect_backfill_failure(url, engine, "duplicate request_id")
    engine.dispose()


@pytest.mark.parametrize(
    ("mutation", "failure_class"),
    [
        ({"seq": 99}, "field mismatch"),
        ({"agent_run_id": "agent-run-WRONG"}, "field mismatch"),
        ({"actor_id": "somebody.else"}, "field mismatch"),
        ({"conversation_id": str(uuid.uuid4())}, "field mismatch"),
    ],
)
def test_backfill_fails_on_field_mismatch(
    tmp_path: Any, mutation: dict[str, Any], failure_class: str
) -> None:
    url = _sqlite_url(tmp_path, f"mm_{next(iter(mutation))}.db")
    _upgrade(url, "0015")
    engine = sa.create_engine(url)
    cid, tid = uuid.uuid4(), uuid.uuid4()
    payload = _valid_payload(tid, cid)
    payload.update(mutation)
    with engine.begin() as conn:
        _seed_conversation(conn, cid)
        _seed_turn(conn, turn_id=tid, conversation_id=cid)
        _seed_chain_row(
            conn,
            request_id=f"conv-turn-{uuid.uuid4().hex}",
            payload=payload,
        )
    _expect_backfill_failure(url, engine, failure_class)
    engine.dispose()


def test_backfill_fails_on_tenant_mismatch(tmp_path: Any) -> None:
    url = _sqlite_url(tmp_path, "mm_tenant.db")
    _upgrade(url, "0015")
    engine = sa.create_engine(url)
    cid, tid = uuid.uuid4(), uuid.uuid4()
    with engine.begin() as conn:
        _seed_conversation(conn, cid)
        _seed_turn(conn, turn_id=tid, conversation_id=cid)
        _seed_chain_row(
            conn,
            request_id=f"conv-turn-{uuid.uuid4().hex}",
            payload=_valid_payload(tid, cid),
            tenant_id="other-tenant",  # chain row column disagrees
        )
    _expect_backfill_failure(url, engine, "field mismatch")
    engine.dispose()


@pytest.mark.parametrize(
    ("raw_payload", "case"),
    [
        ("{not json", "unparseable"),
        (["not", "an", "object"], "non-object"),
        ({"turn_id": "x"}, "missing keys"),
        (None, "seq-type"),  # filled in below: seq as string
    ],
)
def test_backfill_fails_on_malformed_payload(tmp_path: Any, raw_payload: Any, case: str) -> None:
    """Malformed/missing payload fields are an EXPLICIT failure class
    (maintainer precision lock, 2026-07-10)."""
    url = _sqlite_url(tmp_path, f"mal_{case.replace(' ', '_').replace('-', '_')}.db")
    _upgrade(url, "0015")
    engine = sa.create_engine(url)
    cid, tid = uuid.uuid4(), uuid.uuid4()
    if raw_payload is None:
        bad = _valid_payload(tid, cid)
        bad["seq"] = "1"  # wrong type
        raw_payload = bad
    with engine.begin() as conn:
        _seed_conversation(conn, cid)
        _seed_turn(conn, turn_id=tid, conversation_id=cid)
        _seed_chain_row(
            conn,
            request_id=f"conv-turn-{uuid.uuid4().hex}",
            payload=raw_payload,
        )
    _expect_backfill_failure(url, engine, "malformed payload")
    engine.dispose()


def test_prefilled_disagreement_fails_as_field_mismatch(tmp_path: Any) -> None:
    """A partial-state rerun whose pre-filled value disagrees with the chain
    is corruption, never silently overwritten."""
    url, engine, _cid, _tid, _rid = _seeded_0015(tmp_path, "prefill.db")
    with engine.begin() as conn:
        conn.execute(sa.text(f"ALTER TABLE conversation_turns ADD COLUMN {_COLUMN} VARCHAR(64)"))
        conn.execute(sa.text(f"UPDATE conversation_turns SET {_COLUMN} = 'conv-turn-WRONG'"))
    _expect_backfill_failure(url, engine, "field mismatch")
    engine.dispose()


def test_empty_schema_upgrade_is_clean(tmp_path: Any) -> None:
    """Fresh deploys: zero turns -> backfill no-ops -> constraints apply."""
    url = _sqlite_url(tmp_path, "empty.db")
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    cols = {c["name"]: c for c in sa.inspect(engine).get_columns("conversation_turns")}
    assert cols[_COLUMN]["nullable"] is False
    engine.dispose()


def test_backfill_fails_on_identical_duplicate_chain_row(tmp_path: Any) -> None:
    """An IDENTICAL duplicate (same request_id AND same turn_id) violates the
    exactly-one invariant just as a diverging one does — the earlier guards
    only fired on divergence (review finding, 2026-07-10)."""
    url, engine, cid, tid, rid = _seeded_0015(tmp_path, "dup_identical.db")
    with engine.begin() as conn:
        _seed_chain_row(conn, request_id=rid, payload=_valid_payload(tid, cid))
    _expect_backfill_failure(url, engine, "duplicate turn claim")
    engine.dispose()


def test_fully_applied_unstamped_rerun_completes(tmp_path: Any) -> None:
    """The COMPLETE partial state: every 0016 object applied (non-null column,
    unique constraint, both indexes) but alembic_version rewound to 0015 — the
    plain re-run must shape-validate each existing object and no-op cleanly."""
    url, engine, _cid, turn_id, request_id = _seeded_0015(tmp_path, "fullrerun.db")
    _upgrade(url, "head")  # fully applied + stamped 0016
    with engine.begin() as conn:
        conn.execute(sa.text("UPDATE alembic_version SET version_num = '0015'"))
    _upgrade(url, "head")  # over the fully-applied objects
    insp = sa.inspect(engine)
    cols = {c["name"]: c for c in insp.get_columns("conversation_turns")}
    assert cols[_COLUMN]["nullable"] is False
    assert _UQ in {u["name"] for u in insp.get_unique_constraints("conversation_turns")}
    assert _IX_DH in {i["name"] for i in insp.get_indexes("decision_history")}
    assert _IX_CONV in {i["name"] for i in insp.get_indexes("conversations")}
    with engine.connect() as conn:
        value = conn.execute(
            sa.select(_turns_t.c[_COLUMN]).where(_turns_t.c.turn_id == turn_id)
        ).scalar_one()
    assert value == request_id
    engine.dispose()


def test_upgrade_fails_loud_on_wrong_shaped_existing_index(tmp_path: Any) -> None:
    """A pre-existing object with the RIGHT NAME but the WRONG shape is a
    hazard, not a no-op: the guard must shape-validate before skipping."""
    url = _sqlite_url(tmp_path, "wrongshape.db")
    _upgrade(url, "0015")
    engine = sa.create_engine(url)
    with engine.begin() as conn:
        # Right name, wrong columns (missing the sequence column).
        conn.execute(sa.text(f"CREATE INDEX {_IX_DH} ON decision_history (tenant_id, event_type)"))
    with pytest.raises(Exception, match="0016 ddl: existing object shape mismatch"):
        _upgrade(url, "head")
    engine.dispose()


def test_in_process_metadata_parity_with_migrated_unique_constraint(tmp_path: Any) -> None:
    """create_all fixtures must enforce EXACTLY what migrated deployments do
    (review finding, 2026-07-10): the in-process Table carries the same named
    unique constraint over the same column as migration 0016."""
    from cognic_agentos.core.conversation.storage import _conversation_turns

    in_process = {
        c.name: sorted(col.name for col in c.columns)
        for c in _conversation_turns.constraints
        if isinstance(c, sa.UniqueConstraint) and c.name
    }
    assert in_process.get(_UQ) == [_COLUMN]

    url = _sqlite_url(tmp_path, "parity.db")
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    migrated = {
        u["name"]: sorted(u["column_names"])
        for u in sa.inspect(engine).get_unique_constraints("conversation_turns")
    }
    assert migrated.get(_UQ) == [_COLUMN]
    engine.dispose()


def test_upgrade_fails_loud_on_wrong_length_existing_column(tmp_path: Any) -> None:
    """A pre-existing correlation column with the RIGHT NAME but the WRONG
    length must fail the shape guard, never no-op (migrations sit OUTSIDE the
    CC coverage gate — the guard arms need their own pins)."""
    url = _sqlite_url(tmp_path, "wronglen.db")
    _upgrade(url, "0015")
    engine = sa.create_engine(url)
    with engine.begin() as conn:
        conn.execute(sa.text(f"ALTER TABLE conversation_turns ADD COLUMN {_COLUMN} VARCHAR(32)"))
    with pytest.raises(Exception, match="0016 ddl: existing object shape mismatch"):
        _upgrade(url, "head")
    engine.dispose()


def test_upgrade_fails_loud_on_unique_posture_existing_index(tmp_path: Any) -> None:
    """Right name, right columns, but UNIQUE — that violates the required
    NON-UNIQUE query-index contract (uniqueness is a semantic the reader
    never relies on here; ``decision_history.sequence`` is already globally
    unique on its own); the guard must refuse the wrong posture."""
    url = _sqlite_url(tmp_path, "uqposture.db")
    _upgrade(url, "0015")
    engine = sa.create_engine(url)
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                f"CREATE UNIQUE INDEX {_IX_DH} ON decision_history "
                "(tenant_id, event_type, sequence)"
            )
        )
    with pytest.raises(Exception, match="0016 ddl: existing object shape mismatch"):
        _upgrade(url, "head")
    engine.dispose()


def test_uq_shape_guard_rejects_wrong_columns() -> None:
    """The wrong-columns unique-constraint case, tested through the EXACT
    guard upgrade() runs (``_validate_uq_shape``): SQLite cannot express a
    post-hoc table-level UNIQUE, so an end-to-end seeding of this partial
    state is not portable — the extracted helper is the production logic."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "migration_0016_under_test",
        Path(__file__).resolve().parents[3]
        / "src/cognic_agentos/db/migrations/versions/20260710_0016_conversation_read_model.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # Correct shape: no-op.
    module._validate_uq_shape({_UQ: {"column_names": [_COLUMN]}})
    # Absent: no-op (the create path handles it).
    module._validate_uq_shape({})
    # Wrong columns under the right name: fail loud.
    with pytest.raises(RuntimeError, match="0016 ddl: existing object shape mismatch"):
        module._validate_uq_shape({_UQ: {"column_names": ["seq"]}})


# ---------------------------------------------------------------------------
# Oracle function-based-index reflection (the SYS_EXTRACT_UTC shape)
# ---------------------------------------------------------------------------
# ``ix_conversations_tenant_creator_created`` covers ``created_at`` (a ``TIMESTAMP
# WITH TIME ZONE`` column); Oracle indexes it as a function-based index on
# ``SYS_EXTRACT_UTC("COL")`` (column_names[i]=None + the expression under
# expressions[i]). These pins run WITHOUT a live database — the fixture IS the
# shape OBSERVED against live Oracle XE 21 + SQLAlchemy 2.0.49 (byte-coupled to
# reality). The guard-on-existing-index integration on the real Oracle reflection
# is closed by tests/integration/db/test_alembic_migrations.py
# ::test_oracle_0016_conv_index_rerun (0016's guard takes a live Inspector). The
# sibling 0017 pins live in tests/unit/db/test_migration_20260711_0017.py.
_MIGRATION_0016 = "cognic_agentos.db.migrations.versions.20260710_0016_conversation_read_model"
_IX_CONV_COLUMNS = ["tenant_id", "creator_subject", "created_at", "conversation_id"]
_ORACLE_IX_CONV_REFLECTION: dict[str, Any] = {
    "name": _IX_CONV,
    "column_names": ["tenant_id", "creator_subject", None, "conversation_id"],
    "expressions": [
        "tenant_id",
        "creator_subject",
        'SYS_EXTRACT_UTC("CREATED_AT")',
        "conversation_id",
    ],
    "unique": False,
}


def test_resolved_columns_maps_oracle_conv_index_to_plain_columns() -> None:
    # The observed Oracle reflection of the TSTZ-bearing index resolves back to
    # the plain column identity the guard compares against.
    mod = importlib.import_module(_MIGRATION_0016)
    assert mod._resolved_columns(_ORACLE_IX_CONV_REFLECTION) == _IX_CONV_COLUMNS


def test_resolved_columns_is_identity_on_plain_conv_names() -> None:
    # Postgres / SQLite path: column_names fully populated, expressions unused.
    mod = importlib.import_module(_MIGRATION_0016)
    plain = {"name": _IX_CONV, "column_names": list(_IX_CONV_COLUMNS), "expressions": None}
    assert mod._resolved_columns(plain) == _IX_CONV_COLUMNS


def test_resolved_columns_fails_loud_on_conv_non_normalization_expression() -> None:
    # A None-position expression that is NOT the expected SYS_EXTRACT_UTC(col)
    # normalisation must fail loud, not be silently accepted as its column.
    mod = importlib.import_module(_MIGRATION_0016)
    weird = {
        **_ORACLE_IX_CONV_REFLECTION,
        "expressions": ["tenant_id", "creator_subject", 'LOWER("CREATED_AT")', "conversation_id"],
    }
    with pytest.raises(RuntimeError, match="0016 ddl: existing object shape mismatch"):
        mod._resolved_columns(weird)
