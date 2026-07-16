from __future__ import annotations

import importlib
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command

from cognic_agentos.db.migrations.alembic_config import make_alembic_config
from cognic_agentos.db.types import GovernanceJSON

MIGRATION = "cognic_agentos.db.migrations.versions.20260716_0018_approval_assignment_ledger"
ASSIGNMENTS = "approval_assignments"
DECISIONS = "approval_decisions"
NEW_REQUEST_COLUMNS = {
    "required_count",
    "eligible_approvers",
    "decisions_recorded",
    "consumed_at",
    "consumed_by",
}


def _sqlite_url(tmp_path: Any, name: str) -> str:
    return f"sqlite:///{tmp_path / name}"


def _async_url(url: str) -> str:
    return url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)


def _upgrade(url: str, revision: str) -> None:
    command.upgrade(make_alembic_config(_async_url(url)), revision)


def _downgrade(url: str, revision: str) -> None:
    command.downgrade(make_alembic_config(_async_url(url)), revision)


def _stamp(url: str, revision: str) -> None:
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text("UPDATE alembic_version SET version_num = :revision"),
                {"revision": revision},
            )
    finally:
        engine.dispose()


def _inspect(url: str) -> tuple[set[str], dict[str, Any]]:
    engine = sa.create_engine(url)
    try:
        inspector = sa.inspect(engine)
        tables = set(inspector.get_table_names())
        columns = {table: inspector.get_columns(table) for table in tables}
        return tables, columns
    finally:
        engine.dispose()


_requests = sa.table(
    "approval_requests",
    sa.column("request_id", sa.Uuid()),
    sa.column("tenant_id", sa.String(128)),
    sa.column("flow", sa.String(32)),
    sa.column("risk_tier", sa.String(32)),
    sa.column("tool_identity", sa.String(256)),
    sa.column("originator_subject", sa.String(256)),
    sa.column("state", sa.String(16)),
    sa.column("first_approver", sa.String(256)),
    sa.column("second_approver", sa.String(256)),
    sa.column("denier", sa.String(256)),
    sa.column("envelope_digest", sa.LargeBinary()),
    sa.column("args_digest", sa.LargeBinary()),
    sa.column("redacted_context", sa.Text()),
    sa.column("data_classes", GovernanceJSON()),
    sa.column("required_refs", GovernanceJSON()),
    sa.column("created_at", sa.TIMESTAMP(timezone=True)),
    sa.column("expires_at", sa.TIMESTAMP(timezone=True)),
    sa.column("updated_at", sa.TIMESTAMP(timezone=True)),
)


def _seed_request(
    url: str,
    *,
    flow: str,
    first: str | None,
    second: str | None,
) -> uuid.UUID:
    request_id = uuid.uuid4()
    now = datetime(2026, 7, 16, 10, 0, tzinfo=UTC)
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(
                _requests.insert().values(
                    request_id=request_id,
                    tenant_id="t1",
                    flow=flow,
                    risk_tier="payment_action",
                    tool_identity="s/probe_write",
                    originator_subject="analyst.amir",
                    state="pending",
                    first_approver=first,
                    second_approver=second,
                    denier=None,
                    envelope_digest=b"\x01" * 32,
                    args_digest=b"\x02" * 32,
                    redacted_context="{}",
                    data_classes=[],
                    required_refs={},
                    created_at=now,
                    expires_at=now,
                    updated_at=now,
                )
            )
    finally:
        engine.dispose()
    return request_id


def test_revision_wiring() -> None:
    migration = importlib.import_module(MIGRATION)
    assert migration.revision == "0018"
    assert migration.down_revision == "0017"


def test_upgrade_creates_exact_phase_a_shape(tmp_path: Any) -> None:
    url = _sqlite_url(tmp_path, "shape.sqlite")
    _upgrade(url, "head")
    tables, columns = _inspect(url)
    assert {ASSIGNMENTS, DECISIONS} <= tables
    assert {column["name"] for column in columns[ASSIGNMENTS]} == {
        "tenant_id",
        "tool_identity",
        "approver_subjects",
        "updated_by",
        "updated_at",
    }
    assert {column["name"] for column in columns[DECISIONS]} == {
        "request_id",
        "decision_index",
        "tenant_id",
        "approver_subject",
        "reason",
        "decided_at",
    }
    assert {column["name"] for column in columns["approval_requests"]} >= NEW_REQUEST_COLUMNS
    required = next(
        column for column in columns["approval_requests"] if column["name"] == "required_count"
    )
    assert required["nullable"] is True

    engine = sa.create_engine(url)
    try:
        inspector = sa.inspect(engine)
        assert inspector.get_pk_constraint(ASSIGNMENTS)["constrained_columns"] == [
            "tenant_id",
            "tool_identity",
        ]
        assert inspector.get_pk_constraint(DECISIONS)["constrained_columns"] == [
            "request_id",
            "decision_index",
        ]
        uniques = {
            unique["name"]: unique["column_names"]
            for unique in inspector.get_unique_constraints(DECISIONS)
        }
        assert uniques["uq_approval_decisions_request_approver"] == [
            "request_id",
            "approver_subject",
        ]
    finally:
        engine.dispose()


def test_upgrade_backfills_legacy_counts(tmp_path: Any) -> None:
    url = _sqlite_url(tmp_path, "backfill.sqlite")
    _upgrade(url, "0017")
    single = _seed_request(url, flow="require_single_approval", first="reviewer.dana", second=None)
    four = _seed_request(url, flow="require_4_eyes", first="reviewer.dana", second="reviewer.erin")
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                sa.text(
                    "SELECT request_id, required_count, decisions_recorded "
                    "FROM approval_requests ORDER BY required_count"
                )
            ).all()
        by_id = {
            str(uuid.UUID(str(row.request_id))): (row.required_count, row.decisions_recorded)
            for row in rows
        }
        assert by_id[str(single)] == (1, 1)
        assert by_id[str(four)] == (2, 2)
    finally:
        engine.dispose()


def test_upgrade_fails_loud_on_unbackfillable_legacy_flow(tmp_path: Any) -> None:
    url = _sqlite_url(tmp_path, "bad-backfill.sqlite")
    _upgrade(url, "0017")
    _seed_request(url, flow="unexpected_flow", first=None, second=None)
    with pytest.raises(RuntimeError, match="0018 backfill: required_count remains NULL"):
        _upgrade(url, "head")


def test_fully_applied_rerun_is_idempotent(tmp_path: Any) -> None:
    url = _sqlite_url(tmp_path, "rerun.sqlite")
    _upgrade(url, "head")
    _stamp(url, "0017")
    _upgrade(url, "head")
    tables, _ = _inspect(url)
    assert {ASSIGNMENTS, DECISIONS} <= tables


def test_partial_state_rerun_recreates_missing_table(tmp_path: Any) -> None:
    url = _sqlite_url(tmp_path, "partial.sqlite")
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(sa.text("DROP TABLE approval_decisions"))
    finally:
        engine.dispose()
    _stamp(url, "0017")
    _upgrade(url, "head")
    assert DECISIONS in _inspect(url)[0]


def test_guard_fails_loud_on_wrong_shaped_existing_table(tmp_path: Any) -> None:
    url = _sqlite_url(tmp_path, "wrong-table.sqlite")
    _upgrade(url, "0017")
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "CREATE TABLE approval_assignments "
                    "(tenant_id VARCHAR(128) PRIMARY KEY, tool_identity VARCHAR(256))"
                )
            )
    finally:
        engine.dispose()
    with pytest.raises(RuntimeError, match="0018 ddl: existing object shape mismatch"):
        _upgrade(url, "head")


@pytest.mark.parametrize(
    "ddl",
    [
        "ALTER TABLE approval_requests ADD COLUMN required_count TEXT",
        "ALTER TABLE approval_requests ADD COLUMN eligible_approvers TEXT NOT NULL DEFAULT '[]'",
        "ALTER TABLE approval_requests ADD COLUMN decisions_recorded TEXT NOT NULL DEFAULT '0'",
        "ALTER TABLE approval_requests ADD COLUMN consumed_at INTEGER",
        "ALTER TABLE approval_requests ADD COLUMN consumed_by VARCHAR(32)",
    ],
    ids=[
        "required-count-type",
        "eligible-approvers-nullability",
        "decisions-recorded-type",
        "consumed-at-type",
        "consumed-by-length",
    ],
)
def test_guard_fails_loud_on_wrong_shaped_existing_column(tmp_path: Any, ddl: str) -> None:
    url = _sqlite_url(tmp_path, "wrong-column.sqlite")
    _upgrade(url, "0017")
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(sa.text(ddl))
    finally:
        engine.dispose()
    with pytest.raises(RuntimeError, match="0018 ddl: existing object shape mismatch"):
        _upgrade(url, "head")


def test_guard_fails_loud_when_decision_unique_constraint_is_missing(tmp_path: Any) -> None:
    url = _sqlite_url(tmp_path, "missing-uq.sqlite")
    _upgrade(url, "0017")
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "CREATE TABLE approval_decisions ("
                    "request_id CHAR(32) NOT NULL, decision_index INTEGER NOT NULL, "
                    "tenant_id VARCHAR(128) NOT NULL, "
                    "approver_subject VARCHAR(256) NOT NULL, reason TEXT, "
                    "decided_at TIMESTAMP NOT NULL, "
                    "PRIMARY KEY (request_id, decision_index))"
                )
            )
    finally:
        engine.dispose()
    with pytest.raises(RuntimeError, match="0018 ddl: existing object shape mismatch"):
        _upgrade(url, "head")


def test_downgrade_removes_only_phase_a_schema_and_preserves_requests(tmp_path: Any) -> None:
    url = _sqlite_url(tmp_path, "downgrade.sqlite")
    _upgrade(url, "0017")
    request_id = _seed_request(url, flow="require_single_approval", first=None, second=None)
    _upgrade(url, "head")
    _downgrade(url, "0017")
    tables, columns = _inspect(url)
    assert ASSIGNMENTS not in tables and DECISIONS not in tables
    assert NEW_REQUEST_COLUMNS.isdisjoint(
        {column["name"] for column in columns["approval_requests"]}
    )
    engine = sa.create_engine(url)
    try:
        with engine.connect() as conn:
            assert conn.execute(
                sa.select(_requests.c.request_id).where(_requests.c.request_id == request_id)
            ).first()
    finally:
        engine.dispose()
    _upgrade(url, "head")
    assert {ASSIGNMENTS, DECISIONS} <= _inspect(url)[0]


def test_assignment_runtime_table_matches_migration(tmp_path: Any) -> None:
    from cognic_agentos.core.approval.assignments import _approval_assignments

    url = _sqlite_url(tmp_path, "parity.sqlite")
    _upgrade(url, "head")
    _, columns = _inspect(url)
    assert {column["name"] for column in columns[ASSIGNMENTS]} == {
        column.name for column in _approval_assignments.columns
    }
