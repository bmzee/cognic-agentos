"""Approval assignment + N-way decision ledger (M8.5-D D2 phase A).

The revision creates the bank-owned assignment table and the per-request
decision ledger, then adds the progress and future consumption columns to
``approval_requests``. Existing single-approval and four-eyes rows are
backfilled into the generalized count contract. Every DDL step is guarded and
shape-validated so an unstamped Oracle partial application can be rerun safely;
a same-named object with a different shape fails loud.

Revision ID: 0018
Revises: 0017
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NoReturn

import sqlalchemy as sa
from alembic import op

from cognic_agentos.db.types import GovernanceJSON

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | None = None
depends_on: str | None = None

_ASSIGNMENTS = "approval_assignments"
_DECISIONS = "approval_decisions"
_REQUESTS = "approval_requests"
_DECISION_UQ = "uq_approval_decisions_request_approver"


def _fail_ddl(detail: str) -> NoReturn:
    raise RuntimeError(f"0018 ddl: existing object shape mismatch — {detail}")


def _columns(inspector: sa.Inspector, table: str) -> dict[str, Mapping[str, Any]]:
    return {str(column["name"]): column for column in inspector.get_columns(table)}


def _is_uuid_type(column_type: Any) -> bool:
    return isinstance(column_type, sa.Uuid) or (
        isinstance(column_type, sa.CHAR) and column_type.length == 32
    )


def _type_matches(column_type: Any, family: str, length: int | None = None) -> bool:
    if family == "string":
        return isinstance(column_type, sa.String) and column_type.length == length
    if family == "integer":
        return isinstance(column_type, sa.Integer)
    if family == "timestamp":
        return isinstance(column_type, (sa.TIMESTAMP, sa.DateTime))
    if family == "json":
        return isinstance(column_type, (sa.JSON, sa.Text, sa.CLOB))
    if family == "uuid":
        return _is_uuid_type(column_type)
    raise AssertionError(f"unknown migration type family {family!r}")


def _validate_column(
    column: Mapping[str, Any],
    *,
    table: str,
    family: str,
    nullable: bool,
    length: int | None = None,
) -> None:
    name = str(column["name"])
    if not _type_matches(column["type"], family, length):
        _fail_ddl(f"{table}.{name} has incompatible type {column['type']!r}")
    if bool(column["nullable"]) is not nullable:
        _fail_ddl(f"{table}.{name} nullable={column['nullable']!r}, expected {nullable}")


def _validate_table(
    inspector: sa.Inspector,
    *,
    table: str,
    expected: Mapping[str, tuple[str, bool, int | None]],
    primary_key: list[str],
) -> None:
    reflected = _columns(inspector, table)
    if set(reflected) != set(expected):
        _fail_ddl(f"{table} columns {sorted(reflected)!r}, expected {sorted(expected)!r}")
    for name, (family, nullable, length) in expected.items():
        _validate_column(
            reflected[name],
            table=table,
            family=family,
            nullable=nullable,
            length=length,
        )
    actual_pk = list(inspector.get_pk_constraint(table).get("constrained_columns") or [])
    if actual_pk != primary_key:
        _fail_ddl(f"{table} primary key {actual_pk!r}, expected {primary_key!r}")


def _ensure_tables() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    if _ASSIGNMENTS not in tables:
        op.create_table(
            _ASSIGNMENTS,
            sa.Column("tenant_id", sa.String(128), primary_key=True),
            sa.Column("tool_identity", sa.String(256), primary_key=True),
            sa.Column("approver_subjects", GovernanceJSON(), nullable=False),
            sa.Column("updated_by", sa.String(256), nullable=False),
            sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
        )
    else:
        _validate_table(
            inspector,
            table=_ASSIGNMENTS,
            expected={
                "tenant_id": ("string", False, 128),
                "tool_identity": ("string", False, 256),
                "approver_subjects": ("json", False, None),
                "updated_by": ("string", False, 256),
                "updated_at": ("timestamp", False, None),
            },
            primary_key=["tenant_id", "tool_identity"],
        )

    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    if _DECISIONS not in tables:
        op.create_table(
            _DECISIONS,
            sa.Column("request_id", sa.Uuid(), primary_key=True),
            sa.Column("decision_index", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.String(128), nullable=False),
            sa.Column("approver_subject", sa.String(256), nullable=False),
            sa.Column("reason", sa.Text(), nullable=True),
            sa.Column("decided_at", sa.TIMESTAMP(timezone=True), nullable=False),
            sa.UniqueConstraint(
                "request_id",
                "approver_subject",
                name=_DECISION_UQ,
            ),
        )
    else:
        _validate_table(
            inspector,
            table=_DECISIONS,
            expected={
                "request_id": ("uuid", False, None),
                "decision_index": ("integer", False, None),
                "tenant_id": ("string", False, 128),
                "approver_subject": ("string", False, 256),
                "reason": ("string", True, None),
                "decided_at": ("timestamp", False, None),
            },
            primary_key=["request_id", "decision_index"],
        )
        uniques = {
            unique.get("name"): list(unique.get("column_names") or [])
            for unique in inspector.get_unique_constraints(_DECISIONS)
        }
        if uniques.get(_DECISION_UQ) != ["request_id", "approver_subject"]:
            _fail_ddl(
                f"{_DECISION_UQ} columns {uniques.get(_DECISION_UQ)!r}, "
                "expected ['request_id', 'approver_subject']"
            )


def _ensure_request_column(
    name: str,
    column: sa.Column[Any],
    *,
    family: str,
    nullable: bool,
    length: int | None = None,
) -> None:
    inspector = sa.inspect(op.get_bind())
    existing = _columns(inspector, _REQUESTS)
    if name not in existing:
        op.add_column(_REQUESTS, column)
        return
    _validate_column(
        existing[name],
        table=_REQUESTS,
        family=family,
        nullable=nullable,
        length=length,
    )


def _backfill() -> None:
    bind = op.get_bind()
    bind.execute(
        sa.text(
            "UPDATE approval_requests SET required_count = CASE flow "
            "WHEN 'require_single_approval' THEN 1 "
            "WHEN 'require_4_eyes' THEN 2 END "
            "WHERE required_count IS NULL"
        )
    )
    missing = bind.execute(
        sa.text("SELECT COUNT(*) FROM approval_requests WHERE required_count IS NULL")
    ).scalar_one()
    if int(missing) != 0:
        raise RuntimeError(
            f"0018 backfill: required_count remains NULL for {missing} approval request(s)"
        )
    bind.execute(
        sa.text(
            "UPDATE approval_requests SET decisions_recorded = "
            "(CASE WHEN first_approver IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN second_approver IS NOT NULL THEN 1 ELSE 0 END)"
        )
    )


def upgrade() -> None:
    _ensure_tables()
    _ensure_request_column(
        "required_count",
        sa.Column("required_count", sa.Integer(), nullable=True),
        family="integer",
        nullable=True,
    )
    _ensure_request_column(
        "eligible_approvers",
        sa.Column("eligible_approvers", GovernanceJSON(), nullable=True),
        family="json",
        nullable=True,
    )
    _ensure_request_column(
        "decisions_recorded",
        sa.Column(
            "decisions_recorded",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        family="integer",
        nullable=False,
    )
    _ensure_request_column(
        "consumed_at",
        sa.Column("consumed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        family="timestamp",
        nullable=True,
    )
    _ensure_request_column(
        "consumed_by",
        sa.Column("consumed_by", sa.String(64), nullable=True),
        family="string",
        nullable=True,
        length=64,
    )
    _backfill()


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing = _columns(inspector, _REQUESTS)
    drop_columns = [
        name
        for name in (
            "consumed_by",
            "consumed_at",
            "decisions_recorded",
            "eligible_approvers",
            "required_count",
        )
        if name in existing
    ]
    if drop_columns:
        with op.batch_alter_table(_REQUESTS) as batch:
            for name in drop_columns:
                batch.drop_column(name)

    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if _DECISIONS in tables:
        op.drop_table(_DECISIONS)
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if _ASSIGNMENTS in tables:
        op.drop_table(_ASSIGNMENTS)
