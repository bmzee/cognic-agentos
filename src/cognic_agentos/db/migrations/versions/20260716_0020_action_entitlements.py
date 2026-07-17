"""Action entitlements for governed-write dispatch (M8.5-D D2 phase C).

The table grants one subject authority to propose one exact tool action inside
one tenant. This guarded, rerunnable revision keeps action authority separate
from data-scope entitlements.

Revision ID: 0020
Revises: 0019
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NoReturn

import sqlalchemy as sa
from alembic import op

revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | None = None
depends_on: str | None = None

_TABLE = "action_entitlements"
_UQ = "uq_action_entitlements_tenant_subject_tool"
_INDEX = "ix_action_entitlements_tenant_subject"


def _fail_ddl(detail: str) -> NoReturn:
    raise RuntimeError(f"0020 ddl: existing object shape mismatch — {detail}")


def _is_uuid_type(column_type: Any) -> bool:
    return isinstance(column_type, sa.Uuid) or (
        isinstance(column_type, sa.CHAR) and column_type.length == 32
    )


def _validate_column(
    column: Mapping[str, Any],
    *,
    family: str,
    nullable: bool,
    length: int | None = None,
) -> None:
    column_type = column["type"]
    type_matches = (
        _is_uuid_type(column_type)
        if family == "uuid"
        else isinstance(column_type, sa.String) and column_type.length == length
        if family == "string"
        else isinstance(column_type, (sa.TIMESTAMP, sa.DateTime))
        if family == "timestamp"
        else False
    )
    if not type_matches:
        _fail_ddl(f"{_TABLE}.{column['name']} has incompatible type {column_type!r}")
    if bool(column["nullable"]) is not nullable:
        _fail_ddl(f"{_TABLE}.{column['name']} nullable={column['nullable']!r}, expected {nullable}")


def _validate_existing(inspector: sa.Inspector) -> None:
    expected: dict[str, tuple[str, bool, int | None]] = {
        "id": ("uuid", False, None),
        "tenant_id": ("string", False, 128),
        "subject": ("string", False, 256),
        "tool_identity": ("string", False, 256),
        "created_at": ("timestamp", False, None),
    }
    columns = {str(column["name"]): column for column in inspector.get_columns(_TABLE)}
    if set(columns) != set(expected):
        _fail_ddl(f"{_TABLE} columns {sorted(columns)!r}, expected {sorted(expected)!r}")
    for name, (family, nullable, length) in expected.items():
        _validate_column(columns[name], family=family, nullable=nullable, length=length)
    primary_key = list(inspector.get_pk_constraint(_TABLE).get("constrained_columns") or [])
    if primary_key != ["id"]:
        _fail_ddl(f"{_TABLE} primary key {primary_key!r}, expected ['id']")
    unique_constraints = {
        constraint.get("name"): list(constraint.get("column_names") or [])
        for constraint in inspector.get_unique_constraints(_TABLE)
    }
    expected_unique = ["tenant_id", "subject", "tool_identity"]
    if unique_constraints.get(_UQ) != expected_unique:
        _fail_ddl(f"{_UQ} has incompatible shape {unique_constraints.get(_UQ)!r}")
    indexes = {
        index.get("name"): (
            list(index.get("column_names") or []),
            bool(index.get("unique")),
        )
        for index in inspector.get_indexes(_TABLE)
    }
    expected_index = (["tenant_id", "subject"], False)
    if indexes.get(_INDEX) != expected_index:
        _fail_ddl(f"{_INDEX} has incompatible shape {indexes.get(_INDEX)!r}")


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if _TABLE in inspector.get_table_names():
        _validate_existing(inspector)
        return
    op.create_table(
        _TABLE,
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("subject", sa.String(256), nullable=False),
        sa.Column("tool_identity", sa.String(256), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id",
            "subject",
            "tool_identity",
            name=_UQ,
        ),
    )
    op.create_index(_INDEX, _TABLE, ["tenant_id", "subject"], unique=False)


def downgrade() -> None:
    if _TABLE in sa.inspect(op.get_bind()).get_table_names():
        op.drop_index(_INDEX, table_name=_TABLE)
        op.drop_table(_TABLE)
