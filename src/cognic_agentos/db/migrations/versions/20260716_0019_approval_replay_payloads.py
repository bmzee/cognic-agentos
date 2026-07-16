"""Approval replay-payload custody (M8.5-D D2 phase B).

The approval envelope stays value-free. This guarded, rerunnable revision
adds the separate erasable value table whose retained digests bind the exact
approved arguments and terminal result.

Revision ID: 0019
Revises: 0018
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NoReturn

import sqlalchemy as sa
from alembic import op

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | None = None
depends_on: str | None = None

_TABLE = "approval_replay_payloads"
_FK = "fk_approval_replay_payloads_request"


def _fail_ddl(detail: str) -> NoReturn:
    raise RuntimeError(f"0019 ddl: existing object shape mismatch — {detail}")


def _is_uuid_type(column_type: Any) -> bool:
    return isinstance(column_type, sa.Uuid) or (
        isinstance(column_type, sa.CHAR) and column_type.length == 32
    )


def _type_matches(column_type: Any, family: str, length: int | None = None) -> bool:
    if family == "uuid":
        return _is_uuid_type(column_type)
    if family == "string":
        return isinstance(column_type, sa.String) and column_type.length == length
    if family == "binary":
        return isinstance(column_type, (sa.LargeBinary, sa.BLOB))
    if family == "timestamp":
        return isinstance(column_type, (sa.TIMESTAMP, sa.DateTime))
    raise AssertionError(f"unknown migration type family {family!r}")


def _validate_column(
    column: Mapping[str, Any],
    *,
    family: str,
    nullable: bool,
    length: int | None = None,
) -> None:
    name = str(column["name"])
    if not _type_matches(column["type"], family, length):
        _fail_ddl(f"{_TABLE}.{name} has incompatible type {column['type']!r}")
    if bool(column["nullable"]) is not nullable:
        _fail_ddl(f"{_TABLE}.{name} nullable={column['nullable']!r}, expected {nullable}")


def _validate_existing(inspector: sa.Inspector) -> None:
    expected: dict[str, tuple[str, bool, int | None]] = {
        "request_id": ("uuid", False, None),
        "tenant_id": ("string", False, 128),
        "canonical_args": ("binary", True, None),
        "args_digest": ("binary", False, None),
        "result_canonical": ("binary", True, None),
        "result_digest": ("binary", True, None),
        "created_at": ("timestamp", False, None),
        "executed_at": ("timestamp", True, None),
        "erased_at": ("timestamp", True, None),
    }
    columns = {str(column["name"]): column for column in inspector.get_columns(_TABLE)}
    if set(columns) != set(expected):
        _fail_ddl(f"{_TABLE} columns {sorted(columns)!r}, expected {sorted(expected)!r}")
    for name, (family, nullable, length) in expected.items():
        _validate_column(columns[name], family=family, nullable=nullable, length=length)
    primary_key = list(inspector.get_pk_constraint(_TABLE).get("constrained_columns") or [])
    if primary_key != ["request_id"]:
        _fail_ddl(f"{_TABLE} primary key {primary_key!r}, expected ['request_id']")
    foreign_keys = {
        foreign.get("name"): (
            list(foreign.get("constrained_columns") or []),
            str(foreign.get("referred_table")),
            list(foreign.get("referred_columns") or []),
        )
        for foreign in inspector.get_foreign_keys(_TABLE)
    }
    if foreign_keys.get(_FK) != (["request_id"], "approval_requests", ["request_id"]):
        _fail_ddl(f"{_FK} has incompatible shape {foreign_keys.get(_FK)!r}")


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if _TABLE in inspector.get_table_names():
        _validate_existing(inspector)
        return
    op.create_table(
        _TABLE,
        sa.Column(
            "request_id",
            sa.Uuid(),
            sa.ForeignKey(
                "approval_requests.request_id",
                name=_FK,
                ondelete="CASCADE",
            ),
            primary_key=True,
        ),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("canonical_args", sa.LargeBinary(), nullable=True),
        sa.Column("args_digest", sa.LargeBinary(), nullable=False),
        sa.Column("result_canonical", sa.LargeBinary(), nullable=True),
        sa.Column("result_digest", sa.LargeBinary(), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("executed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("erased_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )


def downgrade() -> None:
    if _TABLE in sa.inspect(op.get_bind()).get_table_names():
        op.drop_table(_TABLE)
