"""Conversation pending-approval correlation and typed turns (M8.5-D D2).

Adds the approval request correlator carried by a pending exchange and the
turn-kind discriminator used by the subsequent system-turn slice. Existing
turns backfill to ``exchange`` through the non-null server default.

Revision ID: 0021
Revises: 0020
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NoReturn

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | None = None
depends_on: str | None = None

_TABLE = "conversation_turns"
_APPROVAL_COLUMN = "approval_request_id"
_KIND_COLUMN = "turn_kind"


def _fail_ddl(detail: str) -> NoReturn:
    raise RuntimeError(f"0021 ddl: existing object shape mismatch — {detail}")


def _validate_string_column(
    column: Mapping[str, Any],
    *,
    name: str,
    length: int,
    nullable: bool,
) -> None:
    column_type = column["type"]
    if not isinstance(column_type, sa.String) or column_type.length != length:
        _fail_ddl(f"{_TABLE}.{name} has incompatible type {column_type!r}")
    if bool(column["nullable"]) is not nullable:
        _fail_ddl(f"{_TABLE}.{name} nullable={column['nullable']!r}, expected {nullable}")


def _is_exchange_default(value: Any) -> bool:
    rendered = str(value).strip().lower()
    return rendered in {"exchange", "'exchange'", '"exchange"'} or rendered.startswith(
        "'exchange'::"
    )


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"]: column for column in inspector.get_columns(_TABLE)}

    approval = columns.get(_APPROVAL_COLUMN)
    if approval is None:
        op.add_column(
            _TABLE,
            sa.Column(_APPROVAL_COLUMN, sa.String(64), nullable=True),
        )
    else:
        _validate_string_column(
            approval,
            name=_APPROVAL_COLUMN,
            length=64,
            nullable=True,
        )

    kind = columns.get(_KIND_COLUMN)
    if kind is None:
        op.add_column(
            _TABLE,
            sa.Column(
                _KIND_COLUMN,
                sa.String(16),
                nullable=False,
                server_default=sa.text("'exchange'"),
            ),
        )
    else:
        _validate_string_column(
            kind,
            name=_KIND_COLUMN,
            length=16,
            nullable=False,
        )
        if not _is_exchange_default(kind.get("default")):
            _fail_ddl(
                f"{_TABLE}.{_KIND_COLUMN} default={kind.get('default')!r}, expected 'exchange'"
            )


def downgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns(_TABLE)}
    if _APPROVAL_COLUMN in columns or _KIND_COLUMN in columns:
        with op.batch_alter_table(_TABLE) as batch:
            if _KIND_COLUMN in columns:
                batch.drop_column(_KIND_COLUMN)
            if _APPROVAL_COLUMN in columns:
                batch.drop_column(_APPROVAL_COLUMN)
