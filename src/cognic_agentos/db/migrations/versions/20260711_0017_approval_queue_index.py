"""approval queue index — HP-4 (ADR-014 amendment; M8.5-C spec §2.1 as corrected).

Adds ``ix_approval_requests_tenant_created_request`` on ``(tenant_id,
created_at, request_id)``: tenant-leading for the reviewer queue's WHERE;
``(created_at, request_id)`` is the chronological keyset the paginated
``list_pending`` walks. Guarded + re-runnable: presence is checked via the
inspector; an existing object with a DIFFERENT shape fails loud ("0017 ddl:
existing object shape mismatch") rather than being silently trusted.

The downgrade removes ONLY this derived query index; approval rows and every
governance column are untouched.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

_INDEX = "ix_approval_requests_tenant_created_request"
_TABLE = "approval_requests"
_COLUMNS = ["tenant_id", "created_at", "request_id"]


def _fail_ddl(detail: str) -> None:
    raise RuntimeError(f"0017 ddl: existing object shape mismatch — {detail}")


def _validate_index_shape(idx: Mapping[str, Any]) -> None:
    if idx.get("column_names") != _COLUMNS:
        _fail_ddl(f"{_INDEX} columns {idx.get('column_names')!r} != {_COLUMNS!r}")
    if idx.get("unique"):
        _fail_ddl(f"{_INDEX} is UNIQUE; the queue index must be non-unique")


def upgrade() -> None:
    insp = sa.inspect(op.get_bind())
    existing = {i["name"]: i for i in insp.get_indexes(_TABLE)}
    if _INDEX in existing:
        _validate_index_shape(existing[_INDEX])
        return
    op.create_index(_INDEX, _TABLE, _COLUMNS, unique=False)


def downgrade() -> None:
    insp = sa.inspect(op.get_bind())
    if _INDEX in {i["name"] for i in insp.get_indexes(_TABLE)}:
        op.drop_index(_INDEX, table_name=_TABLE)
