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

import re
from collections.abc import Mapping
from typing import Any, NoReturn

import sqlalchemy as sa
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

_INDEX = "ix_approval_requests_tenant_created_request"
_TABLE = "approval_requests"
_COLUMNS = ["tenant_id", "created_at", "request_id"]

# ``created_at`` is ``TIMESTAMP WITH TIME ZONE``; Oracle indexes such a column as
# a function-based index on ``SYS_EXTRACT_UTC("COL")`` (UTC-normalised for
# correct global ordering), so its reflection reports ``column_names[i] is None``
# with the real column under ``expressions[i]``. Postgres / SQLite report the
# plain name. This pattern matches ONLY that expected TSTZ normalisation — a
# None-position expression of any OTHER shape is a genuinely different index and
# fails loud below rather than being silently accepted.
_ORACLE_TSTZ_INDEX_EXPR = re.compile(
    r'^SYS_EXTRACT_UTC\(\s*"?([A-Za-z_][A-Za-z0-9_$#]*)"?\s*\)$',
    re.IGNORECASE,
)


def _fail_ddl(detail: str) -> NoReturn:
    raise RuntimeError(f"0017 ddl: existing object shape mismatch — {detail}")


def _resolved_columns(idx: Mapping[str, Any]) -> list[str]:
    """The lower-cased underlying column identity per index position — dialect-portable.

    A position whose reflected ``column_names`` entry is a plain name is used as
    is; a ``None`` entry (Oracle's function-based reflection of a ``TIMESTAMP WITH
    TIME ZONE`` column) is resolved back to its column from the matching
    ``SYS_EXTRACT_UTC("COL")`` expression. A ``None`` position whose expression is
    NOT that expected normalisation fails loud — the guard never silently accepts
    an unrecognised expression as if it were the intended column.
    """
    names = list(idx.get("column_names") or [])
    exprs = list(idx.get("expressions") or [])
    resolved: list[str] = []
    for i, name in enumerate(names):
        if name is not None:
            resolved.append(str(name).lower())
            continue
        expr = str(exprs[i]).strip() if i < len(exprs) else ""
        match = _ORACLE_TSTZ_INDEX_EXPR.match(expr)
        if match is None:
            _fail_ddl(f"{_INDEX} column {i} is an unresolved expression {expr!r}")
        resolved.append(match.group(1).lower())
    return resolved


def _validate_index_shape(idx: Mapping[str, Any]) -> None:
    resolved = _resolved_columns(idx)
    if resolved != _COLUMNS:
        _fail_ddl(f"{_INDEX} columns {resolved!r} != {_COLUMNS!r}")
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
