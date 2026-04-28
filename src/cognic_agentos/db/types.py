"""Dialect-portable column types for governance tables.

Sprint 2 — single source of truth for the JSON + fixed-binary-hash
column types shared between the migration (``db/migrations/versions/
20260428_0001_initial_governance_schema.py``) and the runtime Table
definitions used by ``core/audit`` + ``core/decision_history`` +
``core/chain_verifier``.

Oracle-specific handling needed because:

1. **`sa.JSON()` does not compile under SQLAlchemy 2.0.49's Oracle
   dialect.** The Oracle ``JSON`` SQL type was introduced in 21c, but
   SQLAlchemy 2.0.49 does not export an ``oracle.JSON`` type. We bridge
   via a ``TypeDecorator`` that stores as ``CLOB`` on Oracle (with
   app-side ``json.dumps`` / ``json.loads``) and uses native JSON on
   Postgres + SQLite.

2. **`sa.LargeBinary(32)` compiles to ``BLOB`` on Oracle**, not
   ``RAW(32)``. Sprint-2 hash columns require fixed 32-byte semantics
   (UNIQUE-indexed; verifier compares via byte equality). Bridge via
   ``with_variant(oracle.RAW(32), 'oracle')``.

Both bridges are stable wire-format. Any future change to either
constitutes a wire-format migration and requires the same per-edit
review discipline as ``core/canonical.py`` (per AGENTS.md amendment
landed in PR #5).
"""

from __future__ import annotations

import json as _json
from typing import Any

from sqlalchemy import CLOB, JSON, LargeBinary, TypeDecorator
from sqlalchemy.dialects.oracle import RAW
from sqlalchemy.types import TypeEngine


def chain_hash_column_type() -> TypeEngine[bytes]:
    """LargeBinary(32) on Postgres + SQLite, RAW(32) on Oracle.

    Used for ``prev_hash`` + ``hash`` on the evidence tables and
    ``latest_hash`` on ``governance_chain_heads``. Fixed 32-byte
    enforcement happens at three layers:

      1. Oracle: ``RAW(32)`` enforces length at INSERT time.
      2. Postgres: ``BYTEA`` is variable-length — application
         layer (``core.canonical.hash_record``) raises if
         ``prev_hash != 32 bytes``.
      3. The chain verifier walks every row's hash and compares
         byte-for-byte, so any deviation surfaces as a tamper report.
    """

    return LargeBinary(32).with_variant(RAW(32), "oracle")


class GovernanceJSON(TypeDecorator[Any]):
    """JSON-as-CLOB on Oracle; native JSON on Postgres + SQLite.

    Application code reads/writes Python dicts / lists / scalars;
    the dialect layer handles serialization. JSON serialization on
    the Oracle path uses ``json.dumps(..., sort_keys=True,
    ensure_ascii=False)`` so the round-trip preserves ordering.

    The column is NOT the source of truth for chain integrity. Hash
    chains are computed in ``core/audit`` + ``core/decision_history``
    over the canonical envelope BEFORE the row is inserted, and the
    chain verifier re-runs ``core.canonical.canonical_bytes`` over
    the read-back envelope. So whatever shape Oracle stores
    internally (CLOB JSON-text vs native JSON) doesn't affect chain
    integrity — only the per-column query path.
    """

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect: Any) -> Any:
        if dialect.name == "oracle":
            return dialect.type_descriptor(CLOB())
        return dialect.type_descriptor(JSON())

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if dialect.name == "oracle":
            return _json.dumps(value, sort_keys=True, ensure_ascii=False)
        return value

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if dialect.name == "oracle":
            return _json.loads(value)
        return value


__all__: tuple[str, ...] = (
    "GovernanceJSON",
    "chain_hash_column_type",
)
