"""db/types — dialect-bridge column types for governance tables.

Pins the cross-dialect compilation contract:

- chain_hash_column_type() → BYTEA on Postgres, RAW(32) on Oracle, BLOB on SQLite.
- GovernanceJSON()        → native JSON on Postgres + SQLite, CLOB on Oracle.

Plus round-trip behaviour for GovernanceJSON's bind/result hooks.

Without these tests the dialect bridges live only inside an alembic
migration that runs on env-gated integration jobs — meaning a future
edit to db/types could silently regress the migration's DDL without a
default-suite signal. These tests run in `pytest -q` and catch any
shape regression at unit-test time.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import oracle, postgresql, sqlite

from cognic_agentos.db.types import GovernanceJSON, chain_hash_column_type


def _ddl_for(dialect_module: object) -> str:
    """Compile a small fixture table under ``dialect_module``'s dialect."""

    metadata = sa.MetaData()
    t = sa.Table(
        "_dialect_bridge_fixture",
        metadata,
        sa.Column("h", chain_hash_column_type(), nullable=False),
        sa.Column("payload", GovernanceJSON(), nullable=False),
    )
    return str(sa.schema.CreateTable(t).compile(dialect=dialect_module.dialect()))  # type: ignore[attr-defined]


class TestChainHashColumnDDL:
    """``chain_hash_column_type()`` must compile to a fixed-length 32-byte
    binary type on Oracle, native binary on Postgres + SQLite. Hash columns
    are UNIQUE-indexed and the chain verifier compares byte-for-byte; a
    variable-length type on Oracle (BLOB) would weaken UNIQUE semantics
    and add storage overhead."""

    def test_postgres_compiles_to_bytea(self) -> None:
        ddl = _ddl_for(postgresql)
        assert "BYTEA" in ddl
        assert "BLOB" not in ddl

    def test_oracle_compiles_to_raw_32(self) -> None:
        ddl = _ddl_for(oracle)
        assert "RAW(32)" in ddl
        assert "BLOB" not in ddl  # Round-2 P1: must NOT be Oracle BLOB.

    def test_sqlite_compiles_to_blob(self) -> None:
        # SQLite has no fixed-length binary type; BLOB is the only option.
        # Application-layer hash_record() enforces 32-byte length on this path.
        ddl = _ddl_for(sqlite)
        assert "BLOB" in ddl


class TestGovernanceJSONDDL:
    """``GovernanceJSON`` must compile to native JSON where the dialect
    supports it (Postgres, SQLite) and to CLOB on Oracle (where SQLAlchemy
    2.0.49 lacks an Oracle JSON type)."""

    def test_postgres_compiles_to_json(self) -> None:
        ddl = _ddl_for(postgresql)
        assert "JSON" in ddl
        assert "CLOB" not in ddl

    def test_oracle_compiles_to_clob(self) -> None:
        # Round-2 P1: sa.JSON() does not compile under Oracle dialect in
        # SQLAlchemy 2.0.49. The TypeDecorator routes to CLOB instead.
        ddl = _ddl_for(oracle)
        assert "CLOB" in ddl
        assert "JSON" not in ddl

    def test_sqlite_compiles_to_json(self) -> None:
        # SQLite's JSON type is a thin sugar over TEXT, but compiles as JSON.
        ddl = _ddl_for(sqlite)
        assert "JSON" in ddl


class _FakeDialect:
    """Minimal dialect stand-in. process_bind_param / process_result_value
    only inspect dialect.name, so we don't need a real dialect instance."""

    def __init__(self, name: str) -> None:
        self.name = name


class TestGovernanceJSONRoundTrip:
    """The Oracle path serializes via json.dumps(sort_keys=True) on the
    way in and json.loads on the way out. The Postgres / SQLite paths
    pass values through unchanged (their dialects handle JSON natively).
    NULL passes through unchanged on every dialect."""

    def test_oracle_bind_serializes_with_sort_keys(self) -> None:
        gj = GovernanceJSON()
        result = gj.process_bind_param({"b": 2, "a": 1}, _FakeDialect("oracle"))
        # sort_keys=True so dict-key order is stable across runs;
        # the actual JSON column storage is incidental — chain integrity
        # is computed separately via core.canonical.canonical_bytes.
        assert result == '{"a": 1, "b": 2}'

    def test_oracle_result_deserializes(self) -> None:
        gj = GovernanceJSON()
        result = gj.process_result_value('{"a": 1, "b": 2}', _FakeDialect("oracle"))
        assert result == {"a": 1, "b": 2}

    def test_oracle_round_trip_preserves_nested(self) -> None:
        gj = GovernanceJSON()
        original = {"k": [1, 2, 3], "meta": {"x": "y"}}
        bound = gj.process_bind_param(original, _FakeDialect("oracle"))
        recovered = gj.process_result_value(bound, _FakeDialect("oracle"))
        assert recovered == original

    def test_oracle_round_trip_preserves_unicode(self) -> None:
        # ensure_ascii=False so multibyte characters survive.
        gj = GovernanceJSON()
        original = {"city": "Zürich", "label": "naïve"}
        bound = gj.process_bind_param(original, _FakeDialect("oracle"))
        assert isinstance(bound, str)
        assert "Zürich" in bound
        recovered = gj.process_result_value(bound, _FakeDialect("oracle"))
        assert recovered == original

    def test_postgres_bind_passes_through(self) -> None:
        gj = GovernanceJSON()
        v = {"a": 1, "b": [1, 2]}
        assert gj.process_bind_param(v, _FakeDialect("postgresql")) == v

    def test_postgres_result_passes_through(self) -> None:
        gj = GovernanceJSON()
        v = {"a": 1}
        assert gj.process_result_value(v, _FakeDialect("postgresql")) == v

    def test_sqlite_bind_passes_through(self) -> None:
        gj = GovernanceJSON()
        v = ["a", "b", "c"]
        assert gj.process_bind_param(v, _FakeDialect("sqlite")) == v

    def test_none_passes_through_on_every_dialect(self) -> None:
        gj = GovernanceJSON()
        for name in ("oracle", "postgresql", "sqlite"):
            d = _FakeDialect(name)
            assert gj.process_bind_param(None, d) is None
            assert gj.process_result_value(None, d) is None
