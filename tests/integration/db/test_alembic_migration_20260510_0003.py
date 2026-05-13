"""Sprint 7B.1 T4 — Alembic migration ``0003_packs_lifecycle`` round-trip
on real Postgres + Oracle.

Mirrors the Sprint-2 integration suite at ``test_alembic_migrations.py``
+ Sprint-3's structural pattern. Each test does:

  alembic upgrade head   →   alembic downgrade base   →   alembic upgrade head

against a live database, then runs CHECK-constraint enforcement
canaries to prove the ``ck_packs_kind`` + ``ck_packs_state``
constraints actually reject out-of-vocabulary values at the DB layer
(not just at the Pydantic model layer in
``packs/storage.py:352-379``).

Env-gated like the prior integration tests; runs only when the
matching ``COGNIC_RUN_*_INTEGRATION`` env var is set + the matching
compose service is up.

Live-DB on this host: all eight tests self-skip when the env vars
are unset, mirroring the pattern reviewers have come to expect from
the Sprint-7B.1 T3 ``tests/integration/packs/test_storage_lock_serialisation.py``
canaries.
"""

from __future__ import annotations

import os
import subprocess

import pytest

# Default DSNs match the Sprint-1C compose stack — same defaults as
# ``tests/integration/db/test_alembic_migrations.py:27-35``.
POSTGRES_URL = os.environ.get(
    "COGNIC_DATABASE_URL_POSTGRES_TEST",
    "postgresql+asyncpg://cognic:cognic_dev_only@localhost:5432/cognic",
)

ORACLE_URL = os.environ.get(
    "COGNIC_DATABASE_URL_ORACLE_TEST",
    "oracle+oracledb://cognic:cognic_dev_only@localhost:1521/?service_name=XEPDB1",
)


def _alembic(env_url: str, *args: str) -> subprocess.CompletedProcess[str]:
    """Run alembic with COGNIC_DATABASE_URL pinned to the test DSN.
    Returns the CompletedProcess on success; raises CalledProcessError
    on non-zero exit.
    """

    env = os.environ.copy()
    env["COGNIC_DATABASE_URL"] = env_url
    return subprocess.run(
        ["uv", "run", "alembic", *args],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )


# ---------------------------------------------------------------------------
# Postgres
# ---------------------------------------------------------------------------


@pytest.mark.postgres
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION"),
    reason=(
        "live Postgres integration; opt in via "
        "COGNIC_RUN_POSTGRES_INTEGRATION=1 + compose up postgres"
    ),
)
def test_postgres_upgrade_downgrade_upgrade_roundtrip() -> None:
    """Full round-trip pins the migration's ``upgrade()`` /
    ``downgrade()`` symmetry on real Postgres. Catches missing index
    drops + asymmetric ``op.create_table`` / ``op.drop_table`` that
    the SQLite unit test could in principle miss (SQLite's looser
    DDL semantics tolerate some asymmetries silently)."""

    _alembic(POSTGRES_URL, "upgrade", "head")
    _alembic(POSTGRES_URL, "downgrade", "base")
    _alembic(POSTGRES_URL, "upgrade", "head")


@pytest.mark.postgres
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION"),
    reason="live Postgres integration; opt in via COGNIC_RUN_POSTGRES_INTEGRATION=1",
)
async def test_postgres_check_constraint_kind_rejects_unknown_kind() -> None:
    """``ck_packs_kind`` MUST reject ``kind='other'`` at the DB
    layer. The Pydantic model already refuses out-of-vocabulary
    values at construction (Doctrine Lock E layer 1), but the DB
    constraint is the second-layer fail-closed boundary that catches
    a future direct-SQL writer bypassing the model.
    """

    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.ext.asyncio import create_async_engine

    _alembic(POSTGRES_URL, "upgrade", "head")
    engine = create_async_engine(POSTGRES_URL)
    try:
        # P2 reviewer fix (T4 R2 P2): ``pytest.raises(IntegrityError)``
        # OUTSIDE ``engine.begin()`` so the exception propagates and the
        # context manager rolls back. With the prior (catch-inside)
        # shape, the swallowed exception lets the context manager
        # try to COMMIT an already-aborted transaction, surfacing a
        # different error than the CHECK violation we want to prove.
        # Mirror of the working shape at
        # ``tests/integration/packs/test_storage_lock_serialisation.py:520-521``.
        #
        # P2 reviewer fix (T4 R3 P2): digest columns produced by
        # ``decode(repeat('00', 32), 'hex')`` — a real BYTEA expression.
        # Original ``'\\x' || repeat('00', 32)`` is a text-typed
        # concatenation (``repeat`` returns text); Postgres has no
        # implicit text→bytea cast, so the INSERT would fail on type
        # assignment to ``manifest_digest BYTEA NOT NULL`` BEFORE the
        # CHECK constraints fired — recreating the same CHECK-masking
        # problem the R1 P2 fix removed for the Oracle CHAR(32) ``id``
        # column. ``decode(text, 'hex')`` is the standard PG idiom for
        # building BYTEA from a hex string.
        with pytest.raises(IntegrityError):
            async with engine.begin() as conn:
                await conn.execute(
                    text(
                        "INSERT INTO packs ("
                        "id, kind, pack_id, display_name, state, "
                        "manifest_digest, signed_artefact_digest, "
                        "sbom_pointer, tenant_id, created_by, last_actor, "
                        "created_at, updated_at"
                        ") VALUES ("
                        ":id, 'other', 'p', 'p', 'draft', "
                        # BYTEA(32) of zero bytes — decode() returns
                        # bytea directly, no implicit text-cast.
                        "decode(repeat('00', 32), 'hex'), "
                        "decode(repeat('00', 32), 'hex'), "
                        "NULL, NULL, 'a', 'a', NOW(), NOW()"
                        ")"
                    ),
                    {"id": "00000000-0000-0000-0000-000000000001"},
                )
    finally:
        await engine.dispose()


@pytest.mark.postgres
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION"),
    reason="live Postgres integration; opt in via COGNIC_RUN_POSTGRES_INTEGRATION=1",
)
async def test_postgres_check_constraint_state_rejects_unknown_state() -> None:
    """``ck_packs_state`` MUST reject ``state='quarantined'`` at the
    DB layer. Same second-layer rationale as the kind constraint
    canary above.

    P2 reviewer fix (T4 R2 P2): ``pytest.raises`` outside
    ``engine.begin()`` — see kind canary above for full rationale.

    P2 reviewer fix (T4 R3 P2): digest columns built via
    ``decode(repeat('00', 32), 'hex')`` for the same BYTEA-vs-text
    rationale documented on the kind canary.
    """

    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.ext.asyncio import create_async_engine

    _alembic(POSTGRES_URL, "upgrade", "head")
    engine = create_async_engine(POSTGRES_URL)
    try:
        with pytest.raises(IntegrityError):
            async with engine.begin() as conn:
                await conn.execute(
                    text(
                        "INSERT INTO packs ("
                        "id, kind, pack_id, display_name, state, "
                        "manifest_digest, signed_artefact_digest, "
                        "sbom_pointer, tenant_id, created_by, last_actor, "
                        "created_at, updated_at"
                        ") VALUES ("
                        ":id, 'tool', 'p', 'p', 'quarantined', "
                        # BYTEA(32) of zero bytes via real bytea expr.
                        "decode(repeat('00', 32), 'hex'), "
                        "decode(repeat('00', 32), 'hex'), "
                        "NULL, NULL, 'a', 'a', NOW(), NOW()"
                        ")"
                    ),
                    {"id": "00000000-0000-0000-0000-000000000002"},
                )
    finally:
        await engine.dispose()


@pytest.mark.postgres
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION"),
    reason="live Postgres integration; opt in via COGNIC_RUN_POSTGRES_INTEGRATION=1",
)
async def test_postgres_information_schema_check_constraint_inventory() -> None:
    """Live Postgres reflects ``ck_packs_kind`` + ``ck_packs_state``
    in ``information_schema.check_constraints`` after upgrade. Pins
    the constraint-name contract — operator runbooks reference these
    constraint names when diagnosing rejected INSERTs.
    """

    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    _alembic(POSTGRES_URL, "upgrade", "head")
    engine = create_async_engine(POSTGRES_URL)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT constraint_name "
                    "FROM information_schema.check_constraints "
                    "WHERE constraint_name LIKE 'ck_packs_%'"
                )
            )
            names = {r.constraint_name for r in result}
        assert "ck_packs_kind" in names
        assert "ck_packs_state" in names
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Oracle
# ---------------------------------------------------------------------------


@pytest.mark.oracle
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"),
    reason=(
        "live Oracle XE integration; opt in via COGNIC_RUN_ORACLE_INTEGRATION=1 + compose up oracle"
    ),
)
def test_oracle_upgrade_downgrade_upgrade_roundtrip() -> None:
    """Full round-trip on real Oracle XE — catches the Oracle-specific
    asymmetries (RAW(32) compile, TIMESTAMP WITH TIME ZONE compile,
    CHECK constraint syntax) that the SQLite unit substrate cannot
    reach.
    """

    _alembic(ORACLE_URL, "upgrade", "head")
    _alembic(ORACLE_URL, "downgrade", "base")
    _alembic(ORACLE_URL, "upgrade", "head")


@pytest.mark.oracle
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"),
    reason="live Oracle XE integration; opt in via COGNIC_RUN_ORACLE_INTEGRATION=1",
)
async def test_oracle_check_constraint_kind_rejects_unknown_kind() -> None:
    """Same canary as Postgres but for Oracle's CHECK syntax. Oracle
    raises ``ORA-02290: check constraint violated`` which surfaces
    through ``oracledb`` as a ``DatabaseError``; SQLAlchemy wraps it
    as ``IntegrityError``.

    P2 reviewer fix (Sprint-7B.1 T4 R1 P2): ``sa.Uuid()`` compiles to
    ``CHAR(32)`` on Oracle (no native UUID type — the dialect-portable
    seam stores the 32-char hex form without dashes, mirroring what
    SQLAlchemy binds when a Python ``uuid.UUID`` instance is passed
    via the production ``save_draft`` / ``transition`` path). Original
    revision used ``HEXTORAW(REPLACE('...', '-', ''))`` which yields
    a ``RAW(16)`` value — Oracle would raise ORA-12899 / ORA-00932 on
    type conversion BEFORE the ``ck_packs_kind`` CHECK fired, masking
    what the canary claims to test. Use a 32-char hex string literal
    for the ``id`` column; reserve ``HEXTORAW(...)`` for the digest
    columns, which actually ARE ``RAW(32)`` per
    ``chain_hash_column_type()``.
    """

    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.ext.asyncio import create_async_engine

    _alembic(ORACLE_URL, "upgrade", "head")
    engine = create_async_engine(ORACLE_URL)
    try:
        # P2 reviewer fix (T4 R2 P2): ``pytest.raises`` outside
        # ``engine.begin()``. See Postgres kind canary at
        # ``test_postgres_check_constraint_kind_rejects_unknown_kind``
        # for full rationale; mirror at
        # ``tests/integration/packs/test_storage_lock_serialisation.py:520-521``.
        with pytest.raises(IntegrityError):
            async with engine.begin() as conn:
                await conn.execute(
                    text(
                        "INSERT INTO packs ("
                        "id, kind, pack_id, display_name, state, "
                        "manifest_digest, signed_artefact_digest, "
                        "sbom_pointer, tenant_id, created_by, last_actor, "
                        "created_at, updated_at"
                        ") VALUES ("
                        # CHAR(32) UUID-as-hex (sa.Uuid() on Oracle).
                        "'00000000000000000000000000000001', "
                        "'other', 'p', 'p', 'draft', "
                        # RAW(32) digests via chain_hash_column_type().
                        "HEXTORAW(RPAD('00', 64, '0')), HEXTORAW(RPAD('00', 64, '0')), "
                        "NULL, NULL, 'a', 'a', "
                        "SYSTIMESTAMP, SYSTIMESTAMP"
                        ")"
                    )
                )
    finally:
        await engine.dispose()


@pytest.mark.oracle
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"),
    reason="live Oracle XE integration; opt in via COGNIC_RUN_ORACLE_INTEGRATION=1",
)
async def test_oracle_check_constraint_state_rejects_unknown_state() -> None:
    """``ck_packs_state`` rejects ``state='quarantined'`` on Oracle.

    P2 reviewer fix (T4 R1 P2): see kind canary above for the
    ``CHAR(32)`` vs ``RAW(16)`` rationale. Same fix applies — ``id``
    bound as a 32-char hex literal; digest columns stay
    ``HEXTORAW(...)``.

    P2 reviewer fix (T4 R2 P2): ``pytest.raises`` outside
    ``engine.begin()`` so the exception propagates and the context
    manager rolls back, instead of being swallowed inside and forcing
    a COMMIT-on-aborted-transaction failure.
    """

    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.ext.asyncio import create_async_engine

    _alembic(ORACLE_URL, "upgrade", "head")
    engine = create_async_engine(ORACLE_URL)
    try:
        with pytest.raises(IntegrityError):
            async with engine.begin() as conn:
                await conn.execute(
                    text(
                        "INSERT INTO packs ("
                        "id, kind, pack_id, display_name, state, "
                        "manifest_digest, signed_artefact_digest, "
                        "sbom_pointer, tenant_id, created_by, last_actor, "
                        "created_at, updated_at"
                        ") VALUES ("
                        # CHAR(32) UUID-as-hex (sa.Uuid() on Oracle).
                        "'00000000000000000000000000000002', "
                        "'tool', 'p', 'p', 'quarantined', "
                        # RAW(32) digests via chain_hash_column_type().
                        "HEXTORAW(RPAD('00', 64, '0')), HEXTORAW(RPAD('00', 64, '0')), "
                        "NULL, NULL, 'a', 'a', "
                        "SYSTIMESTAMP, SYSTIMESTAMP"
                        ")"
                    )
                )
    finally:
        await engine.dispose()


@pytest.mark.oracle
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"),
    reason="live Oracle XE integration; opt in via COGNIC_RUN_ORACLE_INTEGRATION=1",
)
async def test_oracle_user_constraints_check_constraint_inventory() -> None:
    """Live Oracle exposes ``ck_packs_kind`` + ``ck_packs_state`` via
    ``user_constraints`` after upgrade. Oracle stores constraint names
    upper-cased by default — match case-insensitively. Pins the
    constraint-name contract for Oracle operator runbooks.
    """

    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    _alembic(ORACLE_URL, "upgrade", "head")
    engine = create_async_engine(ORACLE_URL)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT constraint_name FROM user_constraints "
                    "WHERE constraint_type = 'C' "
                    "AND UPPER(table_name) = 'PACKS'"
                )
            )
            names = {r.constraint_name.upper() for r in result}
        assert any("CK_PACKS_KIND" in n for n in names), (
            f"ck_packs_kind not present in Oracle user_constraints; got {names}"
        )
        assert any("CK_PACKS_STATE" in n for n in names), (
            f"ck_packs_state not present in Oracle user_constraints; got {names}"
        )
    finally:
        await engine.dispose()
