"""Migration ``20260711_0017_approval_queue_index`` — the 0016-discipline
mirror (HP-4, spec §2.1 as corrected): revision wiring, index shape,
partial-state AND fully-applied reruns, the three guard-shape negatives,
downgrade round-trip (rows survive; only the derived index is removed),
runtime-table parity.
"""

from __future__ import annotations

import importlib
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command

from cognic_agentos.db.migrations.alembic_config import make_alembic_config

MIGRATION = "cognic_agentos.db.migrations.versions.20260711_0017_approval_queue_index"
INDEX = "ix_approval_requests_tenant_created_request"
COLUMNS = ["tenant_id", "created_at", "request_id"]


def _sqlite_url(tmp_path: Any, name: str) -> str:
    # SYNC url for seeding/inspection; alembic's env.py requires the async
    # driver, so _upgrade/_downgrade swap the scheme (the 0016 lesson).
    return f"sqlite:///{tmp_path / name}"


def _async_url(url: str) -> str:
    return url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)


def _upgrade(url: str, revision: str) -> None:
    command.upgrade(make_alembic_config(_async_url(url)), revision)


def _downgrade(url: str, revision: str) -> None:
    command.downgrade(make_alembic_config(_async_url(url)), revision)


def _index_map(url: str) -> dict[str, Any]:
    engine = sa.create_engine(url)
    try:
        return {str(i["name"]): i for i in sa.inspect(engine).get_indexes("approval_requests")}
    finally:
        engine.dispose()


def _stamp(url: str, revision: str) -> None:
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text("UPDATE alembic_version SET version_num = :rev"), {"rev": revision}
            )
    finally:
        engine.dispose()


def _exec(url: str, *stmts: str) -> None:
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            for stmt in stmts:
                conn.execute(sa.text(stmt))
    finally:
        engine.dispose()


# Typed seed stub (NOT reflection — the 0016 lesson: sqlite reflection strips
# sa.Uuid to CHAR, breaking uuid binds; the typed stub stores values in the
# SAME on-disk format the production Table uses).
_approval_requests_t = sa.table(
    "approval_requests",
    sa.column("request_id", sa.Uuid()),
    sa.column("tenant_id", sa.String(128)),
    sa.column("flow", sa.String(32)),
    sa.column("risk_tier", sa.String(32)),
    sa.column("tool_identity", sa.String(256)),
    sa.column("originator_subject", sa.String(256)),
    sa.column("state", sa.String(16)),
    sa.column("envelope_digest", sa.LargeBinary()),
    sa.column("args_digest", sa.LargeBinary()),
    sa.column("redacted_context", sa.Text()),
    sa.column("data_classes", sa.JSON()),
    sa.column("required_refs", sa.JSON()),
    sa.column("created_at", sa.TIMESTAMP(timezone=True)),
    sa.column("expires_at", sa.TIMESTAMP(timezone=True)),
    sa.column("updated_at", sa.TIMESTAMP(timezone=True)),
)


def _seed_one_request(url: str) -> uuid.UUID:
    request_id = uuid.uuid4()
    when = datetime(2026, 7, 11, 12, 0, 0, tzinfo=UTC)
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(
                _approval_requests_t.insert().values(
                    request_id=request_id,
                    tenant_id="t-0017",
                    flow="require_single_approval",
                    risk_tier="customer_data_read",
                    tool_identity="mcp:seed",
                    originator_subject="analyst.amir",
                    state="pending",
                    envelope_digest=b"\x00" * 32,
                    args_digest=b"\x00" * 32,
                    redacted_context="{}",
                    data_classes=[],
                    required_refs={},
                    created_at=when,
                    expires_at=when,
                    updated_at=when,
                )
            )
    finally:
        engine.dispose()
    return request_id


def test_revision_wiring() -> None:
    mod = importlib.import_module(MIGRATION)
    assert mod.revision == "0017"
    assert mod.down_revision == "0016"


def test_index_created_with_exact_columns(tmp_path: Any) -> None:
    url = _sqlite_url(tmp_path, "shape.sqlite")
    _upgrade(url, "head")
    idx = _index_map(url)
    assert INDEX in idx
    assert idx[INDEX]["column_names"] == COLUMNS
    assert not idx[INDEX]["unique"], "non-unique query index by contract"


def test_fully_applied_rerun_is_idempotent(tmp_path: Any) -> None:
    url = _sqlite_url(tmp_path, "rerun-full.sqlite")
    _upgrade(url, "head")
    _stamp(url, "0016")
    _upgrade(url, "head")  # must guard-skip the existing index, not raise
    assert INDEX in _index_map(url)


def test_partial_state_rerun_recreates_only_the_missing_index(tmp_path: Any) -> None:
    url = _sqlite_url(tmp_path, "rerun-partial.sqlite")
    _upgrade(url, "head")
    _exec(url, f"DROP INDEX {INDEX}")
    _stamp(url, "0016")
    _upgrade(url, "head")
    assert INDEX in _index_map(url)


@pytest.mark.parametrize(
    ("recreate", "match"),
    [
        (
            f"CREATE INDEX {INDEX} ON approval_requests (tenant_id, created_at)",
            "columns",
        ),
        (
            f"CREATE UNIQUE INDEX {INDEX} ON approval_requests (tenant_id, created_at, request_id)",
            "UNIQUE",
        ),
        (
            f"CREATE INDEX {INDEX} ON approval_requests (created_at, tenant_id, request_id)",
            "columns",
        ),
    ],
    ids=["wrong-column-count", "unique-posture", "wrong-column-order"],
)
def test_guard_fails_loud_on_shape_mismatch(tmp_path: Any, recreate: str, match: str) -> None:
    url = _sqlite_url(tmp_path, "guard.sqlite")
    _upgrade(url, "head")
    _exec(url, f"DROP INDEX {INDEX}", recreate)
    _stamp(url, "0016")
    with pytest.raises(RuntimeError, match="0017 ddl: existing object shape mismatch") as exc:
        _upgrade(url, "head")
    assert match in str(exc.value)


def test_downgrade_removes_only_the_index(tmp_path: Any) -> None:
    url = _sqlite_url(tmp_path, "downgrade.sqlite")
    _upgrade(url, "head")
    request_id = _seed_one_request(url)
    _downgrade(url, "0016")
    assert INDEX not in _index_map(url)
    engine = sa.create_engine(url)
    try:
        with engine.connect() as conn:
            row = conn.execute(
                sa.select(_approval_requests_t.c.request_id).where(
                    _approval_requests_t.c.request_id == request_id
                )
            ).first()
        assert row is not None, "downgrade removes ONLY the derived index; rows survive"
    finally:
        engine.dispose()
    # And the round-trip back up recreates it.
    _upgrade(url, "head")
    assert INDEX in _index_map(url)


def test_runtime_table_parity(tmp_path: Any) -> None:
    from cognic_agentos.core.approval.storage import _approval_requests

    url = _sqlite_url(tmp_path, "parity.sqlite")
    _upgrade(url, "head")
    reflected = set(_index_map(url))
    runtime = {i.name for i in _approval_requests.indexes}
    assert INDEX in runtime, "the runtime Table must declare the 0017 index"
    missing = {n for n in runtime if isinstance(n, str)} - reflected
    assert not missing, f"runtime Table declares indexes the migrated DB lacks: {missing}"
