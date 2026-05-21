"""#489 T2 — RelationalAdapter.engine accessor conformance.

Every relational adapter implementation must expose its live
SQLAlchemy AsyncEngine via the read-only `engine` property after
connect(), and fail loud (RuntimeError) before connect(). The #489
lifespan builds AuditStore + DecisionHistoryStore from this accessor.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.db.adapters.oracle_adapter import OracleAdapter
from cognic_agentos.db.adapters.postgres_adapter import PostgresAdapter
from cognic_agentos.db.adapters.protocols import RelationalAdapter
from tests.support.adapter_fixtures import InMemoryRelationalAdapter

_SQLITE_URL = "sqlite+aiosqlite:///:memory:"


def _adapters() -> list[RelationalAdapter]:
    # All three relational adapter implementations. PostgresAdapter and
    # OracleAdapter are constructed against the sqlite URL — neither
    # branches on URL shape; SQLAlchemy picks the driver, so connect()
    # builds a real AsyncEngine without a live Postgres / Oracle process.
    return [
        PostgresAdapter(_SQLITE_URL),
        OracleAdapter(_SQLITE_URL),
        InMemoryRelationalAdapter(),
    ]


@pytest.mark.parametrize("adapter", _adapters(), ids=lambda a: type(a).__name__)
def test_engine_raises_before_connect(adapter: RelationalAdapter) -> None:
    """Pre-connect access fails loud rather than yielding a half-live
    handle (#489 spec §4.2)."""
    with pytest.raises(RuntimeError, match="connect"):
        _ = adapter.engine


@pytest.mark.parametrize("adapter", _adapters(), ids=lambda a: type(a).__name__)
async def test_engine_yields_async_engine_after_connect(
    adapter: RelationalAdapter,
) -> None:
    """After connect() the accessor yields the adapter's live AsyncEngine."""
    await adapter.connect()
    try:
        assert isinstance(adapter.engine, AsyncEngine)
    finally:
        await adapter.close()
