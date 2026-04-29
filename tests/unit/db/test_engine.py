"""db/engine — async SQLAlchemy engine + session factory."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from cognic_agentos.core.config import Settings
from cognic_agentos.db.engine import (
    create_engine_from_settings,
    dispose_engine,
    session_factory_from_engine,
)


@pytest.mark.asyncio
async def test_engine_creates_against_sqlite() -> None:
    s = Settings(database_url="sqlite+aiosqlite:///:memory:", db_driver="postgres")
    engine = create_engine_from_settings(s)
    assert isinstance(engine, AsyncEngine)
    await dispose_engine(engine)


@pytest.mark.asyncio
async def test_session_factory_yields_async_session() -> None:
    s = Settings(database_url="sqlite+aiosqlite:///:memory:", db_driver="postgres")
    engine = create_engine_from_settings(s)
    factory = session_factory_from_engine(engine)
    async with factory() as session:
        assert isinstance(session, AsyncSession)
    await dispose_engine(engine)


@pytest.mark.asyncio
async def test_engine_refuses_empty_url() -> None:
    s = Settings(database_url=None, db_driver="postgres")
    with pytest.raises(ValueError, match="database_url"):
        create_engine_from_settings(s)


@pytest.mark.asyncio
async def test_engine_refuses_empty_string_url() -> None:
    s = Settings(database_url="", db_driver="postgres")
    with pytest.raises(ValueError, match="database_url"):
        create_engine_from_settings(s)
