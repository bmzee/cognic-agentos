"""Shared fixtures for the agent-loop conformance package.

The database is a MIGRATED sqlite file, never ``create_all`` — migration-only
constraints are part of what these tests are meant to exercise
(``feedback_storage_test_migrated_db_not_create_all``).
"""

from __future__ import annotations

import asyncio
import importlib.metadata as _im
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    """A real Alembic-migrated sqlite engine."""
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'conformance.db'}"
    await asyncio.to_thread(command.upgrade, make_alembic_config(url), "head")
    eng = create_async_engine(url)
    yield eng
    await eng.dispose()


@pytest.fixture
def metadata_env(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Redirect distribution LOOKUP to a mutable fake list.

    Only resolution is redirected. ``locate_file`` is supplied by ``FakeDist``
    (see ``_synthetic``), and the extractors' own logic runs for real against
    real bytes on disk. ``agent_manifest`` and ``mcp_manifest`` bind the same
    ``importlib.metadata`` module object, so one patch site covers both.
    """
    dists: list[Any] = []

    def _distribution(name: str) -> Any:
        for dist in dists:
            if dist.metadata["Name"] == name:
                return dist
        raise _im.PackageNotFoundError(name)

    def _distributions() -> Any:
        return iter(list(dists))

    monkeypatch.setattr(_im, "distribution", _distribution)
    monkeypatch.setattr(_im, "distributions", _distributions)
    return dists
