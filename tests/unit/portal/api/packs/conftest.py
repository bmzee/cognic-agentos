"""Sprint 7B.3 T9 — shared SQLite ``engine`` + ``store`` fixtures for the
pack-router approve-endpoint test files.

These two fixtures live in a ``conftest.py`` (not a test module) so
``test_review_approve_5_gate.py`` / ``test_review_approve_override.py``
/ the two ``*_trust_gate_wiring.py`` files can request them as plain
parameters WITHOUT importing — importing a ``@pytest.fixture`` into a
test module + then naming a test parameter the same triggers ruff
``F811``.

Pytest's fixture-override semantics mean any test module in this
directory that defines its OWN ``engine`` / ``store`` fixture (e.g.
``test_review_routes.py``, ``test_operator_routes.py``) shadows these —
so the pre-existing pack-router test files are unaffected; this
conftest only ADDS a fallback for the T9 approve-endpoint files.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.packs.storage import PackRecordStore


@pytest.fixture
async def engine(tmp_path: Any) -> AsyncIterator[AsyncEngine]:
    """SQLite engine seeded with the governance schema + the two chain
    heads — mirrors ``test_review_routes.py::engine``."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'approve_routes.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    yield eng
    await eng.dispose()


@pytest.fixture
async def store(engine: AsyncEngine) -> PackRecordStore:
    return PackRecordStore(engine)
