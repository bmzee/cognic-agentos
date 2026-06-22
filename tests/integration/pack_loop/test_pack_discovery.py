"""Proof 1a Task 1 - the example pack is discoverable as a cognic.tools entry point.

Env-gated: requires the pack to be pip-installed into the venv (its distribution
metadata is read by PluginRegistry.discover()). Skips when not installed so the
default unit run stays green; the proof harness installs it.
"""

import datetime as dt
import importlib.util
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _audit_event, _chain_heads
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.protocol.plugin_registry import PluginRegistry

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("cognic_tool_search") is None,
    reason="cognic-tool-search not installed; run `uv pip install -e examples/cognic-tool-search`",
)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'pack_loop_discovery.db'}"
    eng = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_audit_event.metadata.create_all)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=dt.datetime.now(dt.UTC),
            )
        )
    yield eng
    await eng.dispose()


@pytest.fixture
def registry(engine: AsyncEngine) -> PluginRegistry:
    return PluginRegistry(audit_store=AuditStore(engine))


def test_discover_finds_cognic_tool_search(registry: PluginRegistry) -> None:
    records = [p.record for p in registry.discover()]
    matches = [r for r in records if r.distribution_name == "cognic-tool-search"]
    assert len(matches) == 1, f"expected exactly one cognic-tool-search record, got {matches}"
    rec = matches[0]
    assert rec.kind == "tools"
    assert rec.name == "search_policy_docs"
    assert rec.entry_point_value == "cognic_tool_search:SERVER_DESCRIPTOR"
    assert rec.distribution_version == "0.1.0"
