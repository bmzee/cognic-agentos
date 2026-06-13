"""Sprint 13.6b T2 — gateway_call_ledger token/cost evidence columns (ADR-018 F6).

Pins the three NULLABLE additive columns (`prompt_tokens`, `completion_tokens`,
`estimated_cost_usd`) on `GatewayCallRow` + `_ledger_table`: existing call
sites stay None-default; `write_row` roundtrips NULLs AND values; the new
`quota_exhausted` ledger outcome is accepted.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.llm.ledger import (
    _ALLOWED_OUTCOMES,
    GatewayCallLedger,
    GatewayCallRow,
    _ledger_table,
)


@pytest.fixture
async def sqlite_engine_with_ledger(tmp_path: Any) -> Any:
    url = f"sqlite+aiosqlite:///{tmp_path / 'ledger_quota.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_ledger_table.metadata.create_all)
    yield eng
    await eng.dispose()


def _row(**overrides: Any) -> GatewayCallRow:
    base: dict[str, Any] = {
        "id": uuid.uuid4(),
        "ts": _dt.datetime.now(_dt.UTC),
        "request_id": f"req-{uuid.uuid4().hex[:8]}",
        "tenant_id": "t1",
        "tier": "tier1",
        "litellm_alias": "cognic-tier1-dev",
        "upstream_model": "ollama/qwen3:8b",
        "upstream_api_base": "http://ollama:11434",
        "external": False,
        "provenance": "resolved",
        "latency_ms": 523,
        "outcome": "ok",
        "model_id": None,
    }
    base.update(overrides)
    return GatewayCallRow(**base)


class TestNewFieldsBackwardCompatible:
    def test_construct_without_new_fields_defaults_none(self) -> None:
        # The pre-13.6b call shape (no quota fields) still constructs.
        row = _row()
        assert row.prompt_tokens is None
        assert row.completion_tokens is None
        assert row.estimated_cost_usd is None

    def test_construct_with_token_values(self) -> None:
        row = _row(prompt_tokens=120, completion_tokens=45, estimated_cost_usd=None)
        assert row.prompt_tokens == 120
        assert row.completion_tokens == 45


class TestAllowedOutcomes:
    def test_quota_exhausted_is_an_allowed_outcome(self) -> None:
        assert "quota_exhausted" in _ALLOWED_OUTCOMES

    def test_quota_exhausted_row_constructs(self) -> None:
        assert _row(outcome="quota_exhausted").outcome == "quota_exhausted"


class TestWriteRowRoundtrip:
    async def test_roundtrips_token_values(self, sqlite_engine_with_ledger: AsyncEngine) -> None:
        ledger = GatewayCallLedger(sqlite_engine_with_ledger)
        rid = f"req-{uuid.uuid4().hex[:8]}"
        await ledger.write_row(_row(request_id=rid, prompt_tokens=120, completion_tokens=45))
        async with sqlite_engine_with_ledger.connect() as conn:
            r = (
                await conn.execute(
                    sa.select(
                        _ledger_table.c.prompt_tokens,
                        _ledger_table.c.completion_tokens,
                        _ledger_table.c.estimated_cost_usd,
                    ).where(_ledger_table.c.request_id == rid)
                )
            ).one()
        assert (r.prompt_tokens, r.completion_tokens, r.estimated_cost_usd) == (120, 45, None)

    async def test_roundtrips_nulls(self, sqlite_engine_with_ledger: AsyncEngine) -> None:
        ledger = GatewayCallLedger(sqlite_engine_with_ledger)
        rid = f"req-{uuid.uuid4().hex[:8]}"
        await ledger.write_row(_row(request_id=rid))  # no quota fields → all NULL
        async with sqlite_engine_with_ledger.connect() as conn:
            r = (
                await conn.execute(
                    sa.select(
                        _ledger_table.c.prompt_tokens,
                        _ledger_table.c.completion_tokens,
                        _ledger_table.c.estimated_cost_usd,
                    ).where(_ledger_table.c.request_id == rid)
                )
            ).one()
        assert (r.prompt_tokens, r.completion_tokens, r.estimated_cost_usd) == (None, None, None)
