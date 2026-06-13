"""Sprint 13.6b T6 (ADR-018) — real-Redis atomicity proof for QuotaEngine.

ENV-GATED (the Vault-Z2 precedent): skipped by default; opt in with
``COGNIC_RUN_REDIS_INTEGRATION=1`` + ``COGNIC_REDIS_TEST_URL=<redis url>``.
When opted in but the URL is missing, the suite FAILS LOUD (AssertionError,
NOT pytest.skip) — an operator who asked for the proof must not get a silent
skip.

Proves the decomposed-counter contract holds under TRUE cross-coroutine
concurrency against a live ``redis.asyncio.Redis`` (the dict-fake's
single-loop determinism cannot): N concurrent ``would_admit`` admit AT MOST
the limit (no over-admission), and ``release_reservation`` is exactly-once.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.emergency.quotas import (
    QuotaEngine,
    _reservation_key,
    _reserved_tenant_key,
)

_OPTED_IN = os.environ.get("COGNIC_RUN_REDIS_INTEGRATION") == "1"

pytestmark = pytest.mark.skipif(
    not _OPTED_IN,
    reason=(
        "live Redis atomicity proof; opt in via COGNIC_RUN_REDIS_INTEGRATION=1 "
        "+ COGNIC_REDIS_TEST_URL=<redis url> (e.g. redis://localhost:6379/15)"
    ),
)

_WINDOW = "20260613"


def _require_url() -> str:
    url = os.environ.get("COGNIC_REDIS_TEST_URL")
    # Fail LOUD when opted in but unconfigured (NOT a silent skip).
    assert url, (
        "COGNIC_RUN_REDIS_INTEGRATION=1 but COGNIC_REDIS_TEST_URL is unset — "
        "set it to a disposable Redis DB (e.g. redis://localhost:6379/15)"
    )
    return url


def _engine(client: Any, *, limit: int) -> QuotaEngine:
    settings = build_settings_without_env_file().model_copy(
        update={
            "quota_tokens_per_tenant_per_day": limit,
            "quota_tokens_per_pack_per_day": limit,
        }
    )
    return QuotaEngine(
        redis_client=client,
        settings=settings,
        clock=lambda: datetime(2026, 6, 13, 12, 0, tzinfo=UTC),
    )


@pytest.mark.asyncio
async def test_concurrent_would_admit_never_over_admits() -> None:
    import redis.asyncio as aioredis

    client = aioredis.Redis.from_url(_require_url(), decode_responses=True)
    tenant = f"t-{uuid.uuid4().hex[:12]}"  # unique keyspace per run
    task_ids = [uuid.uuid4() for _ in range(20)]
    try:
        eng = _engine(client, limit=1000)
        # 20 concurrent reservations of 100 each; exactly 10 fit (10*100=1000).
        tasks = [
            eng.would_admit(task_id=task_id, tenant_id=tenant, pack_id="p1", estimated_tokens=100)
            for task_id in task_ids
        ]
        results = await asyncio.gather(*tasks)
        admitted = sum(1 for r in results if r is True)
        assert admitted == 10, f"over/under-admission under concurrency: {admitted} admitted"
        # The reserved counter reflects exactly the admitted total (no leak past
        # the limit; rolled-back refusals left no residue).
        reserved = int(await client.get(_reserved_tenant_key(tenant, _WINDOW)) or 0)
        assert reserved == 1000
    finally:
        # Best-effort cleanup of this run's keyspace.
        async for key in client.scan_iter(match=f"cognic:quota:*:{tenant}:*"):
            await client.delete(key)
        for task_id in task_ids:
            await client.delete(_reservation_key(task_id))
        await client.aclose()


@pytest.mark.asyncio
async def test_release_is_exactly_once_under_concurrency() -> None:
    import redis.asyncio as aioredis

    client = aioredis.Redis.from_url(_require_url(), decode_responses=True)
    tenant = f"t-{uuid.uuid4().hex[:12]}"
    try:
        eng = _engine(client, limit=10000)
        tid = uuid.uuid4()
        assert await eng.would_admit(
            task_id=tid, tenant_id=tenant, pack_id="p1", estimated_tokens=500
        )
        # 5 concurrent releases of the SAME task_id → GETDEL exactly-once means
        # the counter decrements by 500 ONCE (never 5 times).
        await asyncio.gather(*[eng.release_reservation(tid) for _ in range(5)])
        reserved = int(await client.get(_reserved_tenant_key(tenant, _WINDOW)) or 0)
        assert reserved == 0, f"double-release leaked: reserved={reserved}"
    finally:
        async for key in client.scan_iter(match=f"cognic:quota:*:{tenant}:*"):
            await client.delete(key)
        await client.aclose()
