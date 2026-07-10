"""ADR-028 P0 fencing — real-Postgres concurrency canary (env-gated).

Opt in with COGNIC_RUN_POSTGRES_INTEGRATION=1 + COGNIC_DATABASE_URL_POSTGRES_TEST
(the compose PG service + applied migrations), mirroring
tests/integration/packs/test_storage_lock_serialisation.py.

sqlite serialises writers, so the unit suite proves fencing LOGIC only; this
canary proves it under real row locks and genuinely concurrent connections:

  1. N concurrent claim_turn racers -> EXACTLY ONE TurnClaim; every loser gets
     conversation_turn_in_progress.
  2. The lost-lease race on real PG: A claims with a tiny TTL, stalls; B steals;
     delayed A's append refuses conversation_turn_claim_stale and its release
     is a no-op -- B's lease survives and B's own append lands.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.conversation._types import ConversationTurnRefused, TurnClaim
from cognic_agentos.core.conversation.storage import (
    ConversationStore,
    _conversation_turns,
    _conversations,
)
from cognic_agentos.core.decision_history import _decision_history

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.postgres,
    pytest.mark.skipif(
        not (
            os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION")
            and os.environ.get("COGNIC_DATABASE_URL_POSTGRES_TEST")
        ),
        reason=(
            "live Postgres integration; opt in via COGNIC_RUN_POSTGRES_INTEGRATION=1 "
            "+ export COGNIC_DATABASE_URL_POSTGRES_TEST"
        ),
    ),
]


@pytest.fixture
async def pg_engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(os.environ["COGNIC_DATABASE_URL_POSTGRES_TEST"])
    async with engine.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        await conn.execute(delete(_conversation_turns))
        await conn.execute(delete(_conversations))
        await conn.execute(delete(_decision_history))
        for chain_id in ("audit_event", "decision_history"):
            result = await conn.execute(
                update(_chain_heads)
                .where(_chain_heads.c.chain_id == chain_id)
                .values(latest_sequence=0, latest_hash=ZERO_HASH)
            )
            if result.rowcount == 0:
                await conn.execute(
                    _chain_heads.insert().values(
                        chain_id=chain_id,
                        latest_sequence=0,
                        latest_hash=ZERO_HASH,
                        updated_at=datetime.now(UTC),
                    )
                )
    yield engine
    await engine.dispose()


async def _conversation(store: ConversationStore) -> uuid.UUID:
    cid = uuid.uuid4()
    await store.create_conversation(
        conversation_id=cid,
        tenant_id="t1",
        agent_id="analyst",
        creator_subject="s1",
        request_id="req-pg-create",
    )
    return cid


async def test_concurrent_claims_exactly_one_wins(pg_engine: AsyncEngine) -> None:
    store = ConversationStore(pg_engine)
    cid = await _conversation(store)

    async def _race() -> TurnClaim | ConversationTurnRefused:
        try:
            return await store.claim_turn(
                cid,
                tenant_id="t1",
                creator_subject="s1",
                now=datetime.now(UTC),
                claim_ttl_s=300.0,
            )
        except ConversationTurnRefused as exc:
            return exc

    results = await asyncio.gather(*(_race() for _ in range(8)))
    wins = [r for r in results if isinstance(r, TurnClaim)]
    losses = [r for r in results if isinstance(r, ConversationTurnRefused)]
    assert len(wins) == 1, f"expected exactly one winner, got {len(wins)}"
    assert len(losses) == 7
    assert all(loss.reason == "conversation_turn_in_progress" for loss in losses)


async def test_lost_lease_race_is_fenced_on_real_pg(pg_engine: AsyncEngine) -> None:
    store = ConversationStore(pg_engine)
    cid = await _conversation(store)

    # claim_ttl_s is ONE executor-wide constant in deployment; both workers
    # must judge staleness by the same TTL. (The first live run of this canary
    # caught exactly this: B passing a large TTL reads A's tiny lease as live.)
    ttl = 0.05
    claim_a = await store.claim_turn(
        cid,
        tenant_id="t1",
        creator_subject="s1",
        now=datetime.now(UTC),
        claim_ttl_s=ttl,  # tiny TTL: A stalls past it
    )
    await asyncio.sleep(0.1)
    claim_b = await store.claim_turn(
        cid,
        tenant_id="t1",
        creator_subject="s1",
        now=datetime.now(UTC),
        claim_ttl_s=ttl,
    )
    assert claim_a.claim_id != claim_b.claim_id

    with pytest.raises(ConversationTurnRefused) as exc:
        await store.append_turn(
            conversation_id=cid,
            tenant_id="t1",
            seq=1,
            user_message="delayed A",
            answer="must not land",
            agent_run_id="agent-run-A",
            prompt_tokens=1,
            completion_tokens=1,
            actor_id="s1",
            request_id="req-pg-stale",
            claim_id=claim_a.claim_id,
        )
    assert exc.value.reason == "conversation_turn_claim_stale"

    await store.release_claim(cid, tenant_id="t1", claim_id=claim_a.claim_id)  # no-op

    turn_id = await store.append_turn(
        conversation_id=cid,
        tenant_id="t1",
        seq=1,
        user_message="B's turn",
        answer="lands",
        agent_run_id="agent-run-B",
        prompt_tokens=1,
        completion_tokens=1,
        actor_id="s1",
        request_id="req-pg-b",
        claim_id=claim_b.claim_id,
    )
    assert turn_id is not None
    await store.release_claim(cid, tenant_id="t1", claim_id=claim_b.claim_id)
