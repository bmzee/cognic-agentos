"""M8 Task A4 (ADR-027 / spec §3.1) — AssignmentStore over the Alembic-MIGRATED
aiosqlite DB (per ``feedback_storage_test_migrated_db_not_create_all``).

THE INGESTION INVARIANT (fail-closed): a granted row outside the persona's
REQUESTED set refuses at load with ``AgentGrantNotRequested``
(``agent_grant_not_requested``) — NO partial grant set is ever returned, so
operator/config drift can never widen an agent beyond its requested set.
Kind-partitioning is part of the invariant: a ref requested as a skill but
granted as kind="tool" (and vice versa) is out-of-request. The defensive
unknown-kind arm (DB-impossible under the CHECK constraint) is pinned via the
pure ``_validate_and_partition`` helper directly.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.agent._types import (
    AgentGrantNotRequested,
    GrantedCapabilities,
    LoadedAgentRecord,
)
from cognic_agentos.core.agent.assignments import (
    AssignmentStore,
    _agent_assignments,
    _validate_and_partition,
)

_REQUESTED_TOOL = "cognic-tool-oracle-schema/run_readonly_query"


def _record(**overrides: Any) -> LoadedAgentRecord:
    base: dict[str, Any] = {
        "agent_id": "bank-analyst",
        "persona_body": "You are the bank analyst.",
        "persona_sha256": "a" * 64,
        "requested_skills": ("customer-data", "financial-data"),
        "requested_tools": (_REQUESTED_TOOL,),
        "max_steps": 6,
        "risk_tier": "customer_data_read",
        "pack_version": "0.1.0",
        "signed_artefact_digest": None,
        "registered": True,
    }
    base.update(overrides)
    return LoadedAgentRecord(**base)


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    # Migrated DB — NOT create_all (feedback_storage_test_migrated_db_not_create_all).
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'assignments.db'}"
    await asyncio.to_thread(command.upgrade, make_alembic_config(url), "head")
    eng = create_async_engine(url)
    yield eng
    await eng.dispose()


@pytest.fixture
def store(engine: AsyncEngine) -> AssignmentStore:
    return AssignmentStore(engine)


async def _seed_assignment(
    engine: AsyncEngine,
    *,
    tenant_id: str = "t1",
    agent_id: str = "bank-analyst",
    capability_kind: str,
    capability_ref: str,
) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            sa.insert(_agent_assignments).values(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                agent_id=agent_id,
                capability_kind=capability_kind,
                capability_ref=capability_ref,
                created_at=datetime.now(UTC),
            )
        )


# --------------------------------------------------------------------------- #
# Happy path: granted ⊆ requested
# --------------------------------------------------------------------------- #


async def test_load_for_agent_granted_subset_happy_path(
    engine: AsyncEngine, store: AssignmentStore
) -> None:
    await _seed_assignment(engine, capability_kind="skill", capability_ref="customer-data")
    await _seed_assignment(engine, capability_kind="skill", capability_ref="financial-data")
    await _seed_assignment(engine, capability_kind="tool", capability_ref=_REQUESTED_TOOL)

    granted = await store.load_for_agent(tenant_id="t1", agent_id="bank-analyst", record=_record())

    assert granted == GrantedCapabilities(
        skills=frozenset({"customer-data", "financial-data"}),
        tools=frozenset({_REQUESTED_TOOL}),
    )


async def test_load_for_agent_no_rows_returns_empty_grants(store: AssignmentStore) -> None:
    granted = await store.load_for_agent(tenant_id="t1", agent_id="bank-analyst", record=_record())
    assert granted == GrantedCapabilities(skills=frozenset(), tools=frozenset())


# --------------------------------------------------------------------------- #
# THE INGESTION INVARIANT (spec §3.1, fail-closed)
# --------------------------------------------------------------------------- #


async def test_ingestion_invariant_out_of_request_skill_refuses_no_partial(
    engine: AsyncEngine, store: AssignmentStore
) -> None:
    # One out-of-request row AMONG valid ones: the load raises, period — no
    # partial grant set is ever returned (the call has no return value to
    # inspect; the raise IS the fail-closed contract).
    await _seed_assignment(engine, capability_kind="skill", capability_ref="customer-data")
    await _seed_assignment(engine, capability_kind="tool", capability_ref=_REQUESTED_TOOL)
    await _seed_assignment(engine, capability_kind="skill", capability_ref="atm-recon")

    with pytest.raises(AgentGrantNotRequested) as exc_info:
        await store.load_for_agent(tenant_id="t1", agent_id="bank-analyst", record=_record())

    assert exc_info.value.reason == "agent_grant_not_requested"
    assert exc_info.value.capability_ref == "atm-recon"


async def test_kind_partitioning_skill_ref_granted_as_tool_refused(
    engine: AsyncEngine, store: AssignmentStore
) -> None:
    # "customer-data" IS in requested_skills — but granted as kind="tool" it is
    # out-of-request (the requested sets partition by kind).
    await _seed_assignment(engine, capability_kind="tool", capability_ref="customer-data")

    with pytest.raises(AgentGrantNotRequested) as exc_info:
        await store.load_for_agent(tenant_id="t1", agent_id="bank-analyst", record=_record())
    assert exc_info.value.capability_ref == "customer-data"


async def test_kind_partitioning_tool_ref_granted_as_skill_refused(
    engine: AsyncEngine, store: AssignmentStore
) -> None:
    # The requested tool ref granted as kind="skill" is equally out-of-request.
    await _seed_assignment(engine, capability_kind="skill", capability_ref=_REQUESTED_TOOL)

    with pytest.raises(AgentGrantNotRequested) as exc_info:
        await store.load_for_agent(tenant_id="t1", agent_id="bank-analyst", record=_record())
    assert exc_info.value.capability_ref == _REQUESTED_TOOL


# --------------------------------------------------------------------------- #
# Tenant isolation
# --------------------------------------------------------------------------- #


async def test_wrong_tenant_rows_invisible(engine: AsyncEngine, store: AssignmentStore) -> None:
    # Same agent_id under a DIFFERENT tenant: rows are invisible to t1 — the
    # WHERE tenant_id IS the boundary (empty grant, NOT a refusal).
    await _seed_assignment(
        engine, tenant_id="t2", capability_kind="skill", capability_ref="customer-data"
    )
    granted = await store.load_for_agent(tenant_id="t1", agent_id="bank-analyst", record=_record())
    assert granted == GrantedCapabilities(skills=frozenset(), tools=frozenset())


# --------------------------------------------------------------------------- #
# The defensive unknown-kind arm (pure helper, DB-impossible)
# --------------------------------------------------------------------------- #


def test_validate_and_partition_defensive_unknown_kind_refuses() -> None:
    # Built-ins are kernel-owned and implicitly granted at dispatch — NEVER
    # assignment rows. The DB CHECK constraint makes this row unrepresentable;
    # the pure validator refuses it anyway (defense in depth).
    with pytest.raises(AgentGrantNotRequested) as exc_info:
        _validate_and_partition([("builtin", "read_skill")], _record())
    assert exc_info.value.reason == "agent_grant_not_requested"
    assert exc_info.value.capability_ref == "read_skill"
