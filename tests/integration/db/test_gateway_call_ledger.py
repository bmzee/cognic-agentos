"""Sprint 3 T5 live-DB integration tests — gateway_call_ledger
round-trip on real Postgres + Oracle.

End-to-end proof that the T4 migration + T5 ledger primitive
together produce a Postgres-and-Oracle-portable
``gateway_call_ledger`` row that round-trips cleanly with all
Round-6 reviewer-P1 fields (``upstream_api_base``, ``provenance``)
preserved + the ``ts`` column's ``TIMESTAMP WITH TIME ZONE``
semantics intact across both dialects.

Mirrors Sprint 2.5's integration-test shape:

  - Env-gated via ``COGNIC_RUN_POSTGRES_INTEGRATION=1`` /
    ``COGNIC_RUN_ORACLE_INTEGRATION=1`` + the corresponding
    ``COGNIC_DATABASE_URL_*_TEST`` superuser DSN. Without those,
    the tests self-skip cleanly so the unit suite stays hermetic.
  - Uses the SUPERUSER DSN — the runtime role's append-only
    constraint applies to ``audit_event`` / ``decision_history``
    (Sprint-2 chain-of-custody substrate) but NOT to
    ``gateway_call_ledger`` (operational ledger; ADR-007 §"two
    layers" explicitly rejects the chain-head locking pattern
    here). Even so, integration tests run as superuser to keep the
    cleanup posture consistent with the Sprint 2/2.5 substrate
    tests.
"""

from __future__ import annotations

import datetime as _dt
import os
import uuid

import pytest
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.llm.ledger import (
    GatewayCallLedger,
    GatewayCallRow,
    _ledger_table,
)


def _superuser_url(driver: str) -> str:
    """Read the superuser DSN env var. Tests guard with the matching
    ``@pytest.mark.skipif`` so the env var is always present here."""

    return os.environ[f"COGNIC_DATABASE_URL_{driver.upper()}_TEST"]


async def _reset_gateway_call_ledger(engine: AsyncEngine) -> None:
    """Wipe ``gateway_call_ledger`` so each parametrised case starts
    from a clean baseline. No chain-head reset needed — operational
    ledger has no chain head."""

    async with engine.begin() as conn:
        await conn.execute(delete(_ledger_table))


def _make_row(
    *,
    request_id: str = "req-integration",
    upstream_model: str = "ollama/qwen3:8b",
    upstream_api_base: str | None = "http://ollama:11434",
    external: bool = False,
    provenance: str = "resolved",
    outcome: str = "ok",
) -> GatewayCallRow:
    return GatewayCallRow(
        id=uuid.uuid4(),
        ts=_dt.datetime.now(_dt.UTC),
        request_id=request_id,
        tenant_id=None,
        tier="tier1",
        litellm_alias="cognic-tier1-dev",
        upstream_model=upstream_model,
        upstream_api_base=upstream_api_base,
        external=external,
        provenance=provenance,
        latency_ms=523,
        outcome=outcome,
        model_id=None,
    )


async def _drive_round_trip(engine: AsyncEngine) -> None:
    """Write four rows representing all three post-dispatch provenance
    states (``resolved``, ``unresolved``, ``ambiguous``) plus a
    self-hosted vLLM row + read them back. Asserts:

    - All four rows persist.
    - ``upstream_api_base`` round-trips (None + str both preserved).
    - ``provenance`` round-trips for all three dispatched-state values
      (``resolved`` / ``unresolved`` / ``ambiguous``). The
      ``no_dispatch`` value is exercised by unit tests; live-DB
      coverage focuses on the dispatched states that feed
      ``/effective-routing``'s drift detection.
    - ``ts`` is tz-aware on read-back (``TIMESTAMP WITH TIME ZONE``
      preserved on the dialect — Round-1 of T4 review).
    - Ordering is newest-first.
    """

    await _reset_gateway_call_ledger(engine)
    ledger = GatewayCallLedger(engine)

    now = _dt.datetime.now(_dt.UTC)
    rows_in = [
        GatewayCallRow(
            id=uuid.uuid4(),
            ts=now - _dt.timedelta(minutes=1),  # newest
            request_id="req-resolved",
            tenant_id="tenant-a",
            tier="tier1",
            litellm_alias="cognic-tier1-cloud-openai",
            upstream_model="openai/gpt-5.4",
            upstream_api_base=None,
            external=True,
            provenance="resolved",
            latency_ms=812,
            outcome="ok",
            model_id=None,
        ),
        # T5 review reviewer-P2: pin provenance="unresolved" round-trip
        # on real PG + Oracle. The post-dispatch fail-closed path
        # (gateway built _unresolved actual_resolved when LiteLLM
        # returned a model_string not declared in YAML, OR when the
        # response carried no model field) writes this exact shape;
        # ADR-007 provenance discipline depends on it round-tripping
        # correctly.
        GatewayCallRow(
            id=uuid.uuid4(),
            ts=now - _dt.timedelta(minutes=5),
            request_id="req-unresolved",
            tenant_id=None,
            tier="tier1",
            litellm_alias="cognic-tier1-cloud-openai",
            upstream_model="openai/gpt-7",  # not declared in any YAML route
            upstream_api_base=None,  # gateway refused to claim preflight's
            external=True,  # fail-closed
            provenance="unresolved",
            latency_ms=950,
            outcome="denied",  # post-response policy recheck denies
            model_id=None,
        ),
        GatewayCallRow(
            id=uuid.uuid4(),
            ts=now - _dt.timedelta(minutes=10),
            request_id="req-ambiguous",
            tenant_id=None,
            tier="tier1",
            litellm_alias="cognic-tier1-cloud-openai",
            upstream_model="openai/gpt-4o",
            upstream_api_base=None,
            external=True,
            provenance="ambiguous",
            latency_ms=1024,
            outcome="denied",
            model_id=None,
        ),
        GatewayCallRow(
            id=uuid.uuid4(),
            ts=now - _dt.timedelta(minutes=30),  # oldest
            request_id="req-vllm",
            tenant_id="tenant-b",
            tier="tier2",
            litellm_alias="cognic-tier1-vllm",
            upstream_model="openai/Qwen3-8B-Instruct",
            upstream_api_base="http://vllm:8000/v1",
            external=False,
            provenance="resolved",
            latency_ms=235,
            outcome="ok",
            model_id=None,
        ),
    ]

    for row in rows_in:
        await ledger.write_row(row)

    rows_out = await ledger.read_recent_calls(window_minutes=60)
    assert len(rows_out) == 4
    assert [r.request_id for r in rows_out] == [
        "req-resolved",
        "req-unresolved",
        "req-ambiguous",
        "req-vllm",
    ]

    # Round-6 reviewer-P1 fields round-trip:
    by_id = {r.request_id: r for r in rows_out}
    assert by_id["req-resolved"].upstream_api_base is None
    assert by_id["req-resolved"].provenance == "resolved"
    assert by_id["req-resolved"].external is True

    # T5 review reviewer-P2: provenance="unresolved" round-trips with
    # api_base=None preserved on the real dialect. Without this row
    # the Sprint 3 ADR-007 provenance discipline was unproven on
    # live PG/Oracle.
    assert by_id["req-unresolved"].provenance == "unresolved"
    assert by_id["req-unresolved"].upstream_api_base is None
    assert by_id["req-unresolved"].external is True
    assert by_id["req-unresolved"].outcome == "denied"
    assert by_id["req-unresolved"].upstream_model == "openai/gpt-7"

    assert by_id["req-ambiguous"].provenance == "ambiguous"
    assert by_id["req-ambiguous"].outcome == "denied"

    assert by_id["req-vllm"].upstream_api_base == "http://vllm:8000/v1"
    assert by_id["req-vllm"].provenance == "resolved"
    assert by_id["req-vllm"].external is False
    assert by_id["req-vllm"].tier == "tier2"

    # ``ts`` is tz-aware after the dialect round-trip (TIMESTAMP WITH
    # TIME ZONE preserves the offset on PG + Oracle; see T4 review
    # round 1).
    for row in rows_out:
        assert row.ts.tzinfo is not None, (
            f"row {row.request_id} lost tzinfo on round-trip — likely TIMESTAMP type regression"
        )


async def _assert_window_filter(engine: AsyncEngine) -> None:
    """Drive ``read_recent_calls`` against a row outside the window —
    must NOT be returned. Pins the WHERE-clause behaviour against the
    ``ts`` index that drives ``/effective-routing``'s recent-window
    query."""

    await _reset_gateway_call_ledger(engine)
    ledger = GatewayCallLedger(engine)

    now = _dt.datetime.now(_dt.UTC)
    in_window = _make_row(request_id="in-window")
    out_of_window = GatewayCallRow(
        id=uuid.uuid4(),
        ts=now - _dt.timedelta(hours=2),
        request_id="out-of-window",
        tenant_id=None,
        tier="tier1",
        litellm_alias="cognic-tier1-dev",
        upstream_model="ollama/qwen3:8b",
        upstream_api_base="http://ollama:11434",
        external=False,
        provenance="resolved",
        latency_ms=100,
        outcome="ok",
        model_id=None,
    )

    await ledger.write_row(in_window)
    await ledger.write_row(out_of_window)

    rows = await ledger.read_recent_calls(window_minutes=60)
    assert len(rows) == 1
    assert rows[0].request_id == "in-window"


# ---- Postgres ----------------------------------------------------------


_PG_SKIPIF = pytest.mark.skipif(
    not (
        os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION")
        and os.environ.get("COGNIC_DATABASE_URL_POSTGRES_TEST")
    ),
    reason=(
        "live Postgres required; set COGNIC_RUN_POSTGRES_INTEGRATION=1 "
        "+ apply migrations + export COGNIC_DATABASE_URL_POSTGRES_TEST"
    ),
)


@pytest.mark.postgres
@_PG_SKIPIF
async def test_gateway_call_ledger_round_trip_postgres() -> None:
    """Live Postgres: three rows write + read with all Round-6
    fields preserved + tz-aware ts."""
    engine = create_async_engine(_superuser_url("postgres"))
    try:
        await _drive_round_trip(engine)
    finally:
        await engine.dispose()


@pytest.mark.postgres
@_PG_SKIPIF
async def test_gateway_call_ledger_window_filter_postgres() -> None:
    """Live Postgres: ``ts`` index + WHERE clause exclude rows
    outside the window."""
    engine = create_async_engine(_superuser_url("postgres"))
    try:
        await _assert_window_filter(engine)
    finally:
        await engine.dispose()


# ---- Oracle ------------------------------------------------------------


_ORACLE_SKIPIF = pytest.mark.skipif(
    not (
        os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION")
        and os.environ.get("COGNIC_DATABASE_URL_ORACLE_TEST")
    ),
    reason=(
        "live Oracle XE required; set COGNIC_RUN_ORACLE_INTEGRATION=1 "
        "+ apply migrations + export COGNIC_DATABASE_URL_ORACLE_TEST"
    ),
)


@pytest.mark.oracle
@_ORACLE_SKIPIF
async def test_gateway_call_ledger_round_trip_oracle() -> None:
    """Live Oracle XE: three rows write + read with all Round-6
    fields preserved + tz-aware ts (Round-1 of T4 review:
    ``sa.TIMESTAMP(timezone=True)`` preserves the offset on Oracle;
    a regression to ``sa.DateTime(timezone=True)`` would compile to
    ``DATE`` and silently drop the tz here)."""
    engine = create_async_engine(_superuser_url("oracle"))
    try:
        await _drive_round_trip(engine)
    finally:
        await engine.dispose()


@pytest.mark.oracle
@_ORACLE_SKIPIF
async def test_gateway_call_ledger_window_filter_oracle() -> None:
    """Live Oracle XE: ``ts`` index + WHERE clause exclude rows
    outside the window."""
    engine = create_async_engine(_superuser_url("oracle"))
    try:
        await _assert_window_filter(engine)
    finally:
        await engine.dispose()
