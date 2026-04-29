"""Runtime-role append-only canary on real Postgres + Oracle.

Sprint 2 Task 12 — production-grade canary that the operator runbook
``docs/operator-runbooks/governance-tables-grants.md`` was applied.
Without this canary, "INSERT-only" is a code-discipline claim, not
a DB-enforced one — and code discipline can be bypassed by anyone
with raw SQL access.

For each chain (``audit_event`` + ``decision_history``) the canary
asserts three things via the **runtime-role DSN** (NOT a superuser):

1. **Positive append.** ``AuditStore.append()`` /
   ``DecisionHistoryStore.append()`` (the production runtime path,
   not raw SQL) succeeds. The new row lands in the evidence table
   with the returned ``record_id`` + ``sequence`` + ``hash``; the
   chain head moves to the new ``(sequence, hash)``; the chain still
   walks clean end-to-end. This proves the runtime role has all the
   privileges the production append transaction needs:
   INSERT + SELECT on the evidence table AND
   INSERT + SELECT + UPDATE on ``governance_chain_heads``.
2. **Denied UPDATE.** A raw ``UPDATE <evidence_table> SET ...``
   from the runtime-role DSN must raise the dialect's
   permission-denied error (PG: "permission denied for…"; Oracle:
   ``ORA-01031``). After the denial, the chain MUST still walk
   clean (the denied op didn't actually mutate anything).
3. **Denied DELETE.** Same shape for ``DELETE FROM <table>``.

Per the user's instruction: only ``AuditStore.append`` /
``DecisionHistoryStore.append`` mutate ``governance_chain_heads``.
The canary never directly UPDATEs the chain head — every mutation
flows through the production appender.

**Local self-skip.** Tests opt in via two env vars:

  - ``COGNIC_RUN_POSTGRES_INTEGRATION=1`` (or
    ``COGNIC_RUN_ORACLE_INTEGRATION=1``) — gates the live-DB
    integration suite.
  - ``COGNIC_RUNTIME_DATABASE_URL_POSTGRES_TEST`` (or
    ``..._ORACLE_TEST``) — DSN that connects as the GRANTed runtime
    role. Set this AFTER applying the operator runbook in your
    target environment.

If either is missing the test self-skips with a clear reason. CI's
``postgres-integration`` job provisions the role + sets both vars.
"""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import (
    AuditEvent,
    AuditStore,
    _audit_event,
    _chain_heads,
)
from cognic_agentos.core.chain_verifier import ChainVerifier
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    DecisionRecord,
    _decision_history,
)


def _runtime_url(driver: str) -> str:
    """Read the runtime-role DSN env var. Tests calling this guard
    with ``@pytest.mark.skipif`` so the env var is always present."""

    return os.environ[f"COGNIC_RUNTIME_DATABASE_URL_{driver.upper()}_TEST"]


def _evidence_table(chain_id: str):  # type: ignore[no-untyped-def]
    return _audit_event if chain_id == "audit_event" else _decision_history


async def _do_append(
    engine: AsyncEngine, chain_id: str, *, request_id: str
) -> tuple[uuid.UUID, bytes]:
    """Dispatch to the right Store.append for the parametrised chain."""

    if chain_id == "audit_event":
        return await AuditStore(engine).append(
            AuditEvent(
                event_type="canary",
                request_id=request_id,
                payload={"k": "v"},
            )
        )
    return await DecisionHistoryStore(engine).append(
        DecisionRecord(
            decision_type="canary",
            request_id=request_id,
            payload={"k": "v"},
        )
    )


def _assert_permission_denied(exc: BaseException) -> None:
    """Cross-dialect assertion that an exception is permission-denied.

    Postgres surfaces ``permission denied for table …``; Oracle
    surfaces ``ORA-01031: insufficient privileges``. Both also
    sometimes use the word ``privilege`` in error text. Match any.
    """

    msg = str(exc).lower()
    if not (
        "permission denied" in msg
        or "insufficient privilege" in msg
        or "ora-01031" in msg
        or "privilege" in msg
    ):
        raise AssertionError(f"expected permission-denied error from runtime role; got: {exc!r}")


# ---- shared canary bodies (both drivers reuse) ----------------------


async def _canary_can_append(driver: str, chain_id: str) -> None:
    """Positive: drive Store.append() through the runtime-role DSN.
    The row lands; chain head moves; chain still verifies clean."""

    engine = create_async_engine(_runtime_url(driver))
    try:
        # Capture pre-state of the chain head.
        async with engine.connect() as conn:
            head_pre = (
                await conn.execute(
                    select(
                        _chain_heads.c.latest_sequence,
                        _chain_heads.c.latest_hash,
                    ).where(_chain_heads.c.chain_id == chain_id)
                )
            ).one()
        prev_sequence = int(head_pre.latest_sequence)
        prev_hash = bytes(head_pre.latest_hash)

        # Drive the production appender — NOT raw SQL.
        record_id, h = await _do_append(
            engine,
            chain_id,
            request_id=f"canary-positive-{driver}-{chain_id}-{prev_sequence}",
        )

        # Verify the row landed with the expected sequence + hash.
        evidence = _evidence_table(chain_id)
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(
                        evidence.c.record_id,
                        evidence.c.sequence,
                        evidence.c.hash,
                        evidence.c.prev_hash,
                    ).where(evidence.c.record_id == record_id)
                )
            ).one()
        assert row.sequence == prev_sequence + 1
        assert bytes(row.hash) == h
        assert bytes(row.prev_hash) == prev_hash

        # Verify the chain head moved (proves runtime role can UPDATE
        # governance_chain_heads — and that AuditStore.append's
        # compare-and-set transaction succeeded under the runtime DSN).
        async with engine.connect() as conn:
            head_post = (
                await conn.execute(
                    select(
                        _chain_heads.c.latest_sequence,
                        _chain_heads.c.latest_hash,
                    ).where(_chain_heads.c.chain_id == chain_id)
                )
            ).one()
        assert head_post.latest_sequence == prev_sequence + 1
        assert bytes(head_post.latest_hash) == h

        # Chain still walks clean end-to-end.
        report = await ChainVerifier(engine, chain_id).walk()
        assert report.is_clean is True, f"chain dirty after positive canary: {report}"
    finally:
        await engine.dispose()


async def _canary_cannot_update(driver: str, chain_id: str) -> None:
    """Negative: raw UPDATE on the evidence table from the runtime DSN
    must fail with permission-denied. Chain still walks clean."""

    engine = create_async_engine(_runtime_url(driver))
    try:
        verifier = ChainVerifier(engine, chain_id)
        pre_report = await verifier.walk()
        assert pre_report.is_clean is True, f"chain dirty BEFORE denied-UPDATE canary: {pre_report}"

        with pytest.raises((DBAPIError, ProgrammingError)) as exc_info:
            async with engine.connect() as conn:
                await conn.execute(text(f"UPDATE {chain_id} SET payload = payload"))
        _assert_permission_denied(exc_info.value)

        # The denied op didn't actually mutate anything; chain still
        # walks clean and records_checked is unchanged.
        post_report = await verifier.walk()
        assert post_report.is_clean is True
        assert post_report.records_checked == pre_report.records_checked
    finally:
        await engine.dispose()


async def _canary_cannot_delete(driver: str, chain_id: str) -> None:
    """Negative: raw DELETE on the evidence table from the runtime DSN
    must fail with permission-denied. Chain still walks clean."""

    engine = create_async_engine(_runtime_url(driver))
    try:
        verifier = ChainVerifier(engine, chain_id)
        pre_report = await verifier.walk()
        assert pre_report.is_clean is True

        with pytest.raises((DBAPIError, ProgrammingError)) as exc_info:
            async with engine.connect() as conn:
                # WHERE 1=0 → matches no rows even if permission allowed,
                # so we can't accidentally damage anything across CI runs.
                await conn.execute(text(f"DELETE FROM {chain_id} WHERE 1=0"))
        _assert_permission_denied(exc_info.value)

        post_report = await verifier.walk()
        assert post_report.is_clean is True
        assert post_report.records_checked == pre_report.records_checked
    finally:
        await engine.dispose()


# ---- Postgres canary -----------------------------------------------


_PG_SKIPIF = pytest.mark.skipif(
    not (
        os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION")
        and os.environ.get("COGNIC_RUNTIME_DATABASE_URL_POSTGRES_TEST")
    ),
    reason=(
        "live Postgres + runtime-role DSN required; set "
        "COGNIC_RUN_POSTGRES_INTEGRATION=1 + apply the operator runbook + "
        "export COGNIC_RUNTIME_DATABASE_URL_POSTGRES_TEST"
    ),
)


@pytest.mark.postgres
@_PG_SKIPIF
@pytest.mark.parametrize("chain_id", ["audit_event", "decision_history"])
async def test_postgres_runtime_role_can_append(chain_id: str) -> None:
    await _canary_can_append("postgres", chain_id)


@pytest.mark.postgres
@_PG_SKIPIF
@pytest.mark.parametrize("chain_id", ["audit_event", "decision_history"])
async def test_postgres_runtime_role_cannot_update_evidence(chain_id: str) -> None:
    await _canary_cannot_update("postgres", chain_id)


@pytest.mark.postgres
@_PG_SKIPIF
@pytest.mark.parametrize("chain_id", ["audit_event", "decision_history"])
async def test_postgres_runtime_role_cannot_delete_evidence(chain_id: str) -> None:
    await _canary_cannot_delete("postgres", chain_id)


# ---- Oracle canary --------------------------------------------------


_ORACLE_SKIPIF = pytest.mark.skipif(
    not (
        os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION")
        and os.environ.get("COGNIC_RUNTIME_DATABASE_URL_ORACLE_TEST")
    ),
    reason=(
        "live Oracle XE + runtime-role DSN required; set "
        "COGNIC_RUN_ORACLE_INTEGRATION=1 + apply the operator runbook + "
        "export COGNIC_RUNTIME_DATABASE_URL_ORACLE_TEST"
    ),
)


@pytest.mark.oracle
@_ORACLE_SKIPIF
@pytest.mark.parametrize("chain_id", ["audit_event", "decision_history"])
async def test_oracle_runtime_role_can_append(chain_id: str) -> None:
    await _canary_can_append("oracle", chain_id)


@pytest.mark.oracle
@_ORACLE_SKIPIF
@pytest.mark.parametrize("chain_id", ["audit_event", "decision_history"])
async def test_oracle_runtime_role_cannot_update_evidence(chain_id: str) -> None:
    await _canary_cannot_update("oracle", chain_id)


@pytest.mark.oracle
@_ORACLE_SKIPIF
@pytest.mark.parametrize("chain_id", ["audit_event", "decision_history"])
async def test_oracle_runtime_role_cannot_delete_evidence(chain_id: str) -> None:
    await _canary_cannot_delete("oracle", chain_id)
