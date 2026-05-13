"""Sprint 7B.1 T3 — pack-record store ``SELECT ... FOR UPDATE``
serialisation proof on real Postgres + Oracle.

Mirrors ``tests/integration/db/test_concurrent_append.py`` (Sprint 2
T12) and ``tests/integration/db/test_sprint_2_5_chain_integration.py``
(Sprint 2.5 T8 / T9):

  - **Env-gated** via ``COGNIC_RUN_POSTGRES_INTEGRATION=1`` /
    ``COGNIC_RUN_ORACLE_INTEGRATION=1`` + the matching
    ``COGNIC_DATABASE_URL_*_TEST`` superuser DSN. Without those, the
    tests self-skip cleanly so the unit suite stays fast and hermetic.
  - **Superuser DSN** because the test resets chain + pack state via
    raw SQL. Same posture as the Sprint-2 + Sprint-2.5 integration
    suites.

Four canaries (per the plan-of-record T3 §"PG/Oracle integration tests";
the canary count grew from three to four at T3 R1 P2 #3 reviewer fix
when the barrier-based pack-row lock isolation proof landed):

  1. **Competing-transition serialisation (chain-head + pack-row locks
     in COMBINATION).** Two concurrent ``transition()`` calls for the
     same pack record fired via ``asyncio.gather(...)``; exactly one
     wins; the loser's ``validate_transition`` runs against the new
     (already-advanced) state and raises
     :class:`LifecycleTransitionRefused`. Loser's transaction rolls
     back cleanly; chain count incremented exactly once; final state
     cache reflects the winner's transition.

     This canary races at the chain-head FOR UPDATE lock owned by
     ``DecisionHistoryStore.append_with_precondition`` and would still
     pass if the per-pack-row ``with_for_update()`` were removed
     (chain-head lock alone serialises the two callers). The
     pack-row-lock-isolation proof lives in canary #2 below — see
     T3 R1 P2 #3 reviewer fix.
  2. **Pack-row FOR UPDATE forces post-commit state read
     (BARRIER-BASED ISOLATION proof per Doctrine Lock D).**
     Strengthened design at T3 R2 P2 reviewer feedback: the original
     R1 design only proved T2 eventually blocks somewhere; the
     strengthened design proves the precondition's SELECT acquires
     the row lock BEFORE state is read.

     Transaction T1 acquires a raw ``SELECT ... FOR UPDATE`` on the
     pack row WITHOUT touching the chain-head row, then mutates
     ``packs.state`` to ``"withdrawn"`` under the lock (a state from
     which ``transition="submit"`` is invalid), and awaits a release
     barrier (asyncio.Event). Transaction T2 calls
     :meth:`PackRecordStore.transition` with ``transition="submit"``.
     T2 acquires the chain-head FOR UPDATE freely (T1 doesn't hold
     it), then attempts the precondition's
     ``SELECT ... FOR UPDATE`` on the same pack row — and MUST
     BLOCK on T1's lock. The test asserts T2 is still pending after
     a generous sleep window, then releases T1; T1 commits
     ``state="withdrawn"``; T2 unblocks, reads the post-commit
     ``"withdrawn"`` under its FOR UPDATE, ``validate_transition``
     refuses with ``lifecycle_transition_invalid_state_pair``, the
     transaction rolls back, no chain row is emitted, and
     ``packs.state`` remains T1's ``"withdrawn"`` (T2's intended
     UPDATE never fired).

     The four distinguishing assertions
     (refused / right-reason / no-chain-row / state-preserved)
     each catch a different broken-precondition scenario
     independently: a stale-MVCC-read T2 would succeed (catches #1),
     a wrong-reason refusal would mean the validator received bad
     state (catches #2), a falsified chain row would have
     ``from_state="draft"`` despite the row being ``"withdrawn"`` at
     commit time (catches #3), and a lost T1-update would mean T2's
     UPDATE overwrote ``"withdrawn"`` (catches #4). Together they
     prove Doctrine Lock D step 1's future-writer safety guarantee
     independent of any non-state-column writer AND prove the
     SELECT itself is the lock-acquiring statement (not just the
     defence-in-depth UPDATE that follows).
  3. **CHECK constraint enforcement on ``packs.kind``.** Direct DB
     INSERT with ``kind='workflow'`` raises an ``IntegrityError`` —
     pinned at the database layer (Doctrine Lock E layer 2 / 3).
  4. **CHECK constraint enforcement on ``packs.state``.** Direct DB
     INSERT with ``state='quarantined'`` raises an ``IntegrityError``.

Note: T4 lands the Alembic migration that creates ``packs`` on real
PG / Oracle. Until T4, these integration tests rely on
``_metadata.create_all(conn)`` to create ``packs`` alongside the
chain tables — the Sprint-7B.1/T3 ``_packs`` Table object (defined
in ``cognic_agentos.packs.storage`` and registered against the
Sprint-2 shared ``_metadata`` from ``cognic_agentos.core.audit`` at
storage-module import time) makes this work without dependency on
the migration version file. The shared ``_metadata`` itself is
Sprint-2 (``audit_event`` + ``decision_history`` +
``governance_chain_heads``); ``_packs`` is the new Sprint-7B.1
addition. (T3 R2 P3 doctrine attribution fix.)
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.packs.storage import (
    LifecycleTransitionRefused,
    PackRecord,
    PackRecordStore,
    _packs,
)

# ---- env-gate skipifs ------------------------------------------------


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


def _superuser_url(driver: str) -> str:
    return os.environ[f"COGNIC_DATABASE_URL_{driver.upper()}_TEST"]


async def _reset_state(engine: AsyncEngine) -> None:
    """Wipe packs + decision_history rows + reset the chain head to
    genesis. Each parameterisation starts from a clean baseline."""

    async with engine.begin() as conn:
        # Ensure packs + chain tables exist; harmless if already
        # created by the Alembic migration (CREATE TABLE IF NOT EXISTS
        # semantics via SQLAlchemy ``checkfirst``).
        await conn.run_sync(_metadata.create_all)
        await conn.execute(delete(_packs))
        await conn.execute(delete(_decision_history))
        await conn.execute(
            update(_chain_heads)
            .where(_chain_heads.c.chain_id == "decision_history")
            .values(latest_sequence=0, latest_hash=ZERO_HASH)
        )


def _make_record(*, kind: str = "tool", state: str = "draft") -> PackRecord:
    now = datetime.now(UTC)
    return PackRecord(
        id=uuid.uuid4(),
        kind=kind,  # type: ignore[arg-type]
        pack_id="cognic-tool-canary",
        display_name="canary",
        state=state,  # type: ignore[arg-type]
        manifest_digest=b"\x01" * 32,
        signed_artefact_digest=b"\x02" * 32,
        sbom_pointer=None,
        tenant_id=None,
        created_by="canary",
        last_actor="canary",
        created_at=now,
        updated_at=now,
    )


# ---- canary 1: row-lock serialisation under contention ---------------


async def _canary_row_lock_serialisation(driver: str) -> None:
    """Two concurrent ``transition(submit)`` calls for the same pack
    record — exactly one wins; the loser sees the new head state and
    raises :class:`LifecycleTransitionRefused`.

    The serialisation here is dominated by the chain-head FOR UPDATE
    lock owned by ``DecisionHistoryStore.append_with_precondition``;
    the per-pack-row ``with_for_update()`` IS independently proven by
    the barrier-based canary
    :func:`_canary_pack_row_lock_blocks_competing_transition` (T3 R1
    P2 #3 reviewer fix)."""

    engine = create_async_engine(
        _superuser_url(driver),
        pool_size=4,
        max_overflow=0,
    )
    try:
        await _reset_state(engine)

        store = PackRecordStore(engine)
        rec = _make_record()
        await store.save_draft(rec)

        async def _do_submit(label: str) -> tuple[uuid.UUID, bytes] | LifecycleTransitionRefused:
            try:
                return await store.transition(
                    pack_id=rec.id,
                    transition="submit",
                    actor_id=label,
                    tenant_id=None,
                    evidence_pointer=None,
                    request_id=f"req-race-{label}",
                )
            except LifecycleTransitionRefused as exc:
                return exc

        # Fire two parallel calls. With FOR UPDATE row locking on the
        # packs row + the chain-head FOR UPDATE on
        # governance_chain_heads, exactly one wins.
        results = await asyncio.gather(_do_submit("a"), _do_submit("b"))

        wins = [r for r in results if not isinstance(r, LifecycleTransitionRefused)]
        losses = [r for r in results if isinstance(r, LifecycleTransitionRefused)]
        assert len(wins) == 1, f"expected exactly one winner; got {len(wins)} results={results}"
        assert len(losses) == 1, f"expected exactly one loser; got {len(losses)} results={results}"
        # The loser's reason is the generic invalid-state-pair fallthrough
        # because by the time it ran, packs.state was already 'submitted'
        # so its (submitted, submitted) is invalid for transition='submit'.
        assert losses[0].reason == "lifecycle_transition_invalid_state_pair"

        # Chain count incremented exactly once (winner only; loser
        # rolled back).
        chain_count_sql = (
            "SELECT COUNT(*) FROM decision_history WHERE event_type LIKE 'pack.lifecycle.%'"
        )
        async with engine.connect() as conn:
            chain_count = (await conn.execute(text(chain_count_sql))).scalar_one()
        assert chain_count == 1, f"expected 1 chain row; got {chain_count}"

        # Final state cache reflects the winner.
        loaded = await store.load(rec.id)
        assert loaded is not None
        assert loaded.state == "submitted"
    finally:
        await engine.dispose()


@pytest.mark.postgres
@_PG_SKIPIF
async def test_postgres_row_lock_serialises_competing_transitions() -> None:
    await _canary_row_lock_serialisation("postgres")


@pytest.mark.oracle
@_ORACLE_SKIPIF
async def test_oracle_row_lock_serialises_competing_transitions() -> None:
    await _canary_row_lock_serialisation("oracle")


# ---- canary 2: pack-row lock isolation proof (T3 R1 P2 #3) -----------


async def _canary_pack_row_lock_blocks_competing_transition(driver: str) -> None:
    """Barrier-based proof that the precondition's
    ``SELECT ... FOR UPDATE`` actually acquires a row lock BEFORE
    state is read — not just before the subsequent UPDATE issues.
    Strengthened from the original T3 R1 P2 #3 design at T3 R2 P2:
    the original design only proved T2 eventually blocks SOMEWHERE
    in its precondition flow; it could not distinguish "T2 read
    state under the lock" from "T2 read state stale (MVCC) and
    blocked later at the UPDATE". The strengthened design below
    forces T1 to MUTATE state under the lock to a value that makes
    T2's requested transition INVALID, so the only way T2 sees
    that mutation is if T2's SELECT itself acquires the row lock.

    Setup:
      - T1 acquires a raw ``SELECT ... FOR UPDATE`` on the pack row,
        then UPDATEs ``state`` to ``"withdrawn"`` (a state from which
        ``transition="submit"`` is INVALID — falls through the
        validator's per-transition checks to
        ``lifecycle_transition_invalid_state_pair``). T1 holds the
        transaction open via a release barrier.
      - T2 calls :meth:`PackRecordStore.transition` with
        ``transition="submit"``. Internally T2 acquires the
        chain-head FOR UPDATE freely (T1 doesn't hold it), then
        attempts the precondition's ``SELECT ... FOR UPDATE`` on
        the same pack row.

    Expected with CORRECT precondition (``with_for_update()`` on the
    SELECT, defence-in-depth UPDATE after):
      - T2's precondition SELECT BLOCKS on T1's row lock.
      - After ``t1_release`` → T1 commits ``state="withdrawn"``;
        row lock released.
      - T2's SELECT FOR UPDATE returns the post-T1 state
        (``"withdrawn"``) under the lock.
      - ``validate_transition(from="withdrawn", to="submitted",
        kind="tool", "submit")`` returns
        ``"lifecycle_transition_invalid_state_pair"`` (no edge
        ``withdrawn → submitted`` for the ``submit`` transition).
      - T2's precondition raises
        :class:`LifecycleTransitionRefused`; transaction rolls back;
        no chain row inserted; ``packs.state`` remains
        ``"withdrawn"`` (T1's value preserved).

    Expected with BROKEN precondition (``with_for_update()`` removed
    from the SELECT):
      - T2's precondition SELECT is an MVCC snapshot read; reads
        STALE pre-T1 state (``"draft"``); does NOT block.
      - ``validate_transition(from="draft", to="submitted",
        "submit")`` returns ``None`` (legal: ``draft → submitted``).
      - T2's UPDATE BLOCKS on T1's row lock.
      - After T1 commits, T2's UPDATE proceeds, OVERWRITING T1's
        ``"withdrawn"`` with ``"submitted"``. T2 succeeds. Chain row
        is INSERTED with payload ``{from_state: "draft", ...}`` —
        FALSIFIED audit (the row never came from ``draft`` at the
        moment T2's transition committed). Final state is
        ``"submitted"`` (T1's update LOST).

    Distinguishing assertions (each catches the broken-precondition
    case independently):
      1. ``isinstance(t2_result, LifecycleTransitionRefused)`` — T2
         must REFUSE because it read post-T1 ``"withdrawn"`` under
         the lock. If T2 succeeded, the SELECT was stale-read.
      2. ``t2_result.reason == "lifecycle_transition_invalid_state_pair"``
         — confirms the closed-enum dispatch path the validator
         actually fired.
      3. Chain count for ``pack.lifecycle.%`` rows unchanged across
         T2 — refused transitions roll back; no chain row written.
         Specifically catches the FALSIFIED-CHAIN scenario.
      4. ``loaded.state == "withdrawn"`` after — T1's update is
         preserved (T2 didn't overwrite). Specifically catches the
         LOST-UPDATE scenario.

    This is the proper Doctrine Lock D step 1 proof per T3 R2 P2
    reviewer feedback (the original T3 R1 P2 #3 canary was
    insufficient because it could not catch stale pre-lock reads).
    The chain-head lock isolation (T1 never touches the chain-head
    row) is preserved from the original design — T2's precondition
    blocking under contention is on the PACK row exclusively."""

    # PROBE_WINDOW_S — how long we wait to confirm T2 blocks.
    # Generous enough to absorb test-host scheduling jitter under
    # load (CI on a busy runner) but short enough to keep the suite
    # snappy. If T2's transition() did NOT contend with T1 at all,
    # T2 completes in low milliseconds — three orders of magnitude
    # under this window.
    PROBE_WINDOW_S = 1.5
    BARRIER_TIMEOUT_S = 10.0
    # State T1 advances to under its FOR UPDATE lock. Chosen because:
    # a) It's a member of the canonical 11-tuple PackState (CHECK
    #    constraint accepts the raw UPDATE).
    # b) ``submit`` from ``withdrawn`` is INVALID per the validator
    #    (no edge in _VALID_TRANSITIONS["submit"] from withdrawn);
    #    falls to the generic invalid_state_pair fallthrough.
    # c) ``withdrawn`` is observably distinct from both ``"draft"``
    #    (the pre-T1 state) and ``"submitted"`` (T2's intended
    #    target), so the lost-update + falsified-chain scenarios are
    #    mutually-exclusively detectable.
    T1_STATE_ADVANCE = "withdrawn"

    engine = create_async_engine(_superuser_url(driver), pool_size=4, max_overflow=0)
    try:
        await _reset_state(engine)
        store = PackRecordStore(engine)
        rec = _make_record()
        await store.save_draft(rec)

        t1_acquired = asyncio.Event()
        t1_release = asyncio.Event()

        async def t1_hold_then_advance() -> None:
            async with engine.begin() as conn1:
                # 1. Acquire pack-row FOR UPDATE.
                row = (
                    await conn1.execute(
                        select(_packs.c.id).where(_packs.c.id == rec.id).with_for_update()
                    )
                ).first()
                assert row is not None, "T1 setup: pack row not found"
                # 2. Mutate state under the lock to a value that
                # makes T2's requested 'submit' invalid. The mutation
                # is intentionally a raw SQL UPDATE bypassing the
                # lifecycle validator — the test's purpose is to
                # exercise lock semantics, not lifecycle correctness.
                await conn1.execute(
                    update(_packs).where(_packs.c.id == rec.id).values(state=T1_STATE_ADVANCE)
                )
                t1_acquired.set()
                # 3. Hold the row lock + uncommitted state until the
                # main test releases us.
                await t1_release.wait()
            # async-with exits → T1 commits → state="withdrawn"
            # persisted → row lock released → T2 unblocks.

        async def t2_attempt_transition() -> tuple[uuid.UUID, bytes] | LifecycleTransitionRefused:
            try:
                return await store.transition(
                    pack_id=rec.id,
                    transition="submit",
                    actor_id="t2",
                    tenant_id=None,
                    evidence_pointer=None,
                    request_id="req-t2-blocked",
                )
            except LifecycleTransitionRefused as exc:
                return exc

        try:
            t1_task = asyncio.create_task(t1_hold_then_advance())
            await asyncio.wait_for(t1_acquired.wait(), timeout=BARRIER_TIMEOUT_S)

            # Capture the post-save_draft chain count BEFORE T2
            # starts so we can assert no chain row is emitted by
            # T2's refused transition.
            chain_count_before = await _count_lifecycle_chain_rows(engine)

            t2_task = asyncio.create_task(t2_attempt_transition())
            # Probe window: T2 must be PENDING (blocked on the
            # pack-row lock). This catches the case where T2's
            # precondition does not contend with T1 at all.
            await asyncio.sleep(PROBE_WINDOW_S)
            assert not t2_task.done(), (
                "transition() did not block on the pack-row FOR UPDATE held "
                "by T1; Doctrine Lock D step 1 future-writer safety "
                "guarantee broken"
            )

            # Release T1; T1 commits state="withdrawn"; T2 unblocks.
            t1_release.set()
            await asyncio.wait_for(t1_task, timeout=BARRIER_TIMEOUT_S)
            t2_result = await asyncio.wait_for(t2_task, timeout=BARRIER_TIMEOUT_S)

            # ASSERTION 1 — T2 REFUSED (read state under the lock).
            # If T2 succeeded, its precondition SELECT was a stale
            # MVCC snapshot read — broken-precondition case.
            assert isinstance(t2_result, LifecycleTransitionRefused), (
                f"T2 must refuse — it read state under the FOR UPDATE lock "
                f"and saw T1's post-commit state ({T1_STATE_ADVANCE!r}). "
                f"If T2 succeeded, the precondition's SELECT did not acquire "
                f"the row lock and read STALE 'draft' instead, letting T2 "
                f"mistakenly transition over T1's update. Got: {t2_result!r}"
            )
            # ASSERTION 2 — Closed-enum reason matches the validator
            # path that actually fired (validator received
            # from_state=withdrawn, to_state=submitted, transition='submit').
            assert t2_result.reason == "lifecycle_transition_invalid_state_pair", (
                f"T2 refused but with the wrong reason — expected the "
                f"invalid-state-pair fallthrough from validate_transition's "
                f"(withdrawn, submitted) check; got {t2_result.reason!r}"
            )
            # ASSERTION 3 — No chain row inserted by T2 (refusal
            # rolled back). Specifically catches the FALSIFIED-CHAIN
            # scenario: a stale-read T2 would emit a row with
            # from_state='draft' even though state was 'withdrawn'
            # at commit time.
            chain_count_after = await _count_lifecycle_chain_rows(engine)
            assert chain_count_after == chain_count_before, (
                f"T2's refused transition emitted a chain row — the precondition "
                f"refusal did not roll back the transaction. chain rows: "
                f"before={chain_count_before}, after={chain_count_after}"
            )
            # ASSERTION 4 — Final state preserves T1's update. T2's
            # intended UPDATE never fired (precondition refused).
            # Specifically catches the LOST-UPDATE scenario where a
            # stale-read T2 would overwrite T1's value.
            loaded = await store.load(rec.id)
            assert loaded is not None
            assert loaded.state == T1_STATE_ADVANCE, (
                f"final state should be T1's value ({T1_STATE_ADVANCE!r}); got "
                f"{loaded.state!r}. T2 overwrote T1's update — lost-update "
                f"violation, indicates T2's precondition was stale-read."
            )
        finally:
            # Defence-in-depth: ensure T1 never leaks even on test
            # failure (e.g., if any assertion above fires, T2 would
            # otherwise spin forever).
            t1_release.set()
    finally:
        await engine.dispose()


async def _count_lifecycle_chain_rows(engine: AsyncEngine) -> int:
    """Count ``decision_history`` rows whose event_type matches the
    ``pack.lifecycle.*`` family. Used by the barrier canary to assert
    that a refused transition does NOT emit a chain row."""
    sql = "SELECT COUNT(*) FROM decision_history WHERE event_type LIKE 'pack.lifecycle.%'"
    async with engine.connect() as conn:
        return int((await conn.execute(text(sql))).scalar_one())


@pytest.mark.postgres
@_PG_SKIPIF
async def test_postgres_pack_row_lock_blocks_competing_transition() -> None:
    await _canary_pack_row_lock_blocks_competing_transition("postgres")


@pytest.mark.oracle
@_ORACLE_SKIPIF
async def test_oracle_pack_row_lock_blocks_competing_transition() -> None:
    await _canary_pack_row_lock_blocks_competing_transition("oracle")


# ---- canary 3 + 4: CHECK constraint enforcement ----------------------


async def _canary_check_constraint_kind(driver: str) -> None:
    """Direct INSERT with ``kind='workflow'`` raises ``IntegrityError``
    at the database layer — Doctrine Lock E layer 2 / 3."""

    engine = create_async_engine(_superuser_url(driver), pool_size=2, max_overflow=0)
    try:
        await _reset_state(engine)
        with pytest.raises(IntegrityError):
            async with engine.begin() as conn:
                await conn.execute(
                    _packs.insert().values(
                        id=uuid.uuid4(),
                        kind="workflow",  # not in the canonical 4-tuple
                        pack_id="canary",
                        display_name="canary",
                        state="draft",
                        manifest_digest=b"\x01" * 32,
                        signed_artefact_digest=b"\x02" * 32,
                        sbom_pointer=None,
                        tenant_id=None,
                        created_by="c",
                        last_actor="c",
                        created_at=datetime.now(UTC),
                        updated_at=datetime.now(UTC),
                    )
                )
    finally:
        await engine.dispose()


async def _canary_check_constraint_state(driver: str) -> None:
    """Direct INSERT with ``state='quarantined'`` raises
    ``IntegrityError`` at the database layer."""

    engine = create_async_engine(_superuser_url(driver), pool_size=2, max_overflow=0)
    try:
        await _reset_state(engine)
        with pytest.raises(IntegrityError):
            async with engine.begin() as conn:
                await conn.execute(
                    _packs.insert().values(
                        id=uuid.uuid4(),
                        kind="tool",
                        pack_id="canary",
                        display_name="canary",
                        state="quarantined",  # not in the canonical 11-tuple
                        manifest_digest=b"\x01" * 32,
                        signed_artefact_digest=b"\x02" * 32,
                        sbom_pointer=None,
                        tenant_id=None,
                        created_by="c",
                        last_actor="c",
                        created_at=datetime.now(UTC),
                        updated_at=datetime.now(UTC),
                    )
                )
    finally:
        await engine.dispose()


@pytest.mark.postgres
@_PG_SKIPIF
async def test_postgres_check_constraint_rejects_unknown_kind() -> None:
    await _canary_check_constraint_kind("postgres")


@pytest.mark.postgres
@_PG_SKIPIF
async def test_postgres_check_constraint_rejects_unknown_state() -> None:
    await _canary_check_constraint_state("postgres")


@pytest.mark.oracle
@_ORACLE_SKIPIF
async def test_oracle_check_constraint_rejects_unknown_kind() -> None:
    await _canary_check_constraint_kind("oracle")


@pytest.mark.oracle
@_ORACLE_SKIPIF
async def test_oracle_check_constraint_rejects_unknown_state() -> None:
    await _canary_check_constraint_state("oracle")


# ---- canary 5: deterministic update_draft contention (Sprint 7B.2 T4) ----


async def _canary_update_draft_blocks_behind_row_lock_and_refuses(
    driver: str,
) -> None:
    """Sprint 7B.2 T4 plan §"Atomicity specification (Round 4 P2 #3)"
    + halt-summary watchpoint (g) — T4 R2 P2 #2 rewrite using the
    deterministic barrier-based pattern from
    :func:`_canary_pack_row_lock_blocks_competing_transition`.

    Pre-R2: this canary used :func:`asyncio.gather` with no barrier
    or lock orchestration. It accepted the "both succeed" sequential-
    smoke-test outcome, which would have passed even if
    ``update_draft`` failed to honour its ``WHERE state='draft'``
    precondition — the reviewer correctly flagged this as not
    proving contention.

    The barrier-based design forces the race deterministically:

    1. T1 (lock-holder, raw SQL — bypasses the lifecycle validator
       intentionally; the test exercises lock semantics, not the
       validator): acquires ``SELECT ... FOR UPDATE`` on the pack
       row inside an open transaction, then mutates state to
       ``"submitted"`` under the lock. Signals ``t1_acquired`` and
       awaits ``t1_release``.
    2. Main: probes that T2 is PENDING — if T2's atomic UPDATE did
       not contend with T1's row lock, T2 completes in low ms,
       failing the probe assertion.
    3. T2 (the system-under-test): calls
       :meth:`PackRecordStore.update_draft` with a non-empty updates
       dict. update_draft's atomic ``UPDATE packs SET ... WHERE id=...
       AND state='draft'`` blocks waiting for T1's row lock.
    4. Main: releases ``t1_release``. T1 commits state=``"submitted"``
       and releases its row lock.
    5. T2 unblocks. Its UPDATE matches WHERE id=... AND
       state='draft' against the now-``submitted`` row — rowcount=0.
       The Step-4 disambiguation SELECT observes state=``"submitted"``
       and raises :class:`PackRecordRefused` with reason
       ``pack_record_update_non_draft_state``.

    Five assertions pin the contract:

    - **PENDING probe** — T2 must NOT complete during the PROBE_WINDOW;
      if it does, ``update_draft``'s atomic UPDATE did not contend
      with T1's row lock at all (the WHERE-state-draft precondition
      would be a stale-read instead of an under-lock read).
    - **Refusal class + closed-enum reason** —
      :class:`PackRecordRefused` with reason
      ``pack_record_update_non_draft_state``. Any other refusal
      (or success) means the rowcount-disambiguation SELECT misread
      the post-commit state.
    - **Chain count unchanged** — neither T1 (raw SQL) nor T2
      (update_draft refused before its UPDATE landed) emits a chain
      row. Genesis-state pattern preserved under contention.
    - **Final state = "submitted"** — T1's update is preserved;
      T2's refused UPDATE did NOT overwrite (LOST-UPDATE scenario
      negative pin).
    - **last_actor preserved** — T2's refused UPDATE did not bump
      ``last_actor``; the value remains the pre-T1 ``"canary"`` from
      ``save_draft`` (T1's raw SQL UPDATE only touched ``state``).

    SQLite cannot honour row-level ``FOR UPDATE`` locking (database-
    level locks only), so this proof requires real Postgres or Oracle.
    """

    from cognic_agentos.packs.storage import PackRecordRefused

    PROBE_WINDOW_S = 1.5
    BARRIER_TIMEOUT_S = 10.0
    T1_STATE_ADVANCE = "submitted"

    engine = create_async_engine(_superuser_url(driver), pool_size=4, max_overflow=0)
    try:
        await _reset_state(engine)
        store = PackRecordStore(engine)
        rec = _make_record()
        await store.save_draft(rec)

        # Capture the pre-T1 last_actor for the final-state assertion.
        original_last_actor = rec.last_actor

        t1_acquired = asyncio.Event()
        t1_release = asyncio.Event()

        async def t1_hold_then_advance_state() -> None:
            async with engine.begin() as conn1:
                # 1. Acquire pack-row FOR UPDATE.
                row = (
                    await conn1.execute(
                        select(_packs.c.id).where(_packs.c.id == rec.id).with_for_update()
                    )
                ).first()
                assert row is not None, "T1 setup: pack row not found"
                # 2. Raw SQL UPDATE advances state under the lock.
                # Bypasses the lifecycle validator intentionally —
                # this test exercises lock semantics, not state-
                # machine correctness. Critically: does NOT touch
                # last_actor or updated_at, so the final-state
                # assertion can distinguish T1's contribution from
                # any rogue T2 mutation.
                await conn1.execute(
                    update(_packs).where(_packs.c.id == rec.id).values(state=T1_STATE_ADVANCE)
                )
                t1_acquired.set()
                # 3. Hold the row lock + uncommitted state until the
                # main test releases us.
                await t1_release.wait()
            # async-with exits → T1 commits → state="submitted"
            # persisted → row lock released → T2 unblocks.

        async def t2_attempt_update_draft() -> Exception | None:
            try:
                await store.update_draft(
                    pack_id=rec.id,
                    updates={"display_name": "T2-Attempted-Rename"},
                    actor_id="t2-update-actor",
                )
                return None  # T2 reached success — FORBIDDEN
            except PackRecordRefused as exc:
                return exc
            except Exception as exc:
                # Any other exception class is a bug — surface it
                # for the assertion below.
                return exc

        try:
            t1_task = asyncio.create_task(t1_hold_then_advance_state())
            await asyncio.wait_for(t1_acquired.wait(), timeout=BARRIER_TIMEOUT_S)

            chain_count_before = await _count_lifecycle_chain_rows(engine)

            t2_task = asyncio.create_task(t2_attempt_update_draft())

            # PENDING probe — T2's atomic UPDATE must block on T1's
            # row lock during the probe window. If T2 completes,
            # update_draft's WHERE-state-draft predicate was a stale-
            # read (not under the row lock), violating the
            # plan §"Atomicity specification" contract.
            await asyncio.sleep(PROBE_WINDOW_S)
            assert not t2_task.done(), (
                "update_draft did not block on the pack-row FOR UPDATE held "
                "by T1; update_draft's atomic UPDATE failed to honour the "
                "row lock. Plan §'Atomicity specification' Step 3 contract "
                "broken — WHERE state='draft' must read under the lock, "
                "not from a stale MVCC snapshot."
            )

            # Release T1 → T1 commits state="submitted" → T2 unblocks.
            t1_release.set()
            await asyncio.wait_for(t1_task, timeout=BARRIER_TIMEOUT_S)
            t2_result = await asyncio.wait_for(t2_task, timeout=BARRIER_TIMEOUT_S)

            # ASSERTION 1 — T2 refused (read state under the lock).
            assert isinstance(t2_result, PackRecordRefused), (
                f"T2 must refuse with PackRecordRefused — it read state "
                f"under the FOR UPDATE lock and saw T1's post-commit "
                f"state ({T1_STATE_ADVANCE!r}). If T2 succeeded, the "
                f"atomic UPDATE's WHERE predicate did not see the "
                f"post-commit state. Got: {t2_result!r}"
            )

            # ASSERTION 2 — Closed-enum reason matches the rowcount-
            # disambiguation refusal (Step 4: UPDATE rowcount=0 →
            # follow-up SELECT observes state='submitted' →
            # pack_record_update_non_draft_state).
            assert t2_result.reason == "pack_record_update_non_draft_state", (
                f"T2 refused but with the wrong reason — expected "
                f"the rowcount-disambiguation Step-4 reason "
                f"'pack_record_update_non_draft_state' (the follow-up "
                f"SELECT should see state='submitted'); "
                f"got {t2_result.reason!r}"
            )
            # The exception also carries the live state — pin it
            # so a future regression in the disambiguation SELECT
            # surfaces.
            assert t2_result.state == T1_STATE_ADVANCE, (
                f"PackRecordRefused.state field should carry the "
                f"actual non-draft state observed by the follow-up "
                f"SELECT; got {t2_result.state!r}, expected "
                f"{T1_STATE_ADVANCE!r}"
            )

            # ASSERTION 3 — No chain rows emitted. Neither T1 (raw
            # SQL UPDATE) nor T2 (update_draft refused) writes to
            # decision_history. Genesis-state pattern preserved
            # under contention.
            chain_count_after = await _count_lifecycle_chain_rows(engine)
            assert chain_count_after == chain_count_before, (
                f"update_draft contention must not emit chain rows. "
                f"chain rows: before={chain_count_before}, "
                f"after={chain_count_after}"
            )

            # ASSERTION 4 — Final state is T1's value. T2's refused
            # UPDATE never landed — LOST-UPDATE scenario negative pin.
            loaded = await store.load(rec.id)
            assert loaded is not None
            assert loaded.state == T1_STATE_ADVANCE, (
                f"final state should be T1's value ({T1_STATE_ADVANCE!r}); "
                f"got {loaded.state!r}. T2's refused UPDATE wrote anyway — "
                f"plan §'Atomicity specification' Step 3 violated."
            )

            # ASSERTION 5 — last_actor preserved as the original
            # save_draft value. T2's refused UPDATE did not bump
            # last_actor (the auto-bump only fires if the UPDATE
            # actually matched a row). T1's raw SQL deliberately
            # did not touch last_actor.
            assert loaded.last_actor == original_last_actor, (
                f"last_actor should remain the original save_draft "
                f"value ({original_last_actor!r}); got "
                f"{loaded.last_actor!r}. T2's refused UPDATE bumped "
                f"last_actor anyway — atomicity violation."
            )
        finally:
            # Defence-in-depth: ensure T1 never leaks even on
            # assertion failure (otherwise T2 would spin forever
            # waiting on the row lock).
            t1_release.set()
    finally:
        await engine.dispose()


@pytest.mark.postgres
@_PG_SKIPIF
async def test_postgres_update_draft_blocks_behind_row_lock_and_refuses() -> None:
    await _canary_update_draft_blocks_behind_row_lock_and_refuses("postgres")


@pytest.mark.oracle
@_ORACLE_SKIPIF
async def test_oracle_update_draft_blocks_behind_row_lock_and_refuses() -> None:
    await _canary_update_draft_blocks_behind_row_lock_and_refuses("oracle")
